"""
netlab.native.runner — assembles the pieces into a working tunnel.

Two entry points:

    run_server(...)   listens for handshakes, runs an ExitNode per peer
    run_client(...)   handshakes out, runs a local SOCKS5 proxy

and `LocalTunnel`, which starts both on loopback for tests and the GUI panel.

Fragmentation of inner frames
─────────────────────────────
One inner frame can hold 65535 bytes, but a UDP datagram cannot: anything over
the path MTU gets IP-fragmented, and a single lost fragment destroys the whole
datagram.  So `send_payload` splits at MAX_TUNNEL_PAYLOAD, well under a
typical 1500-byte MTU once the UDP, IP and tunnel headers are subtracted.

    1500  Ethernet MTU
    -  20  IPv4 header
    -   8  UDP header
    -  16  tunnel data header
    -  16  Poly1305 tag
    =1440  available for inner frames
    -   7  inner frame header
    =1433  payload — rounded down to 1280 for headroom on tunnelled paths

That 1280 is the same figure config/servers.json uses for WireGuard's MTU, and
for the same reason: it is the IPv6 minimum link MTU, so it survives almost
any path without fragmenting.
"""

from __future__ import annotations

import logging
import threading

from .crypto import KeyPair
from .endpoint import TunnelClient, TunnelServer
from .protocol import MAX_TUNNEL_PAYLOAD, chunk_payload  # noqa: F401 (re-export)
from .socks5 import ExitNode, Socks5Proxy, dispatch_frames

logger = logging.getLogger(__name__)



class LocalTunnel:
    """
    A client and server on loopback, wired together with a SOCKS5 front end.

    Everything runs in one process, which is what makes the tunnel
    demonstrable with no second machine and no network:

        with LocalTunnel() as tunnel:
            # tunnel.proxy_address is a live SOCKS5 proxy
    """

    def __init__(self, socks_port: int = 0, server_port: int = 0) -> None:
        self.server_static = KeyPair.generate()
        self.client_static = KeyPair.generate()

        self.server = TunnelServer(
            self.server_static, ("127.0.0.1", server_port),
            on_payload=self._server_payload,
        )
        self.server.start()

        self.client = TunnelClient(
            self.client_static, self.server_static.public, self.server.address,
            on_payload=self._client_payload,
        )
        self._exit_nodes: dict[int, ExitNode] = {}
        self._socks_port = socks_port
        self.proxy: Socks5Proxy | None = None
        self._lock = threading.Lock()

    # ── lifecycle ────────────────────────────────────────────────────────────

    def start(self, timeout: float = 5.0) -> bool:
        if not self.client.connect(timeout=timeout):
            self.stop()
            return False
        self.proxy = Socks5Proxy(self._client_send, ("127.0.0.1", self._socks_port))
        self.proxy.start()
        return True

    def stop(self) -> None:
        if self.proxy is not None:
            self.proxy.stop()
        for node in self._exit_nodes.values():
            node.stop()
        self.client.close()
        self.server.stop()

    def __enter__(self) -> "LocalTunnel":
        if not self.start():
            raise RuntimeError("tunnel handshake failed")
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    @property
    def proxy_address(self) -> tuple[str, int]:
        assert self.proxy is not None, "start() first"
        return self.proxy.address

    # ── plumbing ─────────────────────────────────────────────────────────────

    def _client_send(self, frame: bytes) -> bool:
        return self.client.send(frame)

    def _client_payload(self, payload: bytes, _sender) -> None:
        if self.proxy is not None:
            dispatch_frames(payload, self.proxy.on_frame)

    def _server_payload(self, payload: bytes, _sender) -> None:
        indices = self.server.peer_indices()
        if not indices:
            return
        index = indices[0]
        with self._lock:
            node = self._exit_nodes.get(index)
            if node is None:
                node = ExitNode(
                    lambda frame, i=index: self.server.send_to(i, frame)
                )
                self._exit_nodes[index] = node
        dispatch_frames(payload, node.on_frame)

    # ── introspection ────────────────────────────────────────────────────────

    def stats(self) -> dict:
        return {
            "client": self.client.stats(),
            "server": self.server.stats(),
            "streams": self.proxy.streams_opened if self.proxy else 0,
        }
