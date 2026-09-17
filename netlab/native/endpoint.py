"""
netlab.native.endpoint — UDP client and server for the native tunnel.

Both sides are threaded rather than asyncio, to stay consistent with the rest
of the codebase (Qt threads, oslab.concurrency) and because the socket loop is
simple enough that an event loop buys nothing.

Threading model
───────────────
    ┌──────────────┐  sendto()   ┌────────────────┐
    │ caller thread│────────────▶│  UDP socket    │
    └──────────────┘             └────────────────┘
                                          │ recvfrom()
                                          ▼
                                 ┌────────────────┐
                                 │ receive thread │──▶ on_payload callback
                                 └────────────────┘

The receive thread owns all decryption; the send path runs on whichever thread
calls `send`.  They touch the same Session, so a lock guards it — send_counter
increments and replay-window updates are both read-modify-write and would
corrupt under concurrency.  This is the same bounded-buffer/critical-section
problem oslab.concurrency demonstrates deliberately.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Callable

from .crypto import HandshakeState, InvalidTag, KeyPair
from .protocol import (
    HANDSHAKE_TIMEOUT_SECONDS,
    KEEPALIVE_SECONDS,
    MSG_HANDSHAKE_INIT,
    MSG_HANDSHAKE_RESP,
    MSG_TRANSPORT_DATA,
    SIZE_INIT,
    SIZE_RESP,
    HandshakeInit,
    HandshakeResponse,
    TransportData,
    message_type,
    pack_data,
    pack_init,
    pack_response,
    unpack_data,
    unpack_init,
    unpack_response,
)
from .session import PeerState, Session

logger = logging.getLogger(__name__)

PayloadHandler = Callable[[bytes, tuple[str, int]], None]

_MAX_DATAGRAM = 65535



#: Socket buffer size requested on both ends.
#:
#: The default UDP receive buffer is small (often 64 KiB). While the Python
#: receive thread is descheduled — which happens constantly on a loaded
#: machine — datagrams arriving faster than it drains them overflow that
#: buffer and the kernel discards them silently.
#:
#: This tunnel carries TCP *stream bytes* rather than whole IP packets, so a
#: dropped datagram removes bytes from the middle of a stream with nothing to
#: retransmit them (see protocol.py, "Not defended against"). Enlarging the
#: buffer does not make the tunnel reliable; it makes the common case stop
#: losing data, which is the difference between a demo that works and one that
#: truncates a large transfer under load.
_SOCKET_BUFFER = 1 << 21   # 2 MiB


def _tune(sock: socket.socket) -> None:
    """Request larger send/receive buffers, ignoring refusal."""
    for option in (socket.SO_RCVBUF, socket.SO_SNDBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, option, _SOCKET_BUFFER)
        except OSError:
            pass   # the OS caps this; the smaller value still works


def _random_index() -> int:
    import os
    return int.from_bytes(os.urandom(4), "little")


class TunnelServer:
    """
    Listens for handshakes and decrypts transport packets from many peers.

    Peers are keyed by their local index, which is why the index exists: it
    turns peer lookup into a dict hit rather than a scan, and it survives the
    peer changing source address.
    """

    def __init__(self, static: KeyPair, bind: tuple[str, int] = ("127.0.0.1", 51820),
                 on_payload: PayloadHandler | None = None) -> None:
        self.static = static
        self.on_payload = on_payload
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _tune(self._sock)
        self._sock.bind(bind)
        self.address = self._sock.getsockname()
        self._peers: dict[int, PeerState] = {}
        self._lock = threading.Lock()
        self._running = False
        self._thread: threading.Thread | None = None
        self.handshakes_completed = 0
        self.replays_dropped = 0
        self.forgeries_dropped = 0

    # ── lifecycle ────────────────────────────────────────────────────────────

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, name="tunnel-server", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        try:
            self._sock.close()
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def __enter__(self) -> "TunnelServer":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    # ── receive loop ─────────────────────────────────────────────────────────

    def _loop(self) -> None:
        self._sock.settimeout(0.2)
        while self._running:
            try:
                datagram, sender = self._sock.recvfrom(_MAX_DATAGRAM)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._handle(datagram, sender)
            except Exception:
                logger.exception("tunnel server failed handling a datagram")

    def _handle(self, datagram: bytes, sender: tuple[str, int]) -> None:
        try:
            kind = message_type(datagram)
        except ValueError:
            return

        if kind == MSG_HANDSHAKE_INIT and len(datagram) == SIZE_INIT:
            self._handle_initiation(datagram, sender)
        elif kind == MSG_TRANSPORT_DATA:
            self._handle_data(datagram, sender)

    def _handle_initiation(self, datagram: bytes, sender: tuple[str, int]) -> None:
        message = unpack_init(datagram)
        state = HandshakeState(self.static.public)

        # Reject junk before doing any curve arithmetic.
        if message.mac1 != state.mac1(datagram[:-16]):
            self.forgeries_dropped += 1
            return

        try:
            remote_static, timestamp = state.read_initiation(
                message.ephemeral, message.encrypted_static,
                message.encrypted_timestamp, self.static,
            )
        except (InvalidTag, ValueError):
            self.forgeries_dropped += 1
            return

        local_index = _random_index()
        ephemeral, encrypted_empty, send_key, recv_key = state.write_response()

        with self._lock:
            peer = self._find_peer_by_static(remote_static) or PeerState()
            # Handshake replay defence: the timestamp must strictly increase.
            if (peer.last_handshake_timestamp is not None
                    and timestamp <= peer.last_handshake_timestamp):
                self.forgeries_dropped += 1
                return
            peer.last_handshake_timestamp = timestamp
            peer.endpoint = sender
            peer.promote(Session(
                send_key=send_key, recv_key=recv_key,
                local_index=local_index, remote_index=message.sender_index,
                is_initiator=False,
            ))
            peer.remote_static = remote_static  # type: ignore[attr-defined]
            self._peers[local_index] = peer
            self.handshakes_completed += 1

        response = HandshakeResponse(
            sender_index=local_index,
            receiver_index=message.sender_index,
            ephemeral=ephemeral,
            encrypted_empty=encrypted_empty,
            mac1=b"\x00" * 16,
        )
        blob = pack_response(response)
        blob = blob[:-16] + state.mac1(blob[:-16])
        self._sock.sendto(blob, sender)

    def _find_peer_by_static(self, remote_static: bytes) -> PeerState | None:
        for peer in self._peers.values():
            if getattr(peer, "remote_static", None) == remote_static:
                return peer
        return None

    def _handle_data(self, datagram: bytes, sender: tuple[str, int]) -> None:
        try:
            message = unpack_data(datagram)
        except ValueError:
            return

        with self._lock:
            peer = self._peers.get(message.receiver_index)
            if peer is None:
                self.forgeries_dropped += 1
                return
            try:
                plaintext = peer.decrypt_any(
                    message.receiver_index, message.counter, message.ciphertext
                )
            except InvalidTag:
                self.forgeries_dropped += 1
                return
            if plaintext is None:
                self.replays_dropped += 1
                return
            peer.endpoint = sender
            peer.last_received = time.monotonic()

        if plaintext and self.on_payload is not None:
            self.on_payload(plaintext, sender)

    # ── send ─────────────────────────────────────────────────────────────────

    def send_to(self, local_index: int, payload: bytes) -> bool:
        """Encrypt and send *payload* to the peer identified by *local_index*."""
        with self._lock:
            peer = self._peers.get(local_index)
            if peer is None or peer.current is None or peer.endpoint is None:
                return False
            counter, ciphertext = peer.current.encrypt(payload)
            blob = pack_data(TransportData(peer.current.remote_index,
                                           counter, ciphertext))
            endpoint = peer.endpoint
            peer.last_sent = time.monotonic()
        try:
            self._sock.sendto(blob, endpoint)
        except OSError:
            # The socket closed underneath us. Relay threads outlive stop() by
            # a moment and will try to send a final FRAME_CLOSE; that is a
            # shutdown race, not a failure, and it must not surface as a
            # traceback in the middle of a demo.
            return False
        return True

    def peer_indices(self) -> list[int]:
        with self._lock:
            return list(self._peers)

    def stats(self) -> dict:
        with self._lock:
            return {
                "handshakes_completed": self.handshakes_completed,
                "replays_dropped": self.replays_dropped,
                "forgeries_dropped": self.forgeries_dropped,
                "peers": {i: p.stats() for i, p in self._peers.items()},
            }


class TunnelClient:
    """Initiates a handshake to a TunnelServer and then sends transport data."""

    def __init__(self, static: KeyPair, server_static_public: bytes,
                 server_address: tuple[str, int],
                 on_payload: PayloadHandler | None = None,
                 keepalive: int | None = None) -> None:
        self.static = static
        self.server_static_public = server_static_public
        self.server_address = server_address
        self.on_payload = on_payload
        # None means "use the configured value" — this is where
        # keepalive_interval in config/settings.json takes effect.
        from .settings import keepalive_interval
        self.keepalive = keepalive if keepalive is not None else keepalive_interval()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _tune(self._sock)
        self._sock.bind(("127.0.0.1", 0))
        self.address = self._sock.getsockname()
        self.peer = PeerState(endpoint=server_address)
        self._lock = threading.Lock()
        self._running = False
        self._thread: threading.Thread | None = None
        self._handshake_done = threading.Event()
        self.replays_dropped = 0
        self.forgeries_dropped = 0

    # ── lifecycle ────────────────────────────────────────────────────────────

    def connect(self, timeout: float | None = None) -> bool:
        """
        Run the handshake and start the receive loop.  True on success.

        None means "use connection_timeout from config/settings.json".
        """
        if timeout is None:
            from .settings import connection_timeout
            timeout = connection_timeout()
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, name="tunnel-client", daemon=True
        )
        self._thread.start()
        self._send_initiation()
        return self._handshake_done.wait(timeout)

    def close(self) -> None:
        self._running = False
        try:
            self._sock.close()
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def __enter__(self) -> "TunnelClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ── handshake ────────────────────────────────────────────────────────────

    def _send_initiation(self) -> None:
        self._state = HandshakeState(self.server_static_public)
        ephemeral, encrypted_static, encrypted_timestamp = \
            self._state.write_initiation(self.static)
        self._local_index = _random_index()
        message = HandshakeInit(
            sender_index=self._local_index,
            ephemeral=ephemeral,
            encrypted_static=encrypted_static,
            encrypted_timestamp=encrypted_timestamp,
            mac1=b"\x00" * 16,
        )
        blob = pack_init(message)
        blob = blob[:-16] + self._state.mac1(blob[:-16])
        self._sock.sendto(blob, self.server_address)

    # ── receive loop ─────────────────────────────────────────────────────────

    def _loop(self) -> None:
        self._sock.settimeout(0.2)
        while self._running:
            try:
                datagram, sender = self._sock.recvfrom(_MAX_DATAGRAM)
            except socket.timeout:
                self._maybe_keepalive()
                continue
            except OSError:
                break
            try:
                self._handle(datagram, sender)
            except Exception:
                logger.exception("tunnel client failed handling a datagram")

    def _handle(self, datagram: bytes, sender: tuple[str, int]) -> None:
        kind = message_type(datagram)
        if kind == MSG_HANDSHAKE_RESP and len(datagram) == SIZE_RESP:
            message = unpack_response(datagram)
            try:
                send_key, recv_key = self._state.read_response(
                    message.ephemeral, message.encrypted_empty, self.static
                )
            except (InvalidTag, ValueError):
                self.forgeries_dropped += 1
                return
            with self._lock:
                self.peer.promote(Session(
                    send_key=send_key, recv_key=recv_key,
                    local_index=self._local_index,
                    remote_index=message.sender_index,
                    is_initiator=True,
                ))
                self.peer.endpoint = sender
            self._handshake_done.set()

        elif kind == MSG_TRANSPORT_DATA:
            try:
                message = unpack_data(datagram)
            except ValueError:
                return
            with self._lock:
                try:
                    plaintext = self.peer.decrypt_any(
                        message.receiver_index, message.counter, message.ciphertext
                    )
                except InvalidTag:
                    self.forgeries_dropped += 1
                    return
                if plaintext is None:
                    self.replays_dropped += 1
                    return
                self.peer.last_received = time.monotonic()
            if plaintext and self.on_payload is not None:
                self.on_payload(plaintext, sender)

    # ── send ─────────────────────────────────────────────────────────────────

    def send(self, payload: bytes) -> bool:
        with self._lock:
            session = self.peer.current
            if session is None:
                return False
            counter, ciphertext = session.encrypt(payload)
            blob = pack_data(TransportData(session.remote_index, counter, ciphertext))
            endpoint = self.peer.endpoint
            self.peer.last_sent = time.monotonic()
        try:
            self._sock.sendto(blob, endpoint)
        except OSError:
            return False        # closing; see TunnelServer.send_to
        return True

    def _maybe_keepalive(self) -> None:
        """
        Send an empty transport packet if the link has been quiet.

        This is what `keepalive_interval` in config/settings.json controls.
        Its real job is refreshing the NAT mapping: a home router drops an
        idle UDP binding after 30-120 s, after which the server's replies have
        nowhere to go until the client speaks again.
        """
        with self._lock:
            if self.peer.current is None:
                return
            quiet_for = time.monotonic() - max(self.peer.last_sent,
                                               self.peer.last_received)
            if quiet_for < self.keepalive:
                return
        self.send(b"")

    def stats(self) -> dict:
        with self._lock:
            data = self.peer.stats()
        data["replays_dropped"] = self.replays_dropped
        data["forgeries_dropped"] = self.forgeries_dropped
        return data
