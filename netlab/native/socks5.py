"""
netlab.native.socks5 — SOCKS5 front-end and tunnel exit node.

Why SOCKS5 rather than a TUN device
────────────────────────────────────
A TUN adapter captures every packet the machine sends, which is what a real
VPN does — but on Windows it means loading wintun.dll through ctypes and
driving its ring-buffer API, and `python-pytun` is Linux-only.  A SOCKS5 proxy
needs no driver, no admin rights, and is demonstrable immediately: point a
browser at 127.0.0.1:1080 and its traffic goes through the tunnel we built.

The trade is honest and worth stating: this tunnels *applications that speak
SOCKS5*, not the whole device.  Traffic from anything not configured to use
the proxy still goes out in the clear.

Shape
─────
    browser ──TCP──▶ Socks5Proxy ──inner frames──▶ [encrypted UDP tunnel]
                                                            │
                     ExitNode ◀───────────────────────────-─┘
                        │
                        └──TCP──▶ origin server

Stream multiplexing
───────────────────
Many TCP connections share one tunnel, so each gets a stream_id and every
inner frame carries it.  This is the same demultiplexing idea as a port
number, one layer up — and the reason the inner frame header exists at all.

RFC 1928, the parts we implement
─────────────────────────────────
    greeting   client → 05 NMETHODS METHODS...
    choice     server → 05 00                  (no authentication)
    request    client → 05 01 00 ATYP ADDR PORT   (01 = CONNECT)
    reply      server → 05 REP 00 01 BND.ADDR BND.PORT

CONNECT only.  BIND and UDP ASSOCIATE are refused with 0x07 (command not
supported) — implementing them would add surface without adding a concept.
No authentication, because the listener is bound to loopback.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import struct
import threading
from typing import Callable

from .protocol import (
    FRAME_CLOSE,
    FRAME_DATA,
    FRAME_OPEN,
    MAX_TUNNEL_PAYLOAD,
    chunk_payload,
    pack_inner,
    unpack_inner,
)

logger = logging.getLogger(__name__)

SOCKS_VERSION = 5
CMD_CONNECT = 1
ATYP_IPV4 = 1
ATYP_DOMAIN = 3
ATYP_IPV6 = 4

REPLY_OK = 0
REPLY_GENERAL_FAILURE = 1
REPLY_HOST_UNREACHABLE = 4
REPLY_CONNECTION_REFUSED = 5
REPLY_CMD_NOT_SUPPORTED = 7

#: Read size for relaying.
#:
#: Deliberately equal to MAX_TUNNEL_PAYLOAD so one read becomes exactly one
#: frame in one datagram.  Reading more and framing it whole produces an
#: oversized datagram that IP fragments; losing one fragment then truncates
#: the TCP stream we are carrying, with no error anywhere.
_CHUNK = MAX_TUNNEL_PAYLOAD

SendFrame = Callable[[bytes], bool]


def _recv_exactly(sock: socket.socket, count: int) -> bytes:
    """Read exactly *count* bytes or raise — TCP gives no message boundaries."""
    chunks = []
    remaining = count
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError(f"peer closed after {count - remaining}/{count} B")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def parse_target(payload: bytes) -> tuple[str, int]:
    """Parse a b'host:port' FRAME_OPEN payload."""
    text = payload.decode("utf-8", "replace")
    host, _, port = text.rpartition(":")
    if not host or not port.isdigit():
        raise ValueError(f"malformed target {text!r}")
    return host, int(port)


class Socks5Proxy:
    """
    Local SOCKS5 listener that forwards each connection over the tunnel.

    One thread per accepted connection.  That is the simplest model that is
    obviously correct, and at demo concurrency the thread-per-connection cost
    is irrelevant — oslab.concurrency covers where it stops being irrelevant.
    """

    def __init__(self, send_frame: SendFrame,
                 bind: tuple[str, int] = ("127.0.0.1", 1080)) -> None:
        self.send_frame = send_frame
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(bind)
        self._sock.listen(64)
        self.address = self._sock.getsockname()
        self._streams: dict[int, socket.socket] = {}
        self._lock = threading.Lock()
        self._next_id = 1
        self._running = False
        self._thread: threading.Thread | None = None
        self.streams_opened = 0

    # ── lifecycle ────────────────────────────────────────────────────────────

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(
            target=self._accept_loop, name="socks5-accept", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        try:
            self._sock.close()
        except OSError:
            pass
        with self._lock:
            for stream in list(self._streams.values()):
                try:
                    stream.close()
                except OSError:
                    pass
            self._streams.clear()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def __enter__(self) -> "Socks5Proxy":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    # ── accept ───────────────────────────────────────────────────────────────

    def _accept_loop(self) -> None:
        self._sock.settimeout(0.2)
        while self._running:
            try:
                client, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._serve, args=(client,), daemon=True
            ).start()

    def _serve(self, client: socket.socket) -> None:
        try:
            target = self._negotiate(client)
        except (ConnectionError, OSError, ValueError) as exc:
            logger.debug("socks5 negotiation failed: %s", exc)
            client.close()
            return

        with self._lock:
            stream_id = self._next_id
            self._next_id += 1
            self._streams[stream_id] = client
            self.streams_opened += 1

        host, port = target
        self.send_frame(pack_inner(FRAME_OPEN, stream_id, f"{host}:{port}".encode()))

        # RFC 1928 wants the bound address; loopback is a legitimate answer and
        # no client we care about inspects it.
        client.sendall(struct.pack("!BBBB", SOCKS_VERSION, REPLY_OK, 0, ATYP_IPV4)
                       + socket.inet_aton("127.0.0.1") + struct.pack("!H", 0))

        self._pump(stream_id, client)

    def _negotiate(self, client: socket.socket) -> tuple[str, int]:
        version, n_methods = struct.unpack("!BB", _recv_exactly(client, 2))
        if version != SOCKS_VERSION:
            raise ValueError(f"not SOCKS5 (version {version})")
        _recv_exactly(client, n_methods)
        client.sendall(struct.pack("!BB", SOCKS_VERSION, 0))  # no auth

        version, command, _, atyp = struct.unpack("!BBBB", _recv_exactly(client, 4))
        if version != SOCKS_VERSION:
            raise ValueError(f"not SOCKS5 (version {version})")
        if command != CMD_CONNECT:
            client.sendall(struct.pack("!BBBB", SOCKS_VERSION,
                                       REPLY_CMD_NOT_SUPPORTED, 0, ATYP_IPV4)
                           + b"\x00" * 6)
            raise ValueError(f"unsupported command {command}")

        if atyp == ATYP_IPV4:
            host = socket.inet_ntoa(_recv_exactly(client, 4))
        elif atyp == ATYP_IPV6:
            host = socket.inet_ntop(socket.AF_INET6, _recv_exactly(client, 16))
        elif atyp == ATYP_DOMAIN:
            length = _recv_exactly(client, 1)[0]
            host = _recv_exactly(client, length).decode("idna", "replace")
        else:
            raise ValueError(f"unknown address type {atyp}")

        port = struct.unpack("!H", _recv_exactly(client, 2))[0]
        return host, port

    def _pump(self, stream_id: int, client: socket.socket) -> None:
        """Relay client → tunnel until the client closes."""
        try:
            while self._running:
                data = client.recv(_CHUNK)
                if not data:
                    break
                for frame in chunk_payload(FRAME_DATA, stream_id, data):
                    self.send_frame(frame)
        except OSError:
            pass
        finally:
            self.send_frame(pack_inner(FRAME_CLOSE, stream_id, b""))
            self._drop(stream_id)

    # ── tunnel → client ──────────────────────────────────────────────────────

    def on_frame(self, kind: int, stream_id: int, payload: bytes) -> None:
        """Deliver a frame that arrived from the tunnel to its local socket."""
        with self._lock:
            client = self._streams.get(stream_id)
        if client is None:
            return
        if kind == FRAME_DATA:
            try:
                client.sendall(payload)
            except OSError:
                self._drop(stream_id)
        elif kind == FRAME_CLOSE:
            # Half-close, do not drop.
            #
            # TCP connections close in each direction independently. The origin
            # closing means "I have no more to send" — it says nothing about
            # data already in flight towards the client. Hard-closing here
            # discards whatever the client has not yet read, which on Windows
            # surfaces as a connection reset on the client's next recv: the
            # response is delivered and then destroyed a moment later.
            #
            # shutdown(SHUT_WR) sends a FIN instead. The client drains what is
            # buffered, sees EOF, and closes its own side; _pump then exits and
            # cleans up.
            try:
                client.shutdown(socket.SHUT_WR)
            except OSError:
                self._drop(stream_id)

    def _drop(self, stream_id: int) -> None:
        with self._lock:
            client = self._streams.pop(stream_id, None)
        if client is not None:
            try:
                client.close()
            except OSError:
                pass


class ExitNode:
    """
    Server-side end of the tunnel: opens real TCP connections and relays.

    This is the piece that makes the destination see the *server's* address
    instead of the client's — the actual point of a VPN, reduced to its
    essentials.
    """

    def __init__(self, send_frame: SendFrame) -> None:
        self.send_frame = send_frame
        self._streams: dict[int, socket.socket] = {}
        # Data can overtake the connect. FRAME_OPEN spawns a thread that dials
        # the origin, and the client's first FRAME_DATA often arrives before
        # that dial returns — a SOCKS5 client sends its request the moment it
        # gets the reply. Without somewhere to put those bytes they are simply
        # dropped and the stream hangs. Pending buffers hold them until the
        # socket exists.
        self._pending: dict[int, list[bytes]] = {}
        self._closing: set[int] = set()
        self._lock = threading.Lock()
        self._running = True
        self.streams_opened = 0
        self.connect_failures = 0
        self.buffered_early_frames = 0

    def stop(self) -> None:
        self._running = False
        with self._lock:
            self._pending.clear()
            self._closing.clear()
            for stream in list(self._streams.values()):
                try:
                    stream.close()
                except OSError:
                    pass
            self._streams.clear()

    def on_frame(self, kind: int, stream_id: int, payload: bytes) -> None:
        if kind == FRAME_OPEN:
            with self._lock:
                # Register the pending buffer synchronously, before the dial
                # thread starts, so no window exists where data has nowhere
                # to go.
                self._pending.setdefault(stream_id, [])
            threading.Thread(
                target=self._open, args=(stream_id, payload), daemon=True
            ).start()
        elif kind == FRAME_DATA:
            with self._lock:
                upstream = self._streams.get(stream_id)
                if upstream is None:
                    if stream_id in self._pending:
                        self._pending[stream_id].append(payload)
                        self.buffered_early_frames += 1
                    return
            try:
                upstream.sendall(payload)
            except OSError:
                self._close(stream_id)
        elif kind == FRAME_CLOSE:
            with self._lock:
                # A close can also overtake the connect. Mark it and let the
                # dial thread tear down once it has flushed.
                if stream_id in self._pending and stream_id not in self._streams:
                    self._closing.add(stream_id)
                    return
            self._close(stream_id)

    def _open(self, stream_id: int, payload: bytes) -> None:
        try:
            host, port = parse_target(payload)
            upstream = socket.create_connection((host, port), timeout=10)
        except (OSError, ValueError) as exc:
            logger.debug("exit node could not connect: %s", exc)
            self.connect_failures += 1
            with self._lock:
                self._pending.pop(stream_id, None)
                self._closing.discard(stream_id)
            self.send_frame(pack_inner(FRAME_CLOSE, stream_id, b""))
            return

        with self._lock:
            self._streams[stream_id] = upstream
            self.streams_opened += 1
            early = self._pending.pop(stream_id, [])
            close_requested = stream_id in self._closing
            self._closing.discard(stream_id)

        # Flush anything that arrived while we were dialling, in order.
        try:
            for chunk in early:
                upstream.sendall(chunk)
        except OSError:
            self._close(stream_id)
            return

        if close_requested:
            try:
                upstream.shutdown(socket.SHUT_WR)
            except OSError:
                pass

        try:
            while self._running:
                data = upstream.recv(_CHUNK)
                if not data:
                    break
                for frame in chunk_payload(FRAME_DATA, stream_id, data):
                    self.send_frame(frame)
        except OSError:
            pass
        finally:
            self.send_frame(pack_inner(FRAME_CLOSE, stream_id, b""))
            self._close(stream_id)

    def _close(self, stream_id: int) -> None:
        with self._lock:
            upstream = self._streams.pop(stream_id, None)
        if upstream is not None:
            try:
                upstream.close()
            except OSError:
                pass


def dispatch_frames(blob: bytes, handler) -> int:
    """
    Walk every inner frame packed into one transport payload.

    Returns the number of frames dispatched.  A transport packet may carry
    several frames, so the caller cannot assume one packet is one frame.
    """
    offset = 0
    count = 0
    while offset < len(blob):
        kind, stream_id, payload, consumed = unpack_inner(blob[offset:])
        handler(kind, stream_id, payload)
        offset += consumed
        count += 1
    return count
