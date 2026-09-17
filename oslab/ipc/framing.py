"""
oslab.ipc.framing — length-prefixed message framing over a byte stream.

The problem
───────────
A pipe or a TCP connection is a byte stream, not a message stream. Write three
messages and the reader may see them as one read, or as seven. There are no
boundaries in the medium, so the protocol has to supply them.

    sender:    [msg A][msg B][msg C]
    receiver:  [msg A + first half of B]   ... then ... [rest of B][msg C]

Three standard answers exist:

    delimiter      terminate with a byte that cannot appear in the payload —
                   simple, but requires escaping, which is where bugs live
    fixed length   every message the same size — wasteful and inflexible
    length prefix  send the length first, then that many bytes  ← used here

Length prefixing is what almost every binary protocol uses: DNS over TCP, TLS
records, and the transport header in netlab.native all do exactly this.

    ┌────────────────┬──────────────────────────┐
    │ length (4 B BE)│ UTF-8 JSON payload       │
    └────────────────┴──────────────────────────┘

Why the maximum size is enforced
────────────────────────────────
The length field is attacker-controlled. A peer that claims 4 GB will make a
naive reader allocate 4 GB and die — a one-line denial of service. MAX_FRAME
caps it, and the cap is checked before any allocation.

Why reads must loop
───────────────────
`recv(n)` returns *up to* n bytes, not exactly n. Treating one read as a whole
message works in testing, where messages are small and arrive intact, and
fails in production under load. `read_exactly` loops until it has what it
asked for.
"""

from __future__ import annotations

import json
import struct
from typing import Any, Callable

LENGTH_PREFIX = 4
MAX_FRAME = 1 << 20      # 1 MiB — far more than any control message needs


class FramingError(ValueError):
    """Raised on a malformed or oversized frame."""


def encode_frame(payload: dict) -> bytes:
    """Serialise *payload* to JSON and prefix it with its length."""
    blob = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if len(blob) > MAX_FRAME:
        raise FramingError(f"frame of {len(blob)} B exceeds {MAX_FRAME} B limit")
    return struct.pack("!I", len(blob)) + blob


def decode_frame(blob: bytes) -> dict:
    """Parse a payload body (without the length prefix)."""
    try:
        value = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FramingError(f"malformed frame body: {exc}") from exc
    if not isinstance(value, dict):
        raise FramingError(f"frame body must be an object, got {type(value).__name__}")
    return value


def read_exactly(read: Callable[[int], bytes], count: int) -> bytes:
    """
    Read exactly *count* bytes, looping until satisfied.

    `read` is any callable with recv-like semantics, so this works over
    sockets, pipes and BytesIO alike.
    """
    chunks: list[bytes] = []
    remaining = count
    while remaining > 0:
        chunk = read(remaining)
        if not chunk:
            raise FramingError(
                f"stream closed after {count - remaining}/{count} bytes"
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_frame(read: Callable[[int], bytes]) -> dict:
    """Read one complete frame, however it is split across reads."""
    header = read_exactly(read, LENGTH_PREFIX)
    (length,) = struct.unpack("!I", header)
    if length > MAX_FRAME:
        # Checked before allocating: a peer claiming 4 GB must not be able to
        # make us try.
        raise FramingError(
            f"peer announced a {length} B frame, above the {MAX_FRAME} B limit"
        )
    if length == 0:
        raise FramingError("zero-length frame")
    return decode_frame(read_exactly(read, length))


class FrameBuffer:
    """
    Incremental reassembler for callers that receive bytes as they arrive.

    Feed it whatever the socket gave you; it yields whole frames as they
    complete and keeps the remainder for next time.
    """

    def __init__(self) -> None:
        self._buffer = bytearray()

    def feed(self, data: bytes) -> list[dict]:
        """Add bytes and return every frame that is now complete."""
        self._buffer += data
        frames: list[dict] = []

        while True:
            if len(self._buffer) < LENGTH_PREFIX:
                break
            (length,) = struct.unpack_from("!I", self._buffer, 0)
            if length > MAX_FRAME:
                raise FramingError(
                    f"peer announced a {length} B frame, above the "
                    f"{MAX_FRAME} B limit"
                )
            if len(self._buffer) < LENGTH_PREFIX + length:
                break       # partial frame: wait for more bytes
            body = bytes(self._buffer[LENGTH_PREFIX:LENGTH_PREFIX + length])
            del self._buffer[:LENGTH_PREFIX + length]
            frames.append(decode_frame(body))

        return frames

    def pending_bytes(self) -> int:
        return len(self._buffer)

    def reset(self) -> None:
        self._buffer.clear()
