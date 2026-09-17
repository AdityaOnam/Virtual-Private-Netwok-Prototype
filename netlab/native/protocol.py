"""
netlab.native.protocol — OnamVPN Native wire format.

This is the protocol specification.  It contains no crypto and no sockets:
only the byte layout, the constants, and the pack/unpack functions.

Design lineage — what is borrowed and what is ours
───────────────────────────────────────────────────
Borrowed from WireGuard (Noise_IK):
  - the four-message shape (initiation / response / data / keepalive)
  - the chaining-key construction: every DH result is mixed into a running
    chaining key C, and transport keys fall out of the final C
  - sender/receiver index for O(1) peer lookup without parsing addresses
  - 64-bit little-endian counter as the AEAD nonce
  - mac1 over a hash of the responder's static key, so a peer that does not
    know the server's public key cannot even produce a well-formed packet

Ours (and deliberately simpler than the real thing):
  - no cookie reply (WireGuard message type 3) and therefore no mac2.  Real
    WireGuard uses these for DoS mitigation under load; we do not implement
    them, so a flood of initiations forces us to do expensive DH.  Stated
    plainly in §"Not defended against" below.
  - no roaming: a peer's endpoint is fixed at handshake time
  - stream multiplexing inside the tunnel (stream_id in the data payload) is
    our own, because we tunnel SOCKS5 connections rather than IP packets

Message formats — all multi-byte integers little-endian
────────────────────────────────────────────────────────
Little-endian throughout, matching WireGuard.  Note this is the opposite of
the network byte order used by IP/TCP/UDP headers in netlab.dissect — a useful
contrast to point at: "network byte order" is a convention of the IP suite,
not a law of protocols.

  Handshake Initiation — type 1 — 132 bytes
  ┌────────┬──────┬────────────────────────────────────────────────────┐
  │ offset │ size │ field                                              │
  ├────────┼──────┼────────────────────────────────────────────────────┤
  │   0    │   1  │ type = 1                                           │
  │   1    │   3  │ reserved (zero)                                    │
  │   4    │   4  │ sender_index          u32 LE                       │
  │   8    │  32  │ ephemeral public key  X25519                       │
  │  40    │  48  │ encrypted_static      32 B key + 16 B tag          │
  │  88    │  28  │ encrypted_timestamp   12 B TAI64N + 16 B tag       │
  │ 116    │  16  │ mac1                  BLAKE2s-128 keyed            │
  └────────┴──────┴────────────────────────────────────────────────────┘

  Handshake Response — type 2 — 76 bytes
  ┌────────┬──────┬────────────────────────────────────────────────────┐
  │   0    │   1  │ type = 2                                           │
  │   1    │   3  │ reserved (zero)                                    │
  │   4    │   4  │ sender_index          u32 LE                       │
  │   8    │   4  │ receiver_index        u32 LE (echoes initiator)    │
  │  12    │  32  │ ephemeral public key  X25519                       │
  │  44    │  16  │ encrypted_empty       0 B plaintext + 16 B tag     │
  │  60    │  16  │ mac1                                               │
  └────────┴──────┴────────────────────────────────────────────────────┘

  Transport Data — type 4 — 16-byte header + ciphertext
  ┌────────┬──────┬────────────────────────────────────────────────────┐
  │   0    │   1  │ type = 4                                           │
  │   1    │   3  │ reserved (zero)                                    │
  │   4    │   4  │ receiver_index        u32 LE                       │
  │   8    │   8  │ counter               u64 LE — the AEAD nonce      │
  │  16    │   n  │ ciphertext + 16 B Poly1305 tag                     │
  └────────┴──────┴────────────────────────────────────────────────────┘

  A keepalive is a Transport Data packet whose plaintext is empty, so it costs
  16 + 16 = 32 bytes on the wire.  It exists to refresh NAT bindings; see
  KEEPALIVE_SECONDS.

Inner frame (inside the AEAD, only for SOCKS5 tunnelling mode)
───────────────────────────────────────────────────────────────
  ┌────────┬──────┬────────────────────────────────────────────────────┐
  │   0    │   1  │ frame kind (see FRAME_*)                           │
  │   1    │   4  │ stream_id             u32 LE                       │
  │   5    │   2  │ payload length        u16 LE                       │
  │   7    │   n  │ payload                                            │
  └────────┴──────┴────────────────────────────────────────────────────┘

Not defended against — stated so nobody assumes otherwise
──────────────────────────────────────────────────────────
  - Denial of service.  No cookie mechanism; each initiation costs two X25519
    operations and an attacker can force them.
  - Traffic analysis.  Packet sizes and timing are not padded or shaped, so
    the shape of a browsing session is visible even though its content is not.
  - Side channels.  Python is not constant-time; this is a teaching
    implementation, not a hardened one.
  - Post-quantum adversaries.  X25519 is classically secure only.
  - Formal verification.  Real Noise_IK has machine-checked proofs.  The
    reduction implemented here does not, and small changes to a Noise pattern
    can break its security properties.
  - Packet loss.  This is a design limitation rather than a security one, and
    it is worth being precise about.  WireGuard tunnels whole IP packets, so
    a dropped datagram costs an inner TCP segment and the inner TCP simply
    retransmits it.  We tunnel SOCKS5 *stream bytes*, so a dropped datagram
    removes bytes from the middle of a TCP stream with nothing to notice or
    repair it.  On loopback that effectively never happens; on a real lossy
    path it would corrupt transfers.  netlab.transport (Phase 3) builds the
    ARQ layer that fixes this, and is the honest answer to "what is missing".

Use WireGuard for anything real.  This exists to make the mechanism legible.
"""

from __future__ import annotations

import struct
from typing import NamedTuple

# ── Protocol identity ────────────────────────────────────────────────────────

PROTOCOL_NAME = b"OnamVPN-v1 X25519 ChaCha20Poly1305 BLAKE2s"
PROLOGUE = b"OnamVPN native tunnel"
LABEL_MAC1 = b"onamvpn-mac1----"

# ── Message types ────────────────────────────────────────────────────────────

MSG_HANDSHAKE_INIT = 1
MSG_HANDSHAKE_RESP = 2
MSG_COOKIE_REPLY = 3      # reserved, not implemented — see module docstring
MSG_TRANSPORT_DATA = 4

# ── Primitive sizes ──────────────────────────────────────────────────────────

KEY_SIZE = 32          # X25519 public key / ChaCha20-Poly1305 key
TAG_SIZE = 16          # Poly1305 authentication tag
MAC_SIZE = 16          # BLAKE2s-128 keyed MAC
NONCE_SIZE = 12        # ChaCha20-Poly1305 nonce
TIMESTAMP_SIZE = 12    # TAI64N
HASH_SIZE = 32         # BLAKE2s-256

# ── struct formats ───────────────────────────────────────────────────────────
# "<" = little-endian, no padding.  Sizes are asserted at import; see below.

FMT_INIT = "<B3sI32s48s28s16s"
FMT_RESP = "<B3sII32s16s16s"
FMT_DATA_HEADER = "<B3sIQ"
FMT_INNER_FRAME = "<BIH"

SIZE_INIT = struct.calcsize(FMT_INIT)              # 132
SIZE_RESP = struct.calcsize(FMT_RESP)              # 76
SIZE_DATA_HEADER = struct.calcsize(FMT_DATA_HEADER)  # 16
SIZE_INNER_FRAME = struct.calcsize(FMT_INNER_FRAME)  # 7

# Hand-computed sizes from the tables above.  If a format string and the
# documented layout ever disagree, this fails at import rather than producing
# packets that silently do not match the spec.
assert SIZE_INIT == 1 + 3 + 4 + 32 + 48 + 28 + 16 == 132, SIZE_INIT
assert SIZE_RESP == 1 + 3 + 4 + 4 + 32 + 16 + 16 == 76, SIZE_RESP
assert SIZE_DATA_HEADER == 1 + 3 + 4 + 8 == 16, SIZE_DATA_HEADER
assert SIZE_INNER_FRAME == 1 + 4 + 2 == 7, SIZE_INNER_FRAME

#: Offset at which mac1 begins in each handshake message.  mac1 covers
#: everything before itself.
MAC1_OFFSET_INIT = SIZE_INIT - MAC_SIZE     # 116
MAC1_OFFSET_RESP = SIZE_RESP - MAC_SIZE     # 60

# ── Inner frame kinds (SOCKS5 tunnelling) ────────────────────────────────────

FRAME_OPEN = 1     # open a stream: payload = "host:port"
FRAME_DATA = 2     # stream payload
FRAME_CLOSE = 3    # half/full close
FRAME_KEEPALIVE = 4

MAX_FRAME_PAYLOAD = 0xFFFF

#: Largest inner payload we will place in a single datagram.
#:
#: An inner frame may hold 64 KiB, but a UDP datagram that large is
#: IP-fragmented into a dozen pieces and losing any one destroys the whole
#: datagram.  Budget for a 1500-byte path:
#:
#:     1500  Ethernet MTU
#:     -  20  IPv4 header
#:     -   8  UDP header
#:     -  16  tunnel data header
#:     -  16  Poly1305 tag
#:     -   7  inner frame header
#:     =1433  available
#:
#: Rounded down to 1280 — the IPv6 minimum link MTU, which survives almost any
#: path without fragmenting.  This is the same figure config/servers.json uses
#: for WireGuard, for exactly the same reason.
MAX_TUNNEL_PAYLOAD = 1280

# ── Timers and limits (WireGuard's, which are well-chosen) ───────────────────

#: Refresh NAT bindings.  Most consumer NATs expire a UDP mapping after
#: 30-120 s of silence; 25 s stays comfortably inside that.  This is the value
#: config/settings.json exposes as `keepalive_interval`.
KEEPALIVE_SECONDS = 25

REKEY_AFTER_MESSAGES = 2 ** 20    # rotate keys well before the counter matters
REJECT_AFTER_MESSAGES = 2 ** 24   # hard stop; never reuse a (key, nonce) pair
REKEY_AFTER_SECONDS = 120
REJECT_AFTER_SECONDS = 180
HANDSHAKE_TIMEOUT_SECONDS = 5

#: Anti-replay window, in packets.  RFC 6479 uses a bitmap of this size.
REPLAY_WINDOW_BITS = 1024


class HandshakeInit(NamedTuple):
    sender_index: int
    ephemeral: bytes
    encrypted_static: bytes
    encrypted_timestamp: bytes
    mac1: bytes


class HandshakeResponse(NamedTuple):
    sender_index: int
    receiver_index: int
    ephemeral: bytes
    encrypted_empty: bytes
    mac1: bytes


class TransportData(NamedTuple):
    receiver_index: int
    counter: int
    ciphertext: bytes


# ── Pack / unpack ────────────────────────────────────────────────────────────

def message_type(data: bytes) -> int:
    """Return the message type byte, or raise if the buffer is empty."""
    if not data:
        raise ValueError("empty datagram")
    return data[0]


def pack_init(msg: HandshakeInit) -> bytes:
    return struct.pack(
        FMT_INIT, MSG_HANDSHAKE_INIT, b"\x00" * 3, msg.sender_index,
        msg.ephemeral, msg.encrypted_static, msg.encrypted_timestamp, msg.mac1,
    )


def unpack_init(data: bytes) -> HandshakeInit:
    if len(data) != SIZE_INIT:
        raise ValueError(f"handshake init must be {SIZE_INIT} B, got {len(data)}")
    kind, _, sender, eph, enc_static, enc_ts, mac1 = struct.unpack(FMT_INIT, data)
    if kind != MSG_HANDSHAKE_INIT:
        raise ValueError(f"expected type {MSG_HANDSHAKE_INIT}, got {kind}")
    return HandshakeInit(sender, eph, enc_static, enc_ts, mac1)


def pack_response(msg: HandshakeResponse) -> bytes:
    return struct.pack(
        FMT_RESP, MSG_HANDSHAKE_RESP, b"\x00" * 3,
        msg.sender_index, msg.receiver_index,
        msg.ephemeral, msg.encrypted_empty, msg.mac1,
    )


def unpack_response(data: bytes) -> HandshakeResponse:
    if len(data) != SIZE_RESP:
        raise ValueError(f"handshake response must be {SIZE_RESP} B, got {len(data)}")
    kind, _, sender, receiver, eph, enc_empty, mac1 = struct.unpack(FMT_RESP, data)
    if kind != MSG_HANDSHAKE_RESP:
        raise ValueError(f"expected type {MSG_HANDSHAKE_RESP}, got {kind}")
    return HandshakeResponse(sender, receiver, eph, enc_empty, mac1)


def pack_data(msg: TransportData) -> bytes:
    header = struct.pack(
        FMT_DATA_HEADER, MSG_TRANSPORT_DATA, b"\x00" * 3,
        msg.receiver_index, msg.counter,
    )
    return header + msg.ciphertext


def unpack_data(data: bytes) -> TransportData:
    if len(data) < SIZE_DATA_HEADER + TAG_SIZE:
        raise ValueError(
            f"transport packet must be at least "
            f"{SIZE_DATA_HEADER + TAG_SIZE} B, got {len(data)}"
        )
    kind, _, receiver, counter = struct.unpack_from(FMT_DATA_HEADER, data, 0)
    if kind != MSG_TRANSPORT_DATA:
        raise ValueError(f"expected type {MSG_TRANSPORT_DATA}, got {kind}")
    return TransportData(receiver, counter, data[SIZE_DATA_HEADER:])


def pack_inner(kind: int, stream_id: int, payload: bytes) -> bytes:
    """Frame a stream payload for transport inside the AEAD."""
    if len(payload) > MAX_FRAME_PAYLOAD:
        raise ValueError(
            f"inner payload {len(payload)} B exceeds {MAX_FRAME_PAYLOAD}"
        )
    return struct.pack(FMT_INNER_FRAME, kind, stream_id, len(payload)) + payload


def unpack_inner(data: bytes) -> tuple[int, int, bytes, int]:
    """
    Parse one inner frame.

    Returns (kind, stream_id, payload, bytes_consumed) so a caller can walk
    several frames packed into one transport packet.
    """
    if len(data) < SIZE_INNER_FRAME:
        raise ValueError(f"inner frame needs {SIZE_INNER_FRAME} B, got {len(data)}")
    kind, stream_id, length = struct.unpack_from(FMT_INNER_FRAME, data, 0)
    end = SIZE_INNER_FRAME + length
    if len(data) < end:
        raise ValueError(
            f"inner frame claims {length} B payload but only "
            f"{len(data) - SIZE_INNER_FRAME} B present"
        )
    return kind, stream_id, data[SIZE_INNER_FRAME:end], end


def nonce_for(counter: int) -> bytes:
    """
    Build the 12-byte ChaCha20-Poly1305 nonce for *counter*.

        4 zero bytes || counter as u64 little-endian

    Worked examples (these are asserted in the test suite):
        counter 0      → 00 00 00 00 00 00 00 00 00 00 00 00
        counter 1      → 00 00 00 00 01 00 00 00 00 00 00 00
        counter 2**32  → 00 00 00 00 00 00 00 00 01 00 00 00

    The counter must never repeat under one key.  Session enforces that by
    rekeying long before REJECT_AFTER_MESSAGES and refusing to encrypt past it.
    """
    if counter < 0 or counter >= 2 ** 64:
        raise ValueError(f"counter {counter} out of range for u64")
    return b"\x00" * 4 + counter.to_bytes(8, "little")


def chunk_payload(kind: int, stream_id: int, data: bytes,
                  size: int | None = None) -> list[bytes]:
    """
    Split *data* into inner frames that each fit inside one datagram.

    Every relay loop must send through this rather than calling pack_inner on
    a whole read: a 16 KiB read becomes one oversized datagram, and a single
    lost IP fragment silently truncates the stream.

    *size* defaults to `mtu_size` from config/settings.json — the setting the
    dialog has always offered and nothing has ever used.
    """
    if size is None:
        try:
            from .settings import tunnel_payload_size
            size = tunnel_payload_size()
        except Exception:
            size = MAX_TUNNEL_PAYLOAD
    if not data:
        return [pack_inner(kind, stream_id, b"")]
    return [
        pack_inner(kind, stream_id, data[i:i + size])
        for i in range(0, len(data), size)
    ]
