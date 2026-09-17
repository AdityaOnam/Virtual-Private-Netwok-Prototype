"""
netlab.dissect.model — data model for decoded packets.

Every decoded packet is a DecodedPacket containing an ordered list of Layer
objects.  Each Layer contains a name and a mapping of field names to FieldView
objects.

Design goals
────────────
1. Sub-byte fields (e.g. IHL is 4 bits, IP Flags are 3 bits) must be
   representable with exact bit_offset + bit_length so the hex-dump panel can
   highlight exactly the right bits.

2. Variable-length regions (e.g. IP Options, TCP Options) must be
   representable as a single FieldView whose bit_length is determined at
   decode time.

3. A field whose received value differs from a computed value (e.g. an
   incorrect IPv4 checksum) must carry both values so the panel can flag the
   error in red without the test needing to re-derive it.

4. The model must be JSON-serialisable (for golden-file comparison in tests)
   with a single .to_dict() call — no custom encoder required.

FieldView invariant
───────────────────
raw_bytes must be exactly the bytes that the (bit_offset, bit_length) span
touches — no more, no less.  The expected range is:

    start = bit_offset // 8
    end   = (bit_offset + bit_length + 7) // 8
    len(raw_bytes) == end - start

__post_init__ enforces this on every FieldView construction.  Any decoder that
provides the wrong raw_bytes will raise ValueError immediately, rather than
silently producing a misleading hex-dump highlight.

Use _field_bytes(hdr, bit_offset, bit_length) to compute the correct slice
automatically and never trigger this error.

Concepts demonstrated (Module A)
─────────────────────────────────
  - OSI / TCP-IP layering and encapsulation — each Layer is one protocol unit
  - Header fields and their bit-level layout
  - Checksums — computed vs received
  - Port multiplexing — shown as src_port / dst_port FieldViews
  - TTL — shown as a FieldView with description explaining its role
  - MTU — exposed via total_length + fragment info in IPv4 layer
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any


# ─────────────────────────────────────────────────────────────────────────────
# FieldView — one header field
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FieldView:
    """
    One field within a protocol header.

    Attributes
    ----------
    value : Any
        The decoded (human-readable) value.
    raw_bytes : bytes
        The raw bytes that overlap this field.  Must satisfy the invariant:
        len(raw_bytes) == (bit_offset + bit_length + 7)//8 - bit_offset//8.
    bit_offset : int
        Bit offset from the start of the enclosing layer's bytes.
        Bit 0 = MSB of byte 0 (network bit order).
    bit_length : int
        Number of bits this field occupies.
    description : str
        One-sentence explanation for the viva panel.
    computed_value : Any, optional
        For verifiable fields (checksums): the value the decoder computed.
        If computed_value != value, is_bad returns True.
    """

    value: Any
    raw_bytes: bytes
    bit_offset: int
    bit_length: int
    description: str
    computed_value: Any = None

    # ── Invariant ─────────────────────────────────────────────────────────────

    def __post_init__(self) -> None:
        """
        Enforce: raw_bytes must span exactly the bytes implied by
        (bit_offset, bit_length).  Raises ValueError on violation so that
        decoder bugs surface immediately rather than silently corrupting
        the hex-dump highlight.
        """
        if self.bit_length <= 0:
            raise ValueError(
                f"FieldView bit_length must be positive, got {self.bit_length}"
            )
        if self.bit_offset < 0:
            raise ValueError(
                f"FieldView bit_offset must be non-negative, got {self.bit_offset}"
            )
        expected_start = self.bit_offset // 8
        expected_end   = (self.bit_offset + self.bit_length + 7) // 8
        expected_len   = expected_end - expected_start
        if len(self.raw_bytes) != expected_len:
            raise ValueError(
                f"FieldView invariant violated: "
                f"bit_offset={self.bit_offset}, bit_length={self.bit_length} "
                f"implies raw_bytes of length {expected_len} "
                f"(bytes [{expected_start}:{expected_end}]), "
                f"but got {len(self.raw_bytes)} bytes"
            )

    # ── Derived properties ────────────────────────────────────────────────────

    @property
    def byte_offset(self) -> int:
        """Byte offset of the first byte that contains this field."""
        return self.bit_offset // 8

    @property
    def byte_length(self) -> int:
        """Number of bytes that overlap with this field (ceiling division)."""
        end_bit  = self.bit_offset + self.bit_length
        end_byte = (end_bit + 7) // 8
        return end_byte - self.byte_offset

    @property
    def is_bad(self) -> bool:
        """True if computed_value is set and does not match the received value."""
        return self.computed_value is not None and self.computed_value != self.value

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "raw_bytes": self.raw_bytes.hex(" "),
            "bit_offset": self.bit_offset,
            "bit_length": self.bit_length,
            "description": self.description,
            "computed_value": self.computed_value,
            "is_bad": self.is_bad,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Layer — one protocol layer
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Layer:
    """
    One protocol layer (Ethernet, IPv4, TCP, …).

    Attributes
    ----------
    name : str
        Human-readable protocol name.
    fields : dict[str, FieldView]
        Ordered mapping of field name → FieldView (insertion order = wire order).
    raw_bytes : bytes
        The raw bytes of this layer's header (NOT including payload).
    payload_offset : int
        Byte offset within raw_bytes where this layer's payload begins.
    """

    name: str
    fields: dict[str, FieldView] = field(default_factory=dict)
    raw_bytes: bytes = b""
    payload_offset: int = 0
    notes: dict = field(default_factory=dict)

    def carries_transport_header(self) -> bool:
        """True if this layer carries the start of the next layer's header."""
        if not self.notes.get("is_fragmented", False):
            return True
        return self.notes.get("is_first_fragment", False)

    def to_dict(self) -> dict:
        # notes is included deliberately: fragmentation state decides whether the
        # chain descends into a transport header, so a golden file that omits it
        # cannot distinguish "no TCP layer because fragment" from "decoder bug".
        return {
            "name": self.name,
            "raw_bytes": self.raw_bytes.hex(" "),
            "payload_offset": self.payload_offset,
            "notes": self.notes,
            "fields": {k: v.to_dict() for k, v in self.fields.items()},
        }


# ─────────────────────────────────────────────────────────────────────────────
# DecodedPacket — top-level result of decoding one frame
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DecodedPacket:
    """
    A fully decoded packet as a layer tree.

    Attributes
    ----------
    timestamp : float
        Capture timestamp (seconds since epoch, or 0.0 for offline).
    raw_frame : bytes
        Complete raw frame as captured.
    layers : list[Layer]
        Decoded layers in wire order: outermost (Ethernet) first.
    capture_source : str
        Adapter name for live capture; filename for pcap playback.
    """

    timestamp: float
    raw_frame: bytes
    layers: list[Layer] = field(default_factory=list)
    capture_source: str = ""

    def get_layer(self, name: str) -> Layer | None:
        for layer in self.layers:
            if layer.name == name:
                return layer
        return None

    def has_layer(self, name: str) -> bool:
        return self.get_layer(name) is not None

    def summary(self) -> str:
        """One-line summary for the packet-list panel."""
        parts: list[str] = []
        ip = self.get_layer("IPv4") or self.get_layer("IPv6")
        if ip:
            src = ip.fields.get("src")
            dst = ip.fields.get("dst")
            if src and dst:
                parts.append(f"{ip.name}  {src.value} → {dst.value}")
        tcp = self.get_layer("TCP")
        udp = self.get_layer("UDP")
        if tcp:
            sp = tcp.fields.get("src_port")
            dp = tcp.fields.get("dst_port")
            if sp and dp:
                parts.append(f"TCP :{sp.value}→:{dp.value}")
        elif udp:
            sp = udp.fields.get("src_port")
            dp = udp.fields.get("dst_port")
            if sp and dp:
                parts.append(f"UDP :{sp.value}→:{dp.value}")
        return "  ".join(parts) if parts else "(unknown)"

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "raw_frame": self.raw_frame.hex(" "),
            "capture_source": self.capture_source,
            "layers": [layer.to_dict() for layer in self.layers],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _field_bytes(hdr: bytes, bit_offset: int, bit_length: int) -> bytes:
    """
    Return the bytes from *hdr* that the (bit_offset, bit_length) span covers.

    Use this in every decoder to compute raw_bytes and automatically satisfy
    the FieldView invariant.

        raw_bytes = _field_bytes(hdr, bit_offset, bit_length)

    This is a pure slice; it never fails as long as the field is within hdr.
    """
    start = bit_offset // 8
    end   = (bit_offset + bit_length + 7) // 8
    return hdr[start:end]


def _extract_bits(data: bytes, bit_offset: int, bit_length: int) -> int:
    """
    Extract *bit_length* bits starting at *bit_offset* from *data*.

    Uses network (big-endian) bit ordering: bit 0 = MSB of byte 0.

    Examples
    --------
    For an IPv4 header byte 0 = 0x45:
      _extract_bits(b'\\x45...', 0, 4)  → 4   (Version = 4)
      _extract_bits(b'\\x45...', 4, 4)  → 5   (IHL = 5)
    """
    if bit_length <= 0:
        raise ValueError(f"bit_length must be positive, got {bit_length}")
    if bit_offset < 0:
        raise ValueError(f"bit_offset must be non-negative, got {bit_offset}")

    byte_start = bit_offset // 8
    byte_end   = (bit_offset + bit_length + 7) // 8
    if byte_end > len(data):
        raise ValueError(
            f"Field [{bit_offset}:{bit_offset+bit_length}) overruns "
            f"buffer of length {len(data)} bytes"
        )

    chunk = int.from_bytes(data[byte_start:byte_end], "big")
    shift = byte_end * 8 - (bit_offset + bit_length)
    chunk >>= shift
    return chunk & ((1 << bit_length) - 1)
