"""
netlab.dissect._fields — FieldView construction helper.

Split out of the original single headers.py (861 lines).  The dissector is
organised by OSI layer so the file structure mirrors the encapsulation model
the module is meant to teach:

    link.py      L2  Ethernet II, 802.1Q
    internet.py  L3  IPv4, IPv6, ICMP/ICMPv6
    transport.py L4  TCP, UDP
    dispatch.py      chains them into a DecodedPacket

headers.py remains as a facade re-exporting every decoder, so existing imports
keep working.
"""

from __future__ import annotations

from .model import FieldView, _field_bytes


def _fv(hdr: bytes, bit_offset: int, bit_length: int,
        value, description: str, computed_value=None) -> FieldView:
    """
    Construct a FieldView with raw_bytes auto-computed from (bit_offset,
    bit_length).  Invariant is guaranteed to be satisfied.
    """
    return FieldView(
        value=value,
        raw_bytes=_field_bytes(hdr, bit_offset, bit_length),
        bit_offset=bit_offset,
        bit_length=bit_length,
        description=description,
        computed_value=computed_value,
    )

