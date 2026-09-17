"""
netlab.dissect.checksums — Internet checksum and transport pseudo-headers.

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

def _inet_checksum(data: bytes) -> int:
    """RFC-1071 one's-complement Internet checksum."""
    if len(data) % 2:
        data += b'\x00'
    total = sum((data[i] << 8) | data[i + 1] for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _transport_pseudo_header(src: bytes, dst: bytes, proto: int,
                              length: int, ip_version: int) -> bytes:
    """Build IPv4 or IPv6 pseudo-header for TCP/UDP/ICMPv6 checksum."""
    if ip_version == 4:
        return src + dst + bytes([0, proto]) + length.to_bytes(2, 'big')
    else:   # IPv6 (RFC 2460 §8.1)
        return src + dst + length.to_bytes(4, 'big') + bytes([0, 0, 0, proto])


def _fmt_mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)

