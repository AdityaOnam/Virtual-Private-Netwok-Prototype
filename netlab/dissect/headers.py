"""
netlab.dissect.headers — facade re-exporting every hand-written decoder.

The decoders used to live here as one 861-line file.  They are now split by
OSI layer, so the file structure mirrors the encapsulation model the module
exists to teach:

    tables.py     protocol number → name lookup tables
    checksums.py  Internet checksum (RFC 1071) + transport pseudo-headers
    _fields.py    FieldView construction helper (_fv)
    link.py       L2   decode_ethernet          (Ethernet II, 802.1Q)
    internet.py   L3   decode_ipv4, decode_ipv6, decode_icmp
    transport.py  L4   decode_tcp, decode_udp
    dispatch.py        decode_packet — chains the above

This module keeps the original import path working:

    from netlab.dissect.headers import decode_ipv4, decode_packet

New code may import from the layer module directly; both are supported.

Concepts demonstrated (Module A)
─────────────────────────────────
  Ethernet : framing, MAC addressing, EtherType, 802.1Q VLAN tagging
  IPv4     : header structure, sub-byte fields, fragmentation, TTL,
             protocol demux, RFC-791 checksum
  IPv6     : 40-byte fixed header, traffic class / flow label, hop limit,
             next-header chain
  TCP      : seq/ack, 9 flag bits, window, options (MSS / Window Scale /
             SACK-Permitted / Timestamps), pseudo-header checksum
  UDP      : connectionless demux, length, optional checksum
  ICMP     : unreachable / time-exceeded / echo; ICMPv6 types
"""

from __future__ import annotations

from .checksums import _inet_checksum, _transport_pseudo_header
from .dispatch import decode_packet
from .internet import decode_icmp, decode_ipv4, decode_ipv6
from .link import decode_ethernet, _fmt_mac
from .tables import (
    _DSCP_NAMES,
    _ETHERTYPES,
    _ICMP4_TYPES,
    _ICMP6_TYPES,
    _IP4_PROTOS,
    _TCP_PORTS,
    _UDP_PORTS,
)
from .transport import _parse_tcp_options, decode_tcp, decode_udp
from ._fields import _fv

__all__ = [
    "decode_ethernet",
    "decode_ipv4",
    "decode_ipv6",
    "decode_tcp",
    "decode_udp",
    "decode_icmp",
    "decode_packet",
]
