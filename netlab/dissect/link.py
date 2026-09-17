"""
netlab.dissect.link — Layer 2 — Ethernet II and 802.1Q VLAN.

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

import socket
import struct
from typing import Any, Optional

from .model import Layer, FieldView, _extract_bits
from ._fields import _fv
from .checksums import _inet_checksum, _transport_pseudo_header
from .tables import _ETHERTYPES


def _fmt_mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


_ETH_MIN = 14   # dst(6) + src(6) + EtherType(2)

def decode_ethernet(data: bytes, layer_offset: int = 0) -> Layer:
    """
    Decode an Ethernet II frame header.

    Handles 802.1Q VLAN tags (EtherType 0x8100): when present, four additional
    bytes appear between the source MAC and the real EtherType; a vlan_tci
    field is inserted and payload_offset is extended by 4.

    Parameters
    ----------
    data : bytes
        Raw frame buffer.
    layer_offset : int
        Byte offset of this Ethernet frame within *data* (usually 0).

    Returns
    -------
    Layer
        name = "Ethernet II"
        payload_offset = 14 normally; 18 with a single 802.1Q tag.
    """
    hdr = data[layer_offset:]
    if len(hdr) < _ETH_MIN:
        raise ValueError(
            f"Ethernet: buffer too short — need {_ETH_MIN} B, got {len(hdr)}"
        )

    layer = Layer(name="Ethernet II", raw_bytes=hdr[:_ETH_MIN], payload_offset=14)
    f = layer.fields

    f["dst"] = _fv(hdr, 0, 48, _fmt_mac(hdr[0:6]),
                   "Destination MAC address: the link-layer address of the "
                   "intended recipient on this LAN segment.")
    f["src"] = _fv(hdr, 48, 48, _fmt_mac(hdr[6:12]),
                   "Source MAC address: the link-layer address of the sender.")
    ethertype_val = struct.unpack_from("!H", hdr, 12)[0]
    etype_name = _ETHERTYPES.get(ethertype_val, f"0x{ethertype_val:04X}")

    # 802.1Q VLAN tag?
    if ethertype_val == 0x8100 and len(hdr) >= 18:
        f["vlan_tpid"] = _fv(hdr, 96, 16, 0x8100,
                             "VLAN Tag Protocol Identifier (0x8100 = 802.1Q). "
                             "Signals that a 4-byte VLAN tag follows.")
        tci = struct.unpack_from("!H", hdr, 14)[0]
        pcp = (tci >> 13) & 0x7
        dei = (tci >> 12) & 0x1
        vid = tci & 0xFFF
        f["vlan_tci"] = _fv(hdr, 112, 16, tci,
                            f"VLAN Tag Control Info: PCP={pcp} DEI={dei} "
                            f"VID={vid} (VLAN {vid}). "
                            "Priority Code Point sets QoS; VLAN ID isolates "
                            "broadcast domains on the same physical switch.")
        real_etype = struct.unpack_from("!H", hdr, 16)[0]
        real_name  = _ETHERTYPES.get(real_etype, f"0x{real_etype:04X}")
        f["real_ethertype"] = _fv(hdr, 128, 16, real_etype,
                                  f"EtherType after 802.1Q tag: {real_name}. "
                                  "Identifies the next layer protocol.")
        layer.raw_bytes    = hdr[:18]
        layer.payload_offset = 18
    else:
        f["ethertype"] = _fv(hdr, 96, 16, ethertype_val,
                             f"EtherType: {etype_name}. "
                             "Identifies the network-layer protocol carried by "
                             "this frame (IPv4=0x0800, IPv6=0x86DD, ARP=0x0806).")
    return layer

