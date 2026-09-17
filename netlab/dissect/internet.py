"""
netlab.dissect.internet — Layer 3 — IPv4, IPv6 and ICMP/ICMPv6.

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
from .tables import _IP4_PROTOS, _DSCP_NAMES, _ICMP4_TYPES, _ICMP6_TYPES

ECN_LABELS = {0: "Not-ECT", 1: "ECT(1)", 2: "ECT(0)", 3: "CE"}


_IP4_MIN = 20

def decode_ipv4(data: bytes, layer_offset: int = 0) -> Layer:
    """
    Decode an IPv4 header (RFC 791) with full checksum verification.

    All sub-byte fields use _fv() so bit_offset + bit_length → raw_bytes is
    mechanically correct and the FieldView invariant is always satisfied.

    Raises
    ------
    ValueError
        Buffer too short, version ≠ 4, or IHL < 5.
    """
    hdr = data[layer_offset:]
    if len(hdr) < _IP4_MIN:
        raise ValueError(f"IPv4: need {_IP4_MIN} B, got {len(hdr)}")

    version = _extract_bits(hdr, 0, 4)
    ihl     = _extract_bits(hdr, 4, 4)
    if version != 4:
        raise ValueError(f"IPv4: version={version}, expected 4")
    if ihl < 5:
        raise ValueError(f"IPv4: IHL={ihl} < 5")

    hlen = ihl * 4
    if len(hdr) < hlen:
        raise ValueError(f"IPv4: IHL says {hlen} B but buffer has {len(hdr)}")

    raw = hdr[:hlen]

    dscp   = _extract_bits(hdr, 8, 6)
    ecn    = _extract_bits(hdr, 14, 2)
    tlen   = struct.unpack_from("!H", hdr, 2)[0]
    if tlen < hlen:
        raise ValueError(f"IPv4: total_length {tlen} is smaller than the {hlen}-byte header")
    ident  = struct.unpack_from("!H", hdr, 4)[0]
    rsvd   = _extract_bits(hdr, 48, 1)
    df     = _extract_bits(hdr, 49, 1)
    mf     = _extract_bits(hdr, 50, 1)
    foff   = _extract_bits(hdr, 51, 13)
    ttl    = hdr[8]
    proto  = hdr[9]
    rx_ck  = struct.unpack_from("!H", hdr, 10)[0]
    zeroed = bytearray(raw); zeroed[10] = zeroed[11] = 0
    cx_ck  = _inet_checksum(bytes(zeroed))
    src_b  = hdr[12:16]; dst_b = hdr[16:20]

    ecn_labels = {0: "Not-ECT", 1: "ECT(1)", 2: "ECT(0)", 3: "CE"}
    layer = Layer(name="IPv4", raw_bytes=raw, payload_offset=hlen)
    layer.notes["is_fragmented"] = (mf == 1 or foff > 0)
    layer.notes["is_first_fragment"] = (foff == 0)
    f = layer.fields

    f["version"]      = _fv(hdr, 0, 4, version,
        "IP version: 4 = IPv4.  Upper nibble of byte 0.")
    f["ihl"]          = _fv(hdr, 4, 4, ihl,
        f"Internet Header Length: {ihl}×32-bit words = {hlen} B. "
        f"IHL > 5 means options are present; payload starts at byte {hlen}.")
    f["dscp"]         = _fv(hdr, 8, 6, dscp,
        f"DSCP: {_DSCP_NAMES.get(dscp, dscp)}. QoS traffic class.")
    f["ecn"]          = _fv(hdr, 14, 2, ecn,
        f"ECN: {ecn_labels.get(ecn, ecn)}. End-to-end congestion signalling.")
    f["total_length"] = _fv(hdr, 16, 16, tlen,
        f"Total length: {tlen} B (header {hlen} + payload {tlen-hlen}). "
        "Datagrams larger than the link MTU must be fragmented.")
    f["identification"]= _fv(hdr, 32, 16, ident,
        f"Identification: 0x{ident:04X}. "
        "Fragments of the same datagram share this value for reassembly.")
    f["reserved_flag"]= _fv(hdr, 48, 1, rsvd,
        "Reserved flag: RFC 791 requires this bit to be zero. "
        "(RFC 3514 jokingly redefines it as the 'Evil Bit' — an April "
        "Fools' RFC, not a real protocol feature.)")
    f["df_flag"]      = _fv(hdr, 49, 1, df,
        f"DF={'SET — fragmentation forbidden' if df else 'clear'}. "
        "When DF=1 and the packet is too large, the router drops it and "
        "sends ICMP Fragmentation Needed. Path MTU Discovery relies on this.")
    f["mf_flag"]      = _fv(hdr, 50, 1, mf,
        f"MF={'SET — more fragments follow' if mf else 'clear (last fragment)'}.")
    f["frag_offset"]  = _fv(hdr, 51, 13, foff,
        f"Fragment offset: {foff}×8 = {foff*8} B into original payload. "
        "8-byte granularity means all non-last fragments must be multiples of 8.")
    f["ttl"]          = _fv(hdr, 64, 8, ttl,
        f"TTL: {ttl}. Decremented by each router; when 0 the packet is "
        "discarded (ICMP Time Exceeded, type 11). Traceroute uses TTL=1,2,…")
    f["protocol"]     = _fv(hdr, 72, 8, proto,
        f"Protocol: {proto} = {_IP4_PROTOS.get(proto, 'Unknown')}. "
        "Layer-3 demux: tells the receiver which transport to hand the payload to.")
    f["checksum"]     = _fv(hdr, 80, 16, rx_ck,
        f"Header checksum: received=0x{rx_ck:04X}, computed=0x{cx_ck:04X}. "
        "One's-complement sum of the IP header only (not payload).",
        computed_value=cx_ck)
    f["src"]          = _fv(hdr, 96, 32, socket.inet_ntoa(src_b),
        f"Source IP: {socket.inet_ntoa(src_b)}.")
    f["dst"]          = _fv(hdr, 128, 32, socket.inet_ntoa(dst_b),
        f"Destination IP: {socket.inet_ntoa(dst_b)}.")

    if ihl > 5:
        opts = raw[20:]
        f["options"] = _fv(hdr, 160, len(opts)*8, opts.hex(" "),
            f"IP Options: {len(opts)} B (IHL={ihl}). "
            "Includes Strict/Loose Source Routing, Record Route, Timestamps.")

    return layer


# ─────────────────────────────────────────────────────────────────────────────
# decode_ipv6
# ─────────────────────────────────────────────────────────────────────────────

_IP6_HDR = 40   # fixed header length

def decode_ipv6(data: bytes, layer_offset: int = 0) -> Layer:
    """
    Decode an IPv6 fixed header (RFC 8200).

    The fixed header is always 40 bytes.  Extension headers (if any) begin at
    payload_offset and are not decoded here — they are left to the caller.

    Raises
    ------
    ValueError
        Buffer too short or version ≠ 6.
    """
    hdr = data[layer_offset:]
    if len(hdr) < _IP6_HDR:
        raise ValueError(f"IPv6: need {_IP6_HDR} B, got {len(hdr)}")

    version = _extract_bits(hdr, 0, 4)
    if version != 6:
        raise ValueError(f"IPv6: version={version}, expected 6")

    tc   = _extract_bits(hdr, 4, 8)    # Traffic Class (bits 4-11)
    fl   = _extract_bits(hdr, 12, 20)  # Flow Label   (bits 12-31)
    plen = struct.unpack_from("!H", hdr, 4)[0]
    nh   = hdr[6]
    hl   = hdr[7]
    src_b = hdr[8:24]
    dst_b = hdr[24:40]
    src_s = socket.inet_ntop(socket.AF_INET6, src_b)
    dst_s = socket.inet_ntop(socket.AF_INET6, dst_b)
    dscp  = (tc >> 2) & 0x3F
    ecn   = tc & 0x3

    ecn_labels = {0: "Not-ECT", 1: "ECT(1)", 2: "ECT(0)", 3: "CE"}
    layer = Layer(name="IPv6", raw_bytes=hdr[:_IP6_HDR], payload_offset=_IP6_HDR)
    f = layer.fields

    f["version"]        = _fv(hdr, 0, 4, version,
        "IP version: 6 = IPv6.  Upper nibble of the first 32-bit word.")
    f["traffic_class"]  = _fv(hdr, 4, 8, tc,
        f"Traffic Class: 0x{tc:02X} "
        f"(DSCP={_DSCP_NAMES.get(dscp, dscp)}, ECN={ecn_labels.get(ecn, ecn)}). "
        "Replaces the IPv4 TOS byte; upper 6 bits = DSCP, lower 2 = ECN.")
    f["flow_label"]     = _fv(hdr, 12, 20, fl,
        f"Flow Label: 0x{fl:05X}. "
        "A non-zero value marks this packet as part of a flow for which the "
        "sender requests special handling (e.g. per-flow load balancing).")
    f["payload_length"] = _fv(hdr, 32, 16, plen,
        f"Payload Length: {plen} B (everything after the 40-byte fixed header, "
        "including any extension headers).  Unlike IPv4 Total Length, this "
        "does NOT include the fixed header itself.")
    f["next_header"]    = _fv(hdr, 48, 8, nh,
        f"Next Header: {nh} = {_IP4_PROTOS.get(nh, 'Unknown')}. "
        "Plays the same role as IPv4 Protocol — identifies the next layer "
        "(or the first extension header).")
    f["hop_limit"]      = _fv(hdr, 56, 8, hl,
        f"Hop Limit: {hl}. IPv6 rename of IPv4 TTL. "
        "Decremented by each router; packet dropped at 0.")
    f["src"]            = _fv(hdr, 64, 128, src_s,
        f"Source IPv6 address: {src_s}.")
    f["dst"]            = _fv(hdr, 192, 128, dst_s,
        f"Destination IPv6 address: {dst_s}.")

    return layer


_ICMP_MIN = 8

def decode_icmp(data: bytes, layer_offset: int = 0,
                ip_version: int = 4,
                src_ip_bytes: Optional[bytes] = None,
                dst_ip_bytes: Optional[bytes] = None,
                payload_length: Optional[int] = None) -> Layer:
    """
    Decode an ICMPv4 (RFC 792) or ICMPv6 (RFC 4443) message.

    Parameters
    ----------
    data : bytes
        Raw frame buffer.
    layer_offset : int
        Byte offset of the ICMP/ICMPv6 header within *data*.
    ip_version : int
        4 → ICMPv4; 6 → ICMPv6.
    src_ip_bytes, dst_ip_bytes : bytes | None
        Required for ICMPv6 checksum (uses IPv6 pseudo-header); unused for v4.
    payload_length : int | None
        ICMPv6 payload length from IPv6 header; used for checksum pseudo-header.

    Raises
    ------
    ValueError
        Buffer shorter than 8 bytes.
    """
    hdr = data[layer_offset:]
    if len(hdr) < _ICMP_MIN:
        raise ValueError(f"ICMP: need {_ICMP_MIN} B, got {len(hdr)}")

    itype = hdr[0]
    icode = hdr[1]
    rx_ck = struct.unpack_from("!H", hdr, 2)[0]
    roh   = hdr[4:8]   # rest-of-header (4 bytes, type-specific)

    type_table = _ICMP6_TYPES if ip_version == 6 else _ICMP4_TYPES
    type_name  = type_table.get(itype, f"type {itype}")

    # Checksum
    cx_ck: Optional[int] = None
    if ip_version == 4:
        zeroed = bytearray(hdr); zeroed[2] = zeroed[3] = 0
        cx_ck  = _inet_checksum(bytes(zeroed))
    elif src_ip_bytes and dst_ip_bytes and payload_length is not None:
        actual = min(payload_length, len(hdr))
        pseudo = _transport_pseudo_header(src_ip_bytes, dst_ip_bytes,
                                          58, actual, 6)
        zeroed = bytearray(hdr[:actual]); zeroed[2] = zeroed[3] = 0
        cx_ck  = _inet_checksum(pseudo + bytes(zeroed))

    # Decode rest-of-header
    roh_val: Any
    if itype in (0, 8) and ip_version == 4:  # Echo Reply / Request
        ident  = int.from_bytes(roh[0:2], "big")
        seq    = int.from_bytes(roh[2:4], "big")
        roh_val = {"identifier": ident, "sequence": seq}
        roh_desc = (f"Echo identifier={ident}, sequence={seq}. "
                    "Ping uses this to match replies to requests.")
    elif itype == 3 and ip_version == 4:  # Destination Unreachable
        mtu     = int.from_bytes(roh[2:4], "big")
        roh_val = {"next_hop_mtu": mtu}
        roh_desc = (f"Next-hop MTU={mtu} (valid for code 4 = Fragmentation "
                    "Needed).  Path MTU Discovery reads this.")
    elif itype == 11 and ip_version == 4:  # Time Exceeded
        roh_val  = {}
        roh_desc = ("Unused (4 bytes, must be zero). "
                    "TTL=0 triggers this; traceroute uses TTL=1,2,… to map hops.")
    elif itype == 2 and ip_version == 6:   # Packet Too Big
        pmtu    = int.from_bytes(roh, "big")
        roh_val = {"mtu": pmtu}
        roh_desc = f"MTU={pmtu}: the maximum packet size for the next link."
    elif itype in (128, 129) and ip_version == 6:  # Echo Request/Reply
        ident   = int.from_bytes(roh[0:2], "big")
        seq     = int.from_bytes(roh[2:4], "big")
        roh_val = {"identifier": ident, "sequence": seq}
        roh_desc = f"Echo identifier={ident}, sequence={seq}."
    else:
        roh_val  = roh.hex()
        roh_desc = f"Type-specific header data (hex): {roh.hex()}."

    code_names_v4: dict[tuple, str] = {
        (3, 0): "Net Unreachable", (3, 1): "Host Unreachable",
        (3, 3): "Port Unreachable", (3, 4): "Fragmentation Needed",
        (11, 0): "TTL Exceeded in Transit", (11, 1): "Fragment Reassembly Time Exceeded",
    }
    code_names_v6: dict[tuple, str] = {
        (1, 0): "No Route to Dest", (1, 3): "Address Unreachable",
        (1, 4): "Port Unreachable",
        (3, 0): "Hop Limit Exceeded", (3, 1): "Fragment Reassembly Time Exceeded",
    }
    code_table = code_names_v6 if ip_version == 6 else code_names_v4
    code_name  = code_table.get((itype, icode), f"code {icode}")

    proto_name = "ICMPv6" if ip_version == 6 else "ICMP"
    layer = Layer(name=proto_name, raw_bytes=hdr[:_ICMP_MIN], payload_offset=_ICMP_MIN)
    f = layer.fields

    f["type"]     = _fv(hdr, 0, 8, itype,
        f"Type: {itype} = {type_name}. "
        "Identifies the ICMP message category.")
    f["code"]     = _fv(hdr, 8, 8, icode,
        f"Code: {icode} = {code_name}. "
        "Sub-type within the message category.")
    ck_desc = (f"Checksum: received=0x{rx_ck:04X}"
               + (f", computed=0x{cx_ck:04X}" if cx_ck is not None else
                  " (not verified)")
               + (". Covers entire ICMP message." if ip_version == 4 else
                  ". Covers ICMPv6 message + IPv6 pseudo-header."))
    f["checksum"] = _fv(hdr, 16, 16, rx_ck, ck_desc, computed_value=cx_ck)
    f["rest_of_header"] = _fv(hdr, 32, 32, roh_val, roh_desc)

    return layer

