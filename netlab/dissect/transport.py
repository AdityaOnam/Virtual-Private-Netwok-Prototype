"""
netlab.dissect.transport — Layer 4 — TCP (with options) and UDP.

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
from .tables import _TCP_PORTS, _UDP_PORTS


def _parse_tcp_options(opts: bytes) -> dict:
    """
    Parse TCP options bytes and return a dict of recognised options.

    Option kinds handled:
      0  = End of Option List
      1  = NOP
      2  = Maximum Segment Size
      3  = Window Scale
      4  = SACK Permitted
      5  = SACK blocks (raw hex)
      8  = Timestamps

    Unknown options are recorded as "kind_NN": "<hex>".
    """
    out: dict = {}
    i = 0
    while i < len(opts):
        kind = opts[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 1 >= len(opts):
            break
        length = opts[i + 1]
        if length < 2 or i + length > len(opts):
            out["parse_error"] = f"truncated option kind={kind} at offset={i}"
            break
        body = opts[i + 2: i + length]
        if kind == 2 and len(body) == 2:
            out["mss"] = int.from_bytes(body, "big")
        elif kind == 3 and len(body) == 1:
            out["window_scale"] = body[0]
        elif kind == 4:
            out["sack_permitted"] = True
        elif kind == 5:
            out["sack_blocks"] = body.hex(" ")
        elif kind == 8 and len(body) == 8:
            out["timestamp_val"]  = int.from_bytes(body[:4], "big")
            out["timestamp_echo"] = int.from_bytes(body[4:], "big")
        else:
            out[f"kind_{kind}"] = body.hex()
        i += length
    return out


# ─────────────────────────────────────────────────────────────────────────────
# decode_tcp
# ─────────────────────────────────────────────────────────────────────────────

_TCP_MIN = 20

def decode_tcp(data: bytes, layer_offset: int = 0,
               src_ip_bytes: Optional[bytes] = None,
               dst_ip_bytes: Optional[bytes] = None,
               ip_version: int = 4,
               transport_length: Optional[int] = None,
               checksum_verifiable: bool = True) -> Layer:
    """
    Decode a TCP segment header (RFC 9293).

    Parameters
    ----------
    data : bytes
        Raw frame buffer.
    layer_offset : int
        Byte offset of the TCP header within *data*.
    src_ip_bytes : bytes | None
        Source IP address bytes (4 for IPv4, 16 for IPv6).
        Required for checksum verification; pass None to skip.
    dst_ip_bytes : bytes | None
        Destination IP address bytes.
    ip_version : int
        4 or 6, used to build the pseudo-header.

    Raises
    ------
    ValueError
        Buffer too short or data_offset < 5.
    """
    hdr = data[layer_offset:]
    if len(hdr) < _TCP_MIN:
        raise ValueError(f"TCP: need {_TCP_MIN} B, got {len(hdr)}")

    sport  = struct.unpack_from("!H", hdr, 0)[0]
    dport  = struct.unpack_from("!H", hdr, 2)[0]
    seq    = struct.unpack_from("!I", hdr, 4)[0]
    ack    = struct.unpack_from("!I", hdr, 8)[0]
    doff   = _extract_bits(hdr, 96, 4)
    if doff < 5:
        raise ValueError(f"TCP: data_offset={doff} < 5")
    hlen   = doff * 4
    if len(hdr) < hlen:
        raise ValueError(f"TCP: data_offset says {hlen} B but buffer has {len(hdr)}")

    raw    = hdr[:hlen]
    # Flag bits
    ns     = _extract_bits(hdr, 103, 1)
    cwr    = _extract_bits(hdr, 104, 1)
    ece    = _extract_bits(hdr, 105, 1)
    urg    = _extract_bits(hdr, 106, 1)
    ack_f  = _extract_bits(hdr, 107, 1)
    psh    = _extract_bits(hdr, 108, 1)
    rst    = _extract_bits(hdr, 109, 1)
    syn    = _extract_bits(hdr, 110, 1)
    fin    = _extract_bits(hdr, 111, 1)
    window = struct.unpack_from("!H", hdr, 14)[0]
    rx_ck  = struct.unpack_from("!H", hdr, 16)[0]
    urgptr = struct.unpack_from("!H", hdr, 18)[0]

    # Checksum verification
    cx_ck: Optional[int] = None
    if src_ip_bytes and dst_ip_bytes and checksum_verifiable:
        # TCP carries no length field of its own, so the segment length must
        # come from IP.  Falling back to len(hdr) includes Ethernet padding
        # (frames are padded to 60 bytes), which makes every small segment —
        # every SYN, ACK and FIN — report a false bad checksum.
        tcp_len    = len(hdr) if transport_length is None else min(transport_length, len(hdr))
        pseudo     = _transport_pseudo_header(src_ip_bytes, dst_ip_bytes,
                                              6, tcp_len, ip_version)
        zeroed     = bytearray(hdr[:tcp_len]); zeroed[16] = zeroed[17] = 0
        cx_ck      = _inet_checksum(pseudo + bytes(zeroed))

    flag_str = "".join(n for n, v in [("NS",ns),("CWR",cwr),("ECE",ece),
        ("URG",urg),("ACK",ack_f),("PSH",psh),("RST",rst),("SYN",syn),
        ("FIN",fin)] if v)

    sport_name = _TCP_PORTS.get(sport, ""); dport_name = _TCP_PORTS.get(dport, "")
    layer = Layer(name="TCP", raw_bytes=raw, payload_offset=hlen)
    f = layer.fields

    f["src_port"]    = _fv(hdr, 0, 16, sport,
        f"Source port: {sport}" + (f" ({sport_name})" if sport_name else "") +
        ". Ephemeral port chosen by the OS for this connection.")
    f["dst_port"]    = _fv(hdr, 16, 16, dport,
        f"Destination port: {dport}" + (f" ({dport_name})" if dport_name else "") +
        ". Identifies the service (demux at Layer 4).")
    f["seq"]         = _fv(hdr, 32, 32, seq,
        f"Sequence number: {seq}. "
        "Labels the first byte of this segment's data in the byte stream; "
        "SYN segments consume one sequence number.")
    f["ack"]         = _fv(hdr, 64, 32, ack,
        f"Acknowledgment number: {ack}. "
        "Valid only when ACK flag is set; equals the next byte the sender "
        "expects from the peer (cumulative ACK).")
    f["data_offset"] = _fv(hdr, 96, 4, doff,
        f"Data offset: {doff}×32-bit words = {hlen} B. "
        f"Length of the TCP header; payload starts at byte {hlen}.")
    f["reserved"]    = _fv(hdr, 100, 3, _extract_bits(hdr, 100, 3),
        "Reserved (3 bits): must be zero.")
    f["ns"]          = _fv(hdr, 103, 1, ns,  "NS (Nonce Sum, ECN-related).")
    f["cwr"]         = _fv(hdr, 104, 1, cwr, "CWR: Congestion Window Reduced.")
    f["ece"]         = _fv(hdr, 105, 1, ece, "ECE: ECN-Echo.")
    f["urg"]         = _fv(hdr, 106, 1, urg, "URG: Urgent Pointer is valid.")
    f["ack_flag"]    = _fv(hdr, 107, 1, ack_f,
        "ACK: Acknowledgment field is valid. Set in all segments after "
        "the initial SYN.")
    f["psh"]         = _fv(hdr, 108, 1, psh,
        "PSH: Push — receiver should pass buffered data to the application "
        "immediately rather than wait for more.")
    f["rst"]         = _fv(hdr, 109, 1, rst, "RST: Reset — abort the connection.")
    f["syn"]         = _fv(hdr, 110, 1, syn,
        "SYN: Synchronise sequence numbers. Set only in the first two "
        "segments of the three-way handshake.")
    f["fin"]         = _fv(hdr, 111, 1, fin,
        "FIN: No more data from sender; initiates connection teardown.")
    f["window"]      = _fv(hdr, 112, 16, window,
        f"Receive window: {window} B. "
        "Flow control: the sender may not send more than this many "
        "unacknowledged bytes at a time.")
    ck_desc = (f"Checksum: received=0x{rx_ck:04X}"
               + (f", computed=0x{cx_ck:04X}" if cx_ck is not None else
                  (" (not verifiable — this is an IP fragment; the TCP checksum "
                   "covers the whole reassembled segment, not this piece)"
                   if not checksum_verifiable else
                   " (not verified — IP addresses not provided)"))
               + ". Covers TCP header + data + pseudo-header (src/dst IP, "
               "protocol=6, TCP length).")
    f["checksum"]    = _fv(hdr, 128, 16, rx_ck, ck_desc, computed_value=cx_ck)
    f["urg_ptr"]     = _fv(hdr, 144, 16, urgptr,
        f"Urgent pointer: {urgptr}. "
        "Valid only when URG is set; points to the last urgent byte.")

    if doff > 5:
        opts_bytes = raw[20:]
        parsed     = _parse_tcp_options(opts_bytes)
        opt_parts  = "; ".join(f"{k}={v}" for k, v in parsed.items())
        f["options"] = _fv(hdr, 160, len(opts_bytes)*8, parsed,
            f"TCP Options ({len(opts_bytes)} B): {opt_parts or 'none recognised'}. "
            "Common options: MSS (max segment size), Window Scale (extend "
            "window to >64 KiB), SACK Permitted, Timestamps.")

    return layer


_UDP_HDR = 8

def decode_udp(data: bytes, layer_offset: int = 0,
               src_ip_bytes: Optional[bytes] = None,
               dst_ip_bytes: Optional[bytes] = None,
               ip_version: int = 4) -> Layer:
    """
    Decode a UDP datagram header (RFC 768).

    Parameters
    ----------
    data, layer_offset, src_ip_bytes, dst_ip_bytes, ip_version
        Same semantics as decode_tcp.

    Raises
    ------
    ValueError
        Buffer shorter than 8 bytes.
    """
    hdr = data[layer_offset:]
    if len(hdr) < _UDP_HDR:
        raise ValueError(f"UDP: need {_UDP_HDR} B, got {len(hdr)}")

    sport = struct.unpack_from("!H", hdr, 0)[0]
    dport = struct.unpack_from("!H", hdr, 2)[0]
    ulen  = struct.unpack_from("!H", hdr, 4)[0]
    rx_ck = struct.unpack_from("!H", hdr, 6)[0]

    cx_ck: Optional[int] = None
    if src_ip_bytes and dst_ip_bytes and rx_ck != 0:
        actual_len = min(ulen, len(hdr))
        pseudo     = _transport_pseudo_header(src_ip_bytes, dst_ip_bytes,
                                              17, actual_len, ip_version)
        zeroed     = bytearray(hdr[:actual_len]); zeroed[6] = zeroed[7] = 0
        cx_ck      = _inet_checksum(pseudo + bytes(zeroed))

    sport_name = _UDP_PORTS.get(sport, ""); dport_name = _UDP_PORTS.get(dport, "")
    layer = Layer(name="UDP", raw_bytes=hdr[:_UDP_HDR], payload_offset=_UDP_HDR)
    f = layer.fields

    f["src_port"] = _fv(hdr, 0, 16, sport,
        f"Source port: {sport}" + (f" ({sport_name})" if sport_name else "") + ".")
    f["dst_port"] = _fv(hdr, 16, 16, dport,
        f"Destination port: {dport}" + (f" ({dport_name})" if dport_name else "") +
        ". Demultiplexes the datagram to the correct application socket.")
    f["length"]   = _fv(hdr, 32, 16, ulen,
        f"UDP length: {ulen} B (header 8 + payload {max(0, ulen-8)} B). "
        "Unlike TCP, UDP delivers whole datagrams — no stream reassembly.")
    ck_desc = (f"Checksum: received=0x{rx_ck:04X}"
               + (", optional (0 = not used)" if rx_ck == 0 else
                  (f", computed=0x{cx_ck:04X}" if cx_ck is not None else
                   " (not verified — IP addresses not provided)"))
               + ". Covers UDP header + data + pseudo-header.")
    f["checksum"] = _fv(hdr, 48, 16, rx_ck, ck_desc, computed_value=cx_ck)

    return layer

