"""
netlab.dissect.dispatch — chains the per-layer decoders into a DecodedPacket.

This is where encapsulation is made concrete: each layer names the protocol of
the one inside it (EtherType → IP Protocol / Next Header), and the dispatcher
walks that chain, accumulating byte offsets.

    Ethernet.ethertype  0x0800 ──▶ IPv4
    IPv4.protocol       6      ──▶ TCP
                        17     ──▶ UDP
                        1      ──▶ ICMP
    IPv6.next_header    58     ──▶ ICMPv6

Two rules that are easy to get wrong and are enforced here:

1. A non-first IP fragment does NOT carry a transport header.  Only fragment 0
   does; later fragments hold raw payload that parses as a convincing but
   entirely fictitious TCP header.

2. The TCP/UDP checksum must be computed over the transport length taken from
   the IP header, not over "the rest of the buffer".  Ethernet pads frames to
   60 bytes, so the buffer routinely contains trailing padding that is not part
   of the segment.  Including it makes every small TCP packet — every SYN, ACK
   and FIN — report a false bad checksum.
"""

from __future__ import annotations

import socket
import struct
from typing import Optional

from .model import DecodedPacket
from .link import decode_ethernet
from .internet import decode_ipv4, decode_ipv6, decode_icmp
from .transport import decode_tcp, decode_udp


def decode_packet(frame: bytes, l2: bool = True,
                  capture_source: str = "",
                  timestamp: float = 0.0) -> DecodedPacket:
    """
    Decode a complete network packet into a DecodedPacket layer tree.

    Parameters
    ----------
    frame : bytes
        Raw frame bytes.
    l2 : bool
        True  → frame starts with an Ethernet header (L2 capture).
        False → frame starts with an IPv4/IPv6 header (raw-socket capture).
    capture_source : str
        Label for the panel (adapter name or pcap filename).
    timestamp : float
        Packet capture timestamp.

    Returns
    -------
    DecodedPacket
        All successfully decoded layers.  Decoding stops at the first malformed
        layer rather than raising: a truncated capture should still show the
        layers that did decode.
    """
    packet = DecodedPacket(timestamp=timestamp, raw_frame=frame,
                           capture_source=capture_source)
    offset = 0
    next_etype: Optional[int] = None

    try:
        if l2:
            eth = decode_ethernet(frame, offset)
            packet.layers.append(eth)
            offset += eth.payload_offset
            real = eth.fields.get("real_ethertype") or eth.fields.get("ethertype")
            next_etype = real.value if real else None
        else:
            first_nibble = (frame[0] >> 4) if frame else 0
            next_etype = 0x0800 if first_nibble == 4 else 0x86DD

        if next_etype == 0x0800:
            ip4 = decode_ipv4(frame, offset)
            packet.layers.append(ip4)
            src_ip = socket.inet_aton(ip4.fields["src"].value)
            dst_ip = socket.inet_aton(ip4.fields["dst"].value)
            proto = ip4.fields["protocol"].value
            offset += ip4.payload_offset

            # Rule 1 — later fragments carry no transport header.
            if not ip4.carries_transport_header():
                return packet

            # Rule 2 — transport length comes from IP, not from the buffer.
            transport_len = ip4.fields["total_length"].value - ip4.payload_offset

            # Rule 3 — a TCP/UDP checksum covers the whole reassembled segment,
            # so it can never validate against fragment 0 alone.  Verifying it
            # here would flag every fragmented datagram as corrupt.
            verifiable = not ip4.notes.get("is_fragmented", False)

            if proto == 6:
                packet.layers.append(
                    decode_tcp(frame, offset, src_ip, dst_ip, 4,
                               transport_length=transport_len,
                               checksum_verifiable=verifiable))
            elif proto == 17:
                packet.layers.append(
                    decode_udp(frame, offset, src_ip, dst_ip, 4))
            elif proto == 1:
                packet.layers.append(
                    decode_icmp(frame, offset, 4, payload_length=transport_len))

        elif next_etype == 0x86DD:
            ip6 = decode_ipv6(frame, offset)
            packet.layers.append(ip6)
            # inet_pton handles "::" compression; stripping colons by hand does not.
            src_ip = socket.inet_pton(socket.AF_INET6, ip6.fields["src"].value)
            dst_ip = socket.inet_pton(socket.AF_INET6, ip6.fields["dst"].value)
            plen = ip6.fields["payload_length"].value
            nh = ip6.fields["next_header"].value
            offset += ip6.payload_offset

            if nh == 6:
                packet.layers.append(
                    decode_tcp(frame, offset, src_ip, dst_ip, 6,
                               transport_length=plen))
            elif nh == 17:
                packet.layers.append(
                    decode_udp(frame, offset, src_ip, dst_ip, 6))
            elif nh == 58:
                packet.layers.append(
                    decode_icmp(frame, offset, 6, src_ip, dst_ip, plen))

    except (ValueError, struct.error, IndexError):
        pass  # partial decode is acceptable; the panel shows what was decoded

    return packet
