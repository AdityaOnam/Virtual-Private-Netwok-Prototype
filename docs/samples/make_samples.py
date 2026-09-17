#!/usr/bin/env python3
"""
docs/samples/make_samples.py — regenerate the dissector's sample captures.

Run from the project root:

    python docs/samples/make_samples.py

The three .pcap files it writes are committed, so the dissector panel and the
test suite work on any machine with no capture driver and no network.  This
script only needs to be re-run if the fixtures change.

Scapy is used here to *build* the frames.  It is not used to decode them
anywhere in netlab — that is the whole point of the module.

Sharp edges deliberately included
──────────────────────────────────
Two bugs were found in the decoders during review, both in paths no test
covered.  Each fixture below pins one of them:

  02_sharp_edges.pcap   a padded 60-byte TCP SYN.  Ethernet pads short frames,
                        and the TCP checksum was originally computed over "the
                        rest of the buffer", folding the padding in and
                        reporting every SYN/ACK/FIN as corrupt.

  02_sharp_edges.pcap   a non-first IP fragment whose payload happens to parse
                        as a plausible TCP header.  The dispatcher originally
                        descended into it and invented ports and sequence
                        numbers out of raw payload bytes.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from scapy.all import (  # noqa: E402
    ICMP,
    IP,
    IPv6,
    TCP,
    UDP,
    DNS,
    DNSQR,
    Dot1Q,
    Ether,
    ICMPv6EchoRequest,
    Raw,
)

from netlab.dissect.capture import write_pcap  # noqa: E402

SAMPLES_DIR = Path(__file__).resolve().parent

CLIENT_MAC = "aa:bb:cc:00:11:22"
ROUTER_MAC = "00:1a:2b:3c:4d:5e"


def _eth(payload):
    return Ether(src=CLIENT_MAC, dst=ROUTER_MAC) / payload


def build_handshake() -> list[bytes]:
    """
    01_tcp_handshake.pcap — a complete TCP three-way handshake plus an HTTP
    GET and its response, then the FIN exchange.

    This is the fixture for the layer tree: Ethernet → IPv4 → TCP, with the
    flag bits changing meaningfully packet to packet.
    """
    client, server = "192.168.1.50", "93.184.216.34"
    sport, dport = 49152, 80
    frames = [
        _eth(IP(src=client, dst=server, ttl=64)
             / TCP(sport=sport, dport=dport, flags="S", seq=1000,
                   options=[("MSS", 1460), ("SAckOK", b""),
                            ("Timestamp", (12345, 0)), ("NOP", None),
                            ("WScale", 7)])),
        _eth(IP(src=server, dst=client, ttl=54)
             / TCP(sport=dport, dport=sport, flags="SA", seq=5000, ack=1001,
                   options=[("MSS", 1400), ("SAckOK", b""), ("WScale", 8)])),
        _eth(IP(src=client, dst=server, ttl=64)
             / TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=5001)),
        _eth(IP(src=client, dst=server, ttl=64)
             / TCP(sport=sport, dport=dport, flags="PA", seq=1001, ack=5001)
             / Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")),
        _eth(IP(src=server, dst=client, ttl=54)
             / TCP(sport=dport, dport=sport, flags="PA", seq=5001, ack=1039)
             / Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")),
        _eth(IP(src=client, dst=server, ttl=64)
             / TCP(sport=sport, dport=dport, flags="FA", seq=1039, ack=5039)),
        _eth(IP(src=server, dst=client, ttl=54)
             / TCP(sport=dport, dport=sport, flags="FA", seq=5039, ack=1040)),
    ]
    return [bytes(f) for f in frames]


def build_sharp_edges() -> list[bytes]:
    """
    02_sharp_edges.pcap — the cases that broke the decoders.

    1. Padded 60-byte TCP SYN      → checksum must ignore Ethernet padding
    2. First fragment (MF=1)       → carries a real TCP header, decode it
    3. Non-first fragment (off=185)→ payload looks like TCP; must NOT decode
    4. UDP with checksum 0         → legal on IPv4, must not be flagged bad
    5. IPv4 with options (IHL=6)   → variable-length header
    6. Corrupted IPv4 checksum     → must be flagged is_bad
    """
    client, server = "10.0.0.5", "1.1.1.1"
    frames: list[bytes] = []

    # 1. Short SYN — a real NIC pads this to 60 bytes on the wire.
    syn = bytes(_eth(IP(src=client, dst=server) / TCP(sport=1234, dport=443, flags="S")))
    frames.append(syn + b"\x00" * (60 - len(syn)))

    # 2 & 3. A datagram split into two fragments.  Both fragments carry the
    # same IP id; only the first carries the TCP header.
    # proto=6 must be set explicitly: Scapy defaults IP.proto to 0 when the
    # payload is Raw, which would make the fragments decode as "unknown" and
    # let the later-fragment check pass for the wrong reason.
    payload = bytes(TCP(sport=1234, dport=80, flags="A", seq=1, ack=1)) + b"X" * 24
    first = IP(src=client, dst=server, id=0x1234, flags="MF", frag=0,
               proto=6) / Raw(payload[:24])
    later = IP(src=client, dst=server, id=0x1234, flags=0, frag=3,
               proto=6) / Raw(payload[24:])
    frames.append(bytes(_eth(first)))
    frames.append(bytes(_eth(later)))

    # 4. DNS query over UDP with the checksum field explicitly zeroed.
    dns = _eth(IP(src=client, dst=server)
               / UDP(sport=53535, dport=53, chksum=0)
               / DNS(rd=1, qd=DNSQR(qname="example.com")))
    frames.append(bytes(dns))

    # 5. IPv4 carrying a Record Route option (IHL = 6).
    opt = _eth(IP(src=client, dst=server, options=[b"\x07\x04\x00\x00"])
               / ICMP(type=8) / Raw(b"A" * 16))
    frames.append(bytes(opt))

    # 6. Deliberately corrupted IPv4 header checksum.
    good = bytearray(bytes(_eth(IP(src=client, dst=server) / ICMP(type=8) / Raw(b"B" * 16))))
    good[14 + 10] ^= 0xFF          # 14 B Ethernet header, then IP byte 10
    frames.append(bytes(good))

    return frames


def build_mixed_protocols() -> list[bytes]:
    """
    03_mixed_protocols.pcap — one packet per protocol the dissector handles,
    so the panel can be demonstrated across all six decoders in one file.
    """
    client = "10.0.0.5"
    frames = [
        # 802.1Q VLAN-tagged IPv4/UDP
        bytes(Ether(src=CLIENT_MAC, dst=ROUTER_MAC)
              / Dot1Q(vlan=100, prio=3)
              / IP(src=client, dst="1.1.1.1")
              / UDP(sport=40000, dport=123) / Raw(b"\x00" * 40)),
        # ICMP echo request and reply
        bytes(_eth(IP(src=client, dst="8.8.8.8") / ICMP(type=8, id=0x1234, seq=1)
                   / Raw(b"abcdefghijklmnop"))),
        bytes(_eth(IP(src="8.8.8.8", dst=client) / ICMP(type=0, id=0x1234, seq=1)
                   / Raw(b"abcdefghijklmnop"))),
        # ICMP time exceeded — what traceroute actually receives
        bytes(_eth(IP(src="203.0.113.1", dst=client, ttl=64)
                   / ICMP(type=11, code=0)
                   / IP(src=client, dst="8.8.8.8", ttl=1) / ICMP(type=8))),
        # IPv6 / TCP
        bytes(_eth(IPv6(src="2001:db8::5", dst="2606:4700:4700::1111", hlim=64)
                   / TCP(sport=50000, dport=443, flags="S"))),
        # IPv6 / ICMPv6 echo
        bytes(_eth(IPv6(src="2001:db8::5", dst="2001:db8::1")
                   / ICMPv6EchoRequest(id=7, seq=1))),
        # WireGuard-shaped UDP to the Cloudflare WARP endpoint — what OnamVPN
        # traffic looks like on the wire once the tunnel is up.
        bytes(_eth(IP(src=client, dst="162.159.192.1")
                   / UDP(sport=51820, dport=2408)
                   / Raw(bytes(range(256))[:128]))),
    ]
    return frames


SAMPLES = {
    "01_tcp_handshake.pcap": build_handshake,
    "02_sharp_edges.pcap": build_sharp_edges,
    "03_mixed_protocols.pcap": build_mixed_protocols,
}


def main() -> int:
    for name, builder in SAMPLES.items():
        frames = builder()
        write_pcap(SAMPLES_DIR / name, frames)
        total = sum(len(f) for f in frames)
        print(f"  wrote {name:26} {len(frames):2} packets, {total:5} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
