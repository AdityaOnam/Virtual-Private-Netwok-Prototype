"""
netlab.dissect.tables — protocol number → name lookup tables.

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

_ETHERTYPES: dict[int, str] = {
    0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6",
    0x8100: "802.1Q VLAN", 0x88A8: "802.1AD Q-in-Q",
    0x8847: "MPLS unicast", 0x8848: "MPLS multicast",
    0x8863: "PPPoE Discovery", 0x8864: "PPPoE Session",
    0x88CC: "LLDP",
}

_IP4_PROTOS: dict[int, str] = {
    1: "ICMP", 2: "IGMP", 4: "IPv4-in-IPv4", 6: "TCP",
    17: "UDP", 41: "IPv6", 47: "GRE", 50: "ESP",
    51: "AH", 58: "ICMPv6", 89: "OSPF", 132: "SCTP",
}

_DSCP_NAMES: dict[int, str] = {
    0: "CS0 (Best Effort)", 8: "CS1", 16: "CS2", 24: "CS3",
    32: "CS4", 40: "CS5", 46: "EF", 48: "CS6", 56: "CS7",
    10: "AF11", 12: "AF12", 14: "AF13",
    18: "AF21", 20: "AF22", 22: "AF23",
    26: "AF31", 28: "AF32", 30: "AF33",
    34: "AF41", 36: "AF42", 38: "AF43",
}

_ICMP4_TYPES: dict[int, str] = {
    0: "Echo Reply", 3: "Destination Unreachable",
    8: "Echo Request", 11: "Time Exceeded",
    12: "Parameter Problem", 5: "Redirect",
}
_ICMP6_TYPES: dict[int, str] = {
    1: "Destination Unreachable", 2: "Packet Too Big",
    3: "Time Exceeded", 4: "Parameter Problem",
    128: "Echo Request", 129: "Echo Reply",
    133: "Router Solicitation", 134: "Router Advertisement",
    135: "Neighbor Solicitation", 136: "Neighbor Advertisement",
}

_TCP_PORTS: dict[int, str] = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 465: "SMTPS", 587: "SMTP-sub",
    993: "IMAPS", 995: "POP3S",
}
_UDP_PORTS: dict[int, str] = {
    53: "DNS", 67: "DHCP-server", 68: "DHCP-client",
    123: "NTP", 161: "SNMP", 500: "IKE",
    2408: "WARP/WireGuard (Cloudflare)", 4500: "NAT-T",
    51820: "WireGuard",
}

