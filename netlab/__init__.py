"""
netlab — Computer-Networks concept demonstrations for OnamVPN.

Each sub-package maps to one or more syllabus modules:
  netlab.dissect    — Module A: packet dissector (Ethernet/IP/TCP/UDP/ICMP)
  netlab.native     — Module B: OnamVPN native tunnel (ECDH + AEAD + SOCKS5)
  netlab.transport  — Module C: ARQ, congestion control, RTT estimation
  netlab.dns        — Module D: DNS wire format, resolver, DoT/DoH, leak test
  netlab.path       — Module E: traceroute, PMTUD, routing + LPM
"""

__version__ = "0.1.0"
