"""
netlab.path.pmtud — Path MTU Discovery.

Every link has a maximum frame size. The path MTU is the smallest MTU along
the whole route, and a sender that exceeds it either fragments the packet or
has it dropped.

How discovery works (RFC 1191)
───────────────────────────────
Send a probe with the Don't Fragment bit set. A router that cannot forward it
must not fragment, so it drops the packet and returns:

    ICMP type 3 (Destination Unreachable), code 4 (Fragmentation Needed)

and — since RFC 1191 — puts the next-hop MTU in the otherwise-unused bytes of
that ICMP header. Binary search on the probe size converges in a handful of
round trips.

The failure mode this has in practice
──────────────────────────────────────
Some networks block all ICMP, believing it to be "just ping". The sender then
gets no error at all: large packets vanish silently while small ones succeed,
so the connection completes its handshake and then hangs on the first big
transfer. This is the ICMP black hole, and it is why MTU problems are
notoriously hard to diagnose — the symptom looks like anything but MTU.

Why OnamVPN uses 1280
──────────────────────
config/servers.json sets MTU = 1280 for the WireGuard tunnel. The arithmetic:

    1500   typical Ethernet MTU
    -  20  outer IPv4 header      (40 if the path is IPv6)
    -   8  outer UDP header
    -  32  WireGuard data header + Poly1305 tag
    =1440  available to the inner packet

1280 sits comfortably below that, and is chosen rather than 1440 because it is
the minimum MTU every IPv6 link must support (RFC 8200 §5). A tunnel at 1280
survives almost any path — including one that is itself tunnelled — without
fragmenting. Trading ~11% of payload efficiency for not having to debug an
ICMP black hole is a good trade.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

from .traceroute import (
    ICMP_DEST_UNREACHABLE,
    build_echo_request,
    traceroute_available,
)

CODE_FRAGMENTATION_NEEDED = 4

IPV4_HEADER = 20
IPV6_HEADER = 40
UDP_HEADER = 8
ICMP_HEADER = 8
WIREGUARD_OVERHEAD = 32     # 16-byte data header + 16-byte Poly1305 tag

MIN_PROBE = 576             # RFC 791 minimum every IPv4 host must accept
MAX_PROBE = 1500
IPV6_MIN_MTU = 1280


@dataclass
class ProbeStep:
    size: int
    succeeded: bool
    reported_mtu: int | None = None
    note: str = ""


@dataclass
class PmtudResult:
    destination: str
    path_mtu: int | None = None
    steps: list[ProbeStep] = field(default_factory=list)
    black_hole: bool = False
    error: str | None = None

    def as_dict(self) -> dict:
        return {
            "destination": self.destination,
            "path_mtu": self.path_mtu,
            "probes": len(self.steps),
            "black_hole": self.black_hole,
            "error": self.error,
            "steps": [
                {"size": s.size, "ok": s.succeeded, "reported_mtu": s.reported_mtu}
                for s in self.steps
            ],
        }


def tunnel_overhead(ip_version: int = 4) -> int:
    """Bytes the tunnel adds to every inner packet."""
    outer = IPV4_HEADER if ip_version == 4 else IPV6_HEADER
    return outer + UDP_HEADER + WIREGUARD_OVERHEAD


def recommended_tunnel_mtu(path_mtu: int, ip_version: int = 4) -> int:
    """
    Largest safe inner MTU for a tunnel over a path of *path_mtu*.

    Never returns more than the path allows, and never less than the IPv6
    minimum unless the path itself is smaller than that.
    """
    usable = path_mtu - tunnel_overhead(ip_version)
    return max(min(usable, path_mtu), min(IPV6_MIN_MTU, usable))


def explain_mtu_choice(path_mtu: int = 1500, ip_version: int = 4) -> dict:
    """The arithmetic behind the configured 1280, spelled out for the panel."""
    overhead = tunnel_overhead(ip_version)
    return {
        "path_mtu": path_mtu,
        "outer_ip_header": IPV4_HEADER if ip_version == 4 else IPV6_HEADER,
        "udp_header": UDP_HEADER,
        "wireguard_overhead": WIREGUARD_OVERHEAD,
        "total_overhead": overhead,
        "max_inner_mtu": path_mtu - overhead,
        "configured_mtu": IPV6_MIN_MTU,
        "why": (
            f"{path_mtu} - {overhead} = {path_mtu - overhead} bytes are "
            f"available to the inner packet. The config uses {IPV6_MIN_MTU} "
            "instead, because that is the minimum MTU every IPv6 link must "
            "support, so the tunnel survives paths that are themselves "
            "tunnelled. The cost is about "
            f"{100 * (1 - IPV6_MIN_MTU / (path_mtu - overhead)):.0f}% of "
            "payload efficiency, traded for not having to debug an ICMP "
            "black hole."
        ),
    }


def discover_path_mtu(destination: str, low: int = MIN_PROBE,
                      high: int = MAX_PROBE,
                      timeout: float = 2.0) -> PmtudResult:
    """
    Binary-search the path MTU with DF-set probes.

    Requires a raw ICMP socket (administrator). Without one, returns a result
    carrying the reason rather than raising.
    """
    available, reason = traceroute_available()
    if not available:
        return PmtudResult(destination, error=reason)

    try:
        destination_ip = socket.gethostbyname(destination)
    except socket.gaierror as exc:
        return PmtudResult(destination, error=f"cannot resolve: {exc}")

    result = PmtudResult(destination)
    best: int | None = None

    while low <= high:
        middle = (low + high) // 2
        succeeded, reported = _probe_size(destination_ip, middle, timeout)
        result.steps.append(ProbeStep(middle, succeeded, reported))

        if reported:
            # The router told us the answer outright — no need to keep searching.
            result.path_mtu = reported
            result.steps[-1].note = "router reported next-hop MTU directly"
            return result

        if succeeded:
            best = middle
            low = middle + 1
        else:
            high = middle - 1

    if best is None:
        result.black_hole = True
        result.error = (
            "no probe of any size got a reply. Either the host does not answer "
            "ICMP at all, or the path is an ICMP black hole — large packets "
            "vanish with no error, which is exactly the situation PMTUD "
            "cannot see through."
        )
        return result

    result.path_mtu = best
    return result


def _probe_size(destination_ip: str, size: int,
                timeout: float) -> tuple[bool, int | None]:
    """
    Send one DF-set probe of *size* bytes total.

    Returns (got_echo_reply, reported_next_hop_mtu).
    """
    payload_size = max(0, size - IPV4_HEADER - ICMP_HEADER)
    packet = build_echo_request(0x4242, size & 0xFFFF, b"M" * payload_size)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)
        # Set the Don't Fragment bit. Windows and Linux spell this differently.
        try:
            if hasattr(socket, "IP_MTU_DISCOVER"):
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MTU_DISCOVER, 2)
            else:
                sock.setsockopt(socket.IPPROTO_IP, 14, 1)   # IP_DONTFRAGMENT
        except OSError:
            pass
    except OSError:
        return False, None

    try:
        sock.sendto(packet, (destination_ip, 0))
        raw, _ = sock.recvfrom(2048)
    except OSError:
        return False, None
    finally:
        sock.close()

    if len(raw) < 28:
        return False, None

    ip_header_len = (raw[0] & 0x0F) * 4
    icmp_type = raw[ip_header_len]
    icmp_code = raw[ip_header_len + 1]

    if icmp_type == ICMP_DEST_UNREACHABLE and icmp_code == CODE_FRAGMENTATION_NEEDED:
        # RFC 1191 puts the next-hop MTU in the last two bytes of the unused
        # word — the field was reserved in RFC 792 and later given this job.
        next_hop_mtu = struct.unpack_from("!H", raw, ip_header_len + 6)[0]
        return False, (next_hop_mtu or None)

    return icmp_type == 0, None
