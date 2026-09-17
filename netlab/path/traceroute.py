"""
netlab.path.traceroute — traceroute from first principles.

The trick
─────────
There is no "tell me the path" message in IP. Traceroute discovers the path by
abusing TTL: every router that forwards a packet decrements TTL, and a router
that decrements it to zero discards the packet and reports the fact with an
ICMP Time Exceeded (type 11). So:

    send a probe with TTL=1  → first router replies Time Exceeded  → hop 1
    send a probe with TTL=2  → second router replies                → hop 2
    ...
    until the destination replies Echo Reply (type 0) instead

Each hop identifies itself by the source address of its ICMP error. That is
the whole mechanism — the path is assembled from error messages.

Why hops show as `*`
────────────────────
A `*` is not a broken router. Many operators rate-limit or suppress ICMP
errors, and some firewalls drop them entirely. A missing hop means "this
router chose not to answer", not "the path stops here" — packets still pass
through it.

Implementation note (plan trap §7.2)
────────────────────────────────────
We set TTL with the IP_TTL socket option and let the kernel build the IP
header, rather than crafting one ourselves. On Windows, sending a hand-built
IP header over a raw socket needs IP_HDRINCL and administrator rights, and
behaves inconsistently across versions. Setting IP_TTL is portable and is what
the system `tracert` does.

Receiving ICMP still requires a raw socket and therefore administrator
privileges — which this app already has, since managing WireGuard tunnels
needs them. Without them, `traceroute_available()` says so rather than
crashing.
"""

from __future__ import annotations

import os
import select
import socket
import struct
import time
from dataclasses import dataclass, field

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_TIME_EXCEEDED = 11
ICMP_DEST_UNREACHABLE = 3

DEFAULT_MAX_HOPS = 30
DEFAULT_PROBES = 3
DEFAULT_TIMEOUT = 2.0


def checksum(data: bytes) -> int:
    """RFC 1071 one's-complement checksum — the same algorithm as IPv4/TCP/UDP."""
    if len(data) % 2:
        data += b"\x00"
    total = sum((data[i] << 8) | data[i + 1] for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_echo_request(identifier: int, sequence: int,
                       payload: bytes = b"onamvpn-traceroute") -> bytes:
    """
    Build an ICMP Echo Request.

    The checksum is computed over the message with the checksum field zeroed,
    then written back — exactly as netlab.dissect verifies it on the way in.
    """
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, identifier, sequence)
    computed = checksum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, computed,
                         identifier, sequence)
    return header + payload


@dataclass
class Hop:
    ttl: int
    address: str | None = None
    hostname: str | None = None
    rtts_ms: list[float] = field(default_factory=list)
    reached_destination: bool = False
    unreachable: bool = False

    @property
    def responded(self) -> bool:
        return self.address is not None

    @property
    def best_ms(self) -> float | None:
        return min(self.rtts_ms) if self.rtts_ms else None

    @property
    def avg_ms(self) -> float | None:
        return sum(self.rtts_ms) / len(self.rtts_ms) if self.rtts_ms else None

    def render(self) -> str:
        if not self.responded:
            return f"{self.ttl:2}  * * *"
        times = "  ".join(f"{rtt:6.1f} ms" for rtt in self.rtts_ms)
        label = self.hostname or self.address
        return f"{self.ttl:2}  {label} ({self.address})  {times}"


@dataclass
class TracerouteResult:
    destination: str
    destination_ip: str
    hops: list[Hop] = field(default_factory=list)
    completed: bool = False
    error: str | None = None

    def render(self) -> str:
        lines = [f"traceroute to {self.destination} ({self.destination_ip}), "
                 f"{len(self.hops)} hops max"]
        lines += [hop.render() for hop in self.hops]
        if self.error:
            lines.append(f"error: {self.error}")
        return "\n".join(lines)

    def as_dict(self) -> dict:
        return {
            "destination": self.destination,
            "destination_ip": self.destination_ip,
            "completed": self.completed,
            "error": self.error,
            "hops": [
                {
                    "ttl": hop.ttl,
                    "address": hop.address,
                    "hostname": hop.hostname,
                    "best_ms": round(hop.best_ms, 1) if hop.best_ms else None,
                    "avg_ms": round(hop.avg_ms, 1) if hop.avg_ms else None,
                    "responded": hop.responded,
                }
                for hop in self.hops
            ],
        }


def traceroute_available() -> tuple[bool, str]:
    """
    Can we actually use a raw ICMP socket?

    Creating the socket is not a sufficient test on Windows, and this is a
    trap worth naming: an unelevated process can call socket(SOCK_RAW,
    IPPROTO_ICMP) successfully and only discover the problem when every probe
    silently returns nothing. The first version of this function did exactly
    that and reported "available" while the trace produced 30 rows of `* * *`.

    So on Windows we check elevation explicitly, which is the real requirement.
    """
    import platform

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.close()
    except PermissionError:
        return False, (
            "raw ICMP sockets require elevated privileges. "
            "Falling back to the system traceroute command."
        )
    except OSError as exc:
        return False, f"raw ICMP socket unavailable: {exc}"

    if platform.system().lower() == "windows":
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                return False, (
                    "Windows allows an unelevated process to create a raw "
                    "socket but not to send or receive on it — every probe "
                    "would time out. Falling back to the system `tracert`."
                )
        except Exception:
            return False, "could not determine privilege level"

    return True, "raw ICMP socket available"


def system_traceroute(destination: str, max_hops: int = DEFAULT_MAX_HOPS,
                      timeout: float = DEFAULT_TIMEOUT,
                      resolve_names: bool = False) -> TracerouteResult:
    """
    Fall back to the operating system's own traceroute and parse its output.

    Less satisfying than building the probes ourselves, but it keeps the panel
    working on an unelevated machine — and the mechanism being demonstrated
    (TTL expiry producing ICMP Time Exceeded) is identical either way. The
    hand-rolled version above is what the write-up points at; this is what runs
    when the privileges are not there.
    """
    import platform
    import re
    import subprocess

    is_windows = platform.system().lower() == "windows"
    if is_windows:
        command = ["tracert", "-h", str(max_hops),
                   "-w", str(int(timeout * 1000))]
        if not resolve_names:
            command.append("-d")
        command.append(destination)
    else:
        command = ["traceroute", "-m", str(max_hops),
                   "-w", str(int(timeout)), destination]

    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=max_hops * timeout + 30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return TracerouteResult(destination, "",
                                error=f"system traceroute failed: {exc}")

    try:
        destination_ip = socket.gethostbyname(destination)
    except socket.gaierror:
        destination_ip = destination

    result = TracerouteResult(destination, destination_ip)
    address_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)")
    time_pattern = re.compile(r"(\d+(?:\.\d+)?)\s*ms")

    for line in completed.stdout.splitlines():
        stripped = line.strip()
        if not stripped or not stripped[0].isdigit():
            continue
        ttl = int(stripped.split()[0])
        addresses = address_pattern.findall(stripped)
        times = [float(t) for t in time_pattern.findall(stripped)]
        hop = Hop(ttl=ttl)
        if addresses:
            hop.address = addresses[-1]
            hop.rtts_ms = times
            if hop.address == destination_ip:
                hop.reached_destination = True
                result.completed = True
        result.hops.append(hop)

    if not result.hops:
        result.error = "could not parse system traceroute output"
    return result


def traceroute_auto(destination: str, **kwargs) -> TracerouteResult:
    """Use raw sockets when privileges allow, otherwise the system command."""
    available, _ = traceroute_available()
    if available:
        return traceroute(destination, **kwargs)
    kwargs.pop("probes", None)
    kwargs.pop("progress", None)
    return system_traceroute(destination, **kwargs)


def traceroute(destination: str, max_hops: int = DEFAULT_MAX_HOPS,
               probes: int = DEFAULT_PROBES, timeout: float = DEFAULT_TIMEOUT,
               resolve_names: bool = True,
               progress=None) -> TracerouteResult:
    """
    Trace the path to *destination*.

    `progress` is called with each completed Hop so a GUI can fill the table
    live rather than waiting for the whole trace — a trace to an unresponsive
    host can take max_hops * probes * timeout seconds.
    """
    available, reason = traceroute_available()
    if not available:
        return TracerouteResult(destination, "", error=reason)

    try:
        destination_ip = socket.gethostbyname(destination)
    except socket.gaierror as exc:
        return TracerouteResult(destination, "", error=f"cannot resolve: {exc}")

    result = TracerouteResult(destination, destination_ip)
    identifier = os.getpid() & 0xFFFF

    for ttl in range(1, max_hops + 1):
        hop = Hop(ttl=ttl)

        for sequence in range(probes):
            address, rtt, kind = _probe(destination_ip, ttl, identifier,
                                        ttl * 100 + sequence, timeout)
            if address is None:
                continue
            hop.address = address
            hop.rtts_ms.append(rtt)
            if kind == ICMP_ECHO_REPLY:
                hop.reached_destination = True
            elif kind == ICMP_DEST_UNREACHABLE:
                hop.unreachable = True

        if hop.responded and resolve_names:
            hop.hostname = _reverse_lookup(hop.address)

        result.hops.append(hop)
        if progress is not None:
            progress(hop)

        if hop.reached_destination:
            result.completed = True
            break

    return result


def _probe(destination_ip: str, ttl: int, identifier: int, sequence: int,
           timeout: float) -> tuple[str | None, float, int | None]:
    """Send one probe at *ttl* and wait for whoever answers."""
    try:
        sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sender.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        sender.settimeout(timeout)
    except OSError:
        return None, 0.0, None

    try:
        packet = build_echo_request(identifier, sequence)
        started = time.perf_counter()
        sender.sendto(packet, (destination_ip, 0))

        deadline = started + timeout
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                return None, 0.0, None
            ready, _, _ = select.select([sender], [], [], remaining)
            if not ready:
                return None, 0.0, None

            raw, source = sender.recvfrom(1024)
            elapsed_ms = (time.perf_counter() - started) * 1000

            kind = _classify(raw, identifier, sequence)
            if kind is not None:
                return source[0], elapsed_ms, kind
    except OSError:
        return None, 0.0, None
    finally:
        sender.close()


def _classify(raw: bytes, identifier: int, sequence: int) -> int | None:
    """
    Decide whether an ICMP message is a reply to *our* probe.

    A Time Exceeded carries the first 8 bytes of the original datagram inside
    it, so the identifier and sequence we sent are recoverable and we can tell
    our probes apart from every other ICMP message on the machine.
    """
    if len(raw) < 28:
        return None
    ip_header_len = (raw[0] & 0x0F) * 4
    if len(raw) < ip_header_len + 8:
        return None

    icmp_type = raw[ip_header_len]

    if icmp_type == ICMP_ECHO_REPLY:
        reply_id, reply_seq = struct.unpack_from("!HH", raw, ip_header_len + 4)
        if reply_id == identifier and reply_seq == sequence:
            return ICMP_ECHO_REPLY
        return None

    if icmp_type in (ICMP_TIME_EXCEEDED, ICMP_DEST_UNREACHABLE):
        # The quoted original datagram starts 8 bytes into the ICMP message.
        quoted = ip_header_len + 8
        if len(raw) < quoted + 28:
            return icmp_type          # too short to verify; accept it
        quoted_ip_len = (raw[quoted] & 0x0F) * 4
        echo_at = quoted + quoted_ip_len + 4
        if len(raw) >= echo_at + 4:
            original_id, original_seq = struct.unpack_from("!HH", raw, echo_at)
            if original_id != identifier or original_seq != sequence:
                return None
        return icmp_type

    return None


def _reverse_lookup(address: str) -> str | None:
    try:
        return socket.gethostbyaddr(address)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def compare_paths(destination: str, **kwargs) -> dict:
    """
    Trace the same destination twice so the caller can diff before/after VPN.

    The second trace is taken by the caller after toggling the tunnel; this
    helper just packages the comparison.
    """
    first = traceroute(destination, **kwargs)
    return {
        "destination": destination,
        "trace": first,
        "hop_count": len(first.hops),
        "responding_hops": sum(1 for hop in first.hops if hop.responded),
    }
