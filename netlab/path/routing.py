"""
netlab.path.routing — routing table parsing and longest-prefix match.

Longest prefix match
────────────────────
A destination usually matches several routes. The winner is the one with the
most specific prefix — the longest netmask — regardless of the order routes
appear in the table. `0.0.0.0/0` matches everything and therefore always loses
to anything else that matches at all, which is exactly what makes it a useful
"default".

The split-default trick
───────────────────────
WireGuard's `AllowedIPs = 0.0.0.0/0` does not replace the existing default
route. It installs two routes instead:

    0.0.0.0/1      →  tunnel     covers   0.0.0.0 – 127.255.255.255
    128.0.0.0/1    →  tunnel     covers 128.0.0.0 – 255.255.255.255

Together those two cover the whole address space, and each has a /1 prefix
which beats the real default route's /0 on specificity. So all traffic goes to
the tunnel *without deleting the original default route* — which matters
enormously, because that original route is how packets reach the VPN server
itself. Delete it and the tunnel cannot carry its own traffic: the classic
self-inflicted outage.

The route to the VPN endpoint stays a /32 through the physical gateway, and
/32 beats /1, so tunnel traffic itself escapes the tunnel. Three prefix
lengths doing three different jobs, decided entirely by longest-prefix match.

This module reads the real table through PlatformOps, so it works with FakeOps
in tests and with `route print` on a live machine.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass


@dataclass
class Route:
    destination: str
    netmask: str
    gateway: str
    interface: str
    metric: int = 0

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network(f"{self.destination}/{self.netmask}",
                                     strict=False)

    @property
    def prefix_length(self) -> int:
        return self.network.prefixlen

    @property
    def cidr(self) -> str:
        return str(self.network)

    @property
    def is_default(self) -> bool:
        return self.prefix_length == 0

    @property
    def is_split_default(self) -> bool:
        """True for the 0.0.0.0/1 and 128.0.0.0/1 pair WireGuard installs."""
        return self.cidr in ("0.0.0.0/1", "128.0.0.0/1")

    def contains(self, address: str) -> bool:
        try:
            return ipaddress.IPv4Address(address) in self.network
        except (ipaddress.AddressValueError, ValueError):
            return False

    def as_dict(self) -> dict:
        return {
            "cidr": self.cidr,
            "gateway": self.gateway,
            "interface": self.interface,
            "metric": self.metric,
            "prefix_length": self.prefix_length,
        }


@dataclass
class LookupResult:
    """A routing decision, with the reasoning kept so the panel can show it."""

    destination: str
    chosen: Route | None
    candidates: list[Route]
    explanation: str

    def as_dict(self) -> dict:
        return {
            "destination": self.destination,
            "chosen": self.chosen.as_dict() if self.chosen else None,
            "candidates": [route.as_dict() for route in self.candidates],
            "explanation": self.explanation,
        }


def parse_windows_route_print(output: str) -> list[Route]:
    """
    Parse the IPv4 section of `route print`.

    Format:
        Network Destination        Netmask          Gateway       Interface  Metric
                  0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.50     25
    """
    routes: list[Route] = []
    in_table = False
    row = re.compile(
        r"^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+"
        r"(\S+)\s+(\S+)\s+(\d+)\s*$"
    )

    for line in output.splitlines():
        if "Network Destination" in line:
            in_table = True
            continue
        if in_table and line.strip().startswith("==="):
            in_table = False
            continue
        if not in_table:
            continue
        match = row.match(line)
        if match:
            destination, netmask, gateway, interface, metric = match.groups()
            routes.append(Route(destination, netmask, gateway, interface,
                                int(metric)))
    return routes


def parse_route_dicts(rows: list[dict]) -> list[Route]:
    """Build Routes from PlatformOps.read_routing_table() output."""
    routes: list[Route] = []
    for row in rows:
        destination = row.get("destination") or row.get("network") or ""
        netmask = row.get("netmask") or row.get("mask") or ""
        if not destination:
            continue
        if not netmask and "/" in destination:
            destination, _, prefix = destination.partition("/")
            netmask = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
        routes.append(Route(
            destination=destination,
            netmask=netmask or "255.255.255.255",
            gateway=row.get("gateway", ""),
            interface=row.get("interface", ""),
            metric=int(row.get("metric", 0) or 0),
        ))
    return routes


def longest_prefix_match(routes: list[Route], destination: str) -> LookupResult:
    """
    Pick the route a router would use for *destination*.

    Longest prefix wins; metric breaks ties. The explanation names the runner-up
    so the panel can show *why* one route beat another rather than asserting it.
    """
    try:
        ipaddress.IPv4Address(destination)
    except (ipaddress.AddressValueError, ValueError):
        return LookupResult(destination, None, [],
                            f"{destination!r} is not a valid IPv4 address")

    candidates = [route for route in routes if route.contains(destination)]
    if not candidates:
        return LookupResult(destination, None, [],
                            "no route matches — the packet is undeliverable")

    candidates.sort(key=lambda r: (-r.prefix_length, r.metric))
    chosen = candidates[0]

    if len(candidates) == 1:
        explanation = (
            f"{chosen.cidr} is the only matching route "
            f"(via {chosen.gateway or 'on-link'} on {chosen.interface})"
        )
    else:
        runner_up = candidates[1]
        if chosen.prefix_length == runner_up.prefix_length:
            explanation = (
                f"{chosen.cidr} and {runner_up.cidr} are equally specific "
                f"(/{chosen.prefix_length}); {chosen.cidr} wins on metric "
                f"{chosen.metric} < {runner_up.metric}"
            )
        else:
            explanation = (
                f"{chosen.cidr} (/{chosen.prefix_length}) beats "
                f"{runner_up.cidr} (/{runner_up.prefix_length}) because a "
                f"longer prefix is more specific — order in the table is "
                f"irrelevant"
            )
        if chosen.is_split_default:
            explanation += (
                ". This is a VPN split-default route: /1 beats the real "
                "default /0 without deleting it, so the route to the VPN "
                "server itself survives."
            )

    return LookupResult(destination, chosen, candidates, explanation)


def describe_split_default(routes: list[Route]) -> dict:
    """Report whether the split-default pair is installed, and what it implies."""
    halves = [route for route in routes if route.is_split_default]
    default = next((route for route in routes if route.is_default), None)
    return {
        "split_default_present": len(halves) == 2,
        "halves": [route.cidr for route in halves],
        "original_default_survives": default is not None,
        "explanation": (
            "0.0.0.0/1 and 128.0.0.0/1 together cover the whole address space "
            "and both beat 0.0.0.0/0 on prefix length, so every packet goes to "
            "the tunnel while the original default route remains available for "
            "reaching the VPN server."
            if len(halves) == 2 else
            "no split-default pair present — traffic is following the ordinary "
            "default route"
        ),
    }
