"""
netlab.dns.leaktest — does the tunnel actually hide DNS?

The claim in README.md is that OnamVPN blocks port 53 on every adapter except
the tunnel, so the ISP cannot see queries. Nothing in the project has ever
checked that claim. This module checks it.

Method
──────
1. Start a capture on the *physical* NIC filtered to UDP port 53.
2. Resolve a unique, unlikely name so the query cannot be answered from any
   cache anywhere.
3. Stop the capture and look for the name in the captured bytes.

    VPN off  → the query appears in plaintext on the physical adapter.
    VPN on   → it does not, because the firewall rule forced it into the
               tunnel (or because encrypted transport was used).

Why a random name
─────────────────
Resolving "example.com" proves nothing: the OS resolver, the router, or the
ISP may answer from cache without a packet leaving the machine, and an absence
of traffic would look like success. A name nobody has ever queried guarantees
a real lookup happens.

Honest limits
─────────────
- Without a capture backend this degrades to comparing the *transport* only
  (plain UDP vs DoT/DoH), which demonstrates the difference in principle but
  does not prove what left the machine.
- A negative result on one adapter does not prove no leak on another. The
  panel names the adapter it watched.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field

from ..dissect.capture import live_capture_available
from .resolver import Resolver
from .wire import encode_name


@dataclass
class LeakResult:
    """One observation: did the name appear in the clear?"""

    label: str
    query_name: str
    transport: str
    packets_captured: int = 0
    name_seen_in_clear: bool = False
    resolved: bool = False
    addresses: list[str] = field(default_factory=list)
    adapter: str = ""
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "label": self.label,
            "transport": self.transport,
            "packets_captured": self.packets_captured,
            "leaked": self.name_seen_in_clear,
            "resolved": self.resolved,
            "adapter": self.adapter,
            "note": self.note,
        }


def unique_query_name(suffix: str = "example.com") -> str:
    """A name nobody has ever looked up, so no cache can short-circuit it."""
    return f"onamvpn-{secrets.token_hex(6)}.{suffix}"


def _capture_for(seconds: float, adapter: str, name: str) -> tuple[int, bool]:
    """
    Sniff UDP :53 on *adapter* and report (packet_count, name_seen).

    The name is searched for in its DNS wire form — length-prefixed labels,
    not the dotted string — because that is what actually appears on the wire.
    """
    from scapy.sendrecv import sniff

    needle = encode_name(name)
    packets: list[bytes] = []

    def collect(packet) -> None:
        packets.append(bytes(packet))

    sniff(iface=adapter, filter="udp port 53", prn=collect,
          store=False, timeout=seconds)

    seen = any(needle in raw for raw in packets)
    return len(packets), seen


def run_leak_test(adapter: str | None = None, transport: str = "udp",
                  capture_seconds: float = 4.0,
                  label: str = "") -> LeakResult:
    """
    Resolve a unique name while watching the physical adapter.

    Set `transport="doh"` to show the encrypted case: the same lookup happens,
    but nothing readable appears on port 53 because the query travelled inside
    HTTPS on port 443.
    """
    query_name = unique_query_name()
    result = LeakResult(
        label=label or f"{transport} transport",
        query_name=query_name,
        transport=transport,
        adapter=adapter or "(none)",
    )

    available, reason = live_capture_available()
    if not available or adapter is None:
        # Degrade honestly rather than pretending to have observed the wire.
        answer = Resolver().resolve(query_name, transport=transport)
        result.resolved = answer.ok
        result.addresses = answer.addresses
        result.note = (
            f"no capture backend ({reason}); transport comparison only — "
            "this shows which protocol was used, not what left the machine"
        )
        return result

    captured: dict = {}

    def watch() -> None:
        captured["count"], captured["seen"] = _capture_for(
            capture_seconds, adapter, query_name
        )

    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    time.sleep(0.5)                       # let the capture attach

    answer = Resolver().resolve(query_name, transport=transport)
    result.resolved = answer.ok
    result.addresses = answer.addresses

    watcher.join(timeout=capture_seconds + 5)
    result.packets_captured = captured.get("count", 0)
    result.name_seen_in_clear = captured.get("seen", False)

    if result.name_seen_in_clear:
        result.note = (
            "the query name was visible in plaintext on this adapter — "
            "anyone on the path learns which site was visited"
        )
    else:
        result.note = (
            "the query name did not appear on this adapter; it was either "
            "encrypted or routed through the tunnel"
        )
    return result


def compare_plain_and_encrypted(adapter: str | None = None) -> dict:
    """
    Run the test twice — plain UDP, then DoH — and contrast.

    This is the demonstration: same resolver, same machine, one lookup
    readable on the wire and one not.
    """
    plain = run_leak_test(adapter, transport="udp", label="plain UDP :53")
    encrypted = run_leak_test(adapter, transport="doh", label="DoH :443")
    return {
        "plain": plain,
        "encrypted": encrypted,
        "verdict": (
            "leak demonstrated: plaintext query visible, encrypted query not"
            if plain.name_seen_in_clear and not encrypted.name_seen_in_clear
            else "inconclusive — see each result's note"
        ),
    }
