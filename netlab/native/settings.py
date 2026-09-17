"""
netlab.native.settings — read tunnel parameters from config/settings.json.

Three settings the Settings dialog has always written and nothing ever read:

    keepalive_interval   how often to send an empty transport packet
    connection_timeout   how long to wait for a handshake response
    mtu_size             largest inner payload per datagram

Wiring them here is what makes them mean something. Each is clamped to a
usable range, because the dialog lets the user pick values that would simply
break the tunnel — a 1-second keepalive floods the link, and an MTU of 9000
fragments on every path.
"""

from __future__ import annotations

import json
from pathlib import Path

from .protocol import (
    HANDSHAKE_TIMEOUT_SECONDS,
    KEEPALIVE_SECONDS,
    MAX_TUNNEL_PAYLOAD,
)

SETTINGS_PATH = Path("config") / "settings.json"


def _load() -> dict:
    if not SETTINGS_PATH.exists():
        return {}
    try:
        return json.loads(SETTINGS_PATH.read_text(encoding="utf-8")) or {}
    except (OSError, json.JSONDecodeError):
        return {}


def keepalive_interval() -> int:
    """
    Seconds between keepalives, clamped to [5, 120].

    Its real job is refreshing the NAT binding: most consumer routers drop an
    idle UDP mapping after 30-120 s, after which the server's replies have
    nowhere to go. Below 5 s it is pure overhead; above 120 s it stops doing
    the job it exists for.
    """
    value = _load().get("keepalive_interval", KEEPALIVE_SECONDS)
    try:
        return max(5, min(120, int(value)))
    except (TypeError, ValueError):
        return KEEPALIVE_SECONDS


def connection_timeout() -> float:
    """Handshake timeout in seconds, clamped to [1, 60]."""
    value = _load().get("connection_timeout", HANDSHAKE_TIMEOUT_SECONDS)
    try:
        return float(max(1, min(60, int(value))))
    except (TypeError, ValueError):
        return float(HANDSHAKE_TIMEOUT_SECONDS)


def tunnel_payload_size() -> int:
    """
    Largest inner payload, clamped to [576, 1432].

    The lower bound is the IPv4 minimum every host must accept. The upper
    bound is what fits a 1500-byte path once the outer IP, UDP, tunnel header
    and Poly1305 tag are subtracted — going above it produces datagrams that
    IP-fragments, and one lost fragment destroys the whole thing.
    """
    value = _load().get("mtu_size", MAX_TUNNEL_PAYLOAD)
    try:
        return max(576, min(1432, int(value)))
    except (TypeError, ValueError):
        return MAX_TUNNEL_PAYLOAD
