"""
netlab.dns.resolver — the same query over three transports, plus a cache.

    UDP :53    the original. Fast, unencrypted, and readable by anyone on the
               path — your ISP sees every name you look up even when the page
               itself is HTTPS.
    DoT :853   DNS over TLS. Same messages, wrapped in TLS with a 2-byte
               length prefix because TLS is a stream and DNS needs framing.
    DoH :443   DNS over HTTPS. The same bytes POSTed as
               application/dns-message. Slowest of the three, and the point is
               not speed: it is indistinguishable from ordinary web traffic,
               so it cannot be blocked without blocking HTTPS.

Truncation and the TCP fallback
────────────────────────────────
A UDP response larger than the negotiated size comes back with the TC bit set
and no useful answer. The resolver must retry over TCP :53 — same message,
prefixed with a 2-byte length. This is the oldest fallback in the protocol and
the reason DNS is specified over both transports.

Why this module exists in a VPN project
────────────────────────────────────────
DNS is the most common way a VPN leaks. The tunnel can be perfectly encrypted
while the OS resolver keeps sending plaintext queries to the ISP's server over
the physical adapter, so an observer learns every site visited without seeing
any content. netlab.dns.leaktest demonstrates that empirically, and this
resolver provides the encrypted alternatives.

`custom_dns`, `primary_dns` and `secondary_dns` in config/settings.json were
written by the Settings dialog and read by nothing. They now select the
upstream server here.
"""

from __future__ import annotations

import json
import socket
import ssl
import struct
import time
from dataclasses import dataclass
from pathlib import Path

from .wire import (
    TYPE_A,
    DnsParseError,
    Message,
    build_query,
    parse_message,
)

DEFAULT_SERVERS = ("1.1.1.1", "1.0.0.1")
DOH_URL = "https://cloudflare-dns.com/dns-query"
DOT_HOST = "1.1.1.1"
DOT_PORT = 853
DOT_SERVER_NAME = "cloudflare-dns.com"


@dataclass
class Answer:
    """One resolution, with enough detail for the panel to explain it."""

    name: str
    transport: str
    addresses: list[str]
    ttl: int
    elapsed_ms: float
    rcode: str
    from_cache: bool = False
    truncated_retry: bool = False
    message: Message | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and bool(self.addresses)

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "transport": self.transport,
            "addresses": self.addresses,
            "ttl": self.ttl,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "rcode": self.rcode,
            "from_cache": self.from_cache,
            "truncated_retry": self.truncated_retry,
            "error": self.error,
        }


def configured_servers() -> tuple[str, ...]:
    """
    Upstream servers from config/settings.json, falling back to Cloudflare.

    Reads `custom_dns` / `primary_dns` / `secondary_dns` — three settings the
    GUI has always written and nothing has ever read until now.
    """
    settings_file = Path("config") / "settings.json"
    if not settings_file.exists():
        return DEFAULT_SERVERS
    try:
        data = json.loads(settings_file.read_text(encoding="utf-8")) or {}
    except (OSError, json.JSONDecodeError):
        return DEFAULT_SERVERS

    if not data.get("custom_dns"):
        return DEFAULT_SERVERS
    servers = [str(data.get(key, "")).strip()
               for key in ("primary_dns", "secondary_dns")]
    servers = [s for s in servers if s]
    return tuple(servers) if servers else DEFAULT_SERVERS


class Resolver:
    """Resolves names over UDP, TCP, DoT or DoH, with an optional cache."""

    def __init__(self, servers: tuple[str, ...] | None = None,
                 timeout: float = 5.0, cache=None) -> None:
        self.servers = servers or configured_servers()
        self.timeout = timeout
        self.cache = cache

    # ── transports ───────────────────────────────────────────────────────────

    def _query_udp(self, query: Message, server: str) -> tuple[bytes, bool]:
        """
        Send over UDP :53, retrying over TCP if the response is truncated.

        Returns (raw_response, did_retry_over_tcp).
        """
        payload = query.encode()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(payload, (server, 53))
            raw, _ = sock.recvfrom(4096)
        finally:
            sock.close()

        parsed = parse_message(raw)
        if parsed.truncated:
            return self._query_tcp(query, server), True
        return raw, False

    def _query_tcp(self, query: Message, server: str) -> bytes:
        """TCP :53 — the message is prefixed with its 2-byte length."""
        payload = query.encode()
        with socket.create_connection((server, 53), timeout=self.timeout) as sock:
            sock.sendall(struct.pack("!H", len(payload)) + payload)
            header = _recv_exactly(sock, 2)
            length = struct.unpack("!H", header)[0]
            return _recv_exactly(sock, length)

    def _query_dot(self, query: Message, server: str = DOT_HOST) -> bytes:
        """
        DNS over TLS :853.

        Certificate verification is on. Turning it off would defeat the entire
        purpose: an attacker who can redirect port 853 could then answer every
        query, which is worse than plaintext because it looks secure.
        """
        payload = query.encode()
        context = ssl.create_default_context()
        with socket.create_connection((server, DOT_PORT), timeout=self.timeout) as raw:
            with context.wrap_socket(raw, server_hostname=DOT_SERVER_NAME) as tls:
                tls.sendall(struct.pack("!H", len(payload)) + payload)
                length = struct.unpack("!H", _recv_exactly(tls, 2))[0]
                return _recv_exactly(tls, length)

    def _query_doh(self, query: Message) -> bytes:
        """DNS over HTTPS — the same bytes, POSTed as application/dns-message."""
        import urllib.request

        payload = query.encode()
        request = urllib.request.Request(
            DOH_URL,
            data=payload,
            headers={
                "Content-Type": "application/dns-message",
                "Accept": "application/dns-message",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return response.read()

    # ── public API ───────────────────────────────────────────────────────────

    def resolve(self, name: str, qtype: int = TYPE_A,
                transport: str = "udp") -> Answer:
        """
        Resolve *name* over *transport* ("udp", "tcp", "dot", "doh").

        Never raises: failures come back as an Answer with `error` set, so the
        panel can show what went wrong instead of dying.
        """
        if self.cache is not None:
            cached = self.cache.get(name, qtype)
            if cached is not None:
                return Answer(
                    name=name, transport=f"{transport} (cached)",
                    addresses=cached.addresses, ttl=cached.remaining_ttl(),
                    elapsed_ms=0.0, rcode="NOERROR", from_cache=True,
                )

        query = build_query(name, qtype)
        server = self.servers[0]
        started = time.perf_counter()
        retried = False

        try:
            if transport == "udp":
                raw, retried = self._query_udp(query, server)
            elif transport == "tcp":
                raw = self._query_tcp(query, server)
            elif transport == "dot":
                raw = self._query_dot(query)
            elif transport == "doh":
                raw = self._query_doh(query)
            else:
                raise ValueError(
                    f"unknown transport {transport!r}; "
                    "expected udp, tcp, dot or doh"
                )
        except ValueError:
            raise
        except (OSError, ssl.SSLError, DnsParseError) as exc:
            return Answer(
                name=name, transport=transport, addresses=[], ttl=0,
                elapsed_ms=(time.perf_counter() - started) * 1000,
                rcode="ERROR", error=f"{type(exc).__name__}: {exc}",
            )

        elapsed = (time.perf_counter() - started) * 1000

        try:
            response = parse_message(raw)
        except DnsParseError as exc:
            return Answer(name=name, transport=transport, addresses=[], ttl=0,
                          elapsed_ms=elapsed, rcode="ERROR",
                          error=f"malformed response: {exc}")

        if response.ident != query.ident:
            # A mismatched ID is the classic cache-poisoning signature: an
            # off-path attacker guessing IDs to beat the real server.
            return Answer(name=name, transport=transport, addresses=[], ttl=0,
                          elapsed_ms=elapsed, rcode="ERROR",
                          error=f"response ID {response.ident} != query "
                                f"ID {query.ident}")

        addresses = response.a_records()
        ttl = min((r.ttl for r in response.answers), default=0)

        answer = Answer(
            name=name, transport=transport, addresses=addresses, ttl=ttl,
            elapsed_ms=elapsed, rcode=response.rcode_name,
            truncated_retry=retried, message=response,
        )
        if self.cache is not None and answer.ok:
            self.cache.put(name, qtype, addresses, ttl)
        return answer

    def compare_transports(self, name: str,
                           transports=("udp", "tcp", "dot", "doh")) -> dict:
        """Resolve the same name every way and report timing side by side."""
        saved_cache, self.cache = self.cache, None
        try:
            return {t: self.resolve(name, transport=t) for t in transports}
        finally:
            self.cache = saved_cache


def _recv_exactly(sock, count: int) -> bytes:
    chunks = []
    remaining = count
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise OSError(f"connection closed after {count - remaining}/{count} B")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
