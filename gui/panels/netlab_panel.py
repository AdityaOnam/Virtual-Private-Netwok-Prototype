"""
gui/panels/netlab_panel.py — Modules B, D, E: tunnel, DNS and path.

Three network demonstrations sharing a tab:

    Tunnel   bring up the native tunnel on loopback, push data through the
             SOCKS5 proxy, and show the handshake and session counters
    DNS      resolve over UDP / TCP / DoT / DoH and compare, with the cache
    Path     traceroute, longest-prefix match, and the MTU arithmetic
"""

from __future__ import annotations

from PySide6.QtCore import QThread, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class _Worker(QThread):
    output = Signal(str)

    def __init__(self, job) -> None:
        super().__init__()
        self.job = job

    def run(self) -> None:
        try:
            self.output.emit(self.job())
        except Exception as exc:
            import traceback
            self.output.emit(
                f"{type(exc).__name__}: {exc}\n\n{traceback.format_exc()}"
            )


class NetLabPanel(QWidget):
    """Native tunnel, DNS transports and path discovery."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._worker: _Worker | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        root = QHBoxLayout(self)

        controls = QWidget()
        controls.setMaximumWidth(360)
        layout = QVBoxLayout(controls)

        tunnel_box = QGroupBox("Native tunnel (Module B)")
        tunnel_layout = QVBoxLayout(tunnel_box)
        tunnel_layout.addWidget(QLabel(
            "Runs our own VPN on loopback: X25519 handshake, ChaCha20-Poly1305 "
            "transport, SOCKS5 front end. Sends data and reports the counters."
        ))
        button = QPushButton("Run tunnel end to end")
        button.clicked.connect(self._run_tunnel)
        tunnel_layout.addWidget(button)
        layout.addWidget(tunnel_box)

        dns_box = QGroupBox("DNS (Module D)")
        dns_form = QFormLayout(dns_box)
        self.dns_name = QLineEdit("one.one.one.one")
        dns_form.addRow("Name:", self.dns_name)
        self.dns_transport = QComboBox()
        self.dns_transport.addItems(["compare all", "udp", "tcp", "dot", "doh"])
        dns_form.addRow("Transport:", self.dns_transport)
        button = QPushButton("Resolve")
        button.clicked.connect(self._run_dns)
        dns_form.addRow(button)
        layout.addWidget(dns_box)

        path_box = QGroupBox("Path and routing (Module E)")
        path_form = QFormLayout(path_box)
        self.path_host = QLineEdit("1.1.1.1")
        path_form.addRow("Destination:", self.path_host)
        button = QPushButton("Traceroute")
        button.clicked.connect(self._run_traceroute)
        path_form.addRow(button)
        button = QPushButton("Routing table and MTU")
        button.clicked.connect(self._run_routing)
        path_form.addRow(button)
        layout.addWidget(path_box)

        layout.addStretch(1)
        root.addWidget(controls)

        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        mono = QFont("Consolas")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self.output.setFont(mono)
        root.addWidget(self.output, stretch=1)

    def _start(self, job) -> None:
        if self._worker is not None and self._worker.isRunning():
            return
        self.output.setPlainText("Running…")
        self._worker = _Worker(job)
        self._worker.output.connect(self.output.setPlainText)
        self._worker.start()

    # ── tunnel ───────────────────────────────────────────────────────────────

    def _run_tunnel(self) -> None:
        def job() -> str:
            import socket
            import struct
            import threading
            import time

            from netlab.native.runner import LocalTunnel

            listener = socket.socket()
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(4)
            origin = listener.getsockname()

            def serve() -> None:
                while True:
                    try:
                        conn, _ = listener.accept()
                    except OSError:
                        return
                    buffer = b""
                    while b"\n" not in buffer:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        buffer += chunk
                    conn.sendall(b"ECHO:" + buffer)
                    conn.close()

            threading.Thread(target=serve, daemon=True).start()

            tunnel = LocalTunnel()
            lines = []
            try:
                if not tunnel.start(timeout=10):
                    return "handshake failed"

                lines += [
                    "Handshake complete.",
                    f"  tunnel server : {tunnel.server.address}",
                    f"  socks5 proxy  : {tunnel.proxy_address}",
                    f"  server pubkey : "
                    f"{tunnel.server_static.public.hex()[:32]}…",
                    f"  client pubkey : "
                    f"{tunnel.client_static.public.hex()[:32]}…",
                    "",
                ]

                sock = socket.create_connection(tunnel.proxy_address, timeout=15)
                sock.sendall(b"\x05\x01\x00")
                sock.recv(2)
                sock.sendall(b"\x05\x01\x00\x01"
                             + socket.inet_aton(origin[0])
                             + struct.pack("!H", origin[1]))
                sock.recv(10)
                payload = b"hello from inside the tunnel\n"
                sock.sendall(payload)

                sock.settimeout(5)
                received = b""
                try:
                    while True:
                        chunk = sock.recv(65536)
                        if not chunk:
                            break
                        received += chunk
                except socket.timeout:
                    pass
                sock.close()

                bulk = b"x" * 100_000 + b"\n"
                sock = socket.create_connection(tunnel.proxy_address, timeout=15)
                sock.sendall(b"\x05\x01\x00")
                sock.recv(2)
                sock.sendall(b"\x05\x01\x00\x01"
                             + socket.inet_aton(origin[0])
                             + struct.pack("!H", origin[1]))
                sock.recv(10)
                started = time.perf_counter()
                sock.sendall(bulk)
                sock.settimeout(20)
                got = b""
                try:
                    while len(got) < len(bulk) + 5:
                        chunk = sock.recv(65536)
                        if not chunk:
                            break
                        got += chunk
                except socket.timeout:
                    pass
                elapsed = time.perf_counter() - started
                sock.close()

                stats = tunnel.stats()
                client = stats["client"]
                server = stats["server"]

                lines += [
                    f"Round trip through SOCKS5:",
                    f"  sent     : {payload!r}",
                    f"  received : {received!r}",
                    "",
                    f"Bulk transfer:",
                    f"  {len(bulk):,} bytes in {elapsed:.2f}s "
                    f"({len(bulk) * 8 / elapsed / 1e6:.1f} Mbit/s)",
                    f"  byte-identical: {got == b'ECHO:' + bulk}",
                    "",
                    "Session state:",
                    f"  state            : {client['state']}",
                    f"  packets sent     : {client['packets_sent']:,}",
                    f"  packets received : {client['packets_received']:,}",
                    f"  send counter     : {client['send_counter']:,}"
                    f"   (the AEAD nonce — never repeats under one key)",
                    f"  replay accepted  : {client['replay_accepted']:,}",
                    f"  replay rejected  : {client['replay_rejected']:,}",
                    f"  replay window    : {client['replay_window']}",
                    "",
                    "Server:",
                    f"  handshakes       : {server['handshakes_completed']}",
                    f"  replays dropped  : {server['replays_dropped']}",
                    f"  forgeries dropped: {server['forgeries_dropped']}",
                    "",
                    "The '#' marks in the replay window are counters already",
                    "seen. A repeat of any of them is rejected; a lower counter",
                    "that has not been seen is accepted, because UDP reorders",
                    "and a lower number is not automatically a replay.",
                ]
                return "\n".join(lines)
            finally:
                tunnel.stop()
                listener.close()

        self._start(job)

    # ── DNS ──────────────────────────────────────────────────────────────────

    def _run_dns(self) -> None:
        name = self.dns_name.text().strip() or "one.one.one.one"
        choice = self.dns_transport.currentText()

        def job() -> str:
            from netlab.dns.cache import DnsCache
            from netlab.dns.resolver import Resolver, configured_servers

            cache = DnsCache()
            resolver = Resolver(cache=cache)
            lines = [f"Resolving {name}",
                     f"  upstream servers: {', '.join(configured_servers())}", ""]

            transports = (("udp", "tcp", "dot", "doh")
                          if choice == "compare all" else (choice,))
            results = resolver.compare_transports(name, transports)

            lines.append(f"  {'transport':10} {'time':>9}  {'rcode':10} addresses")
            for transport, answer in results.items():
                if answer.error:
                    lines.append(f"  {transport:10} {'—':>9}  "
                                 f"{'ERROR':10} {answer.error[:48]}")
                else:
                    lines.append(
                        f"  {transport:10} {answer.elapsed_ms:>8.1f}ms  "
                        f"{answer.rcode:10} {', '.join(answer.addresses)}"
                    )

            answers = {frozenset(a.addresses) for a in results.values() if a.ok}
            lines += [
                "",
                f"  all transports agreed: {len(answers) <= 1}",
                "",
                "UDP is fastest and entirely readable on the wire — your ISP",
                "sees every name you look up even when the page is HTTPS.",
                "DoT wraps the same messages in TLS on port 853, which is",
                "encrypted but obviously DNS. DoH hides inside ordinary HTTPS",
                "on 443, so it cannot be blocked without blocking the web.",
                "The extra time is the TLS handshake, not the lookup.",
                "",
            ]

            first = resolver.resolve(name, transport="udp")
            second = resolver.resolve(name, transport="udp")
            lines += [
                "Cache:",
                f"  first lookup  : {first.elapsed_ms:.1f}ms "
                f"(from cache: {first.from_cache})",
                f"  second lookup : {second.elapsed_ms:.1f}ms "
                f"(from cache: {second.from_cache})",
                f"  ttl remaining : {second.ttl}s",
                f"  stats         : {cache.stats()}",
                "",
                "The TTL is the authority's instruction for how long the answer",
                "may be reused. Honouring it is how an operator moves a service:",
                "lower the TTL, wait for it to expire everywhere, change the",
                "record. A resolver that ignores TTL keeps sending users to a",
                "decommissioned address.",
            ]
            return "\n".join(lines)

        self._start(job)

    # ── path ─────────────────────────────────────────────────────────────────

    def _run_traceroute(self) -> None:
        host = self.path_host.text().strip() or "1.1.1.1"

        def job() -> str:
            from netlab.path.traceroute import traceroute_auto, traceroute_available

            available, reason = traceroute_available()
            result = traceroute_auto(host, max_hops=20, timeout=2.0,
                                     resolve_names=False)
            lines = [
                f"raw ICMP available: {available}",
                f"  {reason}",
                "",
                result.render(),
                "",
                "Traceroute works by abusing TTL: a router that decrements it to",
                "zero discards the packet and reports the fact with ICMP Time",
                "Exceeded. Each hop identifies itself by the source address of",
                "that error — the path is assembled entirely from error messages.",
                "",
                "A `*` is not a broken router. Many operators rate-limit or",
                "suppress ICMP errors, so the hop forwards packets perfectly",
                "while declining to announce itself.",
            ]
            return "\n".join(lines)

        self._start(job)

    def _run_routing(self) -> None:
        def job() -> str:
            import subprocess

            from netlab.path.pmtud import explain_mtu_choice
            from netlab.path.routing import (
                describe_split_default,
                longest_prefix_match,
                parse_windows_route_print,
            )

            lines = ["Routing table (IPv4):", ""]
            try:
                output = subprocess.run(["route", "print", "-4"],
                                        capture_output=True, text=True,
                                        timeout=15).stdout
                routes = parse_windows_route_print(output)
            except (OSError, subprocess.TimeoutExpired) as exc:
                return f"could not read the routing table: {exc}"

            if not routes:
                return "no routes parsed from `route print`"

            for route in routes[:14]:
                lines.append(
                    f"  {route.cidr:20} via {route.gateway:16} "
                    f"on {route.interface:16} metric {route.metric}"
                )
            if len(routes) > 14:
                lines.append(f"  … and {len(routes) - 14} more")

            lines += ["", "Longest-prefix match:", ""]
            for destination in ("8.8.8.8", "1.1.1.1", "192.168.1.1", "127.0.0.1"):
                result = longest_prefix_match(routes, destination)
                if result.chosen:
                    lines.append(f"  {destination:16} → {result.chosen.cidr}")
                    lines.append(f"    {result.explanation}")
                else:
                    lines.append(f"  {destination:16} → {result.explanation}")

            described = describe_split_default(routes)
            lines += [
                "",
                f"Split-default present: {described['split_default_present']}",
                f"  {described['explanation']}",
                "",
                "─" * 60,
                "",
                "MTU arithmetic:",
                "",
            ]
            explained = explain_mtu_choice(1500, 4)
            lines += [
                f"  path MTU            : {explained['path_mtu']}",
                f"  outer IP header     : -{explained['outer_ip_header']}",
                f"  UDP header          : -{explained['udp_header']}",
                f"  WireGuard overhead  : -{explained['wireguard_overhead']}",
                f"  available to inner  : {explained['max_inner_mtu']}",
                f"  configured          : {explained['configured_mtu']}",
                "",
                f"  {explained['why']}",
            ]
            return "\n".join(lines)

        self._start(job)
