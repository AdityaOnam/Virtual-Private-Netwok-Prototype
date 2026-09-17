"""
oslab.daemon.ops — PlatformOps abstraction over all privileged OS operations.

This module defines three things:

1. PlatformOps (Protocol)
   A structural interface (runtime_checkable) over the six OS operations that
   OnamVPN's privileged path needs.  Every method returns a plain Python value
   so tests can substitute FakeOps without any subprocess, admin rights, or
   network access.

2. FakeOps
   Deterministic canned implementation of PlatformOps.  Used by every test in
   tests/.  No subprocess calls; no side effects; no admin required.

3. RealWindowsOps  (bodies filled in Phase 7 — Module F)
   Thin delegation shell that forwards each call to the existing methods in
   vpn_core/real_windows_wireguard.py.  Never reimplements logic.

Call-site audit (existing code this interface covers)
──────────────────────────────────────────────────────
  File                                  Line    Expression → method
  ─────────────────────────────────────────────────────────────────────────────
  vpn_core/real_windows_wireguard.py    326-328  subprocess.run([wg, /uninstall…])
                                                  → uninstall_tunnel_service()
  vpn_core/real_windows_wireguard.py    335-337  subprocess.run([wg, /install…])
                                                  → install_tunnel_service()
  vpn_core/real_windows_wireguard.py    374-375  subprocess.run([wg, /uninstall…])
                                                  → uninstall_tunnel_service()
  vpn_core/real_windows_wireguard.py    454-456  subprocess.run(["powershell"…])
                                                  inside _run_ps()
                                                  → run_firewall_rule()
  vpn_core/real_windows_wireguard.py    662-664  subprocess.run([wg_exe, "show"…])
                                                  inside get_connection_status()
                                                  → wg_show()

Platform notes
──────────────
  RealWindowsOps.list_adapters()     → netsh interface show interface
  RealWindowsOps.read_routing_table()→ route print -4  (IPv4 only; sufficient
                                        for Phase 6 LPM demo of the /1+/1
                                        WireGuard split-default trick)
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Protocol, runtime_checkable


# ─────────────────────────────────────────────────────────────────────────────
# PlatformOps — the interface
# ─────────────────────────────────────────────────────────────────────────────

@runtime_checkable
class PlatformOps(Protocol):
    """
    Structural interface over all privileged OS operations used by OnamVPN.

    All return values are plain Python scalars / collections so that FakeOps
    can satisfy the protocol without any subprocess or OS interaction.
    """

    # ── Firewall ──────────────────────────────────────────────────────────────

    def run_firewall_rule(self, powershell_cmd: str) -> bool:
        """
        Execute a single PowerShell firewall command
        (New-NetFirewallRule / Remove-NetFirewallRule / Set-NetFirewallRule).

        Parameters
        ----------
        powershell_cmd : str
            The complete PowerShell expression to run.

        Returns
        -------
        bool
            True  — command exited with returncode == 0.
            False — non-zero exit, timeout, or any OS error.
        """
        ...

    # ── WireGuard tunnel service ───────────────────────────────────────────────

    def install_tunnel_service(self, config_path: str) -> bool:
        """
        Install and activate a WireGuard tunnel service from a .conf file.

        Equivalent to:
            wireguard.exe /installtunnelservice <config_path>

        Parameters
        ----------
        config_path : str
            Absolute, space-free path to the staged .conf file.
            (WireGuard's service fails when the path contains spaces.)

        Returns
        -------
        bool
            True on success, False on any failure (bad path, not admin, …).
        """
        ...

    def uninstall_tunnel_service(self, tunnel_name: str) -> bool:
        """
        Stop and remove a WireGuard tunnel service.

        Equivalent to:
            wireguard.exe /uninstalltunnelservice <tunnel_name>

        Parameters
        ----------
        tunnel_name : str
            The tunnel name as registered with the Windows service manager
            (= the .conf filename stem, e.g. "wgcf-profile").

        Returns
        -------
        bool
            True on success, False on any failure.
        """
        ...

    # ── wg show ───────────────────────────────────────────────────────────────

    def wg_show(self, tunnel_name: str) -> str:
        """
        Run 'wg show <tunnel_name>' and return its stdout as a raw string.

        Returns empty string on failure (tunnel not active, wg.exe missing,
        not admin) so callers can parse safely without extra error handling.

        Parameters
        ----------
        tunnel_name : str
            Name of the active tunnel interface.

        Returns
        -------
        str
            Raw stdout from ``wg show``, or "" on error.
        """
        ...

    # ── Network adapters ──────────────────────────────────────────────────────

    def list_adapters(self) -> list[dict]:
        """
        List network adapters currently known to the OS.

        Returns
        -------
        list[dict]
            Each dict contains:
              'name'        (str)       – adapter name as shown by the OS
              'description' (str)       – human-readable label
              'status'      (str)       – 'Up', 'Down', or 'Unknown'
              'mac'         (str|None)  – MAC address, or None for virtual/loopback
        """
        ...

    # ── Routing table ─────────────────────────────────────────────────────────

    def read_routing_table(self) -> list[dict]:
        """
        Return the OS IPv4 routing table as a list of route dictionaries.

        Returns
        -------
        list[dict]
            Each dict contains:
              'destination' (str)  – CIDR prefix, e.g. "0.0.0.0/1"
              'gateway'     (str)  – next-hop IP address, or "On-link"
              'interface'   (str)  – adapter name this route is on
              'metric'      (int)  – route metric (lower wins)
        """
        ...


# ─────────────────────────────────────────────────────────────────────────────
# FakeOps — deterministic canned implementation for tests
# ─────────────────────────────────────────────────────────────────────────────

_FAKE_WG_SHOW = """\
interface: wgcf-profile
  public key: bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
  private key: (hidden)
  listening port: 51820

peer: bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
  endpoint: 162.159.193.1:2408
  allowed ips: 0.0.0.0/0, ::/0
  latest handshake: 12 seconds ago
  transfer: 1.44 MiB received, 256 KiB sent
"""

_FAKE_ADAPTERS: list[dict] = [
    {
        "name": "Ethernet",
        "description": "Intel(R) Ethernet Connection",
        "status": "Up",
        "mac": "AA:BB:CC:DD:EE:FF",
    },
    {
        "name": "wgcf-profile",
        "description": "WireGuard Tunnel",
        "status": "Up",
        "mac": None,
    },
    {
        "name": "Loopback Pseudo-Interface 1",
        "description": "Loopback",
        "status": "Up",
        "mac": None,
    },
]

# Replicates the WireGuard split-default trick:
# Two /1 prefixes together cover all of 0.0.0.0/0 and win over the real
# default route (0.0.0.0/0) on prefix length — without deleting it.
# See real_windows_wireguard.py:266 (AllowedIPs = 0.0.0.0/0, ::/0) and
# Phase 6 (Module E) for the full LPM explanation.
_FAKE_ROUTING_TABLE: list[dict] = [
    {"destination": "0.0.0.0/1",    "gateway": "0.0.0.0",   "interface": "wgcf-profile",              "metric": 1},
    {"destination": "128.0.0.0/1",  "gateway": "0.0.0.0",   "interface": "wgcf-profile",              "metric": 1},
    {"destination": "0.0.0.0/0",    "gateway": "192.168.1.1","interface": "Ethernet",                  "metric": 25},
    {"destination": "192.168.1.0/24","gateway": "On-link",   "interface": "Ethernet",                  "metric": 281},
    {"destination": "127.0.0.0/8",  "gateway": "On-link",   "interface": "Loopback Pseudo-Interface 1","metric": 331},
]


class FakeOps:
    """
    Deterministic, side-effect-free implementation of PlatformOps.

    Satisfies ``isinstance(FakeOps(), PlatformOps)`` via the
    runtime_checkable Protocol.  Used in all tests; requires no admin
    rights and no network access.
    """

    # Track calls for assertion in tests
    def __init__(self) -> None:
        self.firewall_calls: list[str] = []
        self.installed_tunnels: list[str] = []
        self.uninstalled_tunnels: list[str] = []

    def run_firewall_rule(self, powershell_cmd: str) -> bool:
        """Record the call; return True (success) unconditionally."""
        self.firewall_calls.append(powershell_cmd)
        return True

    def install_tunnel_service(self, config_path: str) -> bool:
        """Record the call; return True (success) unconditionally."""
        self.installed_tunnels.append(config_path)
        return True

    def uninstall_tunnel_service(self, tunnel_name: str) -> bool:
        """Record the call; return True (success) unconditionally."""
        self.uninstalled_tunnels.append(tunnel_name)
        return True

    def wg_show(self, tunnel_name: str) -> str:
        """Return a canned wg-show response with a 12-second-old handshake."""
        return _FAKE_WG_SHOW

    def list_adapters(self) -> list[dict]:
        """Return three canned adapters (physical + tunnel + loopback)."""
        return list(_FAKE_ADAPTERS)  # return a copy to prevent test pollution

    def read_routing_table(self) -> list[dict]:
        """Return the canned WireGuard split-default routing table."""
        return list(_FAKE_ROUTING_TABLE)


# ─────────────────────────────────────────────────────────────────────────────
# RealWindowsOps — thin delegation shell (bodies implemented in Phase 7)
# ─────────────────────────────────────────────────────────────────────────────

class RealWindowsOps:
    """
    Implements PlatformOps by delegating to the existing methods in
    vpn_core.real_windows_wireguard.RealWindowsWireGuard.

    Never duplicates logic.  Each method is a one-liner that calls into the
    handler that already exists and works.

    Phase 7 (Module F) fills in the method bodies.  Until then this class
    raises NotImplementedError so tests cannot accidentally instantiate it.
    """

    def __init__(self, handler=None) -> None:
        """
        Parameters
        ----------
        handler : RealWindowsWireGuard, optional
            If provided, delegation targets its existing private methods.
            In Phase 7 this will be injected from main.py / daemon/service.py.
        """
        self._handler = handler

    def run_firewall_rule(self, powershell_cmd: str) -> bool:
        """Phase 7: self._handler._run_ps(powershell_cmd)"""
        raise NotImplementedError("RealWindowsOps bodies are implemented in Phase 7")

    def install_tunnel_service(self, config_path: str) -> bool:
        """Phase 7: self._handler._create_wireguard_interface(Path(config_path))"""
        raise NotImplementedError("RealWindowsOps bodies are implemented in Phase 7")

    def uninstall_tunnel_service(self, tunnel_name: str) -> bool:
        """Phase 7: self._handler._remove_wireguard_interface(tunnel_name)"""
        raise NotImplementedError("RealWindowsOps bodies are implemented in Phase 7")

    def wg_show(self, tunnel_name: str) -> str:
        """Phase 7: subprocess.run([wg_exe, 'show', tunnel_name]) → stdout"""
        raise NotImplementedError("RealWindowsOps bodies are implemented in Phase 7")

    def list_adapters(self) -> list[dict]:
        """Phase 7: subprocess.run(['netsh','interface','show','interface']) → parsed"""
        raise NotImplementedError("RealWindowsOps bodies are implemented in Phase 7")

    def read_routing_table(self) -> list[dict]:
        """Phase 7: subprocess.run(['route','print','-4']) → parsed"""
        raise NotImplementedError("RealWindowsOps bodies are implemented in Phase 7")
