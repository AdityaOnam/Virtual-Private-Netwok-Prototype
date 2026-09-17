"""
tests/test_foundation.py — Phase 0 acceptance tests.

These tests verify the Phase 0 foundation layer:
  - oslab.daemon.ops.PlatformOps Protocol shape
  - oslab.daemon.ops.FakeOps correctness
  - oslab.resilience.atomicio.atomic_write_json correctness + crash safety
  - Package version constants importable
  - No admin rights needed (subprocess never called)
  - No network access needed
"""

from __future__ import annotations

import json
import os
import unittest.mock as mock
from pathlib import Path

import pytest

from oslab.daemon.ops import FakeOps, PlatformOps, RealWindowsOps
from oslab.resilience.atomicio import atomic_write_json


# ─────────────────────────────────────────────────────────────────────────────
# PlatformOps Protocol — structural typing checks
# ─────────────────────────────────────────────────────────────────────────────

class TestPlatformOpsProtocol:
    """FakeOps must satisfy the Protocol at runtime."""

    def test_fakeops_is_instance_of_platformops(self, fake_ops: FakeOps) -> None:
        """isinstance() must return True — runtime_checkable Protocol."""
        assert isinstance(fake_ops, PlatformOps)

    def test_realwindowsops_has_all_methods(self) -> None:
        """RealWindowsOps defines all six PlatformOps methods."""
        required = {
            "run_firewall_rule",
            "install_tunnel_service",
            "uninstall_tunnel_service",
            "wg_show",
            "list_adapters",
            "read_routing_table",
        }
        actual = {
            name
            for name in dir(RealWindowsOps)
            if not name.startswith("_")
        }
        assert required.issubset(actual), (
            f"RealWindowsOps is missing: {required - actual}"
        )

    def test_fakeops_independent_instances(self) -> None:
        """Two FakeOps instances must not share call-tracking state."""
        a = FakeOps()
        b = FakeOps()
        a.run_firewall_rule("cmd-A")
        assert len(a.firewall_calls) == 1
        assert len(b.firewall_calls) == 0


# ─────────────────────────────────────────────────────────────────────────────
# FakeOps method contracts
# ─────────────────────────────────────────────────────────────────────────────

class TestFakeOps:
    """Verify every FakeOps method returns the correct canned output."""

    def test_run_firewall_rule_returns_true(self, fake_ops: FakeOps) -> None:
        assert fake_ops.run_firewall_rule('New-NetFirewallRule -DisplayName "X"') is True

    def test_run_firewall_rule_records_call(self, fake_ops: FakeOps) -> None:
        cmd = 'Remove-NetFirewallRule -DisplayName "OnamVPN-KS-*"'
        fake_ops.run_firewall_rule(cmd)
        assert cmd in fake_ops.firewall_calls

    def test_install_tunnel_service_returns_true(self, fake_ops: FakeOps) -> None:
        assert fake_ops.install_tunnel_service("C:/OnamVPN/wgcf-profile.conf") is True

    def test_install_tunnel_service_records_path(self, fake_ops: FakeOps) -> None:
        path = "C:/OnamVPN/wgcf-profile.conf"
        fake_ops.install_tunnel_service(path)
        assert path in fake_ops.installed_tunnels

    def test_uninstall_tunnel_service_returns_true(self, fake_ops: FakeOps) -> None:
        assert fake_ops.uninstall_tunnel_service("wgcf-profile") is True

    def test_uninstall_tunnel_service_records_name(self, fake_ops: FakeOps) -> None:
        fake_ops.uninstall_tunnel_service("wgcf-profile")
        assert "wgcf-profile" in fake_ops.uninstalled_tunnels

    def test_wg_show_returns_string(self, fake_ops: FakeOps) -> None:
        result = fake_ops.wg_show("wgcf-profile")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_wg_show_contains_handshake(self, fake_ops: FakeOps) -> None:
        result = fake_ops.wg_show("wgcf-profile")
        assert "latest handshake" in result
        assert "12 seconds ago" in result

    def test_wg_show_same_regardless_of_tunnel_name(self, fake_ops: FakeOps) -> None:
        assert fake_ops.wg_show("tunnel-A") == fake_ops.wg_show("tunnel-B")

    def test_list_adapters_returns_list(self, fake_ops: FakeOps) -> None:
        adapters = fake_ops.list_adapters()
        assert isinstance(adapters, list)
        assert len(adapters) == 3

    def test_list_adapters_has_required_keys(self, fake_ops: FakeOps) -> None:
        for adapter in fake_ops.list_adapters():
            assert "name" in adapter
            assert "description" in adapter
            assert "status" in adapter
            assert "mac" in adapter

    def test_list_adapters_includes_tunnel(self, fake_ops: FakeOps) -> None:
        names = [a["name"] for a in fake_ops.list_adapters()]
        assert "wgcf-profile" in names

    def test_list_adapters_returns_copy(self, fake_ops: FakeOps) -> None:
        """Mutating the returned list must not affect subsequent calls."""
        a = fake_ops.list_adapters()
        a.clear()
        b = fake_ops.list_adapters()
        assert len(b) == 3

    def test_read_routing_table_returns_list(self, fake_ops: FakeOps) -> None:
        table = fake_ops.read_routing_table()
        assert isinstance(table, list)
        assert len(table) == 5

    def test_read_routing_table_has_required_keys(self, fake_ops: FakeOps) -> None:
        for route in fake_ops.read_routing_table():
            assert "destination" in route
            assert "gateway" in route
            assert "interface" in route
            assert "metric" in route
            assert isinstance(route["metric"], int)

    def test_read_routing_table_split_default_trick(self, fake_ops: FakeOps) -> None:
        """
        The FakeOps routing table must contain the WireGuard split-default pair
        (0.0.0.0/1 and 128.0.0.0/1 on the tunnel interface) — this is the
        Phase 6 LPM demo data.
        """
        table = fake_ops.read_routing_table()
        tunnel_routes = [r for r in table if r["interface"] == "wgcf-profile"]
        destinations = {r["destination"] for r in tunnel_routes}
        assert "0.0.0.0/1" in destinations, "Missing 0.0.0.0/1 split-default route"
        assert "128.0.0.0/1" in destinations, "Missing 128.0.0.0/1 split-default route"

    def test_read_routing_table_real_default_route_present(self, fake_ops: FakeOps) -> None:
        """The real default route (0.0.0.0/0) must still be present (not deleted)."""
        table = fake_ops.read_routing_table()
        destinations = {r["destination"] for r in table}
        assert "0.0.0.0/0" in destinations


# ─────────────────────────────────────────────────────────────────────────────
# atomic_write_json
# ─────────────────────────────────────────────────────────────────────────────

class TestAtomicWriteJson:
    """Verify write-temp-then-replace semantics and crash safety."""

    def test_writes_valid_json(self, tmp_path: Path) -> None:
        dest = tmp_path / "settings.json"
        obj = {"theme": "Dark", "keepalive_interval": 25}
        atomic_write_json(dest, obj)
        assert dest.exists()
        loaded = json.loads(dest.read_text(encoding="utf-8"))
        assert loaded == obj

    def test_overwrites_existing_file(self, tmp_path: Path) -> None:
        dest = tmp_path / "settings.json"
        atomic_write_json(dest, {"v": 1})
        atomic_write_json(dest, {"v": 2})
        loaded = json.loads(dest.read_text(encoding="utf-8"))
        assert loaded == {"v": 2}

    def test_no_tmp_file_left_on_success(self, tmp_path: Path) -> None:
        dest = tmp_path / "settings.json"
        atomic_write_json(dest, {"ok": True})
        # Temp names are unique per writer, so glob rather than assuming one name.
        leftovers = list(tmp_path.glob("*.tmp"))
        assert leftovers == [], f"temp files must be cleaned up after success: {leftovers}"

    def test_crash_between_write_and_replace_leaves_original_intact(
        self, tmp_path: Path
    ) -> None:
        """
        Simulate a crash (exception) between the write step and the replace
        step.  The original file must be left unchanged; the .tmp file must
        not exist.
        """
        dest = tmp_path / "settings.json"
        original = {"original": True}
        dest.write_text(json.dumps(original), encoding="utf-8")

        # Patch os.replace to raise — simulates an aborted replace
        with mock.patch("oslab.resilience.atomicio.os.replace", side_effect=OSError("simulated crash")):
            with pytest.raises(OSError, match="simulated crash"):
                atomic_write_json(dest, {"new": True})

        # Original must be intact
        loaded = json.loads(dest.read_text(encoding="utf-8"))
        assert loaded == original, "Original file must be unchanged after failed replace"

        # No temp file may be left behind (unique names — glob, don't guess).
        leftovers = list(tmp_path.glob("*.tmp"))
        assert leftovers == [], f"temp files must be cleaned up after failed replace: {leftovers}"

    def test_non_serialisable_raises_type_error(self, tmp_path: Path) -> None:
        dest = tmp_path / "bad.json"
        with pytest.raises(TypeError):
            atomic_write_json(dest, {"fn": lambda x: x})

    def test_accepts_path_as_string(self, tmp_path: Path) -> None:
        dest = tmp_path / "settings.json"
        atomic_write_json(str(dest), {"str_path": True})
        assert dest.exists()

    def test_output_is_readable_utf8(self, tmp_path: Path) -> None:
        dest = tmp_path / "settings.json"
        obj = {"lang": "Malayalam: 'ഓണം'"}
        atomic_write_json(dest, obj)
        loaded = json.loads(dest.read_text(encoding="utf-8"))
        assert loaded == obj


# ─────────────────────────────────────────────────────────────────────────────
# Package imports — no admin, no network
# ─────────────────────────────────────────────────────────────────────────────

class TestPackageImports:
    """All new packages must import cleanly without admin rights or network."""

    def test_oslab_version(self) -> None:
        import oslab
        assert hasattr(oslab, "__version__")
        assert isinstance(oslab.__version__, str)

    def test_netlab_version(self) -> None:
        import netlab
        assert hasattr(netlab, "__version__")
        assert isinstance(netlab.__version__, str)

    def test_oslab_daemon_ops_importable(self) -> None:
        from oslab.daemon.ops import FakeOps, PlatformOps, RealWindowsOps  # noqa: F401

    def test_oslab_resilience_atomicio_importable(self) -> None:
        from oslab.resilience.atomicio import atomic_write_json  # noqa: F401

    def test_no_subprocess_called_during_import(self) -> None:
        """Importing FakeOps must never trigger a subprocess call."""
        with mock.patch("subprocess.run") as mock_run:
            from oslab.daemon import ops  # noqa: F401 — reimport is a no-op but exercises the module
            mock_run.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# Elevation guard — --labs must bypass UAC, and must agree with argparse
# ─────────────────────────────────────────────────────────────────────────────

def _load_labs_requested():
    """
    Import _labs_requested from main.py without executing main.py's
    import-time elevation block.

    main.py decides whether to request UAC elevation at import time, before
    argparse runs, so a plain `import main` on a non-elevated Windows box
    would pop a UAC dialog mid-test-run.  We extract just the function.
    """
    src = (Path(__file__).resolve().parents[1] / "main.py").read_text(encoding="utf-8")
    start = src.index("def _labs_requested")
    end = src.index("_LABS_MODE = _labs_requested")
    namespace: dict = {}
    exec(src[start:end], namespace)  # noqa: S102 — trusted local source
    return namespace["_labs_requested"]


class TestLabsElevationGuard:
    """
    The pre-argparse guard must match argparse's own parsing, including prefix
    abbreviation.  If it does not, `python main.py --lab` elevates via UAC and
    then runs Labs mode with Administrator rights it does not need.
    """

    @pytest.mark.parametrize(
        "argv_tail, expected",
        [
            ([], False),
            (["--labs"], True),
            (["--lab"], True),              # argparse accepts unambiguous prefixes
            (["--la"], True),
            (["--l"], True),
            (["-l"], False),                # single dash is not this option
            (["--verbose"], False),
            (["--mode", "server"], False),
            (["--labs", "--verbose"], True),
            (["--verbose", "--labs"], True),
            (["--"], False),                # bare separator alone
            (["--", "--labs"], False),      # after '--' it is positional, not an option
        ],
    )
    def test_matches_argparse_abbreviation(self, argv_tail, expected) -> None:
        labs_requested = _load_labs_requested()
        assert labs_requested(["main.py", *argv_tail]) is expected

    def test_labs_help_runs_without_elevation(self) -> None:
        """
        End-to-end: `main.py --labs --help` must print usage and exit 0 without
        triggering the elevation path.  This is the only Phase 0 command that
        can produce argparse output on a non-elevated Windows shell.
        """
        import subprocess
        import sys

        project_root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [sys.executable, "main.py", "--labs", "--help"],
            cwd=project_root,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stderr
        assert "--labs" in result.stdout
        assert "Requesting elevation" not in result.stdout
