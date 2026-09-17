"""
tests/test_path.py — Phase 6: traceroute, PMTU discovery, routing.

The routing tests are the substantial ones and run entirely offline against a
hand-built table, including the split-default pair a VPN installs. Live
traceroute is exercised only where the environment allows it.
"""

from __future__ import annotations

import pytest

from netlab.path.pmtud import (
    IPV6_MIN_MTU,
    WIREGUARD_OVERHEAD,
    explain_mtu_choice,
    recommended_tunnel_mtu,
    tunnel_overhead,
)
from netlab.path.routing import (
    Route,
    describe_split_default,
    longest_prefix_match,
    parse_route_dicts,
    parse_windows_route_print,
)
from netlab.path.traceroute import (
    Hop,
    build_echo_request,
    checksum,
    system_traceroute,
    traceroute_auto,
    traceroute_available,
)


def sample_table() -> list[Route]:
    """
    A machine with a VPN up.

    Note all three prefix lengths doing different jobs: /32 pins the VPN
    endpoint to the physical gateway, the /1 pair captures everything else for
    the tunnel, and /0 survives underneath them both.
    """
    return [
        Route("0.0.0.0", "0.0.0.0", "192.168.1.1", "192.168.1.50", 25),
        Route("0.0.0.0", "128.0.0.0", "10.8.0.1", "10.8.0.2", 5),
        Route("128.0.0.0", "128.0.0.0", "10.8.0.1", "10.8.0.2", 5),
        Route("162.159.192.1", "255.255.255.255", "192.168.1.1", "192.168.1.50", 5),
        Route("192.168.1.0", "255.255.255.0", "0.0.0.0", "192.168.1.50", 281),
        Route("127.0.0.0", "255.0.0.0", "0.0.0.0", "127.0.0.1", 331),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

class TestRoute:
    def test_cidr_rendering(self) -> None:
        assert Route("192.168.1.0", "255.255.255.0", "", "").cidr == "192.168.1.0/24"

    def test_prefix_length(self) -> None:
        assert Route("0.0.0.0", "128.0.0.0", "", "").prefix_length == 1
        assert Route("0.0.0.0", "0.0.0.0", "", "").prefix_length == 0
        assert Route("1.2.3.4", "255.255.255.255", "", "").prefix_length == 32

    def test_containment(self) -> None:
        route = Route("192.168.1.0", "255.255.255.0", "", "")
        assert route.contains("192.168.1.99") is True
        assert route.contains("192.168.2.1") is False

    def test_split_default_recognised(self) -> None:
        assert Route("0.0.0.0", "128.0.0.0", "", "").is_split_default is True
        assert Route("128.0.0.0", "128.0.0.0", "", "").is_split_default is True
        assert Route("0.0.0.0", "0.0.0.0", "", "").is_split_default is False

    def test_default_recognised(self) -> None:
        assert Route("0.0.0.0", "0.0.0.0", "", "").is_default is True
        assert Route("0.0.0.0", "128.0.0.0", "", "").is_default is False


class TestLongestPrefixMatch:
    def test_split_default_beats_real_default(self) -> None:
        """/1 is more specific than /0, so tunnel routes win without deleting it."""
        result = longest_prefix_match(sample_table(), "8.8.8.8")
        assert result.chosen.cidr == "0.0.0.0/1"
        assert result.chosen.interface == "10.8.0.2"
        assert "longer prefix" in result.explanation

    def test_upper_half_uses_the_other_split_route(self) -> None:
        result = longest_prefix_match(sample_table(), "200.1.2.3")
        assert result.chosen.cidr == "128.0.0.0/1"

    def test_vpn_endpoint_escapes_the_tunnel(self) -> None:
        """
        The /32 to the VPN server must beat the /1 pair, or the tunnel would
        try to carry its own outer packets and deadlock the connection.
        """
        result = longest_prefix_match(sample_table(), "162.159.192.1")
        assert result.chosen.cidr == "162.159.192.1/32"
        assert result.chosen.gateway == "192.168.1.1", "must use the physical gateway"

    def test_lan_route_wins_over_split_default(self) -> None:
        result = longest_prefix_match(sample_table(), "192.168.1.7")
        assert result.chosen.cidr == "192.168.1.0/24"

    def test_order_in_the_table_is_irrelevant(self) -> None:
        forward = longest_prefix_match(sample_table(), "8.8.8.8").chosen.cidr
        reverse = longest_prefix_match(list(reversed(sample_table())),
                                       "8.8.8.8").chosen.cidr
        assert forward == reverse

    def test_metric_breaks_ties_between_equal_prefixes(self) -> None:
        routes = [
            Route("10.0.0.0", "255.0.0.0", "1.1.1.1", "eth0", 100),
            Route("10.0.0.0", "255.0.0.0", "2.2.2.2", "eth1", 5),
        ]
        result = longest_prefix_match(routes, "10.1.2.3")
        assert result.chosen.gateway == "2.2.2.2"
        assert "metric" in result.explanation

    def test_no_match_is_reported(self) -> None:
        routes = [Route("192.168.1.0", "255.255.255.0", "", "eth0")]
        result = longest_prefix_match(routes, "8.8.8.8")
        assert result.chosen is None
        assert "no route matches" in result.explanation

    def test_invalid_address_rejected(self) -> None:
        result = longest_prefix_match(sample_table(), "not-an-ip")
        assert result.chosen is None
        assert "not a valid" in result.explanation


class TestSplitDefaultDescription:
    def test_detected_when_present(self) -> None:
        described = describe_split_default(sample_table())
        assert described["split_default_present"] is True
        assert sorted(described["halves"]) == ["0.0.0.0/1", "128.0.0.0/1"]
        assert described["original_default_survives"] is True

    def test_absent_without_the_pair(self) -> None:
        routes = [Route("0.0.0.0", "0.0.0.0", "192.168.1.1", "eth0")]
        assert describe_split_default(routes)["split_default_present"] is False


class TestRouteParsing:
    def test_parses_windows_route_print(self) -> None:
        output = """
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.50     25
          0.0.0.0        128.0.0.0         10.8.0.1         10.8.0.2      5
      192.168.1.0    255.255.255.0         On-link      192.168.1.50    281
===========================================================================
"""
        routes = parse_windows_route_print(output)
        assert len(routes) == 3
        assert routes[0].cidr == "0.0.0.0/0"
        assert routes[1].cidr == "0.0.0.0/1"
        assert routes[2].cidr == "192.168.1.0/24"

    def test_parses_dicts_with_cidr_destination(self) -> None:
        routes = parse_route_dicts([
            {"destination": "10.0.0.0/8", "gateway": "1.1.1.1",
             "interface": "eth0", "metric": 5},
        ])
        assert routes[0].cidr == "10.0.0.0/8"

    def test_ignores_rows_without_a_destination(self) -> None:
        assert parse_route_dicts([{"gateway": "1.1.1.1"}]) == []


# ─────────────────────────────────────────────────────────────────────────────
# MTU
# ─────────────────────────────────────────────────────────────────────────────

class TestMtu:
    def test_ipv4_overhead_arithmetic(self) -> None:
        # 20 IP + 8 UDP + 32 WireGuard = 60
        assert tunnel_overhead(4) == 60
        assert tunnel_overhead(6) == 80

    def test_wireguard_overhead_is_header_plus_tag(self) -> None:
        assert WIREGUARD_OVERHEAD == 32

    def test_available_inner_mtu_on_ethernet(self) -> None:
        assert explain_mtu_choice(1500, 4)["max_inner_mtu"] == 1440

    def test_configured_value_is_the_ipv6_minimum(self) -> None:
        explained = explain_mtu_choice(1500, 4)
        assert explained["configured_mtu"] == IPV6_MIN_MTU == 1280
        assert "IPv6" in explained["why"]

    def test_recommendation_never_exceeds_the_path(self) -> None:
        assert recommended_tunnel_mtu(1500) <= 1500
        assert recommended_tunnel_mtu(1400) <= 1400

    def test_small_path_produces_small_recommendation(self) -> None:
        assert recommended_tunnel_mtu(600) < 600


# ─────────────────────────────────────────────────────────────────────────────
# ICMP construction
# ─────────────────────────────────────────────────────────────────────────────

class TestIcmp:
    def test_echo_request_checksum_verifies(self) -> None:
        """Checksumming the whole message including its checksum yields zero."""
        assert checksum(build_echo_request(0x1234, 1)) == 0

    def test_echo_request_fields(self) -> None:
        packet = build_echo_request(0xABCD, 7)
        assert packet[0] == 8       # ICMP Echo Request
        assert packet[1] == 0       # code
        assert int.from_bytes(packet[4:6], "big") == 0xABCD
        assert int.from_bytes(packet[6:8], "big") == 7

    def test_payload_is_carried(self) -> None:
        assert build_echo_request(1, 1, b"hello").endswith(b"hello")

    def test_corrupted_packet_fails_checksum(self) -> None:
        packet = bytearray(build_echo_request(1, 1))
        packet[10] ^= 0xFF
        assert checksum(bytes(packet)) != 0


# ─────────────────────────────────────────────────────────────────────────────
# Traceroute
# ─────────────────────────────────────────────────────────────────────────────

class TestTracerouteAvailability:
    def test_availability_check_reports_a_reason(self) -> None:
        available, reason = traceroute_available()
        assert isinstance(available, bool)
        assert isinstance(reason, str) and reason

    def test_unelevated_windows_is_reported_unavailable(self) -> None:
        """
        Windows lets an unelevated process create a raw ICMP socket and then
        silently drops every probe. The check must not be fooled by the
        socket construction succeeding.
        """
        import ctypes
        import platform

        if platform.system().lower() != "windows":
            pytest.skip("Windows-specific behaviour")
        try:
            elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            pytest.skip("cannot determine elevation")

        available, reason = traceroute_available()
        if not elevated:
            assert available is False
            assert "elevat" in reason.lower() or "unelevated" in reason.lower()


class TestHopRendering:
    def test_unresponsive_hop_renders_as_stars(self) -> None:
        assert "* * *" in Hop(ttl=4).render()

    def test_responsive_hop_shows_times(self) -> None:
        hop = Hop(ttl=1, address="192.168.1.1", rtts_ms=[1.5, 2.5])
        rendered = hop.render()
        assert "192.168.1.1" in rendered
        assert "ms" in rendered

    def test_best_and_average(self) -> None:
        hop = Hop(ttl=1, address="10.0.0.1", rtts_ms=[10.0, 20.0, 30.0])
        assert hop.best_ms == 10.0
        assert hop.avg_ms == pytest.approx(20.0)

    def test_empty_hop_has_no_times(self) -> None:
        assert Hop(ttl=1).best_ms is None
        assert Hop(ttl=1).avg_ms is None


def _has_network() -> bool:
    import socket as _socket
    try:
        _socket.create_connection(("1.1.1.1", 53), timeout=2).close()
        return True
    except OSError:
        return False


@pytest.mark.skipif(not _has_network(), reason="no network connectivity")
class TestTracerouteLive:
    def test_auto_finds_a_path(self) -> None:
        """
        Uses raw sockets when elevated, the system command otherwise. Either
        way at least the first hop must answer.
        """
        result = traceroute_auto("1.1.1.1", max_hops=8, timeout=1.5,
                                 resolve_names=False)
        assert result.error is None, result.error
        assert result.hops, "no hops recorded"
        assert any(hop.responded for hop in result.hops), result.render()

    def test_rtts_increase_along_the_path(self) -> None:
        """Later hops are further away, so they are generally slower."""
        result = traceroute_auto("1.1.1.1", max_hops=8, timeout=1.5,
                                 resolve_names=False)
        responding = [h for h in result.hops if h.responded and h.best_ms]
        if len(responding) < 3:
            pytest.skip("too few responding hops to compare")
        assert responding[-1].best_ms >= responding[0].best_ms * 0.5

    def test_unresponsive_hops_do_not_hang(self) -> None:
        """A `*` is a non-answer, not a failure — the trace must continue."""
        result = traceroute_auto("1.1.1.1", max_hops=6, timeout=1.0,
                                 resolve_names=False)
        assert result.error is None
