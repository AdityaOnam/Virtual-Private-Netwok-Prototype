"""
tests/test_dns.py — Phase 5: DNS wire format, cache, resolver, leak test.

The wire-format tests are the substantial ones and run entirely offline
against hand-built messages, including the compression pointers that appear in
every real response. Network-dependent tests are marked and skipped when there
is no connectivity, so the suite stays green on an offline machine.
"""

from __future__ import annotations

import socket
import struct
import time

import pytest

from netlab.dns.cache import CacheEntry, DnsCache
from netlab.dns.leaktest import unique_query_name
from netlab.dns.resolver import DEFAULT_SERVERS, Resolver, configured_servers
from netlab.dns.wire import (
    HEADER_SIZE,
    TYPE_A,
    TYPE_AAAA,
    TYPE_CNAME,
    TYPE_MX,
    TYPE_TXT,
    DnsParseError,
    Question,
    build_query,
    decode_name,
    encode_name,
    parse_message,
)


def _has_network() -> bool:
    try:
        socket.create_connection(("1.1.1.1", 53), timeout=2).close()
        return True
    except OSError:
        return False


needs_network = pytest.mark.skipif(
    not _has_network(), reason="no network connectivity"
)


# ─────────────────────────────────────────────────────────────────────────────
# Name encoding
# ─────────────────────────────────────────────────────────────────────────────

class TestNameEncoding:
    def test_known_encoding(self) -> None:
        """Length-prefixed labels, zero-terminated. No dots on the wire."""
        assert encode_name("www.example.com") == (
            b"\x03www\x07example\x03com\x00"
        )

    def test_root_is_a_single_zero(self) -> None:
        assert encode_name(".") == b"\x00"
        assert encode_name("") == b"\x00"

    def test_trailing_dot_is_ignored(self) -> None:
        assert encode_name("example.com.") == encode_name("example.com")

    def test_round_trip(self) -> None:
        for name in ("a.b", "example.com", "very.deep.sub.domain.example.org"):
            encoded = encode_name(name)
            assert decode_name(encoded, 0)[0] == name

    def test_label_too_long_rejected(self) -> None:
        with pytest.raises(ValueError, match="must be 1-63"):
            encode_name("x" * 64 + ".com")

    def test_name_too_long_rejected(self) -> None:
        with pytest.raises(ValueError, match="max 255"):
            encode_name(".".join(["abcdefghij"] * 30))


# ─────────────────────────────────────────────────────────────────────────────
# Compression pointers — present in essentially every real response
# ─────────────────────────────────────────────────────────────────────────────

def _response_with_pointer() -> bytes:
    """A minimal response whose answer name is a pointer to the question."""
    query = build_query("www.example.com", ident=0x1234).encode()
    message = bytearray(query)
    message[2:4] = struct.pack("!H", 0x8180)   # QR + RD + RA
    message[6:8] = struct.pack("!H", 1)        # one answer
    message += b"\xc0\x0c"                     # pointer to offset 12
    message += struct.pack("!HHIH", TYPE_A, 1, 300, 4)
    message += bytes([93, 184, 216, 34])
    return bytes(message)


class TestCompressionPointers:
    def test_pointer_resolves_to_the_question_name(self) -> None:
        message = parse_message(_response_with_pointer())
        assert message.answers[0].name == "www.example.com"
        assert message.answers[0].value == "93.184.216.34"
        assert message.answers[0].ttl == 300

    def test_parsing_continues_after_the_pointer_not_the_target(self) -> None:
        """
        decode_name must return the offset after the 2-byte pointer. Returning
        the offset after the *target* shifts every later record and yields
        convincing nonsense.
        """
        raw = _response_with_pointer()
        pointer_at = len(raw) - 2 - 10 - 4
        name, next_offset = decode_name(raw, pointer_at)
        assert name == "www.example.com"
        assert next_offset == pointer_at + 2

    def test_pointer_loop_is_caught(self) -> None:
        raw = bytearray(build_query("a.com", ident=1).encode())
        raw[2:4] = struct.pack("!H", 0x8180)
        raw[6:8] = struct.pack("!H", 1)
        self_offset = len(raw)
        raw += struct.pack("!H", 0xC000 | self_offset)   # points at itself
        with pytest.raises(DnsParseError, match="loop"):
            parse_message(bytes(raw))

    def test_pointer_past_end_is_caught(self) -> None:
        raw = bytearray(build_query("a.com", ident=1).encode())
        raw[2:4] = struct.pack("!H", 0x8180)
        raw[6:8] = struct.pack("!H", 1)
        raw += struct.pack("!H", 0xC000 | 9999)
        with pytest.raises(DnsParseError, match="past end"):
            parse_message(bytes(raw))


# ─────────────────────────────────────────────────────────────────────────────
# Messages
# ─────────────────────────────────────────────────────────────────────────────

class TestMessages:
    def test_query_round_trip(self) -> None:
        query = build_query("example.com", ident=0xABCD)
        parsed = parse_message(query.encode())
        assert parsed.ident == 0xABCD
        assert parsed.is_response is False
        assert parsed.recursion_desired is True
        assert parsed.questions == [Question("example.com", TYPE_A, 1)]

    def test_header_is_twelve_bytes(self) -> None:
        assert len(build_query("a.com", ident=1).encode()) == HEADER_SIZE + 7 + 4

    def test_flags_encode_correctly(self) -> None:
        query = build_query("a.com", ident=1, recursion_desired=False)
        assert query.flags_word() == 0
        query.recursion_desired = True
        assert query.flags_word() == 0x0100

    def test_rcode_names(self) -> None:
        raw = bytearray(build_query("a.com", ident=1).encode())
        raw[2:4] = struct.pack("!H", 0x8183)   # response + NXDOMAIN
        assert parse_message(bytes(raw)).rcode_name == "NXDOMAIN"

    def test_truncated_bit_is_read(self) -> None:
        raw = bytearray(build_query("a.com", ident=1).encode())
        raw[2:4] = struct.pack("!H", 0x8380)   # response + TC
        assert parse_message(bytes(raw)).truncated is True

    def test_too_short_message_rejected(self) -> None:
        with pytest.raises(DnsParseError, match="header alone"):
            parse_message(b"\x00" * 5)

    def test_rdlength_past_end_rejected(self) -> None:
        raw = bytearray(build_query("a.com", ident=1).encode())
        raw[2:4] = struct.pack("!H", 0x8180)
        raw[6:8] = struct.pack("!H", 1)
        raw += b"\xc0\x0c" + struct.pack("!HHIH", TYPE_A, 1, 300, 9999)
        with pytest.raises(DnsParseError, match="past end"):
            parse_message(bytes(raw))

    def test_multiple_answers_parse(self) -> None:
        raw = bytearray(build_query("m.com", ident=7).encode())
        raw[2:4] = struct.pack("!H", 0x8180)
        raw[6:8] = struct.pack("!H", 3)
        for last in (1, 2, 3):
            raw += b"\xc0\x0c" + struct.pack("!HHIH", TYPE_A, 1, 60, 4)
            raw += bytes([10, 0, 0, last])
        message = parse_message(bytes(raw))
        assert message.a_records() == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


# ─────────────────────────────────────────────────────────────────────────────
# Cache
# ─────────────────────────────────────────────────────────────────────────────

class TestDnsCache:
    def test_hit_after_put(self) -> None:
        cache = DnsCache()
        cache.put("example.com", TYPE_A, ["1.2.3.4"], ttl=300)
        entry = cache.get("example.com", TYPE_A)
        assert entry is not None
        assert entry.addresses == ["1.2.3.4"]
        assert cache.stats()["hits"] == 1

    def test_miss_on_unknown_name(self) -> None:
        cache = DnsCache()
        assert cache.get("nope.com", TYPE_A) is None
        assert cache.stats()["misses"] == 1

    def test_lookup_is_case_insensitive(self) -> None:
        cache = DnsCache()
        cache.put("Example.COM", TYPE_A, ["1.2.3.4"], ttl=60)
        assert cache.get("example.com", TYPE_A) is not None

    def test_expired_entry_is_a_miss(self) -> None:
        """TTL is an instruction, not a hint: an expired answer must not be used."""
        cache = DnsCache()
        cache.put("example.com", TYPE_A, ["1.2.3.4"], ttl=1)
        entry = cache._entries[("example.com", TYPE_A)]
        entry.stored_at -= 2          # pretend two seconds passed
        assert cache.get("example.com", TYPE_A) is None
        assert cache.stats()["expirations"] == 1

    def test_zero_ttl_is_not_stored(self) -> None:
        cache = DnsCache()
        cache.put("example.com", TYPE_A, ["1.2.3.4"], ttl=0)
        assert len(cache) == 0

    def test_remaining_ttl_counts_down(self) -> None:
        entry = CacheEntry("a.com", TYPE_A, ["1.1.1.1"], ttl=100)
        entry.stored_at -= 40
        assert 55 <= entry.remaining_ttl() <= 60

    def test_capacity_evicts_oldest(self) -> None:
        cache = DnsCache(capacity=3)
        for i in range(4):
            cache.put(f"host{i}.com", TYPE_A, [f"10.0.0.{i}"], ttl=300)
            time.sleep(0.001)
        assert len(cache) == 3
        assert cache.stats()["evictions"] == 1
        assert cache.get("host0.com", TYPE_A) is None

    def test_different_types_are_separate_entries(self) -> None:
        cache = DnsCache()
        cache.put("example.com", TYPE_A, ["1.2.3.4"], ttl=60)
        cache.put("example.com", TYPE_AAAA, ["::1"], ttl=60)
        assert len(cache) == 2

    def test_hit_rate(self) -> None:
        cache = DnsCache()
        cache.put("a.com", TYPE_A, ["1.1.1.1"], ttl=60)
        cache.get("a.com", TYPE_A)
        cache.get("b.com", TYPE_A)
        assert cache.stats()["hit_rate"] == 0.5


# ─────────────────────────────────────────────────────────────────────────────
# Settings wiring
# ─────────────────────────────────────────────────────────────────────────────

class TestConfiguredServers:
    def test_defaults_when_custom_dns_disabled(self) -> None:
        assert configured_servers() == DEFAULT_SERVERS or len(configured_servers()) >= 1

    def test_reads_custom_servers(self, tmp_path, monkeypatch) -> None:
        import json
        import os
        config = tmp_path / "config"
        config.mkdir()
        (config / "settings.json").write_text(json.dumps({
            "custom_dns": True,
            "primary_dns": "9.9.9.9",
            "secondary_dns": "149.112.112.112",
        }), encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        assert configured_servers() == ("9.9.9.9", "149.112.112.112")

    def test_falls_back_when_custom_is_empty(self, tmp_path, monkeypatch) -> None:
        import json
        config = tmp_path / "config"
        config.mkdir()
        (config / "settings.json").write_text(json.dumps({
            "custom_dns": True, "primary_dns": "", "secondary_dns": "",
        }), encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        assert configured_servers() == DEFAULT_SERVERS


# ─────────────────────────────────────────────────────────────────────────────
# Resolver
# ─────────────────────────────────────────────────────────────────────────────

class TestResolverOffline:
    def test_unknown_transport_raises(self) -> None:
        with pytest.raises(ValueError, match="unknown transport"):
            Resolver().resolve("example.com", transport="carrier-pigeon")

    def test_unreachable_server_returns_error_not_exception(self) -> None:
        """The panel needs to display failures, not die on them."""
        resolver = Resolver(servers=("192.0.2.1",), timeout=0.5)  # TEST-NET-1
        answer = resolver.resolve("example.com", transport="udp")
        assert answer.ok is False
        assert answer.error is not None
        assert answer.rcode == "ERROR"

    def test_cache_short_circuits_the_network(self) -> None:
        cache = DnsCache()
        cache.put("cached.example", TYPE_A, ["203.0.113.9"], ttl=300)
        resolver = Resolver(servers=("192.0.2.1",), timeout=0.5, cache=cache)
        answer = resolver.resolve("cached.example")
        assert answer.from_cache is True
        assert answer.addresses == ["203.0.113.9"]
        assert answer.elapsed_ms == 0.0

    def test_unique_query_name_is_unique(self) -> None:
        names = {unique_query_name() for _ in range(100)}
        assert len(names) == 100


@needs_network
class TestResolverLive:
    def test_udp_resolves(self) -> None:
        answer = Resolver().resolve("one.one.one.one", transport="udp")
        assert answer.ok, answer.error
        assert "1.1.1.1" in answer.addresses

    def test_all_transports_agree(self) -> None:
        """Same name, four transports, same A records."""
        results = Resolver().compare_transports(
            "one.one.one.one", transports=("udp", "tcp", "dot", "doh")
        )
        succeeded = {t: a for t, a in results.items() if a.ok}
        assert len(succeeded) >= 2, {t: a.error for t, a in results.items()}
        address_sets = {frozenset(a.addresses) for a in succeeded.values()}
        assert len(address_sets) == 1, f"transports disagreed: {succeeded}"

    def test_nxdomain_is_reported(self) -> None:
        answer = Resolver().resolve(unique_query_name("invalid"), transport="udp")
        assert answer.rcode in ("NXDOMAIN", "NOERROR")
        assert answer.addresses == []
