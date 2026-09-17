"""
tests/test_headers.py — Module A (packet dissector) decoder tests.

Gate 2 scope: the Layer/FieldView model and the IPv4 reference decoder.

Reference packet used throughout
────────────────────────────────
    45 00 00 28 12 34 40 00 40 06 14 87 01 02 03 04 08 08 08 08

    version=4 ihl=5 dscp=0 ecn=0 total_length=40 id=0x1234
    flags: DF set, MF clear, frag_offset=0
    ttl=64 protocol=6 (TCP) checksum=0x1487 src=1.2.3.4 dst=8.8.8.8

Checksum hand-verification (RFC 791 one's complement), checksum field zeroed:
    0x4500 + 0x0028 + 0x1234 + 0x4000 + 0x4006 + 0x0000
          + 0x0102 + 0x0304 + 0x0808 + 0x0808 = 0xEB78
    ~0xEB78 & 0xFFFF = 0x1487  ✓
"""

from __future__ import annotations

import pytest

from netlab.dissect.headers import decode_ipv4, _inet_checksum as _ip4_checksum
from netlab.dissect.model import FieldView, Layer, _extract_bits

GOOD_IPV4 = bytes.fromhex("4500002812344000400614870102030408080808")


# ─────────────────────────────────────────────────────────────────────────────
# _extract_bits — sub-byte extraction
# ─────────────────────────────────────────────────────────────────────────────

class TestExtractBits:
    @pytest.mark.parametrize(
        "data, offset, length, expected",
        [
            (b"\x45", 0, 4, 4),        # IPv4 Version, upper nibble
            (b"\x45", 4, 4, 5),        # IPv4 IHL, lower nibble
            (b"\x00\x00", 0, 16, 0),
            (b"\xff\xff", 0, 16, 0xFFFF),
            (b"\x40\x00", 0, 1, 0),    # reserved flag
            (b"\x40\x00", 1, 1, 1),    # DF set
            (b"\x40\x00", 2, 1, 0),    # MF clear
            (b"\x40\x00", 3, 13, 0),   # frag offset spanning two bytes
            (b"\x20\xb9", 3, 13, 185),  # frag offset = 185, spans bytes 0-1
            (b"\x80", 0, 1, 1),        # MSB-first bit ordering
            (b"\x01", 7, 1, 1),        # last bit of a byte
        ],
    )
    def test_extraction(self, data, offset, length, expected) -> None:
        assert _extract_bits(data, offset, length) == expected

    def test_rejects_overrun(self) -> None:
        with pytest.raises(ValueError, match="overruns"):
            _extract_bits(b"\x45", 0, 16)

    def test_rejects_zero_length(self) -> None:
        with pytest.raises(ValueError, match="bit_length must be positive"):
            _extract_bits(b"\x45", 0, 0)

    def test_rejects_negative_offset(self) -> None:
        with pytest.raises(ValueError, match="bit_offset must be non-negative"):
            _extract_bits(b"\x45", -1, 4)


# ─────────────────────────────────────────────────────────────────────────────
# FieldView invariant — raw_bytes must match the bit span
# ─────────────────────────────────────────────────────────────────────────────

class TestFieldViewInvariant:
    """
    raw_bytes and (bit_offset, bit_length) are two descriptions of the same
    span.  If they may disagree, the hex-dump panel highlights the wrong bytes.
    The original decoder did exactly this for the three one-bit IPv4 flags.
    """

    def test_accepts_consistent_field(self) -> None:
        fv = FieldView(
            value=1, raw_bytes=b"\x40", bit_offset=1, bit_length=1, description=""
        )
        assert fv.byte_length == 1

    def test_rejects_over_broad_raw_bytes(self) -> None:
        """A one-bit flag inside byte 6 must not claim bytes 6-7."""
        with pytest.raises(ValueError, match="FieldView invariant violated"):
            FieldView(
                value=1,
                raw_bytes=b"\x40\x00",   # two bytes
                bit_offset=49,           # but the span touches only byte 6
                bit_length=1,
                description="",
            )

    def test_rejects_too_narrow_raw_bytes(self) -> None:
        with pytest.raises(ValueError, match="FieldView invariant violated"):
            FieldView(
                value=0,
                raw_bytes=b"\x00",       # one byte
                bit_offset=51,           # 13 bits from bit 51 spans bytes 6-7
                bit_length=13,
                description="",
            )

    def test_spanning_field_is_accepted(self) -> None:
        fv = FieldView(
            value=185, raw_bytes=b"\x20\xb9", bit_offset=51, bit_length=13, description=""
        )
        assert fv.byte_length == 2


# ─────────────────────────────────────────────────────────────────────────────
# IPv4 checksum
# ─────────────────────────────────────────────────────────────────────────────

class TestIPv4Checksum:
    def test_computed_matches_hand_derivation(self) -> None:
        zeroed = bytearray(GOOD_IPV4)
        zeroed[10] = zeroed[11] = 0
        assert _ip4_checksum(bytes(zeroed)) == 0x1487

    def test_full_header_sums_to_zero(self) -> None:
        """A valid header including its checksum checksums to 0."""
        assert _ip4_checksum(GOOD_IPV4) == 0

    def test_good_checksum_not_flagged(self) -> None:
        layer = decode_ipv4(GOOD_IPV4)
        assert layer.fields["checksum"].is_bad is False

    def test_corrupted_checksum_is_flagged(self) -> None:
        corrupt = bytearray(GOOD_IPV4)
        corrupt[10] ^= 0xFF
        layer = decode_ipv4(bytes(corrupt))
        chk = layer.fields["checksum"]
        assert chk.value == 0xEB87
        assert chk.computed_value == 0x1487
        assert chk.is_bad is True, "corrupted checksum must be detected"


# ─────────────────────────────────────────────────────────────────────────────
# IPv4 field decoding
# ─────────────────────────────────────────────────────────────────────────────

class TestIPv4Fields:
    @pytest.mark.parametrize(
        "name, value, bit_offset, bit_length",
        [
            ("version", 4, 0, 4),
            ("ihl", 5, 4, 4),
            ("dscp", 0, 8, 6),
            ("ecn", 0, 14, 2),
            ("total_length", 40, 16, 16),
            ("identification", 0x1234, 32, 16),
            ("reserved_flag", 0, 48, 1),
            ("df_flag", 1, 49, 1),
            ("mf_flag", 0, 50, 1),
            ("frag_offset", 0, 51, 13),
            ("ttl", 64, 64, 8),
            ("protocol", 6, 72, 8),
            ("checksum", 0x1487, 80, 16),
            ("src", "1.2.3.4", 96, 32),
            ("dst", "8.8.8.8", 128, 32),
        ],
    )
    def test_field_value_and_layout(self, name, value, bit_offset, bit_length) -> None:
        fv = decode_ipv4(GOOD_IPV4).fields[name]
        assert fv.value == value
        assert fv.bit_offset == bit_offset
        assert fv.bit_length == bit_length

    def test_every_field_raw_bytes_matches_its_span(self) -> None:
        """The invariant must hold for every field the decoder emits."""
        for name, fv in decode_ipv4(GOOD_IPV4).fields.items():
            assert len(fv.raw_bytes) == fv.byte_length, name

    def test_flag_fields_highlight_one_byte(self) -> None:
        """
        Regression: the three one-bit flags live entirely in byte 6 and must
        not carry the two-byte flags+frag_offset word as raw_bytes.
        """
        layer = decode_ipv4(GOOD_IPV4)
        for name in ("reserved_flag", "df_flag", "mf_flag"):
            assert len(layer.fields[name].raw_bytes) == 1, name
        # frag_offset genuinely spans both bytes
        assert len(layer.fields["frag_offset"].raw_bytes) == 2

    def test_fields_are_in_wire_order(self) -> None:
        offsets = [fv.bit_offset for fv in decode_ipv4(GOOD_IPV4).fields.values()]
        assert offsets == sorted(offsets)

    def test_payload_offset(self) -> None:
        layer = decode_ipv4(GOOD_IPV4)
        assert layer.payload_offset == 20
        assert layer.payload_offset == len(layer.raw_bytes)

    def test_decodes_at_nonzero_layer_offset(self) -> None:
        """Simulates an IP header sitting after a 14-byte Ethernet header."""
        framed = b"\xaa" * 14 + GOOD_IPV4
        layer = decode_ipv4(framed, layer_offset=14)
        assert layer.fields["src"].value == "1.2.3.4"
        assert layer.fields["checksum"].is_bad is False


# ─────────────────────────────────────────────────────────────────────────────
# Variable-length header (IP options)
# ─────────────────────────────────────────────────────────────────────────────

class TestIPv4Options:
    def _ihl6_packet(self) -> bytes:
        """IHL=6 → 24-byte header with 4 bytes of options, checksum recomputed."""
        hdr = bytearray(GOOD_IPV4)
        hdr[0] = 0x46                      # version 4, IHL 6
        hdr[2:4] = (44).to_bytes(2, "big")  # total_length = 24 header + 20 payload
        hdr += b"\x07\x04\x00\x00"          # Record Route option, 4 bytes
        hdr[10] = hdr[11] = 0
        hdr[10:12] = _ip4_checksum(bytes(hdr)).to_bytes(2, "big")
        return bytes(hdr)

    def test_options_present_and_sized(self) -> None:
        layer = decode_ipv4(self._ihl6_packet())
        assert layer.fields["ihl"].value == 6
        assert layer.payload_offset == 24
        opts = layer.fields["options"]
        assert opts.bit_offset == 160
        assert opts.bit_length == 32
        assert len(opts.raw_bytes) == 4

    def test_options_absent_when_ihl_is_5(self) -> None:
        assert "options" not in decode_ipv4(GOOD_IPV4).fields

    def test_checksum_valid_over_extended_header(self) -> None:
        assert decode_ipv4(self._ihl6_packet()).fields["checksum"].is_bad is False


# ─────────────────────────────────────────────────────────────────────────────
# Malformed input
# ─────────────────────────────────────────────────────────────────────────────

class TestIPv4Malformed:
    def test_empty_buffer(self) -> None:
        with pytest.raises(ValueError, match="need 20 B"):
            decode_ipv4(b"")

    def test_truncated_header(self) -> None:
        with pytest.raises(ValueError, match="need 20 B"):
            decode_ipv4(GOOD_IPV4[:10])

    def test_wrong_version(self) -> None:
        bad = bytearray(GOOD_IPV4)
        bad[0] = 0x65
        with pytest.raises(ValueError, match="expected 4"):
            decode_ipv4(bytes(bad))

    def test_ihl_below_minimum(self) -> None:
        bad = bytearray(GOOD_IPV4)
        bad[0] = 0x44
        with pytest.raises(ValueError, match="IHL=4 < 5"):
            decode_ipv4(bytes(bad))

    def test_ihl_exceeds_buffer(self) -> None:
        bad = bytearray(GOOD_IPV4)
        bad[0] = 0x46  # claims 24 bytes, buffer holds 20
        with pytest.raises(ValueError, match="IHL says 24 B"):
            decode_ipv4(bytes(bad))

    def test_total_length_smaller_than_header(self) -> None:
        """Total Length counts header + payload; it cannot be under the header."""
        bad = bytearray(GOOD_IPV4)
        bad[2:4] = (10).to_bytes(2, "big")
        with pytest.raises(ValueError, match="smaller than the 20-byte header"):
            decode_ipv4(bytes(bad))

    def test_trailing_ethernet_padding_is_accepted(self) -> None:
        """
        Ethernet pads frames to 60 bytes, so total_length < len(buffer) is
        legitimate and must NOT be rejected.
        """
        padded = GOOD_IPV4 + b"\x00" * 26
        assert decode_ipv4(padded).fields["total_length"].value == 40


# ─────────────────────────────────────────────────────────────────────────────
# Fragmentation — the decode chain must not parse a later fragment as transport
# ─────────────────────────────────────────────────────────────────────────────

class TestIPv4Fragmentation:
    def _fragment(self, frag_offset: int, mf: int) -> bytes:
        hdr = bytearray(GOOD_IPV4)
        flags_frag = (mf << 13) | frag_offset
        hdr[6:8] = flags_frag.to_bytes(2, "big")
        hdr[10] = hdr[11] = 0
        hdr[10:12] = _ip4_checksum(bytes(hdr)).to_bytes(2, "big")
        return bytes(hdr)

    def test_unfragmented_carries_transport_header(self) -> None:
        layer = decode_ipv4(GOOD_IPV4)
        assert layer.notes["is_fragmented"] is False
        assert layer.carries_transport_header() is True

    def test_first_fragment_carries_transport_header(self) -> None:
        layer = decode_ipv4(self._fragment(frag_offset=0, mf=1))
        assert layer.notes["is_fragmented"] is True
        assert layer.notes["is_first_fragment"] is True
        assert layer.carries_transport_header() is True

    def test_later_fragment_does_not(self) -> None:
        """Fragment at offset 185 holds raw payload, not a TCP header."""
        layer = decode_ipv4(self._fragment(frag_offset=185, mf=1))
        assert layer.fields["frag_offset"].value == 185
        assert layer.carries_transport_header() is False

    def test_last_fragment_does_not(self) -> None:
        layer = decode_ipv4(self._fragment(frag_offset=185, mf=0))
        assert layer.carries_transport_header() is False


# ─────────────────────────────────────────────────────────────────────────────
# Serialisation — golden-file support
# ─────────────────────────────────────────────────────────────────────────────

class TestSerialisation:
    def test_to_dict_is_json_serialisable(self) -> None:
        import json
        blob = json.dumps(decode_ipv4(GOOD_IPV4).to_dict())
        assert "1.2.3.4" in blob

    def test_raw_bytes_rendered_as_hex(self) -> None:
        d = decode_ipv4(GOOD_IPV4).to_dict()
        assert d["fields"]["src"]["raw_bytes"] == "01 02 03 04"

    def test_is_bad_exposed_in_dict(self) -> None:
        d = decode_ipv4(GOOD_IPV4).to_dict()
        assert d["fields"]["checksum"]["is_bad"] is False


# ─────────────────────────────────────────────────────────────────────────────
# Gate 3 review additions — traps the decoder suite did not cover
#
# Each of these was probed by hand during cross-verification against Scapy.
# The decoders passed all three behaviours; these lock them in.
# ─────────────────────────────────────────────────────────────────────────────

import struct

from netlab.dissect.headers import decode_packet, _inet_checksum


def _ipv4_frame(payload: bytes, proto: int, flags_frag: int = 0x4000) -> bytes:
    """Build a valid IPv4 header (checksum recomputed) wrapping *payload*."""
    hdr = bytearray(
        struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(payload), 1, flags_frag, 64, proto, 0)
        + bytes([10, 0, 0, 1])
        + bytes([1, 1, 1, 1])
    )
    hdr[10:12] = _inet_checksum(bytes(hdr)).to_bytes(2, "big")
    return bytes(hdr) + payload


class TestUDPZeroChecksum:
    """
    RFC 768: on IPv4 a UDP checksum of 0 means the sender did not compute one.
    Flagging it as corrupt would show a false error on legitimate traffic.
    """

    def test_zero_checksum_is_not_flagged_bad(self) -> None:
        udp = struct.pack("!HHHH", 1234, 53, 12, 0) + b"test"
        layer = decode_packet(_ipv4_frame(udp, proto=17), l2=False).get_layer("UDP")
        assert layer.fields["checksum"].value == 0
        assert layer.fields["checksum"].is_bad is False


class TestFragmentChaining:
    """
    Only fragment 0 carries the transport header.  decode_packet must consult
    carries_transport_header() before descending, or a later fragment's payload
    decodes into convincing nonsense.
    """

    # A syntactically valid 20-byte TCP header (data offset = 5).  Fragment 0
    # genuinely starts with one of these; later fragments do not, which is the
    # whole point of the check.
    _TCP_HEADER = struct.pack(
        "!HHIIBBHHH", 1234, 80, 1, 2, (5 << 4), 0x02, 1024, 0, 0
    )

    def _fragment(self, frag_offset: int, mf: int) -> bytes:
        return _ipv4_frame(
            self._TCP_HEADER,
            proto=6,
            flags_frag=(mf << 13) | frag_offset,
        )

    def test_first_fragment_descends_into_transport(self) -> None:
        packet = decode_packet(self._fragment(frag_offset=0, mf=1), l2=False)
        assert packet.get_layer("IPv4").carries_transport_header() is True
        assert packet.has_layer("TCP")

    def test_later_fragment_does_not_descend(self) -> None:
        packet = decode_packet(self._fragment(frag_offset=185, mf=1), l2=False)
        ip = packet.get_layer("IPv4")
        assert ip.fields["frag_offset"].value == 185
        assert ip.carries_transport_header() is False
        assert not packet.has_layer("TCP"), "later fragment must not decode as TCP"


class TestNotesSerialisation:
    """
    Fragmentation state decides whether a transport layer appears at all, so a
    golden file that omits notes cannot tell "absent because fragment" from
    "absent because the decoder broke".
    """

    def test_notes_present_in_layer_dict(self) -> None:
        ip = decode_packet(_ipv4_frame(b"\x00" * 8, proto=17), l2=False).get_layer("IPv4")
        assert "notes" in ip.to_dict()
        assert ip.to_dict()["notes"]["is_fragmented"] is False

    def test_notes_round_trip_json(self) -> None:
        import json
        frame = _ipv4_frame(b"\xde\xad" * 8, proto=6, flags_frag=(1 << 13) | 185)
        blob = json.loads(json.dumps(decode_packet(frame, l2=False).to_dict()))
        ip = next(layer for layer in blob["layers"] if layer["name"] == "IPv4")
        assert ip["notes"]["is_fragmented"] is True
        assert ip["notes"]["is_first_fragment"] is False


class TestEthernetPaddingChecksum:
    """
    Ethernet pads frames to 60 bytes.  TCP has no length field of its own, so
    the segment length must come from IP — computing the checksum over "the
    rest of the buffer" pulls in the padding and makes every small segment
    (every SYN, ACK and FIN) report a false bad checksum.
    """

    def _syn_frame(self) -> bytes:
        tcp = struct.pack("!HHIIBBHHH", 1234, 80, 1, 0, (5 << 4), 0x02, 1024, 0, 0)
        frame = _ipv4_frame(tcp, proto=6)
        # recompute the TCP checksum so the unpadded frame is genuinely valid
        pseudo = frame[12:16] + frame[16:20] + bytes([0, 6]) + len(tcp).to_bytes(2, "big")
        ck = _inet_checksum(pseudo + tcp)
        tcp = tcp[:16] + ck.to_bytes(2, "big") + tcp[18:]
        return _ipv4_frame(tcp, proto=6)

    def test_unpadded_checksum_is_valid(self) -> None:
        layer = decode_packet(self._syn_frame(), l2=False).get_layer("TCP")
        assert layer.fields["checksum"].is_bad is False

    def test_padding_does_not_break_checksum(self) -> None:
        padded = self._syn_frame() + b"\x00" * 6
        layer = decode_packet(padded, l2=False).get_layer("TCP")
        assert layer.fields["checksum"].is_bad is False, (
            "trailing Ethernet padding must not be included in the TCP checksum"
        )


class TestDescriptionsAreRendered:
    """
    Field descriptions are read aloud in the viva, so an unrendered f-string
    placeholder is a user-visible defect.  One shipped: the TCP data_offset
    description contained a literal "{hlen}".
    """

    def test_no_unrendered_placeholders(self) -> None:
        frame = _ipv4_frame(
            struct.pack("!HHIIBBHHH", 1, 2, 0, 0, (5 << 4), 0x02, 1024, 0, 0),
            proto=6,
        )
        for layer in decode_packet(frame, l2=False).layers:
            for name, fv in layer.fields.items():
                assert "{" not in fv.description, f"{layer.name}.{name}: {fv.description}"
