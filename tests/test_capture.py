"""
tests/test_capture.py — pcap reader, golden decodes, and the independent
cross-check against Scapy.

Why two kinds of check
──────────────────────
A golden file pins the decoders against *themselves*: it catches unintended
change, but it cannot catch a decoder that was wrong from the start — the
golden would simply record the wrong answer.

TestScapyCrossCheck is the real check. Scapy is a separate implementation by
different authors, so agreement on field values is meaningful evidence. It is
weaker than tshark (both are Python, and both could in principle share a
misreading of an RFC) but it is genuinely independent of this codebase.

Everything here runs offline with no capture driver and no admin rights.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netlab.dissect.capture import (
    LINKTYPE_ETHERNET,
    PCAP_MAGIC_US,
    CaptureBackendUnavailable,
    LiveCapture,
    PcapFileCapture,
    live_capture_available,
    write_pcap,
)

SAMPLES = Path(__file__).resolve().parents[1] / "docs" / "samples"
PCAPS = sorted(SAMPLES.glob("*.pcap"))

scapy = pytest.importorskip("scapy.all", reason="scapy is the independent reference")


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures exist
# ─────────────────────────────────────────────────────────────────────────────

def test_sample_pcaps_are_committed() -> None:
    """The panel and every test below depend on these being in the repo."""
    names = {p.name for p in PCAPS}
    assert names == {
        "01_tcp_handshake.pcap",
        "02_sharp_edges.pcap",
        "03_mixed_protocols.pcap",
    }, f"unexpected sample set: {sorted(names)}"


# ─────────────────────────────────────────────────────────────────────────────
# pcap file format
# ─────────────────────────────────────────────────────────────────────────────

class TestPcapReader:
    @pytest.mark.parametrize("pcap", PCAPS, ids=lambda p: p.stem)
    def test_reads_header(self, pcap: Path) -> None:
        cap = PcapFileCapture(pcap)
        assert cap.info.link_type == LINKTYPE_ETHERNET
        assert cap.info.is_l2 is True
        assert cap.version == (2, 4)

    @pytest.mark.parametrize("pcap", PCAPS, ids=lambda p: p.stem)
    def test_packet_count_matches_iteration(self, pcap: Path) -> None:
        cap = PcapFileCapture(pcap)
        assert len(cap) == sum(1 for _ in cap.packets())

    @pytest.mark.parametrize("pcap", PCAPS, ids=lambda p: p.stem)
    def test_every_packet_decodes_to_at_least_ethernet(self, pcap: Path) -> None:
        for packet in PcapFileCapture(pcap).packets():
            assert packet.layers, "no layer decoded at all"
            assert packet.layers[0].name == "Ethernet II"

    def test_big_endian_file_is_read(self, tmp_path: Path) -> None:
        """
        The magic number carries the writing host's byte order.  Hand-build a
        big-endian file and confirm it is detected.
        """
        import struct
        frame = bytes(PcapFileCapture(PCAPS[0])._raw[24 + 16: 24 + 16 + 60])
        blob = struct.pack(">IHHiIII", PCAP_MAGIC_US, 2, 4, 0, 0, 65535, 1)
        blob += struct.pack(">IIII", 1, 0, len(frame), len(frame)) + frame
        path = tmp_path / "be.pcap"
        path.write_bytes(blob)
        cap = PcapFileCapture(path)
        assert cap._endian == ">"
        assert len(cap) == 1

    def test_rejects_non_pcap(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.pcap"
        path.write_bytes(b"not a pcap file at all, just some bytes here ok")
        with pytest.raises(ValueError, match="not a libpcap file"):
            PcapFileCapture(path)

    def test_rejects_too_short(self, tmp_path: Path) -> None:
        path = tmp_path / "short.pcap"
        path.write_bytes(b"\xd4\xc3\xb2\xa1")
        with pytest.raises(ValueError, match="too short"):
            PcapFileCapture(path)

    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            PcapFileCapture(tmp_path / "nope.pcap")

    def test_truncated_final_record_is_dropped_not_crashed(self, tmp_path: Path) -> None:
        """A capture cut off mid-packet must yield the whole packets and stop."""
        original = PCAPS[0].read_bytes()
        path = tmp_path / "cut.pcap"
        path.write_bytes(original[:-10])
        cap = PcapFileCapture(path)
        assert len(cap) < len(PcapFileCapture(PCAPS[0]))
        list(cap.packets())  # must not raise

    def test_round_trip_write_then_read(self, tmp_path: Path) -> None:
        frames = [bytes(range(60)), bytes(range(40))]
        path = tmp_path / "rt.pcap"
        write_pcap(path, frames)
        cap = PcapFileCapture(path)
        assert len(cap) == 2
        assert [p.raw_frame for p in cap.packets()] == frames


# ─────────────────────────────────────────────────────────────────────────────
# Golden decodes — regression only
# ─────────────────────────────────────────────────────────────────────────────

class TestGoldenDecodes:
    @pytest.mark.parametrize("pcap", PCAPS, ids=lambda p: p.stem)
    def test_matches_golden(self, pcap: Path) -> None:
        golden_path = pcap.with_suffix(".golden.json")
        assert golden_path.exists(), (
            f"{golden_path.name} missing — run docs/samples/make_goldens.py"
        )
        golden = json.loads(golden_path.read_text(encoding="utf-8"))
        actual = [p.to_dict() for p in PcapFileCapture(pcap).packets()]
        assert actual == golden["packets"]


# ─────────────────────────────────────────────────────────────────────────────
# Independent cross-check — our decoders vs Scapy
# ─────────────────────────────────────────────────────────────────────────────

class TestScapyCrossCheck:
    """
    Field-by-field agreement between our hand-written decoders and Scapy.

    Only fields both sides expose are compared, and only where the semantics
    are identical — e.g. Scapy reports IPv4 `flags` as a symbolic set, so the
    DF/MF bits are compared individually rather than as a unit.
    """

    def _pairs(self, pcap: Path):
        """Yield (our_packet, scapy_packet) for every frame in *pcap*."""
        from scapy.layers.l2 import Ether
        for packet in PcapFileCapture(pcap).packets():
            yield packet, Ether(packet.raw_frame)

    @pytest.mark.parametrize("pcap", PCAPS, ids=lambda p: p.stem)
    def test_ipv4_fields_agree(self, pcap: Path) -> None:
        from scapy.layers.inet import IP
        compared = 0
        for ours, theirs in self._pairs(pcap):
            layer = ours.get_layer("IPv4")
            if layer is None or IP not in theirs:
                continue
            ref = theirs[IP]
            assert layer.fields["src"].value == ref.src
            assert layer.fields["dst"].value == ref.dst
            assert layer.fields["ttl"].value == ref.ttl
            assert layer.fields["protocol"].value == ref.proto
            assert layer.fields["ihl"].value == ref.ihl
            assert layer.fields["total_length"].value == ref.len
            assert layer.fields["identification"].value == ref.id
            assert layer.fields["frag_offset"].value == ref.frag
            assert layer.fields["df_flag"].value == int(bool(ref.flags.DF))
            assert layer.fields["mf_flag"].value == int(bool(ref.flags.MF))
            compared += 1
        assert compared, f"no IPv4 packets compared in {pcap.name}"

    @pytest.mark.parametrize("pcap", PCAPS, ids=lambda p: p.stem)
    def test_tcp_fields_agree(self, pcap: Path) -> None:
        from scapy.layers.inet import TCP
        compared = 0
        for ours, theirs in self._pairs(pcap):
            layer = ours.get_layer("TCP")
            if layer is None or TCP not in theirs:
                continue
            ref = theirs[TCP]
            assert layer.fields["src_port"].value == ref.sport
            assert layer.fields["dst_port"].value == ref.dport
            assert layer.fields["seq"].value == ref.seq
            assert layer.fields["ack"].value == ref.ack
            assert layer.fields["window"].value == ref.window
            assert layer.fields["data_offset"].value == ref.dataofs
            assert layer.fields["syn"].value == int(bool(ref.flags.S))
            assert layer.fields["ack_flag"].value == int(bool(ref.flags.A))
            assert layer.fields["fin"].value == int(bool(ref.flags.F))
            assert layer.fields["psh"].value == int(bool(ref.flags.P))
            compared += 1
        assert compared, f"no TCP packets compared in {pcap.name}"

    def test_tcp_options_agree(self) -> None:
        """MSS / Window Scale / SACK-Permitted parsed the same as Scapy."""
        from scapy.layers.inet import TCP
        seen = 0
        for ours, theirs in self._pairs(SAMPLES / "01_tcp_handshake.pcap"):
            layer = ours.get_layer("TCP")
            if layer is None or "options" not in layer.fields:
                continue
            parsed = layer.fields["options"].value
            ref = dict((k, v) for k, v in theirs[TCP].options if isinstance(k, str))
            if "MSS" in ref:
                assert parsed["mss"] == ref["MSS"]
                seen += 1
            if "WScale" in ref:
                assert parsed["window_scale"] == ref["WScale"]
            if "SAckOK" in ref:
                assert parsed.get("sack_permitted") is True
        assert seen >= 2, "expected MSS in both SYN and SYN-ACK"

    @pytest.mark.parametrize("pcap", PCAPS, ids=lambda p: p.stem)
    def test_udp_fields_agree(self, pcap: Path) -> None:
        from scapy.layers.inet import UDP
        for ours, theirs in self._pairs(pcap):
            layer = ours.get_layer("UDP")
            if layer is None or UDP not in theirs:
                continue
            ref = theirs[UDP]
            assert layer.fields["src_port"].value == ref.sport
            assert layer.fields["dst_port"].value == ref.dport
            assert layer.fields["length"].value == ref.len

    def test_ipv6_fields_agree(self) -> None:
        from scapy.layers.inet6 import IPv6
        compared = 0
        for ours, theirs in self._pairs(SAMPLES / "03_mixed_protocols.pcap"):
            layer = ours.get_layer("IPv6")
            if layer is None or IPv6 not in theirs:
                continue
            ref = theirs[IPv6]
            assert layer.fields["src"].value == ref.src
            assert layer.fields["dst"].value == ref.dst
            assert layer.fields["hop_limit"].value == ref.hlim
            assert layer.fields["payload_length"].value == ref.plen
            assert layer.fields["next_header"].value == ref.nh
            compared += 1
        assert compared, "no IPv6 packets compared"

    @pytest.mark.parametrize("pcap", PCAPS, ids=lambda p: p.stem)
    def test_ethernet_fields_agree(self, pcap: Path) -> None:
        for ours, theirs in self._pairs(pcap):
            eth = ours.get_layer("Ethernet II")
            assert eth.fields["src"].value == theirs.src
            assert eth.fields["dst"].value == theirs.dst


# ─────────────────────────────────────────────────────────────────────────────
# Checksum verdicts on the sharp-edge fixture
# ─────────────────────────────────────────────────────────────────────────────

class TestSharpEdges:
    """
    Every packet in 02_sharp_edges.pcap previously provoked a wrong answer.
    Exactly one of them is genuinely corrupt.
    """

    def _packets(self) -> list:
        return list(PcapFileCapture(SAMPLES / "02_sharp_edges.pcap").packets())

    def test_only_the_corrupt_packet_is_flagged(self) -> None:
        flagged = [
            (i, f"{layer.name}.{name}")
            for i, packet in enumerate(self._packets())
            for layer in packet.layers
            for name, field in layer.fields.items()
            if field.is_bad
        ]
        assert flagged == [(5, "IPv4.checksum")], (
            f"exactly one packet should be corrupt, got {flagged}"
        )

    def test_padded_syn_checksum_survives_ethernet_padding(self) -> None:
        packet = self._packets()[0]
        assert len(packet.raw_frame) == 60, "fixture must be a padded short frame"
        assert packet.get_layer("TCP").fields["checksum"].is_bad is False

    def test_first_fragment_decodes_transport(self) -> None:
        packet = self._packets()[1]
        assert packet.get_layer("IPv4").notes["is_fragmented"] is True
        assert packet.has_layer("TCP")

    def test_first_fragment_checksum_is_not_verified(self) -> None:
        """A TCP checksum covers the reassembled segment, not one fragment."""
        field = self._packets()[1].get_layer("TCP").fields["checksum"]
        assert field.computed_value is None
        assert field.is_bad is False
        assert "fragment" in field.description

    def test_later_fragment_does_not_decode_transport(self) -> None:
        packet = self._packets()[2]
        assert packet.get_layer("IPv4").fields["frag_offset"].value > 0
        assert not packet.has_layer("TCP"), "later fragment must not decode as TCP"

    def test_udp_zero_checksum_not_flagged(self) -> None:
        assert self._packets()[3].get_layer("UDP").fields["checksum"].value == 0
        assert self._packets()[3].get_layer("UDP").fields["checksum"].is_bad is False

    def test_ipv4_options_present(self) -> None:
        layer = self._packets()[4].get_layer("IPv4")
        assert layer.fields["ihl"].value == 6
        assert "options" in layer.fields

    def test_corrupt_checksum_flagged(self) -> None:
        field = self._packets()[5].get_layer("IPv4").fields["checksum"]
        assert field.is_bad is True
        assert field.computed_value != field.value


# ─────────────────────────────────────────────────────────────────────────────
# Live capture degrades rather than crashing
# ─────────────────────────────────────────────────────────────────────────────

class TestLiveCaptureDegradation:
    """
    Trap §7.1: on Windows, Scapy needs Npcap.  Without it the panel must say so
    and fall back to pcap replay, never crash.
    """

    def test_availability_check_never_raises(self) -> None:
        available, reason = live_capture_available()
        assert isinstance(available, bool)
        assert isinstance(reason, str) and reason

    def test_unavailable_backend_raises_typed_error(self, monkeypatch) -> None:
        monkeypatch.setattr(
            "netlab.dissect.capture.live_capture_available",
            lambda: (False, "Npcap not installed"),
        )
        with pytest.raises(CaptureBackendUnavailable, match="Npcap not installed"):
            LiveCapture("eth0")
