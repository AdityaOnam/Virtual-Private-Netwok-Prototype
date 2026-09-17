"""
tests/test_transport.py — Phase 3: ARQ, RTT estimation, congestion control.

Everything runs on a virtual clock with a seeded PRNG, so the suite is fast
and every result is reproducible — a congestion graph that changes between
runs cannot be explained to an examiner.
"""

from __future__ import annotations

import pytest

from netlab.transport.arq import (
    Ack,
    CumulativeReceiver,
    GoBackN,
    SelectiveReceiver,
    Segment,
    SelectiveRepeat,
    StopAndWait,
)
from netlab.transport.congestion import (
    MSS,
    CongestionState,
    RenoController,
    bandwidth_delay_product,
)
from netlab.transport.harness import (
    TransferConfig,
    compare_protocols,
    run_transfer,
)
from netlab.transport.impairment import Clock, ImpairedLink
from netlab.transport.rtt import MAX_RTO, MIN_RTO, RttEstimator


# ─────────────────────────────────────────────────────────────────────────────
# Impairment layer — determinism is the foundation everything else rests on
# ─────────────────────────────────────────────────────────────────────────────

class TestImpairedLink:
    def test_clean_link_delivers_everything(self) -> None:
        clock = Clock()
        link = ImpairedLink(clock, delay_ms=10, seed=1)
        for i in range(50):
            assert link.send(bytes([i])) is True
        clock.advance(0.011)
        assert len(list(link.deliver())) == 50

    def test_delay_is_respected(self) -> None:
        clock = Clock()
        link = ImpairedLink(clock, delay_ms=20, seed=1)
        link.send(b"x")
        clock.advance(0.019)
        assert list(link.deliver()) == []
        clock.advance(0.002)
        assert list(link.deliver()) == [b"x"]

    def test_loss_is_applied(self) -> None:
        clock = Clock()
        link = ImpairedLink(clock, loss=0.5, seed=4)
        sent = sum(link.send(b"x") for _ in range(400))
        assert 150 < sent < 250, f"expected roughly half of 400, got {sent}"
        assert link.stats.dropped == 400 - sent

    def test_same_seed_same_trace(self) -> None:
        def trace(seed: int) -> list[bool]:
            link = ImpairedLink(Clock(), loss=0.3, jitter_ms=5, seed=seed)
            return [link.send(bytes([i % 256])) for i in range(200)]

        assert trace(11) == trace(11)
        assert trace(11) != trace(12)

    def test_duplication_delivers_twice(self) -> None:
        clock = Clock()
        link = ImpairedLink(clock, duplicate=1.0, delay_ms=1, seed=1)
        link.send(b"dup")
        clock.advance(0.01)
        assert list(link.deliver()) == [b"dup", b"dup"]

    def test_bandwidth_cap_creates_queueing_delay(self) -> None:
        """A bottleneck is what gives congestion control something to find."""
        clock = Clock()
        link = ImpairedLink(clock, bandwidth_bps=8000, seed=1)  # 1000 B/s
        for _ in range(10):
            link.send(b"x" * 1000)
        clock.advance(0.5)
        delivered_early = len(list(link.deliver()))
        clock.advance(20.0)
        delivered_late = len(list(link.deliver()))
        assert delivered_early < 10
        assert delivered_early + delivered_late == 10

    @pytest.mark.parametrize("field", ["loss", "reorder", "duplicate"])
    def test_probabilities_validated(self, field: str) -> None:
        with pytest.raises(ValueError, match="in \\[0, 1\\]"):
            ImpairedLink(Clock(), **{field: 1.5})


# ─────────────────────────────────────────────────────────────────────────────
# RTT estimation and Karn's algorithm
# ─────────────────────────────────────────────────────────────────────────────

class TestRttEstimator:
    def test_first_sample_seeds_estimator(self) -> None:
        estimator = RttEstimator()
        estimator.sample(0.100)
        assert estimator.srtt == pytest.approx(0.100)
        assert estimator.rttvar == pytest.approx(0.050)
        assert estimator.rto == pytest.approx(0.300)

    def test_converges_on_a_steady_path(self) -> None:
        estimator = RttEstimator()
        for _ in range(100):
            estimator.sample(0.100)
        assert estimator.srtt == pytest.approx(0.100, abs=1e-3)
        assert estimator.rttvar < 0.005
        assert estimator.rto == pytest.approx(0.200, abs=0.02)

    def test_variance_widens_the_timeout(self) -> None:
        """
        The 4*RTTVAR term: a jittery path gets a looser RTO than a steady one
        with the same mean, because on a jittery path being late is normal.
        """
        steady = RttEstimator()
        jittery = RttEstimator()
        for i in range(60):
            steady.sample(0.100)
            jittery.sample(0.050 if i % 2 else 0.150)
        assert jittery.rto > steady.rto

    def test_rto_is_clamped(self) -> None:
        low = RttEstimator()
        low.sample(0.0001)
        assert low.rto >= MIN_RTO
        high = RttEstimator()
        high.rto = MAX_RTO
        assert high.back_off() == MAX_RTO

    def test_karn_ignores_retransmitted_sample(self) -> None:
        """
        The headline rule: an ACK for a retransmitted segment is ambiguous, so
        it must not move SRTT. Measuring it shortens the RTO, which causes more
        spurious retransmissions, which shortens it further.
        """
        estimator = RttEstimator()
        for _ in range(20):
            estimator.sample(0.100)
        before_srtt, before_rto = estimator.srtt, estimator.rto

        assert estimator.sample(0.001, was_retransmitted=True) is False

        assert estimator.srtt == before_srtt
        assert estimator.rto == before_rto
        assert estimator.samples_ignored_karn == 1

    def test_backoff_doubles(self) -> None:
        estimator = RttEstimator()
        estimator.sample(0.100)
        first = estimator.rto
        assert estimator.back_off() == pytest.approx(min(first * 2, MAX_RTO))
        assert estimator.backoffs == 1

    def test_reset_backoff_restores_estimate(self) -> None:
        estimator = RttEstimator()
        estimator.sample(0.100)
        computed = estimator.rto
        estimator.back_off()
        estimator.back_off()
        assert estimator.rto > computed
        estimator.reset_backoff()
        assert estimator.rto == pytest.approx(computed)

    def test_history_records_every_change(self) -> None:
        estimator = RttEstimator()
        estimator.sample(0.1, now=1.0)
        estimator.back_off(now=2.0)
        assert [h["t"] for h in estimator.history] == [1.0, 2.0]


# ─────────────────────────────────────────────────────────────────────────────
# Congestion control
# ─────────────────────────────────────────────────────────────────────────────

class TestRenoController:
    def test_starts_in_slow_start_at_one_segment(self) -> None:
        reno = RenoController()
        assert reno.state is CongestionState.SLOW_START
        assert reno.cwnd_segments == pytest.approx(1.0)

    def test_slow_start_doubles_per_rtt(self) -> None:
        """One extra segment per ACK means the window doubles each round."""
        reno = RenoController(ssthresh=1e9)
        for _ in range(4):
            reno.on_ack()
        assert reno.cwnd_segments == pytest.approx(5.0)

    def test_switches_to_congestion_avoidance_at_ssthresh(self) -> None:
        reno = RenoController(ssthresh=4.0 * MSS)
        for _ in range(3):
            reno.on_ack()
        assert reno.state is CongestionState.CONGESTION_AVOIDANCE

    def test_congestion_avoidance_is_linear(self) -> None:
        """MSS^2/cwnd per ACK sums to about one segment per RTT."""
        reno = RenoController(cwnd=10.0 * MSS, ssthresh=1.0 * MSS)
        start = reno.cwnd_segments
        for _ in range(10):
            reno.on_ack()
        assert reno.cwnd_segments == pytest.approx(start + 1.0, abs=0.1)

    def test_timeout_collapses_to_one_segment(self) -> None:
        reno = RenoController(cwnd=32.0 * MSS, ssthresh=64.0 * MSS)
        reno.on_timeout()
        assert reno.cwnd_segments == pytest.approx(1.0)
        assert reno.ssthresh_segments == pytest.approx(16.0)
        assert reno.state is CongestionState.SLOW_START

    def test_three_duplicate_acks_trigger_fast_retransmit(self) -> None:
        reno = RenoController(cwnd=20.0 * MSS, ssthresh=64.0 * MSS)
        assert reno.on_duplicate_ack() is False
        assert reno.on_duplicate_ack() is False
        assert reno.on_duplicate_ack() is True
        assert reno.state is CongestionState.FAST_RECOVERY
        assert reno.fast_retransmits == 1

    def test_fast_retransmit_does_not_collapse_cwnd(self) -> None:
        """
        The asymmetry that matters: duplicate ACKs mean packets are still
        arriving, so halve. A timeout means nothing is arriving, so restart.
        """
        dup = RenoController(cwnd=32.0 * MSS, ssthresh=64.0 * MSS)
        for _ in range(3):
            dup.on_duplicate_ack()

        timeout = RenoController(cwnd=32.0 * MSS, ssthresh=64.0 * MSS)
        timeout.on_timeout()

        assert dup.cwnd_segments > 16.0
        assert timeout.cwnd_segments == pytest.approx(1.0)
        assert dup.cwnd > timeout.cwnd

    def test_new_ack_exits_fast_recovery(self) -> None:
        reno = RenoController(cwnd=32.0 * MSS, ssthresh=64.0 * MSS)
        for _ in range(3):
            reno.on_duplicate_ack()
        expected = reno.ssthresh
        reno.on_ack()
        assert reno.cwnd == pytest.approx(expected)
        assert reno.state is CongestionState.CONGESTION_AVOIDANCE

    def test_ssthresh_never_below_two_segments(self) -> None:
        reno = RenoController(cwnd=1.0 * MSS)
        for _ in range(8):
            reno.on_timeout()
        assert reno.ssthresh_segments >= 2.0

    def test_window_is_min_of_cwnd_and_receiver(self) -> None:
        reno = RenoController(cwnd=100.0 * MSS)
        assert reno.window_bytes(receiver_window=10.0 * MSS) == 10.0 * MSS


class TestBandwidthDelayProduct:
    def test_known_value(self) -> None:
        # 10 Mbit/s, 100 ms RTT → 125 000 bytes in flight to fill the pipe
        assert bandwidth_delay_product(10_000_000, 0.1) == pytest.approx(125_000)


# ─────────────────────────────────────────────────────────────────────────────
# Receivers
# ─────────────────────────────────────────────────────────────────────────────

class TestReceivers:
    def test_cumulative_discards_out_of_order(self) -> None:
        receiver = CumulativeReceiver()
        receiver.on_segment(Segment(0, b"a"))
        ack = receiver.on_segment(Segment(2, b"c"))   # gap at 1
        assert ack.ack == 1, "must repeat the last in-order ACK"
        assert receiver.discarded == 1
        assert receiver.delivered == [b"a"]

    def test_selective_buffers_out_of_order(self) -> None:
        receiver = SelectiveReceiver()
        receiver.on_segment(Segment(0, b"a"))
        receiver.on_segment(Segment(2, b"c"))          # buffered, not dropped
        assert receiver.delivered == [b"a"]
        receiver.on_segment(Segment(1, b"b"))          # fills the gap
        assert receiver.delivered == [b"a", b"b", b"c"]
        # The high-water mark is 2: the gap-filling segment is inserted before
        # the run is drained, so both sit in the buffer for an instant. That
        # is the memory the receiver genuinely had to have available, which is
        # the cost Selective Repeat pays for its cheaper retransmissions.
        assert receiver.buffered_peak == 2
        assert receiver.buffer == {}, "buffer must drain once the gap closes"

    def test_selective_rejects_duplicate(self) -> None:
        receiver = SelectiveReceiver()
        receiver.on_segment(Segment(0, b"a"))
        receiver.on_segment(Segment(0, b"a"))
        assert receiver.delivered == [b"a"]
        assert receiver.duplicate_acks_sent == 1


class TestWireEncoding:
    def test_segment_round_trip(self) -> None:
        segment = Segment(12345, b"payload")
        assert Segment.decode(segment.encode()).seq == 12345
        assert Segment.decode(segment.encode()).payload == b"payload"

    def test_ack_round_trip(self) -> None:
        for selective in (True, False):
            ack = Ack(999, selective=selective)
            decoded = Ack.decode(ack.encode())
            assert decoded.ack == 999
            assert decoded.selective is selective

    def test_ack_is_distinguishable_from_segment(self) -> None:
        assert Ack.is_ack(Ack(1).encode()) is True
        assert Ack.is_ack(Segment(1, b"x").encode()) is False


# ─────────────────────────────────────────────────────────────────────────────
# End-to-end transfers
# ─────────────────────────────────────────────────────────────────────────────

class TestTransfers:
    @pytest.mark.parametrize("protocol", ["stop-and-wait", "go-back-n",
                                          "selective-repeat"])
    def test_clean_link_delivers_exactly(self, protocol: str) -> None:
        result = run_transfer(TransferConfig(protocol=protocol, segments=60,
                                             loss=0.0, seed=1))
        assert result.delivered_ok is True
        assert result.stats.segments_retransmitted == 0

    @pytest.mark.parametrize("protocol", ["stop-and-wait", "go-back-n",
                                          "selective-repeat"])
    def test_lossy_link_still_delivers_in_order(self, protocol: str) -> None:
        """20% loss, and the byte stream still arrives complete and ordered."""
        result = run_transfer(TransferConfig(protocol=protocol, segments=60,
                                             loss=0.2, window=8, seed=7))
        assert result.delivered_ok is True, "ARQ must reconstruct the stream"
        assert result.stats.segments_retransmitted > 0

    @pytest.mark.parametrize("seed", [3, 7, 11])
    def test_go_back_n_retransmits_more_than_selective_repeat(self, seed: int) -> None:
        """
        The defining trade: Go-Back-N resends the whole window after a loss,
        Selective Repeat resends only what was lost.
        """
        results = compare_protocols(segments=100, loss=0.2, window=8, seed=seed)
        gbn = results["go-back-n"].stats.segments_retransmitted
        sr = results["selective-repeat"].stats.segments_retransmitted
        assert gbn > sr, f"seed {seed}: GBN {gbn} should exceed SR {sr}"

    def test_selective_repeat_is_more_efficient(self) -> None:
        results = compare_protocols(segments=100, loss=0.2, window=8, seed=7)
        assert (results["selective-repeat"].stats.efficiency
                > results["go-back-n"].stats.efficiency)

    def test_stop_and_wait_is_slowest_on_a_long_path(self) -> None:
        """One segment per RTT, whatever the bandwidth."""
        results = compare_protocols(segments=80, loss=0.0, delay_ms=25,
                                    window=16, seed=1)
        assert (results["stop-and-wait"].stats.elapsed
                > results["go-back-n"].stats.elapsed * 3)

    def test_window_size_increases_throughput(self) -> None:
        small = run_transfer(TransferConfig(protocol="go-back-n", segments=100,
                                            window=2, congestion_control=False,
                                            seed=1))
        large = run_transfer(TransferConfig(protocol="go-back-n", segments=100,
                                            window=32, congestion_control=False,
                                            seed=1))
        assert large.stats.elapsed < small.stats.elapsed

    def test_reordering_does_not_corrupt_the_stream(self) -> None:
        result = run_transfer(TransferConfig(protocol="selective-repeat",
                                             segments=80, reorder=0.3,
                                             jitter_ms=8, seed=5))
        assert result.delivered_ok is True

    def test_duplication_does_not_corrupt_the_stream(self) -> None:
        result = run_transfer(TransferConfig(protocol="go-back-n", segments=80,
                                             duplicate=0.2, seed=5))
        assert result.delivered_ok is True

    def test_unknown_protocol_rejected(self) -> None:
        with pytest.raises(ValueError, match="unknown protocol"):
            run_transfer(TransferConfig(protocol="tcp-vegas"))


class TestReproducibility:
    def test_same_seed_produces_identical_trace(self) -> None:
        """Required for the demo: the graph must be the same every run."""
        config = TransferConfig(protocol="go-back-n", segments=120, loss=0.1,
                                seed=42)
        assert run_transfer(config).trace == run_transfer(config).trace

    def test_different_seed_produces_a_different_trace(self) -> None:
        a = run_transfer(TransferConfig(protocol="go-back-n", segments=120,
                                        loss=0.1, seed=42))
        b = run_transfer(TransferConfig(protocol="go-back-n", segments=120,
                                        loss=0.1, seed=43))
        assert a.trace != b.trace


class TestCongestionInTransfer:
    def _lossy_run(self):
        return run_transfer(TransferConfig(
            protocol="go-back-n", segments=400, window=64, loss=0.02,
            delay_ms=25, bandwidth_bps=8_000_000, seed=5,
        ))

    def test_produces_both_loss_signals(self) -> None:
        result = self._lossy_run()
        kinds = {event.kind for event in result.congestion_events}
        assert "fast-retransmit" in kinds
        assert "timeout" in kinds

    def test_timeout_collapses_and_fast_retransmit_does_not(self) -> None:
        result = self._lossy_run()
        for event in result.congestion_events:
            if event.kind == "timeout":
                assert event.cwnd == pytest.approx(MSS)
            if event.kind == "fast-retransmit":
                assert event.cwnd > MSS

    def test_cwnd_shows_a_sawtooth(self) -> None:
        """Growth, a drop, then growth again — the AIMD signature."""
        result = self._lossy_run()
        cwnd = [p["cwnd_segments"] for p in result.trace if p["event"] == "ack"]
        assert len(cwnd) > 50
        rises = sum(1 for a, b in zip(cwnd, cwnd[1:]) if b > a)
        falls = sum(1 for a, b in zip(cwnd, cwnd[1:]) if b < a)
        assert rises > 20, "cwnd must grow"
        assert falls > 3, "cwnd must be cut repeatedly"

    def test_slow_start_precedes_congestion_avoidance(self) -> None:
        result = run_transfer(TransferConfig(protocol="go-back-n", segments=300,
                                             window=64, loss=0.0, delay_ms=20,
                                             bandwidth_bps=4_000_000, seed=2))
        states = [event.kind for event in result.congestion_events]
        assert "slow-start-exit" in states

    def test_window_limited_is_reported(self) -> None:
        """A small window on a fat pipe is not congestion, and says so."""
        result = run_transfer(TransferConfig(
            protocol="go-back-n", segments=60, window=2, delay_ms=50,
            bandwidth_bps=100_000_000, congestion_control=False, seed=1,
        ))
        assert "window-limited" in result.bottleneck()

    def test_link_limited_is_reported(self) -> None:
        result = run_transfer(TransferConfig(
            protocol="go-back-n", segments=60, window=256, delay_ms=5,
            bandwidth_bps=1_000_000, congestion_control=False, seed=1,
        ))
        assert "link-limited" in result.bottleneck()
