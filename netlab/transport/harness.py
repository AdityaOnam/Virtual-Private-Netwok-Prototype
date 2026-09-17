"""
netlab.transport.harness — runs a transfer and records what happened.

The simulation is event-stepped on a virtual clock, so a transfer that would
take a minute of wall time completes in milliseconds and produces an identical
trace every run.  Reproducibility is not a nicety here: a congestion-control
graph that looks different each time cannot be explained in a viva.

    result = run_transfer(TransferConfig(protocol="go-back-n", loss=0.1, seed=1))
    result.stats.efficiency
    result.trace          # per-event cwnd / rtt / window snapshots
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .arq import PROTOCOLS, Ack, Segment, TransferStats
from .congestion import MSS, RenoController, bandwidth_delay_product
from .impairment import Clock, ImpairedLink

#: Simulation step.  Small enough to resolve RTO expiry cleanly, large enough
#: that a long transfer does not take forever to step through.
TICK = 0.001

#: Guard against a configuration that can never finish (e.g. 100% loss).
MAX_SIM_SECONDS = 600.0


@dataclass
class TransferConfig:
    protocol: str = "go-back-n"
    segments: int = 200
    payload_size: int = MSS
    window: int = 8
    loss: float = 0.0
    delay_ms: float = 20.0
    jitter_ms: float = 0.0
    reorder: float = 0.0
    duplicate: float = 0.0
    bandwidth_bps: float | None = None
    congestion_control: bool = True
    seed: int = 1

    def rtt_seconds(self) -> float:
        """Base round trip: forward delay plus return delay."""
        return 2 * self.delay_ms / 1000.0


@dataclass
class TransferResult:
    config: TransferConfig
    stats: TransferStats
    trace: list[dict]
    congestion_events: list = field(default_factory=list)
    rtt_history: list[dict] = field(default_factory=list)
    delivered_ok: bool = False
    receiver_peak_buffer: int = 0
    timed_out: bool = False

    # ── derived ──────────────────────────────────────────────────────────────

    @property
    def bdp_bytes(self) -> float:
        if not self.config.bandwidth_bps:
            return 0.0
        return bandwidth_delay_product(self.config.bandwidth_bps,
                                       self.config.rtt_seconds())

    @property
    def window_bytes(self) -> float:
        return self.config.window * self.config.payload_size

    def bottleneck(self) -> str:
        """
        Which limit is actually binding.

        A sender whose window is below the bandwidth-delay product can never
        fill the link, however clean it is — and that looks exactly like
        congestion on a throughput graph unless you check.
        """
        if not self.config.bandwidth_bps:
            return "no bandwidth limit configured"
        if self.window_bytes < self.bdp_bytes:
            return (
                f"window-limited: {self.window_bytes:.0f} B window < "
                f"{self.bdp_bytes:.0f} B BDP — the link cannot be filled "
                f"regardless of loss"
            )
        return (
            f"link-limited: {self.window_bytes:.0f} B window >= "
            f"{self.bdp_bytes:.0f} B BDP — the window is not the constraint"
        )

    def summary(self) -> dict:
        return {
            "protocol": self.config.protocol,
            "delivered_ok": self.delivered_ok,
            "elapsed_s": round(self.stats.elapsed, 3),
            "segments_sent": self.stats.segments_sent,
            "retransmitted": self.stats.segments_retransmitted,
            "efficiency": round(self.stats.efficiency, 3),
            "timeouts": self.stats.timeouts,
            "fast_retransmits": self.stats.fast_retransmits,
            "goodput_bps": round(self.stats.goodput_bps),
            "bottleneck": self.bottleneck(),
        }


def run_transfer(config: TransferConfig) -> TransferResult:
    """
    Run one transfer to completion and return its trace.

    Two independent impaired links model the two directions, seeded
    differently so forward loss and ACK loss are not correlated — correlated
    impairments produce artefacts that do not occur on real paths.
    """
    if config.protocol not in PROTOCOLS:
        raise ValueError(
            f"unknown protocol {config.protocol!r}; "
            f"expected one of {sorted(PROTOCOLS)}"
        )

    sender_cls, receiver_cls = PROTOCOLS[config.protocol]
    clock = Clock()

    forward = ImpairedLink(
        clock, loss=config.loss, delay_ms=config.delay_ms,
        jitter_ms=config.jitter_ms, reorder=config.reorder,
        duplicate=config.duplicate, bandwidth_bps=config.bandwidth_bps,
        seed=config.seed,
    )
    reverse = ImpairedLink(
        clock, loss=config.loss, delay_ms=config.delay_ms,
        jitter_ms=config.jitter_ms, seed=config.seed + 9973,
    )

    payloads = [
        bytes([(i + j) % 256 for j in range(config.payload_size)])
        for i in range(config.segments)
    ]

    congestion = (RenoController()
                  if config.congestion_control and config.protocol != "stop-and-wait"
                  else None)
    sender = sender_cls(payloads, forward, clock, window=config.window,
                        congestion=congestion)
    receiver = receiver_cls()

    timed_out = False
    while not sender.is_done():
        now = clock.now
        sender.fill_window(now)

        for raw in forward.deliver(now):
            ack = receiver.on_segment(Segment.decode(raw))
            reverse.send(ack.encode(), now)

        for raw in reverse.deliver(now):
            if Ack.is_ack(raw):
                sender.on_ack(Ack.decode(raw), now)

        sender.check_timeouts(now)
        clock.advance(TICK)

        if clock.now > MAX_SIM_SECONDS:
            timed_out = True
            break

    sender.stats.elapsed = clock.now
    sender.stats.segments_delivered = len(receiver.delivered)
    sender.stats.bytes_delivered = sum(len(p) for p in receiver.delivered)
    if congestion is not None:
        sender.stats.fast_retransmits = congestion.fast_retransmits

    return TransferResult(
        config=config,
        stats=sender.stats,
        trace=sender.trace,
        congestion_events=congestion.events if congestion else [],
        rtt_history=sender.rtt.history,
        delivered_ok=receiver.delivered == payloads,
        receiver_peak_buffer=getattr(receiver, "buffered_peak", 0),
        timed_out=timed_out,
    )


def compare_protocols(**overrides) -> dict[str, TransferResult]:
    """Run all three protocols under identical conditions."""
    return {
        name: run_transfer(TransferConfig(protocol=name, **overrides))
        for name in PROTOCOLS
    }
