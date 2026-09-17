"""
netlab.transport.congestion — TCP Reno congestion control.

Flow control and congestion control are different problems that both limit the
sender.  Flow control protects the *receiver* (it advertises a window saying
how much buffer it has).  Congestion control protects the *network*, which
advertises nothing at all — so the sender has to infer capacity from the only
signal it gets: whether packets arrive.

    send window = min(cwnd, receiver window)

The state machine (RFC 5681)
─────────────────────────────

                    cwnd < ssthresh
    ┌──────────────────────────────────────────┐
    │              SLOW START                  │
    │   cwnd += 1 MSS per ACK  → doubles/RTT   │
    └──────────────────────────────────────────┘
                    │ cwnd >= ssthresh
                    ▼
    ┌──────────────────────────────────────────┐
    │          CONGESTION AVOIDANCE            │
    │   cwnd += MSS*MSS/cwnd per ACK  → +1/RTT │
    └──────────────────────────────────────────┘
          │                          │
          │ 3 duplicate ACKs         │ timeout
          ▼                          ▼
    ┌──────────────┐          ssthresh = cwnd/2
    │ FAST RECOVERY│          cwnd     = 1 MSS
    │ ssthresh=cwnd/2         → SLOW START
    │ cwnd = ssthresh + 3     (the drastic response: a timeout means
    │ +1 MSS per dup ACK       the sender learned nothing for a whole
    └──────────────┘           RTO, so it restarts from scratch)
          │ new ACK
          ▼  cwnd = ssthresh  → CONGESTION AVOIDANCE

Why "slow start" is not slow
────────────────────────────
It is the fastest phase — cwnd doubles every RTT.  The name is historical: it
is slow compared to the original TCP, which simply blasted the receiver's
whole advertised window on the first RTT and collapsed the early internet.

Why the two loss signals differ so much
───────────────────────────────────────
Three duplicate ACKs mean packets are still arriving — the path works, one
segment was lost. Halving cwnd is proportionate. A timeout means nothing has
arrived for a whole RTO: the sender has no idea what the path looks like any
more, so it drops to one segment and re-probes. This asymmetry is the single
most important thing to be able to point at on the graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

MSS = 1460  # bytes; the classic Ethernet-derived maximum segment size


class CongestionState(Enum):
    SLOW_START = "slow start"
    CONGESTION_AVOIDANCE = "congestion avoidance"
    FAST_RECOVERY = "fast recovery"


@dataclass
class CongestionEvent:
    t: float
    kind: str
    state: str
    cwnd: float
    ssthresh: float
    note: str = ""


@dataclass
class RenoController:
    """
    TCP Reno.

    `cwnd` and `ssthresh` are in bytes; `cwnd_segments` renders them in the
    units the textbook diagrams use.
    """

    cwnd: float = float(MSS)
    ssthresh: float = 64 * 1024.0
    state: CongestionState = CongestionState.SLOW_START
    duplicate_acks: int = 0
    events: list[CongestionEvent] = field(default_factory=list)
    timeouts: int = 0
    fast_retransmits: int = 0

    # ── views ────────────────────────────────────────────────────────────────

    @property
    def cwnd_segments(self) -> float:
        return self.cwnd / MSS

    @property
    def ssthresh_segments(self) -> float:
        return self.ssthresh / MSS

    def window_bytes(self, receiver_window: float | None = None) -> float:
        """Effective send window: congestion and flow control together."""
        if receiver_window is None:
            return self.cwnd
        return min(self.cwnd, receiver_window)

    # ── signals ──────────────────────────────────────────────────────────────

    def on_ack(self, acked_bytes: int = MSS, now: float = 0.0) -> None:
        """A new (non-duplicate) ACK arrived."""
        self.duplicate_acks = 0

        if self.state is CongestionState.FAST_RECOVERY:
            # Recovery is over: deflate the window to what we decided the path
            # can carry and resume the slow linear probe.
            self.cwnd = self.ssthresh
            self.state = CongestionState.CONGESTION_AVOIDANCE
            self._record(now, "exit-fast-recovery",
                         "new ACK ends recovery; cwnd deflates to ssthresh")
            return

        if self.cwnd < self.ssthresh:
            # Slow start: one extra segment per ACK, so cwnd doubles per RTT.
            self.cwnd += MSS
            self.state = CongestionState.SLOW_START
            if self.cwnd >= self.ssthresh:
                self.state = CongestionState.CONGESTION_AVOIDANCE
                self._record(now, "slow-start-exit",
                             "cwnd reached ssthresh; switching to linear growth")
        else:
            # Congestion avoidance: MSS^2/cwnd per ACK sums to ~1 MSS per RTT.
            self.state = CongestionState.CONGESTION_AVOIDANCE
            self.cwnd += (MSS * MSS) / self.cwnd

    def on_duplicate_ack(self, now: float = 0.0) -> bool:
        """
        A duplicate ACK arrived.  Returns True if fast retransmit fires.

        Three duplicates, not one: one or two are the ordinary consequence of
        reordering, and retransmitting on the first would make every reordered
        path look lossy.
        """
        self.duplicate_acks += 1

        if self.state is CongestionState.FAST_RECOVERY:
            # Each duplicate proves another segment left the network.
            self.cwnd += MSS
            return False

        if self.duplicate_acks == 3:
            self.ssthresh = max(self.cwnd / 2.0, 2 * MSS)
            self.cwnd = self.ssthresh + 3 * MSS   # the 3 that already arrived
            self.state = CongestionState.FAST_RECOVERY
            self.fast_retransmits += 1
            self._record(now, "fast-retransmit",
                         "3 duplicate ACKs: one segment lost, path still alive")
            return True

        return False

    def on_timeout(self, now: float = 0.0) -> None:
        """
        The retransmission timer expired.

        Nothing has been heard for an entire RTO, so every assumption about
        the path is stale.  Collapse to one segment and start over.
        """
        self.ssthresh = max(self.cwnd / 2.0, 2 * MSS)
        self.cwnd = float(MSS)
        self.state = CongestionState.SLOW_START
        self.duplicate_acks = 0
        self.timeouts += 1
        self._record(now, "timeout",
                     "no ACK for a whole RTO: cwnd collapses to 1 MSS")

    # ── bookkeeping ──────────────────────────────────────────────────────────

    def _record(self, now: float, kind: str, note: str = "") -> None:
        self.events.append(CongestionEvent(
            t=now, kind=kind, state=self.state.value,
            cwnd=self.cwnd, ssthresh=self.ssthresh, note=note,
        ))

    def snapshot(self, now: float) -> dict:
        return {
            "t": now,
            "cwnd": self.cwnd,
            "cwnd_segments": self.cwnd_segments,
            "ssthresh": self.ssthresh,
            "ssthresh_segments": self.ssthresh_segments,
            "state": self.state.value,
        }

    def __repr__(self) -> str:
        return (
            f"RenoController(cwnd={self.cwnd_segments:.1f} MSS, "
            f"ssthresh={self.ssthresh_segments:.1f} MSS, state={self.state.value})"
        )


def bandwidth_delay_product(bandwidth_bps: float, rtt_seconds: float) -> float:
    """
    BDP in bytes — how much data must be in flight to keep a link busy.

    A sender whose window is below BDP can never fill the pipe no matter how
    little loss there is: it sends a window, then waits an RTT for the ACK.
    That is a *window* limit, not a congestion limit, and the two are
    constantly confused.  The transport panel computes both and says which one
    is actually binding.
    """
    return bandwidth_bps * rtt_seconds / 8.0
