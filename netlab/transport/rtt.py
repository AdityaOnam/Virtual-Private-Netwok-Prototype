"""
netlab.transport.rtt — RTT estimation and retransmission timeout.

Jacobson/Karels (RFC 6298).  The sender cannot know the right timeout in
advance — too short and it retransmits packets that were merely slow, too long
and it sits idle after a real loss — so it measures.

    SRTT   = (1 - alpha) * SRTT   + alpha * sample        alpha = 1/8
    RTTVAR = (1 - beta)  * RTTVAR + beta  * |SRTT - sample|   beta = 1/4
    RTO    = SRTT + 4 * RTTVAR                     clamped to [200ms, 60s]

The 4*RTTVAR term is the interesting part: the timeout tracks not just the
average delay but how *variable* it is.  A steady 100 ms path gets a tight
timeout; a path bouncing between 50 and 500 ms gets a loose one, because on
that path a late packet is normal rather than evidence of loss.

Karn's algorithm
────────────────
When a segment is retransmitted and an ACK arrives, the ACK is ambiguous: it
may be for the original or for the retransmission, and the two have different
elapsed times. Measuring either way corrupts SRTT — and corrupts it in the
dangerous direction, because if the ACK was really for the original the
measured time is far too short, which shortens the RTO, which causes more
spurious retransmissions, which is a feedback loop.

Karn's rule: do not sample RTT from a retransmitted segment at all.  Instead
double the RTO on every timeout (exponential backoff) and only resume sampling
once a segment is acknowledged without having been retransmitted.
"""

from __future__ import annotations

from dataclasses import dataclass, field

ALPHA = 1.0 / 8.0
BETA = 1.0 / 4.0
K = 4.0

MIN_RTO = 0.200    # RFC 6298 §2.4 recommends 1s; 200ms keeps demos brisk
MAX_RTO = 60.0
INITIAL_RTO = 1.0


@dataclass
class RttEstimator:
    """
    Tracks SRTT, RTTVAR and RTO for one connection.

    Every state change is recorded in `history` so the panel can plot the RTO
    envelope against the raw samples — the picture that makes the 4*RTTVAR
    term obvious.
    """

    srtt: float | None = None
    rttvar: float | None = None
    rto: float = INITIAL_RTO
    samples_taken: int = 0
    samples_ignored_karn: int = 0
    backoffs: int = 0
    history: list[dict] = field(default_factory=list)

    def sample(self, measured: float, *, was_retransmitted: bool = False,
               now: float = 0.0) -> bool:
        """
        Feed one RTT measurement.  Returns True if it was used.

        Pass `was_retransmitted=True` for an ACK covering a segment that was
        sent more than once; Karn's algorithm discards it.
        """
        if was_retransmitted:
            self.samples_ignored_karn += 1
            self._record(now, measured, used=False)
            return False

        if measured <= 0:
            return False

        if self.srtt is None:
            # RFC 6298 §2.2 — first measurement seeds the estimator.
            self.srtt = measured
            self.rttvar = measured / 2.0
        else:
            self.rttvar = (1 - BETA) * self.rttvar + BETA * abs(self.srtt - measured)
            self.srtt = (1 - ALPHA) * self.srtt + ALPHA * measured

        self.rto = self._clamp(self.srtt + K * self.rttvar)
        self.samples_taken += 1
        self._record(now, measured, used=True)
        return True

    def back_off(self, now: float = 0.0) -> float:
        """
        Double the RTO after a timeout.

        This is the only thing that moves the timeout while segments are being
        retransmitted, since Karn forbids sampling during that period.
        """
        self.rto = self._clamp(self.rto * 2.0)
        self.backoffs += 1
        self._record(now, None, used=False)
        return self.rto

    def reset_backoff(self) -> None:
        """Recompute RTO from the estimators after a clean ACK."""
        if self.srtt is not None and self.rttvar is not None:
            self.rto = self._clamp(self.srtt + K * self.rttvar)

    @staticmethod
    def _clamp(value: float) -> float:
        return max(MIN_RTO, min(MAX_RTO, value))

    def _record(self, now: float, measured: float | None, used: bool) -> None:
        self.history.append({
            "t": now,
            "sample": measured,
            "srtt": self.srtt,
            "rttvar": self.rttvar,
            "rto": self.rto,
            "used": used,
        })

    def __repr__(self) -> str:
        srtt = f"{self.srtt * 1000:.1f}ms" if self.srtt else "—"
        return f"RttEstimator(srtt={srtt}, rto={self.rto * 1000:.0f}ms)"
