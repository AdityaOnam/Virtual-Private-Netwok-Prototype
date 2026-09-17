"""
netlab.transport.arq — Automatic Repeat reQuest: three protocols, one interface.

All three solve the same problem — deliver an ordered byte stream over a link
that loses, delays and reorders — and differ only in how much state they keep
and how much they retransmit.

    Stop-and-Wait    window 1.  Send, wait for ACK, send next.
                     Correct, trivial, and hopeless on a long path: one
                     segment per RTT regardless of bandwidth.

    Go-Back-N        window N, cumulative ACK, ONE timer.
                     Receiver discards anything out of order, so a single loss
                     forces the sender to resend that segment and everything
                     after it. Cheap receiver, expensive recovery.

    Selective Repeat window N, per-segment ACK, per-segment timer.
                     Receiver buffers out-of-order segments, so only the lost
                     one is resent. Expensive receiver, cheap recovery.

The trade is receiver memory against wasted bandwidth, and it is the reason
real TCP started as Go-Back-N and grew SACK — selective acknowledgement — once
memory got cheap and bandwidth-delay products got large.

Sequence-number space
─────────────────────
Selective Repeat needs the window to be at most half the sequence space, or
the receiver cannot distinguish a retransmission of an old segment from a new
one that happens to reuse the number. We sidestep this by using a 64-bit
counter that never wraps in any plausible run, and say so rather than silently
depending on it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from .congestion import MSS, RenoController
from .impairment import Clock, ImpairedLink
from .rtt import RttEstimator


@dataclass
class Segment:
    """One data segment on the wire."""

    seq: int
    payload: bytes
    sent_at: float = 0.0
    retransmitted: bool = False

    def encode(self) -> bytes:
        return self.seq.to_bytes(8, "big") + self.payload

    @staticmethod
    def decode(raw: bytes) -> "Segment":
        return Segment(int.from_bytes(raw[:8], "big"), raw[8:])


@dataclass
class Ack:
    """
    An acknowledgement.

    `cumulative` means "I have everything below this number" (Go-Back-N and
    Stop-and-Wait).  `selective` names one specific segment (Selective
    Repeat).  Real TCP sends a cumulative ACK and optionally attaches
    selective blocks, which is why it can interoperate with receivers that
    understand neither.
    """

    ack: int
    selective: bool = False

    def encode(self) -> bytes:
        return b"A" + self.ack.to_bytes(8, "big") + (b"S" if self.selective else b"C")

    @staticmethod
    def decode(raw: bytes) -> "Ack":
        return Ack(int.from_bytes(raw[1:9], "big"), raw[9:10] == b"S")

    @staticmethod
    def is_ack(raw: bytes) -> bool:
        return bool(raw) and raw[:1] == b"A"


@dataclass
class TransferStats:
    segments_sent: int = 0
    segments_retransmitted: int = 0
    segments_delivered: int = 0
    acks_sent: int = 0
    duplicate_acks: int = 0
    timeouts: int = 0
    fast_retransmits: int = 0
    bytes_delivered: int = 0
    elapsed: float = 0.0

    @property
    def goodput_bps(self) -> float:
        return (self.bytes_delivered * 8 / self.elapsed) if self.elapsed else 0.0

    @property
    def efficiency(self) -> float:
        """Fraction of transmissions that were not retransmissions."""
        if not self.segments_sent:
            return 0.0
        return 1.0 - self.segments_retransmitted / self.segments_sent


class ArqSender(ABC):
    """
    Common interface for the three senders.

    The harness drives every sender identically:

        sender.fill_window(now)     put whatever the window allows on the link
        sender.on_ack(ack, now)     process an acknowledgement
        sender.check_timeouts(now)  retransmit whatever expired
        sender.is_done()
    """

    def __init__(self, payloads: list[bytes], link: ImpairedLink, clock: Clock,
                 window: int = 8, *, congestion: RenoController | None = None) -> None:
        self.payloads = payloads
        self.link = link
        self.clock = clock
        self.window = window
        self.congestion = congestion
        self.rtt = RttEstimator()
        self.stats = TransferStats()
        self.base = 0          # oldest unacknowledged sequence number
        self.next_seq = 0      # next sequence number to send
        self.trace: list[dict] = []

    # ── window ───────────────────────────────────────────────────────────────

    def effective_window(self) -> int:
        """
        Window in segments.

        With a congestion controller attached, cwnd bounds the advertised
        window — this is `min(cwnd, rwnd)` from the textbook, in segments.
        """
        if self.congestion is None:
            return self.window
        return max(1, int(min(self.window, self.congestion.cwnd / MSS)))

    def is_done(self) -> bool:
        return self.base >= len(self.payloads)

    def _record(self, now: float, event: str, seq: int | None = None) -> None:
        self.trace.append({
            "t": now,
            "event": event,
            "seq": seq,
            "base": self.base,
            "next_seq": self.next_seq,
            "window": self.effective_window(),
            "cwnd_segments": (self.congestion.cwnd_segments
                              if self.congestion else self.effective_window()),
            "ssthresh_segments": (self.congestion.ssthresh_segments
                                  if self.congestion else None),
            "srtt": self.rtt.srtt,
            "rto": self.rtt.rto,
            "in_flight": self.next_seq - self.base,
        })

    def _transmit(self, seq: int, now: float, *, retransmit: bool) -> None:
        segment = Segment(seq, self.payloads[seq], sent_at=now,
                          retransmitted=retransmit)
        self.link.send(segment.encode(), now)
        self.stats.segments_sent += 1
        if retransmit:
            self.stats.segments_retransmitted += 1
        self._record(now, "retransmit" if retransmit else "send", seq)

    @abstractmethod
    def fill_window(self, now: float) -> None: ...

    @abstractmethod
    def on_ack(self, ack: Ack, now: float) -> None: ...

    @abstractmethod
    def check_timeouts(self, now: float) -> None: ...


# ─────────────────────────────────────────────────────────────────────────────
# Stop-and-Wait
# ─────────────────────────────────────────────────────────────────────────────

class StopAndWait(ArqSender):
    """
    Window of one.

    Throughput is one segment per RTT no matter how fast the link is — on a
    100 Mbit/s path with 50 ms RTT that is roughly 0.2 Mbit/s, a 500x waste.
    That gap is the entire motivation for windowing.
    """

    def __init__(self, *args, **kwargs) -> None:
        kwargs["window"] = 1
        kwargs.pop("congestion", None)
        super().__init__(*args, **kwargs)
        self._sent_at: float | None = None
        self._was_retransmitted = False

    def fill_window(self, now: float) -> None:
        if self.next_seq > self.base or self.is_done():
            return
        self._transmit(self.base, now, retransmit=False)
        self.next_seq = self.base + 1
        self._sent_at = now
        self._was_retransmitted = False

    def on_ack(self, ack: Ack, now: float) -> None:
        if ack.ack <= self.base:
            self.stats.duplicate_acks += 1
            return
        if self._sent_at is not None:
            self.rtt.sample(now - self._sent_at,
                            was_retransmitted=self._was_retransmitted, now=now)
            self.rtt.reset_backoff()
        self.base = ack.ack
        self.next_seq = self.base
        self._sent_at = None
        self._record(now, "ack", ack.ack)

    def check_timeouts(self, now: float) -> None:
        if self._sent_at is None or self.is_done():
            return
        if now - self._sent_at >= self.rtt.rto:
            self.stats.timeouts += 1
            self.rtt.back_off(now)
            self._transmit(self.base, now, retransmit=True)
            self._sent_at = now
            self._was_retransmitted = True


# ─────────────────────────────────────────────────────────────────────────────
# Go-Back-N
# ─────────────────────────────────────────────────────────────────────────────

class GoBackN(ArqSender):
    """
    Cumulative ACK, one timer for the oldest unacknowledged segment.

    On timeout the sender resends `base` and everything already sent after it,
    because the receiver discarded all of it. That is the "go back N".
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._sent_at: dict[int, float] = {}
        self._retransmitted: set[int] = set()

    def fill_window(self, now: float) -> None:
        limit = min(self.base + self.effective_window(), len(self.payloads))
        while self.next_seq < limit:
            self._transmit(self.next_seq, now, retransmit=False)
            self._sent_at[self.next_seq] = now
            self.next_seq += 1

    def on_ack(self, ack: Ack, now: float) -> None:
        if ack.ack <= self.base:
            self.stats.duplicate_acks += 1
            if self.congestion is not None and self.congestion.on_duplicate_ack(now):
                self.stats.fast_retransmits += 1
                self._transmit(self.base, now, retransmit=True)
                self._retransmitted.add(self.base)
                self._sent_at[self.base] = now
            return

        newly_acked = ack.ack - self.base
        sent_at = self._sent_at.get(ack.ack - 1)
        if sent_at is not None:
            self.rtt.sample(now - sent_at,
                            was_retransmitted=(ack.ack - 1) in self._retransmitted,
                            now=now)
            self.rtt.reset_backoff()

        for seq in range(self.base, ack.ack):
            self._sent_at.pop(seq, None)
            self._retransmitted.discard(seq)
        self.base = ack.ack

        if self.congestion is not None:
            for _ in range(newly_acked):
                self.congestion.on_ack(MSS, now)
        self._record(now, "ack", ack.ack)

    def check_timeouts(self, now: float) -> None:
        if self.is_done() or self.base not in self._sent_at:
            return
        if now - self._sent_at[self.base] < self.rtt.rto:
            return

        self.stats.timeouts += 1
        self.rtt.back_off(now)
        if self.congestion is not None:
            self.congestion.on_timeout(now)

        # Go back N: everything from base onward is resent.
        for seq in range(self.base, self.next_seq):
            self._transmit(seq, now, retransmit=True)
            self._sent_at[seq] = now
            self._retransmitted.add(seq)


# ─────────────────────────────────────────────────────────────────────────────
# Selective Repeat
# ─────────────────────────────────────────────────────────────────────────────

class SelectiveRepeat(ArqSender):
    """
    Per-segment ACK and per-segment timer: only the lost segment is resent.

    The cost is bookkeeping at both ends — the receiver must buffer
    out-of-order segments and the sender must track a timer per segment
    instead of one for the whole window.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._sent_at: dict[int, float] = {}
        self._acked: set[int] = set()
        self._retransmitted: set[int] = set()

    def fill_window(self, now: float) -> None:
        limit = min(self.base + self.effective_window(), len(self.payloads))
        while self.next_seq < limit:
            if self.next_seq not in self._acked:
                self._transmit(self.next_seq, now, retransmit=False)
                self._sent_at[self.next_seq] = now
            self.next_seq += 1

    def on_ack(self, ack: Ack, now: float) -> None:
        seq = ack.ack
        if seq in self._acked:
            self.stats.duplicate_acks += 1
            if self.congestion is not None and self.congestion.on_duplicate_ack(now):
                self.stats.fast_retransmits += 1
                self._retransmit_oldest(now)
            return

        self._acked.add(seq)
        sent_at = self._sent_at.pop(seq, None)
        if sent_at is not None:
            self.rtt.sample(now - sent_at,
                            was_retransmitted=seq in self._retransmitted, now=now)
            self.rtt.reset_backoff()
        self._retransmitted.discard(seq)

        if self.congestion is not None:
            self.congestion.on_ack(MSS, now)

        # Slide past every contiguous acknowledged segment at the bottom.
        while self.base in self._acked:
            self.base += 1
        self._record(now, "ack", seq)

    def _retransmit_oldest(self, now: float) -> None:
        for seq in range(self.base, self.next_seq):
            if seq not in self._acked:
                self._transmit(seq, now, retransmit=True)
                self._sent_at[seq] = now
                self._retransmitted.add(seq)
                return

    def check_timeouts(self, now: float) -> None:
        expired = [
            seq for seq, sent in self._sent_at.items()
            if now - sent >= self.rtt.rto and seq not in self._acked
        ]
        if not expired:
            return
        self.stats.timeouts += 1

        # Back off only when a segment that was ALREADY retransmitted expires
        # again.  Selective Repeat runs an independent timer per segment, so a
        # first-time expiry says "this one segment was lost", not "the path is
        # in trouble" — and doubling the shared RTO on every such event makes
        # the protocol progressively deaf, which is what made it slower than
        # Go-Back-N here despite retransmitting less.
        #
        # Exponential backoff is for repeated failure of the same segment,
        # which is the situation Karn's algorithm actually describes.
        repeated = [seq for seq in expired if seq in self._retransmitted]
        if repeated:
            self.rtt.back_off(now)
            if self.congestion is not None:
                self.congestion.on_timeout(now)
        elif self.congestion is not None:
            # A single lost segment on a live path is the same signal fast
            # retransmit responds to: halve, do not collapse.
            self.congestion.on_duplicate_ack(now)
            self.congestion.on_duplicate_ack(now)
            self.congestion.on_duplicate_ack(now)

        for seq in sorted(expired):
            self._transmit(seq, now, retransmit=True)
            self._sent_at[seq] = now
            self._retransmitted.add(seq)


# ─────────────────────────────────────────────────────────────────────────────
# Receivers
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CumulativeReceiver:
    """
    Go-Back-N / Stop-and-Wait receiver.

    Anything out of order is discarded and the last in-order ACK is repeated.
    Those repeats are exactly the duplicate ACKs fast retransmit counts.
    """

    expected: int = 0
    delivered: list[bytes] = field(default_factory=list)
    duplicate_acks_sent: int = 0
    discarded: int = 0

    def on_segment(self, segment: Segment) -> Ack:
        if segment.seq == self.expected:
            self.delivered.append(segment.payload)
            self.expected += 1
        else:
            self.discarded += 1
            self.duplicate_acks_sent += 1
        return Ack(self.expected, selective=False)


@dataclass
class SelectiveReceiver:
    """
    Selective Repeat receiver: buffers out-of-order segments.

    The buffer is what buys the cheaper recovery — and what costs the memory.
    """

    expected: int = 0
    buffer: dict[int, bytes] = field(default_factory=dict)
    delivered: list[bytes] = field(default_factory=list)
    duplicate_acks_sent: int = 0
    buffered_peak: int = 0

    def on_segment(self, segment: Segment) -> Ack:
        if segment.seq < self.expected or segment.seq in self.buffer:
            self.duplicate_acks_sent += 1
            return Ack(segment.seq, selective=True)

        self.buffer[segment.seq] = segment.payload
        self.buffered_peak = max(self.buffered_peak, len(self.buffer))
        while self.expected in self.buffer:
            self.delivered.append(self.buffer.pop(self.expected))
            self.expected += 1
        return Ack(segment.seq, selective=True)


PROTOCOLS = {
    "stop-and-wait": (StopAndWait, CumulativeReceiver),
    "go-back-n": (GoBackN, CumulativeReceiver),
    "selective-repeat": (SelectiveRepeat, SelectiveReceiver),
}
