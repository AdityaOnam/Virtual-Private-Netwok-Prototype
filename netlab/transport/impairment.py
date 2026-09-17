"""
netlab.transport.impairment — a deliberately bad link.

Every result in this module has to be reproducible in a viva, which means the
link cannot depend on the real internet.  ImpairedLink sits between a sender
and a receiver and applies loss, delay, jitter, reordering, duplication and a
bandwidth cap — all driven by a seeded PRNG, so the same seed produces the
same trace every run.

Virtual time
────────────
The link runs on an injected clock rather than time.time().  Tests advance the
clock instantly, so a 60-second transfer simulates in milliseconds and never
flakes on a loaded machine.  The GUI passes a real clock.

    link = ImpairedLink(clock, loss=0.1, delay_ms=20, seed=42)
    link.send(packet, now)        # may drop, may delay, may duplicate
    for pkt in link.deliver(now): # whatever is due by `now`
        ...

Bandwidth is a token bucket: each packet needs len(packet) tokens, tokens
refill at `bandwidth_bps / 8` per second, and a packet that cannot be paid for
waits.  That produces real queueing delay under load, which is what makes the
congestion-control graphs interesting — without a bottleneck there is nothing
for congestion control to discover.
"""

from __future__ import annotations

import heapq
import random
from dataclasses import dataclass, field
from typing import Iterator


class Clock:
    """
    Virtual clock.  `advance` moves time forward instantly.

    Injectable so tests never sleep: the difference between a suite that takes
    90 seconds and one that takes 90 milliseconds.
    """

    __slots__ = ("now",)

    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def advance(self, seconds: float) -> float:
        self.now += seconds
        return self.now


@dataclass(order=True)
class _InFlight:
    due: float
    sequence: int
    payload: bytes = field(compare=False)


@dataclass
class LinkStats:
    sent: int = 0
    delivered: int = 0
    dropped: int = 0
    duplicated: int = 0
    reordered: int = 0
    bytes_sent: int = 0

    @property
    def loss_rate(self) -> float:
        return self.dropped / self.sent if self.sent else 0.0


class ImpairedLink:
    """
    A one-way link with configurable impairments.

    Parameters
    ----------
    clock : Clock
        Time source; the link never reads the wall clock itself.
    loss : float
        Probability in [0, 1] that a packet is discarded outright.
    delay_ms : float
        Base one-way delay.  RTT is twice this when two links are paired.
    jitter_ms : float
        Uniform +/- jitter added to the base delay.  Large jitter relative to
        delay is what produces reordering.
    reorder : float
        Probability a packet is given a *negative* extra delay, jumping ahead
        of one already queued.
    duplicate : float
        Probability a packet is delivered twice — the case a naive replay
        filter gets wrong.
    bandwidth_bps : float | None
        Token-bucket rate limit.  None means unlimited.
    seed : int
        PRNG seed.  Same seed, same trace, every time.
    """

    def __init__(self, clock: Clock, *, loss: float = 0.0, delay_ms: float = 0.0,
                 jitter_ms: float = 0.0, reorder: float = 0.0,
                 duplicate: float = 0.0, bandwidth_bps: float | None = None,
                 seed: int = 0) -> None:
        for name, value in (("loss", loss), ("reorder", reorder),
                            ("duplicate", duplicate)):
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be in [0, 1], got {value}")

        self.clock = clock
        self.loss = loss
        self.delay = delay_ms / 1000.0
        self.jitter = jitter_ms / 1000.0
        self.reorder = reorder
        self.duplicate = duplicate
        self.bandwidth_bps = bandwidth_bps
        self._random = random.Random(seed)
        self._queue: list[_InFlight] = []
        self._sequence = 0
        self._bucket_tokens = 0.0
        self._bucket_updated = clock.now
        self._last_due = 0.0
        self.stats = LinkStats()

    # ── bandwidth ────────────────────────────────────────────────────────────

    def _serialisation_delay(self, size: int, now: float) -> float:
        """
        Time until the link can afford to send *size* bytes.

        This is where queueing delay comes from: offer more than the link can
        carry and packets wait, RTT climbs, and congestion control has
        something real to react to.
        """
        if self.bandwidth_bps is None:
            return 0.0
        rate = self.bandwidth_bps / 8.0
        self._bucket_tokens = min(
            rate, self._bucket_tokens + (now - self._bucket_updated) * rate
        )
        self._bucket_updated = now
        if self._bucket_tokens >= size:
            self._bucket_tokens -= size
            return 0.0
        deficit = size - self._bucket_tokens
        self._bucket_tokens = 0.0
        return deficit / rate

    # ── send / deliver ───────────────────────────────────────────────────────

    def send(self, payload: bytes, now: float | None = None) -> bool:
        """
        Offer a packet to the link.  Returns False if it was dropped.

        A dropped packet is silently gone — no error, no notification.  That
        is the whole problem ARQ exists to solve.
        """
        now = self.clock.now if now is None else now
        self.stats.sent += 1
        self.stats.bytes_sent += len(payload)

        if self._random.random() < self.loss:
            self.stats.dropped += 1
            return False

        queue_delay = self._serialisation_delay(len(payload), now)
        due = now + self.delay + queue_delay
        if self.jitter:
            due += self._random.uniform(-self.jitter, self.jitter)
        if self._random.random() < self.reorder:
            due -= self.delay * 0.5
            self.stats.reordered += 1
        due = max(due, now)

        self._push(due, payload)

        if self._random.random() < self.duplicate:
            self.stats.duplicated += 1
            self._push(due + 0.001, payload)

        return True

    def _push(self, due: float, payload: bytes) -> None:
        heapq.heappush(self._queue, _InFlight(due, self._sequence, payload))
        self._sequence += 1

    def deliver(self, now: float | None = None) -> Iterator[bytes]:
        """Yield every packet whose delivery time has arrived."""
        now = self.clock.now if now is None else now
        while self._queue and self._queue[0].due <= now:
            item = heapq.heappop(self._queue)
            self.stats.delivered += 1
            yield item.payload

    def next_due(self) -> float | None:
        """When the next packet is due, or None if the link is idle."""
        return self._queue[0].due if self._queue else None

    def in_flight(self) -> int:
        return len(self._queue)

    def __repr__(self) -> str:
        return (
            f"ImpairedLink(loss={self.loss}, delay={self.delay * 1000:.0f}ms, "
            f"in_flight={len(self._queue)}, {self.stats})"
        )
