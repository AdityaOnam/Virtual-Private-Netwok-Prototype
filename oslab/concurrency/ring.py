"""
oslab.concurrency.ring — bounded buffer, with the locks optional.

The classic producer-consumer problem, built so the broken version and the
correct version are the same code with one flag flipped. A race you can only
describe is not a demonstration; a race you can make happen on demand is.

The critical section
────────────────────
`put` and `get` both read a field, compute from it, and write it back:

    self._count = self._count + 1      # three operations, not one

Between the read and the write another thread can run. Python's bytecode makes
this concrete — that line compiles to LOAD_ATTR, then arithmetic, then
STORE_ATTR, and the interpreter can switch threads between any two bytecodes.
Two threads interleaved there both read the same old value and both write the
same new one, so one increment vanishes.

Why the GIL does not save you
─────────────────────────────
A common and wrong belief is that the GIL makes Python threads safe. The GIL
guarantees only that one bytecode runs at a time; it says nothing about
grouping several bytecodes into an atomic unit. `x += 1` is not atomic in
CPython and never has been. The GIL means you will not corrupt the
interpreter's own memory — it does not mean your counter is correct.

Condition variables, not sleeping
──────────────────────────────────
A full buffer must make the producer wait. Polling in a loop with a sleep
burns CPU and adds latency; a condition variable puts the thread on a queue
the OS scheduler ignores until someone signals it.

    with not_full:                       # acquire the lock
        while self._count == capacity:   # while, not if — see below
            not_full.wait()              # release lock, sleep, reacquire

The `while` matters. `wait()` can return without the condition holding: a
spurious wakeup, or another thread that was signalled first and consumed the
space. Re-checking in a loop is the only correct pattern.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any


@dataclass
class RingStats:
    puts: int = 0
    gets: int = 0
    producer_blocks: int = 0
    consumer_blocks: int = 0
    producer_blocked_seconds: float = 0.0
    consumer_blocked_seconds: float = 0.0
    dropped: int = 0

    def as_dict(self) -> dict:
        return {
            "puts": self.puts,
            "gets": self.gets,
            "producer_blocks": self.producer_blocks,
            "consumer_blocks": self.consumer_blocks,
            "producer_blocked_ms": round(self.producer_blocked_seconds * 1000, 1),
            "consumer_blocked_ms": round(self.consumer_blocked_seconds * 1000, 1),
            "dropped": self.dropped,
        }


class BoundedRing:
    """
    Fixed-capacity circular buffer shared between producer and consumer threads.

    Parameters
    ----------
    capacity : int
        Slots in the ring.
    safe : bool
        True  — every access holds the mutex (correct).
        False — no locking at all, so the races are reachable on demand.

    `safe=False` is not a performance option. It exists to make the failure
    visible, and it is never used outside the demo and its tests.
    """

    def __init__(self, capacity: int = 64, *, safe: bool = True) -> None:
        if capacity < 1:
            raise ValueError(f"capacity must be positive, got {capacity}")
        self.capacity = capacity
        self.safe = safe
        self._slots: list[Any] = [None] * capacity
        self._head = 0          # next write position
        self._tail = 0          # next read position
        self._count = 0
        self.stats = RingStats()

        self._lock = threading.Lock()
        self._not_full = threading.Condition(self._lock)
        self._not_empty = threading.Condition(self._lock)
        self._closed = False

    # ── introspection ────────────────────────────────────────────────────────

    def __len__(self) -> int:
        return self._count

    @property
    def is_full(self) -> bool:
        return self._count >= self.capacity

    @property
    def is_empty(self) -> bool:
        return self._count == 0

    def occupancy(self) -> float:
        return self._count / self.capacity

    def close(self) -> None:
        """Wake every waiter so threads can exit."""
        with self._lock:
            self._closed = True
            self._not_full.notify_all()
            self._not_empty.notify_all()

    # ── unsynchronised core ──────────────────────────────────────────────────
    #
    # Deliberately not atomic. Each of these is read-modify-write, which is
    # exactly the window another thread slips through.

    def _unsafe_put(self, item: Any) -> None:
        self._slots[self._head] = item
        self._head = (self._head + 1) % self.capacity
        self._count = self._count + 1
        self.stats.puts = self.stats.puts + 1

    def _unsafe_get(self) -> Any:
        item = self._slots[self._tail]
        self._slots[self._tail] = None
        self._tail = (self._tail + 1) % self.capacity
        self._count = self._count - 1
        self.stats.gets = self.stats.gets + 1
        return item

    # ── public API ───────────────────────────────────────────────────────────

    def put(self, item: Any, timeout: float | None = None) -> bool:
        """
        Add *item*, blocking while the ring is full.

        Returns False if the ring closed or the timeout expired.
        """
        if not self.safe:
            # No lock, no blocking, no correctness. Drops on overflow so the
            # unsafe demo terminates instead of corrupting indices forever.
            if self._count >= self.capacity:
                self.stats.dropped += 1
                return False
            self._unsafe_put(item)
            return True

        import time
        with self._not_full:
            if self.is_full:
                self.stats.producer_blocks += 1
                started = time.monotonic()
                # `while`, not `if`: wait() may return spuriously, and another
                # producer may have taken the slot we were woken for.
                while self.is_full and not self._closed:
                    if not self._not_full.wait(timeout):
                        self.stats.producer_blocked_seconds += \
                            time.monotonic() - started
                        return False
                self.stats.producer_blocked_seconds += time.monotonic() - started
            if self._closed:
                return False
            self._unsafe_put(item)
            self._not_empty.notify()
            return True

    def get(self, timeout: float | None = None) -> Any:
        """
        Remove and return the oldest item, blocking while the ring is empty.

        Returns None if the ring closed or the timeout expired.
        """
        if not self.safe:
            if self._count <= 0:
                return None
            return self._unsafe_get()

        import time
        with self._not_empty:
            if self.is_empty:
                self.stats.consumer_blocks += 1
                started = time.monotonic()
                while self.is_empty and not self._closed:
                    if not self._not_empty.wait(timeout):
                        self.stats.consumer_blocked_seconds += \
                            time.monotonic() - started
                        return None
                self.stats.consumer_blocked_seconds += time.monotonic() - started
            if self.is_empty:
                return None
            item = self._unsafe_get()
            self._not_full.notify()
            return item

    def __repr__(self) -> str:
        mode = "safe" if self.safe else "UNSAFE"
        return f"BoundedRing({self._count}/{self.capacity}, {mode})"


class SharedCounter:
    """
    A counter incremented from many threads — the smallest possible race.

    `increment()` on an unsafe counter loses updates because `+= 1` is three
    bytecodes. The lost count is the demonstration: with N threads each adding
    M, the correct total is N*M and the unsafe total is reliably less.
    """

    def __init__(self, *, safe: bool = True) -> None:
        self.safe = safe
        self.value = 0
        self._lock = threading.Lock()

    @staticmethod
    def _combine(current: int) -> int:
        """
        The 'compute' half of a read-compute-write critical section.

        This is a function call on purpose, and the reason is a real detail of
        CPython rather than a trick.

        A thread switch can only happen where the interpreter checks its
        eval-breaker, and as of 3.12 that is at call boundaries and loop
        back-edges — not between two arbitrary bytecodes. So this:

            current = self.value        # LOAD_ATTR
            self.value = current + 1    # STORE_ATTR

        has no check between the load and the store, and runs effectively
        atomically however hard the scheduler is pushed. That is an artefact of
        one interpreter's implementation, not a guarantee of the language, and
        relying on it is how code becomes mysteriously broken on a different
        Python or under free-threading.

        Putting a call between the read and the write restores the preemption
        point and makes the race observable. It is also the more honest model:
        real critical sections read state, compute something, and write back —
        exactly like Session.encrypt incrementing a counter, or ReplayWindow
        updating its bitmap.
        """
        return current + 1

    def increment(self) -> None:
        if self.safe:
            with self._lock:
                self.value = self._combine(self.value)
        else:
            # Read … compute … write, with a preemption point in the middle.
            current = self.value
            updated = self._combine(current)
            self.value = updated

    def run_contended(self, threads: int, per_thread: int,
                      switch_interval: float | None = 1e-6) -> dict:
        """
        Run the experiment and report what was lost.

        About `switch_interval`
        ───────────────────────
        The race is real but its window is a single bytecode boundary, and
        CPython only considers switching threads every `sys.getswitchinterval()`
        seconds — 5 ms by default. Across 800 000 increments that is only a few
        hundred opportunities to preempt, and almost none of them land in the
        one-bytecode gap between reading the counter and writing it back. Run
        as-is, the unsafe counter usually produces the right answer, which
        teaches precisely the wrong lesson: that the code is fine.

        Dropping the interval to a microsecond makes the interpreter consider
        switching constantly. That does not fabricate the bug — the code is
        equally broken either way — it raises scheduling pressure so the
        existing bug becomes observable, the same way a loaded production
        machine does. This is why races hide in testing and appear under load.

        Pass None to keep the default interval and watch the race stay hidden.
        """
        import sys

        self.value = 0
        original = sys.getswitchinterval()
        if switch_interval is not None:
            sys.setswitchinterval(switch_interval)

        def work() -> None:
            for _ in range(per_thread):
                self.increment()

        try:
            workers = [threading.Thread(target=work) for _ in range(threads)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join()
        finally:
            sys.setswitchinterval(original)

        expected = threads * per_thread
        return {
            "expected": expected,
            "actual": self.value,
            "lost": expected - self.value,
            "safe": self.safe,
            "correct": self.value == expected,
            "switch_interval": switch_interval,
        }
