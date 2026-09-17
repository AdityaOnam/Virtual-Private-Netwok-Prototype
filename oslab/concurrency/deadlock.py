"""
oslab.concurrency.deadlock — cause one, detect it, recover from it, prevent it.

Coffman's four conditions
─────────────────────────
A deadlock requires all four simultaneously. Break any one and it cannot occur.

  1. Mutual exclusion   a resource is held by at most one thread
  2. Hold and wait      a thread holding one resource waits for another
  3. No preemption      a resource cannot be taken away, only released
  4. Circular wait      a cycle exists in the "waits for" relation

The demo below arranges all four, then the fix removes (4) by imposing a
global order on lock acquisition — the cheapest of the four to break in
practice, and the one real systems actually use.

    Thread A            Thread B
    ────────            ────────
    acquire L1          acquire L2
       │                   │
       │  (both now hold one and want the other)
       ▼                   ▼
    acquire L2 ──✗      acquire L1 ──✗
       waits for B's      waits for A's
       lock               lock

                    L1 ──held by── A
                     ▲              │
                     │           waits for
                  waits for         │
                     │              ▼
                     B ──held by── L2

    The wait-for graph has a cycle, which is exactly what detection looks for.

Why the stagger matters
───────────────────────
Without a deliberate pause between acquiring the first lock and reaching for
the second, thread A usually finishes before B even starts, and the deadlock
does not happen. That is the same reason the race in ring.py hides at the
default switch interval: the bug is real, the window is narrow. A demo that
only deadlocks sometimes teaches nothing, so the window is widened on purpose.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


class WaitForGraph:
    """
    Tracks who holds what and who waits for what, and finds cycles.

    This is how a database or an OS detects deadlock at runtime: maintain the
    graph, and when a thread has waited too long, look for a cycle. If one
    exists, the deadlock is certain — not a guess.
    """

    def __init__(self) -> None:
        self._holds: dict[str, str] = {}          # resource -> owner
        self._waits: dict[str, str] = {}          # thread   -> resource wanted
        self._lock = threading.Lock()

    def acquired(self, thread: str, resource: str) -> None:
        with self._lock:
            self._holds[resource] = thread
            self._waits.pop(thread, None)

    def waiting(self, thread: str, resource: str) -> None:
        with self._lock:
            self._waits[thread] = resource

    def released(self, thread: str, resource: str) -> None:
        with self._lock:
            if self._holds.get(resource) == thread:
                del self._holds[resource]
            self._waits.pop(thread, None)

    def snapshot(self) -> dict:
        with self._lock:
            return {"holds": dict(self._holds), "waits": dict(self._waits)}

    def detect_cycle(self) -> list[str]:
        """
        Return the threads forming a wait-for cycle, or [] if there is none.

        Walk thread → resource it wants → thread holding that resource, and so
        on. Returning to a thread already on the path means a cycle.
        """
        with self._lock:
            holds = dict(self._holds)
            waits = dict(self._waits)

        for start in waits:
            path: list[str] = []
            position: dict[str, int] = {}
            current: str | None = start
            while current is not None:
                # Returning to a thread already on this path is the cycle.
                # Reaching a thread that waits for nothing is not: it will
                # finish and release, so the chain drains. Conflating the two
                # reports deadlock on a perfectly healthy chain, which is
                # worse than not detecting one — a false alarm sends you
                # hunting a bug that does not exist.
                if current in position:
                    return path[position[current]:]
                position[current] = len(path)
                path.append(current)

                resource = waits.get(current)
                if resource is None:
                    break                      # this thread is runnable
                current = holds.get(resource)  # None ⇒ resource is free
        return []


@dataclass
class DeadlockResult:
    deadlocked: bool
    cycle: list[str] = field(default_factory=list)
    graph: dict = field(default_factory=dict)
    elapsed: float = 0.0
    recovered: bool = False
    order: str = ""
    completed: list[str] = field(default_factory=list)


def run_deadlock_demo(stagger: float = 0.05,
                      detect_after: float = 0.5) -> DeadlockResult:
    """
    Two threads, two locks, opposite order. Reliably deadlocks.

    Returns once detection has run. The threads are daemons, so a genuine
    deadlock does not prevent the process exiting; the locks are simply
    abandoned, which is what makes this safe to run from a GUI button.
    """
    graph = WaitForGraph()
    lock_one = threading.Lock()
    lock_two = threading.Lock()
    completed: list[str] = []
    started = threading.Barrier(2)

    def worker(name: str, first: threading.Lock, first_name: str,
               second: threading.Lock, second_name: str) -> None:
        started.wait()
        first.acquire()
        graph.acquired(name, first_name)
        time.sleep(stagger)          # widen the window; see module docstring
        graph.waiting(name, second_name)
        if second.acquire(timeout=10):
            graph.acquired(name, second_name)
            completed.append(name)
            second.release()
        first.release()
        graph.released(name, first_name)

    threads = [
        threading.Thread(target=worker, args=("A", lock_one, "L1", lock_two, "L2"),
                         daemon=True),
        threading.Thread(target=worker, args=("B", lock_two, "L2", lock_one, "L1"),
                         daemon=True),
    ]
    begin = time.monotonic()
    for thread in threads:
        thread.start()

    time.sleep(detect_after)
    cycle = graph.detect_cycle()

    return DeadlockResult(
        deadlocked=bool(cycle),
        cycle=cycle,
        graph=graph.snapshot(),
        elapsed=time.monotonic() - begin,
        order="opposite (A: L1→L2, B: L2→L1)",
        completed=list(completed),
    )


def run_ordered_demo(stagger: float = 0.05) -> DeadlockResult:
    """
    The prevention: both threads take the locks in the same global order.

    This breaks Coffman condition 4 (circular wait). No cycle can form, so no
    detection or recovery machinery is needed at all — which is why lock
    ordering is the standard answer rather than deadlock detection.
    """
    graph = WaitForGraph()
    lock_one = threading.Lock()
    lock_two = threading.Lock()
    completed: list[str] = []
    started = threading.Barrier(2)

    def worker(name: str) -> None:
        started.wait()
        # Both threads: L1 first, always.
        lock_one.acquire()
        graph.acquired(name, "L1")
        time.sleep(stagger)
        graph.waiting(name, "L2")
        lock_two.acquire()
        graph.acquired(name, "L2")
        completed.append(name)
        lock_two.release()
        graph.released(name, "L2")
        lock_one.release()
        graph.released(name, "L1")

    threads = [threading.Thread(target=worker, args=(name,), daemon=True)
               for name in ("A", "B")]
    begin = time.monotonic()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    return DeadlockResult(
        deadlocked=bool(graph.detect_cycle()),
        cycle=graph.detect_cycle(),
        graph=graph.snapshot(),
        elapsed=time.monotonic() - begin,
        order="consistent (both: L1→L2)",
        completed=list(completed),
    )


def run_timeout_recovery_demo(stagger: float = 0.05,
                              timeout: float = 0.3) -> DeadlockResult:
    """
    Recovery rather than prevention: acquire with a timeout, and if it expires,
    release what you hold and retry.

    This breaks condition 2 (hold and wait) after the fact. It works, but it
    costs a wasted attempt and can livelock if both threads keep backing off
    in lockstep — which is why the random jitter below matters and why
    ordering is preferred where it is possible.
    """
    import random

    graph = WaitForGraph()
    lock_one = threading.Lock()
    lock_two = threading.Lock()
    completed: list[str] = []
    victims: list[str] = []
    started = threading.Barrier(2)

    def worker(name: str, first: threading.Lock, first_name: str,
               second: threading.Lock, second_name: str) -> None:
        started.wait()
        for _ in range(10):
            first.acquire()
            graph.acquired(name, first_name)
            time.sleep(stagger)
            graph.waiting(name, second_name)
            if second.acquire(timeout=timeout):
                graph.acquired(name, second_name)
                completed.append(name)
                second.release()
                first.release()
                graph.released(name, first_name)
                return
            # Back out entirely rather than holding and waiting.
            victims.append(name)
            first.release()
            graph.released(name, first_name)
            time.sleep(random.uniform(0.01, 0.05))

    threads = [
        threading.Thread(target=worker, args=("A", lock_one, "L1", lock_two, "L2"),
                         daemon=True),
        threading.Thread(target=worker, args=("B", lock_two, "L2", lock_one, "L1"),
                         daemon=True),
    ]
    begin = time.monotonic()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    return DeadlockResult(
        deadlocked=False,
        cycle=[],
        graph=graph.snapshot(),
        elapsed=time.monotonic() - begin,
        recovered=bool(victims),
        order=f"opposite, with {timeout}s timeout and backoff",
        completed=list(completed),
    )
