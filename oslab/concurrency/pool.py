"""
oslab.concurrency.pool — an instrumented thread pool.

Threads are not free: each one costs memory for its stack and costs the
scheduler a context switch to run. A pool creates a fixed number up front and
feeds them from a queue, so the cost is paid once.

What this adds over concurrent.futures is the record: submit time, start time,
end time and worker id for every task, which is what lets the panel draw the
real Gantt chart and measure the real speedup curve instead of asserting one.

Amdahl's law
────────────
Speedup is bounded by the part of the work that cannot be parallelised:

    speedup(n) = 1 / (s + (1 - s)/n)

where s is the serial fraction. With s = 0.05, even infinite workers give at
most 20x. The panel measures the actual speedup at several pool sizes, fits s
from the two-worker point, and plots the prediction against the measurement —
the gap between them is scheduling overhead and contention, which is the part
the formula does not model.

Why this matters here
─────────────────────
`thread_count` in config/settings.json was written by the settings dialog and
read by nothing. It now sets the pool size used for the server-latency scan,
so the setting has an observable effect and the speedup curve is measured on
real work rather than a simulation.
"""

from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class TaskRecord:
    """Timing for one task — the raw material for the Gantt chart."""

    task_id: int
    name: str
    submitted: float
    started: float | None = None
    finished: float | None = None
    worker: int | None = None
    error: str | None = None

    @property
    def wait_time(self) -> float:
        """Time spent queued before a worker picked it up."""
        return (self.started - self.submitted) if self.started else 0.0

    @property
    def service_time(self) -> float:
        """Time spent actually running."""
        if self.started is None or self.finished is None:
            return 0.0
        return self.finished - self.started

    @property
    def turnaround_time(self) -> float:
        """Submit to finish — what the caller actually experiences."""
        if self.finished is None:
            return 0.0
        return self.finished - self.submitted

    def as_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "name": self.name,
            "worker": self.worker,
            "wait_ms": round(self.wait_time * 1000, 2),
            "service_ms": round(self.service_time * 1000, 2),
            "turnaround_ms": round(self.turnaround_time * 1000, 2),
            "error": self.error,
        }


class InstrumentedPool:
    """
    Fixed-size worker pool that records the timing of every task.

    Usage:

        with InstrumentedPool(workers=4) as pool:
            for target in targets:
                pool.submit(probe, target, name=str(target))
            results = pool.drain()
    """

    def __init__(self, workers: int = 4) -> None:
        if workers < 1:
            raise ValueError(f"workers must be positive, got {workers}")
        self.workers = workers
        self._queue: queue.Queue = queue.Queue()
        self._records: dict[int, TaskRecord] = {}
        self._results: dict[int, Any] = {}
        self._lock = threading.Lock()
        self._next_id = 0
        self._threads: list[threading.Thread] = []
        self._running = False
        self.started_at: float | None = None
        self.finished_at: float | None = None

    # ── lifecycle ────────────────────────────────────────────────────────────

    def start(self) -> None:
        self._running = True
        self.started_at = time.monotonic()
        for index in range(self.workers):
            thread = threading.Thread(
                target=self._worker, args=(index,),
                name=f"pool-{index}", daemon=True,
            )
            thread.start()
            self._threads.append(thread)

    def _worker(self, index: int) -> None:
        while self._running:
            try:
                item = self._queue.get(timeout=0.05)
            except queue.Empty:
                continue
            if item is None:
                self._queue.task_done()
                return

            task_id, fn, args, kwargs = item
            with self._lock:
                record = self._records[task_id]
                record.started = time.monotonic()
                record.worker = index
            try:
                result = fn(*args, **kwargs)
                with self._lock:
                    self._results[task_id] = result
            except Exception as exc:
                with self._lock:
                    self._records[task_id].error = f"{type(exc).__name__}: {exc}"
            finally:
                with self._lock:
                    self._records[task_id].finished = time.monotonic()
                self._queue.task_done()

    def submit(self, fn: Callable, *args, name: str = "", **kwargs) -> int:
        """Queue a task and return its id."""
        with self._lock:
            task_id = self._next_id
            self._next_id += 1
            self._records[task_id] = TaskRecord(
                task_id=task_id,
                name=name or getattr(fn, "__name__", "task"),
                submitted=time.monotonic(),
            )
        self._queue.put((task_id, fn, args, kwargs))
        return task_id

    def drain(self, timeout: float | None = None) -> dict[int, Any]:
        """Wait for every queued task, then return results by task id."""
        self._queue.join()
        self.finished_at = time.monotonic()
        with self._lock:
            return dict(self._results)

    def stop(self) -> None:
        self._running = False
        for _ in self._threads:
            self._queue.put(None)
        for thread in self._threads:
            thread.join(timeout=1.0)
        self._threads.clear()

    def __enter__(self) -> "InstrumentedPool":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    # ── metrics ──────────────────────────────────────────────────────────────

    @property
    def elapsed(self) -> float:
        if self.started_at is None:
            return 0.0
        end = self.finished_at or time.monotonic()
        return end - self.started_at

    def records(self) -> list[TaskRecord]:
        with self._lock:
            return sorted(self._records.values(), key=lambda r: r.task_id)

    def metrics(self) -> dict:
        records = [r for r in self.records() if r.finished is not None]
        if not records:
            return {"tasks": 0}
        waits = [r.wait_time for r in records]
        turnarounds = [r.turnaround_time for r in records]
        return {
            "tasks": len(records),
            "workers": self.workers,
            "elapsed_s": round(self.elapsed, 4),
            "avg_wait_ms": round(sum(waits) / len(waits) * 1000, 2),
            "avg_turnaround_ms": round(sum(turnarounds) / len(turnarounds) * 1000, 2),
            "errors": sum(1 for r in records if r.error),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Amdahl measurement
# ─────────────────────────────────────────────────────────────────────────────

def amdahl_speedup(serial_fraction: float, workers: int) -> float:
    """Predicted speedup for a given serial fraction and worker count."""
    if not 0.0 <= serial_fraction <= 1.0:
        raise ValueError(f"serial fraction must be in [0, 1], got {serial_fraction}")
    return 1.0 / (serial_fraction + (1.0 - serial_fraction) / workers)


def estimate_serial_fraction(t1: float, tn: float, n: int) -> float:
    """
    Recover the serial fraction from two measurements (Karp-Flatt).

        s = (1/speedup - 1/n) / (1 - 1/n)

    Measuring it rather than assuming it is what makes the comparison honest:
    an assumed s can be tuned until the prediction matches.
    """
    if n <= 1 or tn <= 0 or t1 <= 0:
        return 0.0
    speedup = t1 / tn
    return max(0.0, min(1.0, (1.0 / speedup - 1.0 / n) / (1.0 - 1.0 / n)))


def measure_scaling(task: Callable, count: int,
                    worker_counts: tuple[int, ...] = (1, 2, 4, 8)) -> dict:
    """
    Run *count* copies of *task* at each pool size and measure the speedup.

    Returns measured times, measured speedups, the serial fraction fitted from
    the two-worker point, and Amdahl's prediction at every size — so the panel
    plots measurement against theory rather than theory alone.
    """
    times: dict[int, float] = {}
    for workers in worker_counts:
        with InstrumentedPool(workers=workers) as pool:
            for index in range(count):
                pool.submit(task, name=f"task-{index}")
            pool.drain()
            times[workers] = pool.elapsed

    baseline = times[worker_counts[0]]
    speedups = {n: baseline / t if t else 0.0 for n, t in times.items()}

    fit_n = worker_counts[1] if len(worker_counts) > 1 else 1
    serial = estimate_serial_fraction(baseline, times[fit_n], fit_n)

    return {
        "times": times,
        "speedups": speedups,
        "serial_fraction": serial,
        "predicted": {n: amdahl_speedup(serial, n) for n in worker_counts},
        "measured_not_simulated": True,
    }


# ─────────────────────────────────────────────────────────────────────────────
# The GIL, measured
# ─────────────────────────────────────────────────────────────────────────────

def cpu_bound_task(iterations: int = 300_000) -> int:
    """Pure Python arithmetic — holds the GIL the entire time."""
    total = 0
    for i in range(iterations):
        total += i * i
    return total


def io_bound_task(seconds: float = 0.05) -> float:
    """
    Blocking sleep — stands in for a network round trip.

    time.sleep releases the GIL, which is the whole reason the server-latency
    scan gets faster with more workers while the arithmetic above does not.
    """
    time.sleep(seconds)
    return seconds


def compare_workload_scaling(
    count: int = 16,
    worker_counts: tuple[int, ...] = (1, 2, 4, 8),
) -> dict:
    """
    Scale the same pool over CPU-bound and I/O-bound work and compare.

    This is the measurement that explains why `thread_count` helps the latency
    scan and would not help, say, encryption:

      CPU-bound   speedup stays near 1.0, and often drops below it. Python
                  bytecode needs the GIL, so only one thread executes at a
                  time and the extra threads add context switches and
                  contention without adding throughput. Amdahl's law is not
                  what is limiting this — the interpreter is.

      I/O-bound   speedup rises nearly linearly. A thread blocked in a socket
                  or a sleep has released the GIL, so the others run. This is
                  the regime the VPN's latency scan lives in.

    The conclusion is not "threads are useless in Python" but "threads help
    exactly when the work waits". For CPU-bound work the answer is processes,
    which have their own interpreter and their own GIL.
    """
    cpu = measure_scaling(cpu_bound_task, count, worker_counts)
    io = measure_scaling(io_bound_task, count, worker_counts)

    best = max(worker_counts)
    return {
        "cpu_bound": cpu,
        "io_bound": io,
        "verdict": {
            "cpu_speedup_at_max_workers": round(cpu["speedups"][best], 2),
            "io_speedup_at_max_workers": round(io["speedups"][best], 2),
            "explanation": (
                "CPU-bound work does not scale because Python bytecode "
                "requires the GIL; I/O-bound work scales because a blocked "
                "thread has released it."
            ),
        },
    }
