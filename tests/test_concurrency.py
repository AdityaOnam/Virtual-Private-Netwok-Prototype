"""
tests/test_concurrency.py — Phase 4: races, bounded buffers, deadlock, pools.

The race tests deliberately run the *broken* code and assert that it breaks.
A test suite that only exercises the correct path would pass just as happily
against an implementation with no locks at all.
"""

from __future__ import annotations

import threading
import time

import pytest

from oslab.concurrency.deadlock import (
    WaitForGraph,
    run_deadlock_demo,
    run_ordered_demo,
    run_timeout_recovery_demo,
)
from oslab.concurrency.pool import (
    InstrumentedPool,
    amdahl_speedup,
    compare_workload_scaling,
    estimate_serial_fraction,
    io_bound_task,
    measure_scaling,
)
from oslab.concurrency.ring import BoundedRing, SharedCounter


# ─────────────────────────────────────────────────────────────────────────────
# The race
# ─────────────────────────────────────────────────────────────────────────────

class TestSharedCounter:
    def test_safe_counter_is_always_exact(self) -> None:
        for _ in range(5):
            result = SharedCounter(safe=True).run_contended(8, 20_000)
            assert result["correct"] is True
            assert result["lost"] == 0

    def test_unsafe_counter_loses_updates(self) -> None:
        """
        Run the broken version ten times and require it to break most of them.

        A race that never manifests demonstrates nothing, so this asserts the
        failure rather than tolerating it.
        """
        losses = [
            SharedCounter(safe=False).run_contended(8, 20_000)["lost"]
            for _ in range(10)
        ]
        broken = sum(1 for lost in losses if lost > 0)
        assert broken >= 8, (
            f"expected the unsafe counter to lose updates in at least 8/10 runs, "
            f"got {broken}. Losses: {losses}"
        )

    def test_default_switch_interval_often_hides_the_race(self) -> None:
        """
        The same broken code usually looks correct at CPython's default 5 ms
        switch interval. This is why races survive testing and surface in
        production: the bug is constant, the exposure is not.
        """
        hidden = sum(
            1 for _ in range(5)
            if SharedCounter(safe=False)
            .run_contended(4, 20_000, switch_interval=None)["lost"] == 0
        )
        assert hidden >= 3, (
            "at the default switch interval the race should usually hide; "
            f"it only hid {hidden}/5 times"
        )

    def test_lost_updates_never_exceed_expected(self) -> None:
        result = SharedCounter(safe=False).run_contended(4, 10_000)
        assert 0 <= result["actual"] <= result["expected"]


# ─────────────────────────────────────────────────────────────────────────────
# Bounded buffer
# ─────────────────────────────────────────────────────────────────────────────

class TestBoundedRing:
    def test_fifo_order(self) -> None:
        ring = BoundedRing(capacity=8)
        for i in range(5):
            ring.put(i)
        assert [ring.get() for _ in range(5)] == [0, 1, 2, 3, 4]

    def test_wraps_around(self) -> None:
        ring = BoundedRing(capacity=4)
        for i in range(4):
            ring.put(i)
        assert ring.get() == 0
        assert ring.get() == 1
        ring.put(98)
        ring.put(99)
        assert [ring.get() for _ in range(4)] == [2, 3, 98, 99]

    def test_producer_blocks_when_full(self) -> None:
        ring = BoundedRing(capacity=2)
        ring.put("a")
        ring.put("b")
        assert ring.is_full is True
        assert ring.put("c", timeout=0.05) is False
        assert ring.stats.producer_blocks == 1

    def test_consumer_blocks_when_empty(self) -> None:
        ring = BoundedRing(capacity=2)
        assert ring.get(timeout=0.05) is None
        assert ring.stats.consumer_blocks == 1

    def test_producer_resumes_when_space_appears(self) -> None:
        ring = BoundedRing(capacity=1)
        ring.put("first")

        def consume_later() -> None:
            time.sleep(0.05)
            ring.get()

        threading.Thread(target=consume_later, daemon=True).start()
        assert ring.put("second", timeout=2.0) is True

    def test_no_items_lost_under_contention(self) -> None:
        """4 producers, 4 consumers, 10 000 items, nothing lost or duplicated."""
        ring = BoundedRing(capacity=32)
        total = 10_000
        produced = list(range(total))
        consumed: list[int] = []
        consumed_lock = threading.Lock()
        counter = iter(produced)
        counter_lock = threading.Lock()

        def produce() -> None:
            while True:
                with counter_lock:
                    item = next(counter, None)
                if item is None:
                    return
                ring.put(item)

        def consume() -> None:
            while True:
                item = ring.get(timeout=0.5)
                if item is None:
                    return
                with consumed_lock:
                    consumed.append(item)

        producers = [threading.Thread(target=produce) for _ in range(4)]
        consumers = [threading.Thread(target=consume) for _ in range(4)]
        for thread in producers + consumers:
            thread.start()
        for thread in producers:
            thread.join(timeout=30)
        for thread in consumers:
            thread.join(timeout=30)

        assert sorted(consumed) == produced, (
            f"expected {total} unique items, got {len(consumed)} "
            f"({len(set(consumed))} unique)"
        )

    def test_close_releases_waiters(self) -> None:
        ring = BoundedRing(capacity=1)
        released = threading.Event()

        def wait_forever() -> None:
            ring.get(timeout=5)
            released.set()

        threading.Thread(target=wait_forever, daemon=True).start()
        time.sleep(0.05)
        ring.close()
        assert released.wait(2.0) is True

    def test_unsafe_ring_drops_instead_of_blocking(self) -> None:
        ring = BoundedRing(capacity=2, safe=False)
        assert ring.put(1) is True
        assert ring.put(2) is True
        assert ring.put(3) is False
        assert ring.stats.dropped == 1

    def test_capacity_validated(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            BoundedRing(capacity=0)


# ─────────────────────────────────────────────────────────────────────────────
# Deadlock
# ─────────────────────────────────────────────────────────────────────────────

class TestWaitForGraph:
    def test_detects_a_two_node_cycle(self) -> None:
        graph = WaitForGraph()
        graph.acquired("A", "L1")
        graph.acquired("B", "L2")
        graph.waiting("A", "L2")
        graph.waiting("B", "L1")
        assert sorted(graph.detect_cycle()) == ["A", "B"]

    def test_no_cycle_when_nobody_waits(self) -> None:
        graph = WaitForGraph()
        graph.acquired("A", "L1")
        graph.acquired("B", "L2")
        assert graph.detect_cycle() == []

    def test_no_cycle_for_a_simple_chain(self) -> None:
        """A waits for B's lock, but B waits for nothing: no cycle."""
        graph = WaitForGraph()
        graph.acquired("B", "L2")
        graph.waiting("A", "L2")
        assert graph.detect_cycle() == []

    def test_detects_a_three_node_cycle(self) -> None:
        graph = WaitForGraph()
        for thread, held, wanted in (("A", "L1", "L2"),
                                     ("B", "L2", "L3"),
                                     ("C", "L3", "L1")):
            graph.acquired(thread, held)
            graph.waiting(thread, wanted)
        assert sorted(graph.detect_cycle()) == ["A", "B", "C"]

    def test_release_clears_the_cycle(self) -> None:
        graph = WaitForGraph()
        graph.acquired("A", "L1")
        graph.acquired("B", "L2")
        graph.waiting("A", "L2")
        graph.waiting("B", "L1")
        assert graph.detect_cycle()
        graph.released("B", "L2")
        assert graph.detect_cycle() == []


class TestDeadlockDemos:
    def test_opposite_order_deadlocks_reliably(self) -> None:
        """Must deadlock every time, or it is not a demonstration."""
        results = [run_deadlock_demo() for _ in range(3)]
        assert all(r.deadlocked for r in results)
        for result in results:
            assert sorted(result.cycle) == ["A", "B"]
            assert result.completed == [], "neither thread should finish"

    def test_graph_shows_the_expected_shape(self) -> None:
        result = run_deadlock_demo()
        assert result.graph["holds"] == {"L1": "A", "L2": "B"}
        assert result.graph["waits"] == {"A": "L2", "B": "L1"}

    def test_consistent_order_prevents_deadlock(self) -> None:
        """Breaking Coffman condition 4 makes the cycle impossible."""
        result = run_ordered_demo()
        assert result.deadlocked is False
        assert sorted(result.completed) == ["A", "B"]

    def test_timeout_recovery_completes_both_threads(self) -> None:
        """Breaking condition 2 after the fact: back out and retry."""
        result = run_timeout_recovery_demo()
        assert result.deadlocked is False
        assert sorted(result.completed) == ["A", "B"]
        assert result.recovered is True, "at least one thread should have backed off"


# ─────────────────────────────────────────────────────────────────────────────
# Thread pool
# ─────────────────────────────────────────────────────────────────────────────

class TestInstrumentedPool:
    def test_runs_every_task(self) -> None:
        with InstrumentedPool(workers=4) as pool:
            for i in range(20):
                pool.submit(lambda x=i: x * 2, name=f"t{i}")
            results = pool.drain()
        assert sorted(results.values()) == [i * 2 for i in range(20)]

    def test_records_timing_for_each_task(self) -> None:
        # 60 ms per task: Windows' time.monotonic has ~15.6 ms granularity, so
        # a 10 ms task can start and finish inside one tick and measure as
        # exactly zero. That is a property of the clock, not of the pool.
        with InstrumentedPool(workers=2) as pool:
            for _ in range(6):
                pool.submit(io_bound_task, 0.06)
            pool.drain()
            records = pool.records()
        assert len(records) == 6
        for record in records:
            assert record.started is not None
            assert record.finished is not None
            assert record.service_time > 0
            assert record.worker in (0, 1)

    def test_errors_are_captured_not_raised(self) -> None:
        def explode() -> None:
            raise ValueError("boom")

        with InstrumentedPool(workers=2) as pool:
            pool.submit(explode)
            pool.submit(lambda: 42)
            results = pool.drain()
            metrics = pool.metrics()
        assert metrics["errors"] == 1
        assert 42 in results.values()

    def test_more_workers_spread_the_work(self) -> None:
        with InstrumentedPool(workers=4) as pool:
            for _ in range(16):
                pool.submit(io_bound_task, 0.02)
            pool.drain()
            workers_used = {r.worker for r in pool.records()}
        assert len(workers_used) >= 2

    def test_worker_count_validated(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            InstrumentedPool(workers=0)


class TestAmdahl:
    def test_perfectly_parallel_scales_linearly(self) -> None:
        assert amdahl_speedup(0.0, 8) == pytest.approx(8.0)

    def test_fully_serial_never_scales(self) -> None:
        assert amdahl_speedup(1.0, 64) == pytest.approx(1.0)

    def test_known_value(self) -> None:
        # 5% serial, 8 workers → 1 / (0.05 + 0.95/8) ≈ 5.93
        assert amdahl_speedup(0.05, 8) == pytest.approx(5.93, abs=0.01)

    def test_serial_fraction_is_bounded(self) -> None:
        assert 0.0 <= estimate_serial_fraction(1.0, 0.5, 2) <= 1.0
        assert estimate_serial_fraction(1.0, 1.0, 2) == pytest.approx(1.0)

    def test_scaling_uses_measured_times(self) -> None:
        result = measure_scaling(lambda: io_bound_task(0.01), count=8,
                                 worker_counts=(1, 2))
        assert result["measured_not_simulated"] is True
        assert result["times"][1] > 0 and result["times"][2] > 0
        assert result["speedups"][1] == pytest.approx(1.0)


class TestGilBehaviour:
    """
    The GIL, measured rather than asserted.

    This is the answer to "why does thread_count help the latency scan but not
    encryption": threads help exactly when the work waits.
    """

    def test_io_bound_work_scales_but_cpu_bound_does_not(self) -> None:
        result = compare_workload_scaling(count=8, worker_counts=(1, 4))
        io_speedup = result["io_bound"]["speedups"][4]
        cpu_speedup = result["cpu_bound"]["speedups"][4]

        assert io_speedup > 2.5, (
            f"I/O-bound work should scale with workers, got {io_speedup:.2f}x"
        )
        assert cpu_speedup < 1.6, (
            f"CPU-bound Python cannot scale past the GIL, got {cpu_speedup:.2f}x"
        )
        assert io_speedup > cpu_speedup
