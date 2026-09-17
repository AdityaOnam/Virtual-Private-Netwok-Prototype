"""
tests/test_oslab.py — Phases 7 and 8: IPC framing, scheduling, memory, resilience.

All offline, no admin, no network.
"""

from __future__ import annotations

import io
import json
import os
import struct
import threading
import time

import pytest

from oslab.ipc.framing import (
    LENGTH_PREFIX,
    MAX_FRAME,
    FrameBuffer,
    FramingError,
    decode_frame,
    encode_frame,
    read_exactly,
    read_frame,
)
from oslab.memory.bufferpool import (
    BufferPool,
    PoolExhausted,
    compare_allocation_strategies,
    demonstrate_zero_copy,
)
from oslab.resilience.atomicio import atomic_write_json
from oslab.resilience.signals import Journal, TeardownRegistry
from oslab.resilience.singleton import AlreadyRunning, SingleInstance
from oslab.scheduling.algorithms import (
    Job,
    compare_algorithms,
    jobs_from_measurements,
    schedule_fcfs,
    schedule_priority,
    schedule_round_robin,
    schedule_sjf,
)


# ─────────────────────────────────────────────────────────────────────────────
# IPC framing
# ─────────────────────────────────────────────────────────────────────────────

class TestFraming:
    def test_round_trip(self) -> None:
        frame = encode_frame({"cmd": "status", "id": 7})
        assert read_frame(io.BytesIO(frame).read) == {"cmd": "status", "id": 7}

    def test_length_prefix_is_four_big_endian_bytes(self) -> None:
        frame = encode_frame({"a": 1})
        (length,) = struct.unpack("!I", frame[:LENGTH_PREFIX])
        assert length == len(frame) - LENGTH_PREFIX

    def test_partial_reads_reassemble(self) -> None:
        """
        recv() returns *up to* n bytes. A reader that assumes one read is one
        message works in tests and fails under load.
        """
        frame = encode_frame({"cmd": "connect", "server": "frankfurt"})
        remaining = iter([frame[:3], frame[3:7], frame[7:20], frame[20:]])
        buffered = bytearray()

        def dribble(count: int) -> bytes:
            while len(buffered) < count:
                chunk = next(remaining, b"")
                if not chunk:
                    break
                buffered.extend(chunk)
            taken = bytes(buffered[:count])
            del buffered[:count]
            return taken

        assert read_frame(dribble) == {"cmd": "connect", "server": "frankfurt"}

    def test_oversized_frame_rejected_before_allocating(self) -> None:
        """A peer claiming 4 GB must not make us try to allocate it."""
        hostile = struct.pack("!I", 4_000_000_000)
        with pytest.raises(FramingError, match="above the"):
            read_frame(io.BytesIO(hostile + b"x" * 10).read)

    def test_encoding_oversized_payload_rejected(self) -> None:
        with pytest.raises(FramingError, match="exceeds"):
            encode_frame({"blob": "x" * (MAX_FRAME + 1)})

    def test_zero_length_frame_rejected(self) -> None:
        with pytest.raises(FramingError, match="zero-length"):
            read_frame(io.BytesIO(struct.pack("!I", 0)).read)

    def test_malformed_json_rejected(self) -> None:
        body = b"{not json"
        blob = struct.pack("!I", len(body)) + body
        with pytest.raises(FramingError, match="malformed"):
            read_frame(io.BytesIO(blob).read)

    def test_non_object_body_rejected(self) -> None:
        body = b"[1,2,3]"
        blob = struct.pack("!I", len(body)) + body
        with pytest.raises(FramingError, match="must be an object"):
            read_frame(io.BytesIO(blob).read)

    def test_truncated_stream_reports_progress(self) -> None:
        with pytest.raises(FramingError, match="stream closed after"):
            read_exactly(io.BytesIO(b"ab").read, 10)


class TestFrameBuffer:
    def test_multiple_frames_in_one_chunk(self) -> None:
        buffer = FrameBuffer()
        blob = encode_frame({"n": 1}) + encode_frame({"n": 2}) + encode_frame({"n": 3})
        assert buffer.feed(blob) == [{"n": 1}, {"n": 2}, {"n": 3}]

    def test_frame_split_across_chunks(self) -> None:
        buffer = FrameBuffer()
        blob = encode_frame({"cmd": "disconnect"})
        assert buffer.feed(blob[:5]) == []
        assert buffer.pending_bytes() == 5
        assert buffer.feed(blob[5:]) == [{"cmd": "disconnect"}]

    def test_remainder_is_kept_for_next_feed(self) -> None:
        buffer = FrameBuffer()
        first, second = encode_frame({"a": 1}), encode_frame({"b": 2})
        assert buffer.feed(first + second[:4]) == [{"a": 1}]
        assert buffer.feed(second[4:]) == [{"b": 2}]

    def test_oversized_announcement_rejected(self) -> None:
        buffer = FrameBuffer()
        with pytest.raises(FramingError, match="above the"):
            buffer.feed(struct.pack("!I", 4_000_000_000))

    def test_reset_discards_partial(self) -> None:
        buffer = FrameBuffer()
        buffer.feed(encode_frame({"a": 1})[:3])
        buffer.reset()
        assert buffer.pending_bytes() == 0


# ─────────────────────────────────────────────────────────────────────────────
# Scheduling
# ─────────────────────────────────────────────────────────────────────────────

def probe_jobs() -> list[Job]:
    """Durations taken from real server probes."""
    return [
        Job(0, "frankfurt", 0.30),
        Job(1, "mumbai", 0.05),
        Job(2, "newyork", 0.20),
        Job(3, "warp", 0.08),
    ]


class TestScheduling:
    def test_fcfs_runs_in_arrival_order(self) -> None:
        result = schedule_fcfs(probe_jobs())
        assert [job.name for job in result.jobs] == \
               ["frankfurt", "mumbai", "newyork", "warp"]

    def test_fcfs_shows_the_convoy_effect(self) -> None:
        """The long job at the front delays everything behind it."""
        fcfs = schedule_fcfs(probe_jobs()).metrics()
        sjf = schedule_sjf(probe_jobs()).metrics()
        assert fcfs["avg_waiting"] > sjf["avg_waiting"]

    def test_sjf_minimises_average_waiting_time(self) -> None:
        """
        SJF is provably optimal for average waiting time, so nothing else can
        beat it on the same job set.
        """
        jobs = probe_jobs()
        sjf = schedule_sjf(jobs).metrics()["avg_waiting"]
        for scheduler in (schedule_fcfs, schedule_priority):
            assert scheduler(probe_jobs()).metrics()["avg_waiting"] >= sjf - 1e-9

    def test_sjf_runs_shortest_first(self) -> None:
        result = schedule_sjf(probe_jobs())
        assert [job.name for job in result.jobs] == \
               ["mumbai", "warp", "newyork", "frankfurt"]

    def test_round_robin_gives_the_best_response_time(self) -> None:
        """
        The interactive trade: RR loses on turnaround and wins on response,
        which is what a user actually feels.
        """
        rr = schedule_round_robin(probe_jobs(), quantum=0.05).metrics()
        fcfs = schedule_fcfs(probe_jobs()).metrics()
        assert rr["avg_response"] < fcfs["avg_response"]

    def test_round_robin_costs_more_context_switches(self) -> None:
        rr = schedule_round_robin(probe_jobs(), quantum=0.05).metrics()
        fcfs = schedule_fcfs(probe_jobs()).metrics()
        assert rr["context_switches"] > fcfs["context_switches"]

    def test_smaller_quantum_means_more_switches(self) -> None:
        coarse = schedule_round_robin(probe_jobs(), quantum=0.10).metrics()
        fine = schedule_round_robin(probe_jobs(), quantum=0.01).metrics()
        assert fine["context_switches"] > coarse["context_switches"]

    def test_large_quantum_degenerates_to_fcfs(self) -> None:
        """A quantum longer than every job means nobody is ever preempted."""
        rr = schedule_round_robin(probe_jobs(), quantum=10.0)
        fcfs = schedule_fcfs(probe_jobs())
        assert rr.metrics()["avg_turnaround"] == \
               pytest.approx(fcfs.metrics()["avg_turnaround"])

    def test_quantum_must_be_positive(self) -> None:
        with pytest.raises(ValueError, match="quantum must be positive"):
            schedule_round_robin(probe_jobs(), quantum=0)

    def test_priority_order_is_respected(self) -> None:
        jobs = [
            Job(0, "low", 0.1, priority=9),
            Job(1, "high", 0.1, priority=1),
            Job(2, "mid", 0.1, priority=5),
        ]
        result = schedule_priority(jobs)
        assert [job.name for job in result.jobs] == ["high", "mid", "low"]

    def test_aging_rescues_a_starving_job(self) -> None:
        """
        Without aging a low-priority job waits behind every newcomer. Aging
        raises its effective priority the longer it waits, which guarantees it
        eventually runs.
        """
        # A high-priority job must be ready at t=0 alongside the low-priority
        # one, and more must keep arriving while it runs — otherwise the very
        # first scheduling decision has only the low-priority job to choose
        # from and it runs immediately, starving nothing.
        def make() -> list[Job]:
            return [
                Job(0, "starving", 0.05, arrival=0.00, priority=9),
                Job(1, "urgent-a", 0.10, arrival=0.00, priority=1),
                Job(2, "urgent-b", 0.10, arrival=0.05, priority=1),
                Job(3, "urgent-c", 0.10, arrival=0.15, priority=1),
            ]

        without = [job.name for job in schedule_priority(make()).jobs]
        with_aging = [job.name for job in schedule_priority(make(), aging=500).jobs]
        assert without.index("starving") > with_aging.index("starving")

    def test_all_jobs_complete_under_every_algorithm(self) -> None:
        for name, result in compare_algorithms(probe_jobs()).items() \
                if False else compare_algorithms(probe_jobs())["results"].items():
            assert all(job.completed is not None for job in result.jobs), name
            assert all(job.remaining < 1e-9 for job in result.jobs), name

    def test_total_work_is_conserved(self) -> None:
        """Scheduling changes the order, never the amount of work."""
        for result in compare_algorithms(probe_jobs())["results"].values():
            served = sum(item.duration for item in result.timeline)
            assert served == pytest.approx(sum(j.duration for j in probe_jobs()))

    def test_gantt_renders(self) -> None:
        chart = schedule_fcfs(probe_jobs()).gantt(width=30)
        assert "frankfurt" in chart
        assert "█" in chart

    def test_jobs_from_measurements(self) -> None:
        jobs = jobs_from_measurements([("a", 0.1), ("b", 0.2)])
        assert [job.duration for job in jobs] == [0.1, 0.2]


# ─────────────────────────────────────────────────────────────────────────────
# Memory
# ─────────────────────────────────────────────────────────────────────────────

class TestBufferPool:
    def test_acquire_and_release(self) -> None:
        pool = BufferPool(block_size=128, capacity=4)
        buffer = pool.acquire()
        assert pool.in_use == 1
        buffer.release()
        assert pool.in_use == 0
        assert pool.available == 4

    def test_blocks_are_reused_not_reallocated(self) -> None:
        """Steady-state allocation count must fall to zero."""
        pool = BufferPool(block_size=128, capacity=2)
        for _ in range(100):
            buffer = pool.acquire()
            buffer.release()
        assert pool.stats.reuse_rate == 1.0
        assert pool.stats.allocations == 2

    def test_exhaustion_is_backpressure_not_corruption(self) -> None:
        pool = BufferPool(block_size=64, capacity=2, allow_growth=False)
        pool.acquire()
        pool.acquire()
        with pytest.raises(PoolExhausted, match="backpressure"):
            pool.acquire()
        assert pool.stats.exhaustions == 1

    def test_growth_when_allowed(self) -> None:
        pool = BufferPool(block_size=64, capacity=1, allow_growth=True)
        pool.acquire()
        pool.acquire()
        assert pool.capacity == 2

    def test_context_manager_releases(self) -> None:
        pool = BufferPool(block_size=64, capacity=2)
        with pool.acquire() as buffer:
            buffer.write(b"hello")
            assert pool.in_use == 1
        assert pool.in_use == 0

    def test_double_release_is_safe(self) -> None:
        pool = BufferPool(block_size=64, capacity=2)
        buffer = pool.acquire()
        buffer.release()
        buffer.release()
        assert pool.available == 2

    def test_write_and_view(self) -> None:
        pool = BufferPool(block_size=64, capacity=1)
        buffer = pool.acquire()
        buffer.write(b"packet")
        assert bytes(buffer.view()) == b"packet"
        assert len(buffer) == 6

    def test_oversized_write_rejected(self) -> None:
        pool = BufferPool(block_size=8, capacity=1)
        with pytest.raises(ValueError, match="does not fit"):
            pool.acquire().write(b"x" * 9)

    def test_view_is_zero_copy(self) -> None:
        """A memoryview is a window, not a copy — mutations show through."""
        pool = BufferPool(block_size=16, capacity=1)
        buffer = pool.acquire()
        buffer.write(b"abcd")
        view = buffer.view()
        buffer._storage[0] = ord("z")
        assert bytes(view) == b"zbcd"

    def test_internal_fragmentation_is_reported(self) -> None:
        """A 64-byte ACK in a 2048-byte block wastes the difference."""
        pool = BufferPool(block_size=2048, capacity=4)
        for _ in range(4):
            pool.acquire(requested=64).release()
        assert pool.stats.internal_fragmentation > 0.9

    def test_invalid_configuration_rejected(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            BufferPool(block_size=0, capacity=4)


class TestMemoryMeasurements:
    def test_pooling_lowers_peak_memory(self) -> None:
        result = compare_allocation_strategies(packets=5000)
        assert result["pooled"]["peak_bytes"] < result["naive"]["peak_bytes"]
        assert result["pooled"]["reuse_rate"] > 0.9

    def test_memoryview_copies_nothing(self) -> None:
        result = demonstrate_zero_copy()
        assert result["bytes_copied_by_memoryview"] == 0
        assert result["bytes_copied_by_slicing"] > 1_000_000


# ─────────────────────────────────────────────────────────────────────────────
# Resilience
# ─────────────────────────────────────────────────────────────────────────────

class TestSingleInstance:
    def test_second_acquire_is_refused(self, tmp_path) -> None:
        first = SingleInstance("test-lock", tmp_path)
        first.acquire()
        try:
            with pytest.raises(AlreadyRunning, match="already holds"):
                SingleInstance("test-lock", tmp_path).acquire()
        finally:
            first.release()

    def test_lock_is_reusable_after_release(self, tmp_path) -> None:
        first = SingleInstance("test-lock", tmp_path)
        first.acquire()
        first.release()
        second = SingleInstance("test-lock", tmp_path)
        second.acquire()
        assert second.acquired is True
        second.release()

    def test_context_manager(self, tmp_path) -> None:
        with SingleInstance("ctx", tmp_path) as instance:
            assert instance.acquired is True
            assert SingleInstance.is_available("ctx", tmp_path) is False
        assert SingleInstance.is_available("ctx", tmp_path) is True

    def test_different_names_do_not_collide(self, tmp_path) -> None:
        with SingleInstance("alpha", tmp_path):
            with SingleInstance("beta", tmp_path):
                pass

    def test_holder_info_records_pid(self, tmp_path) -> None:
        with SingleInstance("pidtest", tmp_path) as instance:
            assert instance.holder_info().get("pid") == str(os.getpid())

    def test_stale_lock_file_does_not_block(self, tmp_path) -> None:
        """
        A leftover file must not prevent startup. The descriptor lock — not
        the file's existence — is what enforces exclusion, which is exactly
        why this is better than a PID file.
        """
        (tmp_path / "stale.lock").write_text("pid=999999\n", encoding="utf-8")
        with SingleInstance("stale", tmp_path) as instance:
            assert instance.acquired is True

    def test_double_release_is_safe(self, tmp_path) -> None:
        instance = SingleInstance("dbl", tmp_path)
        instance.acquire()
        instance.release()
        instance.release()


class TestTeardownRegistry:
    def test_runs_in_reverse_order(self) -> None:
        """Teardown is a stack: last set up, first torn down."""
        order: list[str] = []
        registry = TeardownRegistry()
        for name in ("socket", "tunnel", "firewall"):
            registry.register(name, lambda n=name: order.append(n))
        registry.run("test")
        assert order == ["firewall", "tunnel", "socket"]

    def test_one_failure_does_not_stop_the_rest(self) -> None:
        """
        The firewall rules must come off even if an earlier handler threw.
        A teardown that aborts halfway is how a machine ends up with no
        internet and no explanation.
        """
        done: list[str] = []
        registry = TeardownRegistry()
        registry.register("firewall", lambda: done.append("firewall"))
        registry.register("broken", lambda: (_ for _ in ()).throw(RuntimeError("x")))
        registry.register("socket", lambda: done.append("socket"))
        results = registry.run("test")
        assert done == ["socket", "firewall"]
        assert any(r["ok"] is False for r in results)
        assert sum(1 for r in results if r["ok"]) == 2

    def test_runs_only_once(self) -> None:
        count: list[int] = []
        registry = TeardownRegistry()
        registry.register("x", lambda: count.append(1))
        registry.run("first")
        registry.run("second")
        assert len(count) == 1

    def test_reset_clears(self) -> None:
        registry = TeardownRegistry()
        registry.register("x", lambda: None)
        assert len(registry) == 1
        registry.reset()
        assert len(registry) == 0


class TestJournal:
    def test_pending_entry_survives(self, tmp_path) -> None:
        """
        Nothing runs on SIGKILL, so recovery has to happen at next startup.
        The journal is what makes that possible.
        """
        path = tmp_path / "recovery.json"
        journal = Journal.open(path)
        journal.begin("killswitch", {"rule": "OnamVPN-Block-All"})

        reopened = Journal.open(path)
        assert "killswitch" in reopened.pending()
        assert reopened.pending()["killswitch"]["detail"]["rule"] == \
               "OnamVPN-Block-All"

    def test_completed_entry_is_removed(self, tmp_path) -> None:
        path = tmp_path / "recovery.json"
        journal = Journal.open(path)
        journal.begin("killswitch")
        journal.complete("killswitch")
        assert Journal.open(path).pending() == {}

    def test_missing_file_is_empty(self, tmp_path) -> None:
        assert Journal.open(tmp_path / "nope.json").pending() == {}

    def test_corrupt_file_does_not_crash(self, tmp_path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("{not json", encoding="utf-8")
        assert Journal.open(path).pending() == {}

    def test_clear(self, tmp_path) -> None:
        path = tmp_path / "recovery.json"
        journal = Journal.open(path)
        journal.begin("a")
        journal.clear()
        assert Journal.open(path).pending() == {}
