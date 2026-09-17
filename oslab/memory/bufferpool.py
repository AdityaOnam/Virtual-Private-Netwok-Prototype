"""
oslab.memory.bufferpool — a slab allocator for packet buffers, and zero-copy views.

Why pool at all
───────────────
A capture loop allocates a buffer per packet. At 10 000 packets/second that is
10 000 allocations and 10 000 collections every second, and the garbage
collector has to walk them all. Pooling allocates the buffers once and hands
out the same objects forever: the steady-state allocation rate becomes zero.

This is a slab allocator — fixed-size blocks from a pre-allocated arena, with
a free list. It is what kernels use for exactly this workload, and the reason
is the same: uniform object sizes mean allocation is a list pop rather than a
search, and there is no external fragmentation because every block is
interchangeable.

    arena:  [ block 0 ][ block 1 ][ block 2 ] ... [ block N ]
    free:   → 0 → 1 → 2 → ... → N

    acquire() pops the head of the free list       O(1)
    release() pushes it back                        O(1)

Internal vs external fragmentation
──────────────────────────────────
Fixed-size blocks eliminate *external* fragmentation (free memory stranded in
unusably small gaps) but create *internal* fragmentation: a 64-byte ACK stored
in a 2048-byte block wastes 1984 bytes. `utilisation()` reports exactly that,
and it is the trade a slab allocator makes deliberately.

Zero copy
─────────
`memoryview` slices a buffer without copying it. Parsing a 1500-byte packet by
slicing headers off the front copies the payload repeatedly:

    header = data[:20]        # copies 20 bytes
    rest   = data[20:]        # copies 1480 bytes  ← the expensive one

With a memoryview both are free — they are windows onto the same memory. For a
dissector walking four layers that is the difference between copying the
payload four times and not at all.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass


class PoolExhausted(RuntimeError):
    """Raised when every block is in use and the pool cannot grow."""


@dataclass
class PoolStats:
    acquires: int = 0
    releases: int = 0
    reuses: int = 0
    allocations: int = 0
    exhaustions: int = 0
    peak_in_use: int = 0
    bytes_requested: int = 0
    bytes_provided: int = 0

    @property
    def reuse_rate(self) -> float:
        return self.reuses / self.acquires if self.acquires else 0.0

    @property
    def internal_fragmentation(self) -> float:
        """Fraction of handed-out bytes that were never used."""
        if not self.bytes_provided:
            return 0.0
        return 1.0 - self.bytes_requested / self.bytes_provided

    def as_dict(self) -> dict:
        return {
            "acquires": self.acquires,
            "releases": self.releases,
            "reuses": self.reuses,
            "fresh_allocations": self.allocations,
            "reuse_rate": round(self.reuse_rate, 3),
            "peak_in_use": self.peak_in_use,
            "internal_fragmentation": round(self.internal_fragmentation, 3),
            "exhaustions": self.exhaustions,
        }


class Buffer:
    """
    One fixed-size block, returned to the pool when released.

    `view(n)` gives a zero-copy memoryview of the first n bytes — the part
    actually written — without copying anything.
    """

    __slots__ = ("_storage", "_pool", "_length", "block_size", "released")

    def __init__(self, block_size: int, pool: "BufferPool | None" = None) -> None:
        self._storage = bytearray(block_size)
        self._pool = pool
        self._length = 0
        self.block_size = block_size
        self.released = False

    def write(self, data: bytes) -> int:
        """Copy *data* into the block; returns how many bytes were stored."""
        if len(data) > self.block_size:
            raise ValueError(
                f"{len(data)} B does not fit a {self.block_size} B block"
            )
        self._storage[:len(data)] = data
        self._length = len(data)
        return self._length

    def view(self, length: int | None = None) -> memoryview:
        """Zero-copy window onto the written bytes."""
        end = self._length if length is None else length
        return memoryview(self._storage)[:end]

    def __len__(self) -> int:
        return self._length

    def release(self) -> None:
        if self._pool is not None and not self.released:
            self._pool.release(self)

    def __enter__(self) -> "Buffer":
        return self

    def __exit__(self, *exc) -> None:
        self.release()


class BufferPool:
    """
    Fixed-size block pool with a free list.

    Parameters
    ----------
    block_size : int
        Bytes per block. Default 2048 — one Ethernet frame with headroom.
    capacity : int
        Blocks pre-allocated. Acquiring beyond this either grows the pool or
        raises, depending on `allow_growth`.
    allow_growth : bool
        False makes exhaustion an error, which is what a real packet pool
        wants: it bounds memory use, and a full pool is backpressure telling
        you the consumer cannot keep up.
    """

    def __init__(self, block_size: int = 2048, capacity: int = 256,
                 allow_growth: bool = False) -> None:
        if block_size < 1 or capacity < 1:
            raise ValueError("block_size and capacity must both be positive")
        self.block_size = block_size
        self.capacity = capacity
        self.allow_growth = allow_growth
        self._free: list[Buffer] = [Buffer(block_size, self) for _ in range(capacity)]
        self._in_use = 0
        self._lock = threading.Lock()
        self.stats = PoolStats(allocations=capacity)

    def acquire(self, requested: int | None = None) -> Buffer:
        """Take a block from the free list."""
        with self._lock:
            self.stats.acquires += 1
            if self._free:
                buffer = self._free.pop()
                self.stats.reuses += 1
            elif self.allow_growth:
                buffer = Buffer(self.block_size, self)
                self.capacity += 1
                self.stats.allocations += 1
            else:
                self.stats.exhaustions += 1
                raise PoolExhausted(
                    f"all {self.capacity} blocks are in use. This is "
                    "backpressure, not a bug: the consumer is not keeping up."
                )
            buffer.released = False
            self._in_use += 1
            self.stats.peak_in_use = max(self.stats.peak_in_use, self._in_use)
            if requested is not None:
                self.stats.bytes_requested += requested
                self.stats.bytes_provided += self.block_size
            return buffer

    def release(self, buffer: Buffer) -> None:
        with self._lock:
            if buffer.released:
                return          # double release is a no-op, not a corruption
            buffer.released = True
            buffer._length = 0
            self._free.append(buffer)
            self._in_use -= 1
            self.stats.releases += 1

    @property
    def available(self) -> int:
        return len(self._free)

    @property
    def in_use(self) -> int:
        return self._in_use

    def utilisation(self) -> dict:
        return {
            "capacity": self.capacity,
            "in_use": self._in_use,
            "available": self.available,
            "block_size": self.block_size,
            "bytes_reserved": self.capacity * self.block_size,
            **self.stats.as_dict(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Measuring the difference
# ─────────────────────────────────────────────────────────────────────────────

def compare_allocation_strategies(packets: int = 20_000,
                                  packet_size: int = 1400) -> dict:
    """
    Pooled versus naive allocation, measured with tracemalloc.

    Reports peak memory and elapsed time for both. The pooled path allocates
    `capacity` blocks once; the naive path allocates one object per packet and
    leaves them all to the collector.
    """
    import time
    import tracemalloc

    payload = bytes(packet_size)

    tracemalloc.start()
    started = time.perf_counter()
    for _ in range(packets):
        buffer = bytearray(packet_size)     # fresh allocation every time
        buffer[:packet_size] = payload
    naive_time = time.perf_counter() - started
    _, naive_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    pool = BufferPool(block_size=2048, capacity=64)
    tracemalloc.start()
    started = time.perf_counter()
    for _ in range(packets):
        buffer = pool.acquire(requested=packet_size)
        buffer.write(payload)
        buffer.release()
    pooled_time = time.perf_counter() - started
    _, pooled_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "packets": packets,
        "naive": {"peak_bytes": naive_peak, "seconds": round(naive_time, 4)},
        "pooled": {"peak_bytes": pooled_peak, "seconds": round(pooled_time, 4),
                   **pool.utilisation()},
        "peak_ratio": round(naive_peak / pooled_peak, 2) if pooled_peak else 0.0,
        "note": (
            "The pool allocates 64 blocks once and reuses them; the naive path "
            "allocates one object per packet. The reuse rate shows the "
            "steady-state allocation count falling to zero."
        ),
    }


def demonstrate_zero_copy(packet_size: int = 1500, layers: int = 4) -> dict:
    """
    Slicing bytes copies; slicing a memoryview does not.

    Peeling four headers off a packet by slicing copies the remaining payload
    four times. With a memoryview it copies nothing, which is why the dissector
    in netlab.dissect takes offsets rather than re-slicing.
    """
    import time

    data = bytes(packet_size)
    header = 20
    iterations = 20_000

    started = time.perf_counter()
    for _ in range(iterations):
        rest = data
        for _ in range(layers):
            rest = rest[header:]        # copies the remainder each time
    copy_time = time.perf_counter() - started

    started = time.perf_counter()
    for _ in range(iterations):
        rest = memoryview(data)
        for _ in range(layers):
            rest = rest[header:]        # a window, not a copy
    view_time = time.perf_counter() - started

    bytes_copied = iterations * sum(
        packet_size - header * (i + 1) for i in range(layers)
    )
    return {
        "iterations": iterations,
        "layers": layers,
        "slicing_seconds": round(copy_time, 4),
        "memoryview_seconds": round(view_time, 4),
        "speedup": round(copy_time / view_time, 2) if view_time else 0.0,
        "bytes_copied_by_slicing": bytes_copied,
        "bytes_copied_by_memoryview": 0,
    }
