# Module G — Concurrency

Races, bounded buffers, deadlock and the GIL — each demonstrated by running
the broken code and watching it break, then running the fix.

A test suite that only exercises the correct path would pass just as happily
against an implementation with no locks at all.

## Concepts demonstrated

| Concept | Where |
|---|---|
| Race conditions | `ring.py` — `SharedCounter` |
| Critical sections | `ring.py` — read-compute-write |
| Mutexes | `ring.py` — `threading.Lock` |
| Condition variables | `ring.py` — `not_full` / `not_empty` |
| Bounded-buffer producer-consumer | `ring.py` — `BoundedRing` |
| Deadlock and Coffman's conditions | `deadlock.py` |
| Deadlock detection | `deadlock.py` — `WaitForGraph.detect_cycle()` |
| Deadlock prevention | `deadlock.py` — `run_ordered_demo()` |
| Deadlock recovery | `deadlock.py` — `run_timeout_recovery_demo()` |
| Thread pools | `pool.py` — `InstrumentedPool` |
| Amdahl's law | `pool.py` — measured against prediction |
| The GIL | `pool.py` — `compare_workload_scaling()` |

## The race, and why making it appear was the hard part

The demonstration is eight threads incrementing a shared counter. Expected
total 400,000; the unsafe version loses roughly 270,000 of them.

**The first version produced the correct answer 10 times out of 10.**

That is worth understanding, because it teaches more than the race itself. In
CPython 3.12 a thread switch can only happen where the interpreter checks its
eval-breaker, and as of 3.12 that is at *call boundaries and loop back-edges*
— not between two arbitrary bytecodes. So this:

```python
current = self.value        # LOAD_ATTR
self.value = current + 1    # STORE_ATTR
```

has no preemption point between the load and the store. It runs atomically
however hard the scheduler is pushed.

That is an artefact of one interpreter's implementation, not a guarantee of
the language. Code relying on it breaks on a different Python, under
free-threading, or on any other runtime.

Two changes make the bug observable:

1. **A realistic critical section.** `_combine()` is a function call between
   the read and the write, which restores the preemption point. It is also the
   more honest model — real critical sections read state, compute something,
   and write back, exactly like `Session.encrypt` incrementing a counter or
   `ReplayWindow` updating its bitmap.
2. **Raised scheduling pressure.** `sys.setswitchinterval(1e-6)` makes the
   interpreter consider switching constantly. This does not fabricate the bug;
   the code is equally broken either way. It raises exposure, the way a loaded
   production machine does.

**At the default 5 ms switch interval, the same broken code still usually
produces the right answer.** That is the finding: the bug is constant, the
exposure is not. It is why races survive testing and appear under load, and it
is asserted as a test
(`test_default_switch_interval_often_hides_the_race`).

## Deadlock

All four Coffman conditions must hold simultaneously. Break any one and
deadlock cannot occur.

```
1. Mutual exclusion   a resource is held by at most one thread
2. Hold and wait      a thread holding one resource waits for another
3. No preemption      a resource cannot be taken away, only released
4. Circular wait      a cycle exists in the "waits for" relation

    L1 ──held by── A
     ▲              │
     │           waits for
  waits for         │
     │              ▼
     B ──held by── L2
```

The demo arranges all four with a deliberate stagger between acquiring the
first lock and reaching for the second. Without it, thread A usually finishes
before B starts — the same narrow-window problem as the race. A demo that only
deadlocks sometimes teaches nothing.

Two fixes, both shown:

- **Ordering** breaks condition 4. Both threads take L1 first, always. No
  cycle can form, so no detection machinery is needed at all. This is what
  real systems use.
- **Timeout and back off** breaks condition 2 after the fact. It works, but
  wastes the work already done and can livelock if both threads back off in
  lockstep — which is why the retry delay is randomised.

**A defect found here:** the cycle detector originally reported a cycle for a
simple chain (A waits for a lock B holds, B waits for nothing). A
false-positive deadlock is worse than a missed one, because it sends you
hunting a bug that does not exist. The fix distinguishes "returned to a thread
already on this path" from "reached a thread that is runnable".

## The GIL, measured

The panel scales the same pool over two workloads and reports both:

```
CPU-bound (pure Python arithmetic)
   workers      time   speedup    amdahl
         1    2.000s     1.00x     1.00x
         8    1.531s     1.31x     1.38x

I/O-bound (blocking sleep)
   workers      time   speedup    amdahl
         1    0.813s     1.00x     1.00x
         8    0.125s     6.50x     6.31x
```

CPU-bound work does not scale because Python bytecode requires the GIL, so
only one thread executes at a time and the extras add context switches without
adding throughput. A thread blocked in a socket or a sleep has *released* the
GIL, so I/O-bound work scales nearly linearly.

The conclusion is not "threads are useless in Python" but **threads help
exactly when the work waits**. For CPU-bound work the answer is processes,
which have their own interpreter and their own GIL.

This is also the answer to why `thread_count` in the Settings dialog helps the
server-latency scan — probing servers is I/O-bound — and would not help
encryption.

## Running it

```bash
python main.py --labs        # Concurrency tab
```

Four buttons. The race demo runs 10 unsafe and 10 safe trials and prints every
one, including the default-interval run where the race hides.

## Expected output

```
WITHOUT a mutex:
  run 0: actual    135,357  lost    264,643   ← updates lost
  ...
  10/10 runs lost updates.

WITH a mutex:
  10/10 runs exact.

  at the default interval: lost 0
```

**Wrong results to watch for:**

- `0/10 runs lost updates` in unsafe mode — the race is not manifesting. Raise
  the iteration count. A race that never appears demonstrates nothing, and the
  test asserts at least 8 of 10.
- Any loss at all in safe mode — the mutex is not covering the whole critical
  section.
- The deadlock demo completing both threads — the stagger is too small, or the
  locks are being taken in the same order.

## The existing threads in this project

Audited during Phase 4:

| Thread | Shared state | Race? |
|---|---|---|
| `ConnectionMonitor` (`gui/main_window.py:24`) | polls handler status | No — single read, no compound update |
| `PingTestThread` (`gui/server_grid.py:19`) | own results dict | No — writes are per-thread, joined before use |
| `TunnelServer._loop` (`netlab/native/endpoint.py`) | `Session` counters, replay bitmap | **Yes** — guarded by `self._lock` |
| `ThreadPoolExecutor` (`vpn_core/speedtest_utils.py:215`) | futures | No — the executor serialises collection |

The tunnel is the one place with a genuine compound update on shared state:
`send_counter` increments and replay-window updates are both read-modify-write,
and both are inside the lock. That is the same shape as the demo counter, which
is not a coincidence — it is why the demo uses that shape.

## Limits

- **`sys.setswitchinterval` is global.** The demo restores the original value
  in a `finally`, but while it runs the whole process is under raised
  scheduling pressure.
- **The unsafe ring drops rather than blocking.** Without a lock there is no
  safe way to block, so `safe=False` mode discards on overflow to keep the
  demo terminating instead of corrupting its indices forever.
- **Amdahl fitting uses two points.** The serial fraction comes from the
  two-worker measurement (Karp-Flatt). With more points a proper fit would be
  better, but two is enough to show prediction diverging from measurement.
