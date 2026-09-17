# Modules H, I, J — Scheduling, Memory, Resilience

Three smaller OS modules sharing one tab, each a single measurement rather than
an interactive laboratory.

## Module H — CPU Scheduling

Four classic algorithms, scheduling **real measured probe durations** rather
than invented numbers. The same job set goes through each, so the comparison is
like for like.

### Concepts

| Concept | Where |
|---|---|
| FCFS and the convoy effect | `algorithms.py` — `schedule_fcfs` |
| Shortest Job First, and why it is unimplementable | `schedule_sjf` |
| Round Robin and the quantum | `schedule_round_robin` |
| Priority scheduling and starvation | `schedule_priority` |
| Aging | `schedule_priority(aging=...)` |
| Preemption and context-switch cost | `switch_cost` parameter |
| Waiting / turnaround / response time | `ScheduleResult.metrics()` |
| Gantt charts | `ScheduleResult.gantt()` |

### The metrics, and which one users feel

```
waiting time    = turnaround - service    (time spent not running)
turnaround time = completion - arrival    (total time in the system)
response time   = first run - arrival     (time until anything happens)
```

Response time is the one interactive users notice. Round Robin wins on it and
loses on turnaround, which is exactly the trade an interactive scheduler makes.

### Measured output

Four probes: frankfurt 0.30s, mumbai 0.05s, newyork 0.20s, warp 0.08s.

| algorithm | waiting | turnaround | response | switches |
|---|---|---|---|---|
| FCFS | 0.300 | 0.458 | 0.300 | 3 |
| SJF | **0.128** | **0.285** | 0.128 | 3 |
| Round Robin | 0.240 | 0.397 | **0.075** | 12 |
| Priority | 0.300 | 0.458 | 0.300 | 3 |

SJF wins average waiting time — it is provably optimal for that metric, so
nothing can beat it on the same job set. Round Robin wins response time at the
cost of 4x the context switches.

### The honest catch about SJF

SJF is optimal **and unimplementable in general**: it needs to know how long
each job will take before running it. Here the durations were measured first,
which is the cheat that makes the comparison possible. Real schedulers estimate
from history, and their estimates are wrong.

### Starvation and aging

Without aging, a stream of high-priority jobs starves a low-priority one
indefinitely. `aging` raises a waiting job's effective priority by that much
per second, which guarantees it eventually runs.

Demonstrating this correctly took a second attempt. The first test had all jobs
arrive at once, so the very first scheduling decision had only the
low-priority job available and it ran immediately — starving nothing. The
demonstration needs a high-priority job ready at t=0 *and* more arriving while
it runs.

---

## Module I — Memory Management

### Concepts

| Concept | Where |
|---|---|
| Slab allocation | `bufferpool.py` — `BufferPool` |
| Free lists | `BufferPool._free` — O(1) acquire and release |
| Internal vs external fragmentation | `PoolStats.internal_fragmentation` |
| Backpressure | `PoolExhausted` |
| Zero-copy | `Buffer.view()` — `memoryview` |
| Allocation cost measurement | `compare_allocation_strategies` with `tracemalloc` |

### Why pool at all

A capture loop allocates a buffer per packet. At 10,000 packets/second that is
10,000 allocations and 10,000 collections every second, and the garbage
collector walks them all. Pooling allocates once and hands out the same objects
forever: **steady-state allocation becomes zero**.

```
arena:  [ block 0 ][ block 1 ][ block 2 ] ... [ block N ]
free:   → 0 → 1 → 2 → ... → N

acquire() pops the head of the free list       O(1)
release() pushes it back                        O(1)
```

Fixed-size blocks eliminate **external** fragmentation (free memory stranded in
unusably small gaps) but create **internal** fragmentation: a 64-byte ACK in a
2048-byte block wastes 1984 bytes. `utilisation()` reports exactly that — it is
the trade a slab allocator makes deliberately.

### Zero copy

`memoryview` slices without copying. Parsing a packet by slicing headers off
the front copies the payload repeatedly:

```python
header = data[:20]        # copies 20 bytes
rest   = data[20:]        # copies 1480 bytes  ← the expensive one
```

Measured over 20,000 four-layer parses: **116,000,000 bytes copied by slicing,
zero by memoryview.** That is why `netlab/dissect` passes offsets around
instead of re-slicing.

---

## Module J — Resilience

### Concepts

| Concept | Where |
|---|---|
| Cross-process mutual exclusion | `singleton.py` |
| Advisory file locks | `msvcrt.locking` / `fcntl.flock` |
| Signal handling | `signals.py` — SIGINT, SIGTERM, SIGBREAK |
| Windows console control events | `signals.py` — `SetConsoleCtrlHandler` |
| Ordered teardown | `signals.TeardownRegistry` |
| Crash consistency | `signals.Journal` |
| Atomic file replacement | `atomicio.py` |

### Why the VPN needs a single-instance lock

Two copies both managing the same tunnel and firewall rules is a real failure:
one tears down rules the other just installed, and the kill switch ends up
either permanently on (no internet) or permanently off (no protection).

**A `threading.Lock` cannot do this.** A mutex lives inside one process's
address space; a second process gets its own copy and sees nothing. Mutual
exclusion *between* processes has to go through the kernel, and the portable
way to ask is a lock on a file.

The lock is held by the file **descriptor**, which is the property that
matters: when a process dies — even killed with SIGKILL or TerminateProcess,
with no chance to clean up — the OS closes its descriptors and the lock is
released automatically.

**Why not a PID file.** Two holes a descriptor lock does not have: a crash
leaves the file behind so the next start refuses to run, and PIDs are recycled
so the PID in the file may belong to something unrelated.

**A defect found here:** the Windows lock was originally taken at byte 0. A
Windows lock is *mandatory*, not advisory, so that made the file's own
diagnostics unreadable to every other handle — including `holder_info()` in the
same process. The lock now sits at offset 4096.

### Why teardown ordering matters

OnamVPN's kill switch installs firewall rules blocking all traffic outside the
tunnel. If the process dies without removing them, the machine has no internet
and no obvious explanation.

Handlers run in **reverse registration order** — a stack, last set up is first
torn down — and each is individually guarded. One raising must not prevent the
rest: the firewall rules have to come off even if closing a socket failed
first.

### Two things that make signals harder than they look

**Ctrl+C under a Qt event loop.** Python signal handlers only run between
interpreter bytecodes. While Qt is blocked in its C++ event loop no Python
executes, so a SIGINT is recorded and then sits there. `install_qt_nudge` runs
a QTimer a few times a second that does nothing — each firing returns control
to Python briefly, which is enough for a pending handler to run.

**Windows console control events.** Closing the console window sends
CTRL_CLOSE_EVENT, which is not a signal and never reaches Python's signal
module. It needs `SetConsoleCtrlHandler`. Windows then gives roughly five
seconds before killing the process, so teardown must be quick.

### What cannot be caught

SIGKILL, TerminateProcess, and power loss. **Nothing runs.**

Anything that must survive those has to be recoverable at *startup*, which is
what the journal is for: record the intent before acting, clear it after, and
on the next launch clean up whatever is still recorded.

```python
journal.begin("killswitch", {"rule": "OnamVPN-Block-All"})
...apply the firewall rule...
journal.complete("killswitch")
```

The journal is written through `atomic_write_json`, so the crash it exists to
survive cannot corrupt it.

### Atomicity is not durability

`os.replace` is atomic: a reader sees either the old file or the new one,
never a torn one. That is **not** the same as durability — after a power loss
the rename can be recorded while the data is still in the page cache, giving
an atomically-renamed empty file.

`atomic_write_json` therefore does `flush()` + `os.fsync()` *before* the
replace, plus a best-effort parent-directory fsync on POSIX. The original
version had neither, and its docstring implied the rename alone gave both
guarantees.

---

## Running it

```bash
python main.py --labs        # OS Lab tab
```

Three buttons: compare schedulers (with a quantum slider), measure allocation
and copying, demonstrate the lock and journal.

## Expected output

Scheduler: SJF lowest average waiting, RR lowest response with the most
switches, and four Gantt charts.

Memory: pooled peak memory below naive, reuse rate 100%, zero bytes copied by
memoryview.

Resilience: second instance refused, teardown running in reverse with one
failure not stopping the rest, journal entry surviving a simulated crash.

**Wrong results to watch for:**

- Another algorithm beating SJF on average waiting time — impossible if both
  are correct, so one is not.
- Total work not conserved across algorithms — scheduling changes the order,
  never the amount. Asserted in the tests.
- The second `SingleInstance` acquiring successfully — the lock is not
  crossing the process boundary.
- Teardown stopping at the failing handler — the guard is missing.

## Verification

`tests/test_oslab.py`, 58 tests. Highlights:

- SJF is not beaten by any other algorithm on average waiting time
- a large quantum makes Round Robin degenerate to FCFS exactly
- aging changes the position of a starving job
- a stale lock file does *not* block startup — the descriptor lock, not the
  file's existence, is what enforces exclusion
- teardown runs in reverse and survives a raising handler
- a pending journal entry is still there after reopening

## Limits

- **The scheduler is single-CPU.** No multiprocessor scheduling, load
  balancing or affinity.
- **Non-preemptive SJF and Priority.** Shortest-Remaining-Time-First and
  preemptive priority are not implemented.
- **The pool is not lock-free.** A mutex guards the free list, which is fine at
  demo rates and would be a bottleneck at line rate.
- **No mmap-backed pcap log.** Planned for Module I and not built; the pcap
  *writer* in `netlab/dissect/capture.py` exists and produces files Wireshark
  opens, but it is not memory-mapped or circular.
- **The signal handlers are not installed in the running app.** The machinery
  is built and tested; wiring it into `main.py`'s startup would change the
  default path, which was out of scope for this pass.
