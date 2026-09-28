# 04 — Operating Systems Concepts

Concept-specific questions for Modules F (IPC framing), G (Concurrency), H (Scheduling),
I (Memory) and J (Resilience).

---

# Module G — Concurrency

## The race condition

**Q1. What does the race demo do?**
Eight threads each increment a shared counter. Expected total 400,000; the unsafe version
loses roughly 270,000 of them.

**Q2. Why is a lost update possible at all?**
`value = value + 1` is three operations — read, add, write. If two threads read the same
value before either writes, one increment is overwritten and disappears.

**Q3. The first version of this demo produced the correct answer 10 times out of 10. Why?**
In CPython 3.12 a thread switch can only happen where the interpreter checks its
**eval-breaker**, and as of 3.12 that is at *call boundaries and loop back-edges* — not
between two arbitrary bytecodes. So:
```python
current = self.value        # LOAD_ATTR
self.value = current + 1    # STORE_ATTR
```
has no preemption point between the load and the store. It runs atomically however hard the
scheduler is pushed.

**Q4. Is that a guarantee you can rely on?**
No. It is an artefact of one interpreter's implementation, not a property of the language.
Code relying on it breaks on a different Python, under free-threading (PEP 703), or on any
other runtime.

**Q5. What two changes made the bug observable?**
(1) **A realistic critical section** — `_combine()` is a function call between the read and
the write, which restores the preemption point. It is also the more honest model: real
critical sections read state, compute something, and write back, exactly like
`Session.encrypt` incrementing a counter or `ReplayWindow` updating its bitmap.
(2) **Raised scheduling pressure** — `sys.setswitchinterval(1e-6)` makes the interpreter
consider switching constantly.

**Q6. Isn't lowering the switch interval fabricating the bug?**
No. The code is equally broken either way. It raises **exposure**, the way a loaded
production machine does. It does not create the defect.

**Q7. What is the actual finding of this module?**
**The bug is constant; the exposure is not.** At the default 5 ms switch interval the same
broken code still usually produces the right answer — asserted as a test
(`test_default_switch_interval_often_hides_the_race`). That is why races survive testing and
surface under production load.

**Q8. What would a wrong result look like?**
`0/10 runs lost updates` in unsafe mode — the race is not manifesting, so the demo
demonstrates nothing (the test asserts at least 8 of 10). Or *any* loss in safe mode — the
mutex is not covering the whole critical section.

**Q9. Why is a test suite that only exercises the correct path insufficient?**
It would pass just as happily against an implementation with no locks at all.

## Synchronisation primitives

**Q10. What is a mutex and what does it guarantee?**
`threading.Lock` — at most one thread inside the critical section at a time, within one
process.

**Q11. What are condition variables for, and which ones are used here?**
Waiting until a predicate holds without spinning. `BoundedRing` uses `not_full` (producers
wait) and `not_empty` (consumers wait).

**Q12. Why does the *unsafe* bounded ring drop instead of blocking?**
Without a lock there is no safe way to block, so `safe=False` mode discards on overflow — to
keep the demo terminating instead of corrupting its indices forever.

## Deadlock

**Q13. State the four Coffman conditions.**
1. **Mutual exclusion** — a resource is held by at most one thread.
2. **Hold and wait** — a thread holding one resource waits for another.
3. **No preemption** — a resource cannot be taken away, only released.
4. **Circular wait** — a cycle exists in the "waits for" relation.

All four must hold **simultaneously**. Break any one and deadlock cannot occur.

**Q14. Draw the cycle.**
```
    L1 ──held by── A
     ▲              │
     │           waits for
  waits for         │
     │              ▼
     B ──held by── L2
```

**Q15. Why does the demo need a deliberate stagger?**
Without it, thread A usually finishes before B starts — the same narrow-window problem as
the race. **A demo that only deadlocks sometimes teaches nothing.**

**Q16. What are the two fixes shown, and which condition does each break?**
- **Lock ordering** breaks condition 4 (circular wait). Both threads take L1 first, always;
  no cycle can form, so no detection machinery is needed at all. **This is what real systems
  use.**
- **Timeout and back off** breaks condition 2 (hold and wait) after the fact. It works, but
  wastes the work already done and can **livelock** if both threads back off in lockstep —
  which is why the retry delay is randomised.

**Q17. Why is prevention preferred over detection?**
Detection costs bookkeeping and only tells you after the fact; ordering makes the state
unreachable. A system that cannot form a cycle needs no detector.

**Q18. Describe the deadlock-detector defect.**
The cycle detector originally reported a cycle for a simple **chain** — A waits for a lock B
holds, B waits for nothing. A false-positive deadlock is **worse than a missed one**,
because it sends you hunting a bug that does not exist. The fix distinguishes "returned to a
thread already on this path" from "reached a thread that is runnable".

## The GIL

**Q19. What is the GIL?**
The Global Interpreter Lock — only one thread executes Python bytecode at a time.

**Q20. Give the measured numbers.**
```
CPU-bound (pure Python)            I/O-bound (blocking sleep)
  workers   time    speedup          workers   time    speedup
        1   2.000s    1.00x                1   0.813s    1.00x
        8   1.531s    1.31x                8   0.125s    6.50x
```

**Q21. Explain both results.**
CPU-bound work does not scale because Python bytecode requires the GIL, so only one thread
executes at a time and the extras add context switches without adding throughput. A thread
blocked in a socket or a sleep has **released** the GIL, so I/O-bound work scales nearly
linearly.

**Q22. What is the correct conclusion?**
Not "threads are useless in Python" but **threads help exactly when the work waits**. For
CPU-bound work the answer is processes, which have their own interpreter and their own GIL.

**Q23. How does this apply to this project's own settings?**
It is why `thread_count` in the Settings dialog helps the server-latency scan — probing
servers is I/O-bound (the startup scan went 6.23 s → 1.11 s, 5.6×) — and would **not** help
encryption.

**Q24. What is Amdahl's law and how is it used here?**
Speedup is bounded by the serial fraction: `S(n) = 1 / (s + (1−s)/n)`. The panel measures
actual speedup and compares it against the prediction.

**Q25. Where does the serial fraction come from?**
From the two-worker measurement, via the Karp-Flatt metric (`estimate_serial_fraction`). A
proper fit would use more points; two is enough to show prediction diverging from
measurement, and the limit is stated.

## The project's own threads

**Q26. Which threads exist in this project, and which have races?**

| Thread | Shared state | Race? |
|---|---|---|
| `ConnectionMonitor` (`gui/main_window.py:24`) | polls handler status | No — single read, no compound update |
| `PingTestThread` (`gui/server_grid.py:19`) | own results dict | No — writes are per-thread, joined before use |
| `TunnelServer._loop` (`netlab/native/endpoint.py`) | `Session` counters, replay bitmap | **Yes** — guarded by `self._lock` |
| `ThreadPoolExecutor` (`vpn_core/speedtest_utils.py:215`) | futures | No — the executor serialises collection |

**Q27. Why does the demo counter have the shape it does?**
Because it matches the one genuine compound update in the project: `send_counter`
increments and replay-window updates are both read-modify-write, and both are inside the
lock. That is not a coincidence — the demo uses that shape deliberately.

**Q28. What is the stated limit of the switch-interval trick?**
`sys.setswitchinterval` is **global**. The demo restores the original value in a `finally`,
but while it runs the whole process is under raised scheduling pressure.

---

# Module H — CPU Scheduling

**Q29. What is scheduled, and why does that matter?**
**Real measured probe durations**, not invented numbers — frankfurt 0.30 s, mumbai 0.05 s,
newyork 0.20 s, warp 0.08 s. The same job set goes through each algorithm, so the
comparison is like for like.

**Q30. Define the three metrics.**
```
waiting time    = turnaround - service    (time spent not running)
turnaround time = completion - arrival    (total time in the system)
response time   = first run - arrival     (time until anything happens)
```

**Q31. Which metric do interactive users actually feel?**
**Response time.** Round Robin wins on it and loses on turnaround — exactly the trade an
interactive scheduler makes.

**Q32. Give the measured comparison.**

| algorithm | waiting | turnaround | response | switches |
|---|---|---|---|---|
| FCFS | 0.300 | 0.458 | 0.300 | 3 |
| SJF | **0.128** | **0.285** | 0.128 | 3 |
| Round Robin | 0.240 | 0.397 | **0.075** | 12 |
| Priority | 0.300 | 0.458 | 0.300 | 3 |

**Q33. Why can nothing beat SJF on average waiting time?**
It is **provably optimal** for that metric on a given job set — putting a shorter job before
a longer one can only reduce total waiting. If another algorithm appears to beat it, one of
the two is incorrect. That is asserted in the tests.

**Q34. What is the honest catch about SJF?**
It is optimal **and unimplementable in general**: it needs to know how long each job will
take before running it. Here the durations were measured first, which is the cheat that
makes the comparison possible. Real schedulers estimate from history, and their estimates
are wrong.

**Q35. What is the convoy effect?**
Under FCFS, one long job at the head of the queue delays every short job behind it,
inflating average waiting time far beyond what the work requires.

**Q36. What happens to Round Robin as the quantum grows?**
It degenerates to FCFS **exactly** — asserted in the tests. As the quantum shrinks,
response time improves and context-switch cost dominates.

**Q37. What is starvation and how is it fixed?**
Under priority scheduling, a stream of high-priority jobs can starve a low-priority one
indefinitely. **Aging** raises a waiting job's effective priority by a fixed amount per
second, which guarantees it eventually runs.

**Q38. Demonstrating starvation took a second attempt. Why?**
The first test had all jobs arrive at once, so the very first scheduling decision had only
the low-priority job available and it ran immediately — starving nothing. The demonstration
needs a high-priority job ready at t=0 **and** more arriving while it runs.

**Q39. What invariant must hold across all four algorithms?**
Total work is conserved — scheduling changes the **order**, never the **amount**. Asserted
in the tests.

**Q40. What are the module's limits?**
Single-CPU only — no multiprocessor scheduling, load balancing or affinity. SJF and Priority
are **non-preemptive**; Shortest-Remaining-Time-First and preemptive priority are not
implemented.

---

# Module I — Memory Management

**Q41. Why pool buffers at all?**
A capture loop allocates a buffer per packet. At 10,000 packets/second that is 10,000
allocations and 10,000 collections every second, and the garbage collector walks them all.
Pooling allocates once and hands out the same objects forever: **steady-state allocation
becomes zero.**

**Q42. How does the slab allocator work?**
```
arena:  [ block 0 ][ block 1 ][ block 2 ] ... [ block N ]
free:   → 0 → 1 → 2 → ... → N

acquire() pops the head of the free list       O(1)
release() pushes it back                        O(1)
```

**Q43. Distinguish internal and external fragmentation.**
**External**: free memory stranded in unusably small gaps *between* allocations.
**Internal**: waste *inside* an allocated block. Fixed-size blocks eliminate external
fragmentation but create internal — a 64-byte ACK in a 2048-byte block wastes 1984 bytes.

**Q44. Is that a flaw?**
No — it is the trade a slab allocator makes **deliberately**, and `utilisation()` reports
exactly how much is being paid.

**Q45. What is backpressure here?**
`PoolExhausted` — when no block is free, the pool refuses rather than allocating without
bound. Refusing work is a design decision, not a failure.

**Q46. What is zero-copy and why does slicing cost so much?**
`memoryview` slices without copying. Parsing a packet by slicing headers off the front
copies the payload repeatedly:
```python
header = data[:20]        # copies 20 bytes
rest   = data[20:]        # copies 1480 bytes  ← the expensive one
```

**Q47. Give the measured figure.**
Over 20,000 four-layer parses: **116,000,000 bytes copied by slicing, zero by memoryview.**
That is why `netlab/dissect` passes offsets around instead of re-slicing.

**Q48. What are the module's limits?**
The pool is **not lock-free** — a mutex guards the free list, which is fine at demo rates and
would be a bottleneck at line rate. And there is no mmap-backed circular pcap log; the pcap
*writer* in `netlab/dissect/capture.py` exists and produces files Wireshark opens, but it is
not memory-mapped or circular.

---

# Module J — Resilience

**Q49. Why does the VPN need a single-instance lock?**
Two copies both managing the same tunnel and firewall rules is a real failure: one tears
down rules the other just installed, and the kill switch ends up either permanently on (no
internet) or permanently off (no protection).

**Q50. Why can a `threading.Lock` not do this?**
A mutex lives inside **one process's address space**; a second process gets its own copy and
sees nothing. Mutual exclusion *between* processes has to go through the kernel, and the
portable way to ask is a lock on a file (`msvcrt.locking` on Windows, `fcntl.flock` on
POSIX).

**Q51. What property makes a descriptor lock the right tool?**
The lock is held by the file **descriptor**. When a process dies — even killed with SIGKILL
or TerminateProcess, with no chance to clean up — the OS closes its descriptors and the lock
is released automatically.

**Q52. Why not a PID file?**
Two holes a descriptor lock does not have: a crash leaves the file behind, so the next start
refuses to run; and PIDs are recycled, so the PID in the file may belong to something
unrelated.

**Q53. Describe the Windows locking defect.**
The Windows lock was originally taken at byte 0. A Windows lock is **mandatory**, not
advisory, so that made the file's own diagnostics unreadable to every other handle —
including `holder_info()` in the same process. The lock now sits at offset 4096.

**Q54. What is tested about the lock that people usually get wrong?**
That a **stale lock file does not block startup** — the descriptor lock, not the file's
existence, is what enforces exclusion.

**Q55. Why does teardown order matter in this project specifically?**
The kill switch installs firewall rules blocking all traffic outside the tunnel. If the
process dies without removing them, the machine has no internet and no obvious explanation.

**Q56. In what order do teardown handlers run, and why?**
**Reverse registration order** — a stack, last set up is first torn down — because later
resources may depend on earlier ones.

**Q57. Why is each handler individually guarded?**
One raising must not prevent the rest. The firewall rules have to come off even if closing a
socket failed first.

**Q58. Why is Ctrl+C hard under a Qt event loop?**
Python signal handlers only run **between interpreter bytecodes**. While Qt is blocked in
its C++ event loop no Python executes, so a SIGINT is recorded and then just sits there.

**Q59. How is that fixed?**
`install_qt_nudge` runs a QTimer a few times a second that does nothing — each firing
returns control to Python briefly, which is enough for a pending handler to run.

**Q60. Why is closing a console window not a signal?**
Closing the console sends **CTRL_CLOSE_EVENT**, a Windows console control event that never
reaches Python's signal module. It needs `SetConsoleCtrlHandler`. Windows then gives roughly
**five seconds** before killing the process, so teardown must be quick.

**Q61. What cannot be caught at all?**
SIGKILL, TerminateProcess, and power loss. **Nothing runs.**

**Q62. So how do you survive those?**
Anything that must survive them has to be recoverable at **startup**. That is what the
journal is for: record the intent before acting, clear it after, and on the next launch
clean up whatever is still recorded.
```python
journal.begin("killswitch", {"rule": "OnamVPN-Block-All"})
...apply the firewall rule...
journal.complete("killswitch")
```

**Q63. What guarantee does `os.replace` give?**
Atomicity: a reader sees either the old file or the new one, never a torn one.

**Q64. Why is atomicity not durability?**
After a power loss the rename can be recorded while the data is still in the page cache,
giving an **atomically-renamed empty file**.

**Q65. How is that handled?**
`atomic_write_json` does `flush()` + `os.fsync()` *before* the replace, plus a best-effort
parent-directory fsync on POSIX. The original version had neither, and its docstring implied
the rename alone gave both guarantees.

**Q66. Why is the journal written through `atomic_write_json`?**
So the crash it exists to survive cannot corrupt it.

**Q67. What is the stated limit of this module?**
**The signal handlers are not installed in the running app.** The machinery is built and
tested; wiring it into `main.py`'s startup would change the default path, which was out of
scope for that pass.

---

# Module F — IPC Message Framing

**Q68. What problem does framing solve?**
A pipe or a TCP connection is a **byte stream, not a message stream**. Write three messages
and the reader may see them as one read, or as seven:
```
sender:    [msg A][msg B][msg C]
receiver:  [msg A + first half of B]  ...then...  [rest of B][msg C]
```
There are no boundaries in the medium, so the protocol has to supply them.

**Q69. What are the three standard framing strategies and their trade-offs?**

| Strategy | Trade-off |
|---|---|
| **Delimiter** | Simple, but requires escaping — which is where bugs live |
| **Fixed length** | Wasteful and inflexible |
| **Length prefix** | What almost every binary protocol uses ← used here |

**Q70. What is the frame format here?**
```
┌────────────────┬──────────────────────────┐
│ length (4 B BE)│ UTF-8 JSON payload       │
└────────────────┴──────────────────────────┘
```

**Q71. Where else does this project use length-prefix framing?**
DNS over TCP (2-byte prefix), TLS records, and `netlab/native`'s transport header — which
makes it a useful idea to point at across three modules.

**Q72. Why must reads loop?**
`recv(n)` returns *up to* n bytes, not exactly n. Treating one read as one message works in
testing, where messages are small and arrive intact, and fails in production under load.
`read_exactly` loops until satisfied.

**Q73. What is the denial-of-service risk in a length prefix?**
**The length field is attacker-controlled.** A peer that claims 4 GB will make a naive
reader allocate 4 GB and die — a one-line DoS.

**Q74. How is it mitigated?**
`MAX_FRAME` (1 MiB) caps it, and **the cap is checked before any allocation happens**, not
after.

**Q75. What is `FrameBuffer` for?**
Feeding arbitrary chunks in and getting whole frames out: several frames in one chunk, one
frame split across chunks, and the remainder kept for the next feed.

**Q76. Why was the rest of Module F deliberately not built?**
The phase creates a real **privilege boundary**, and a boundary with a flaw is worse than no
boundary — a request type that lets an unprivileged caller run an arbitrary command or write
an arbitrary path is a security bug, not a bug. The plan gated this work behind design
review specifically so the trust boundary and the authentication scheme would be examined
before anything ran elevated.

**Q77. What exists, and what remains?**
`oslab/daemon/ops.py` defines the `PlatformOps` interface both sides would use, with a
working `FakeOps` for tests. `RealWindowsOps` is stubbed — every method raises
`NotImplementedError` — and the delegation targets it names (`_run_ps`,
`_create_wireguard_interface`, `_remove_wireguard_interface` in
`vpn_core/real_windows_wireguard.py`) all exist, so **the remaining work is wiring rather
than design**. There is still no named-pipe transport, no elevated helper process, no
per-session authentication token, and the GUI still runs elevated as a whole.
