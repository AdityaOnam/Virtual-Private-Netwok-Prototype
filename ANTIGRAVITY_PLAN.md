# OnamVPN — CN + OS Concept Revamp: Implementation Brief for Antigravity

> **Audience:** Antigravity (agentic IDE) executing this plan.
> **Reviewer:** a second agent cross-verifying each phase against the acceptance tests.
> **Target:** a Computer Networks + Operating Systems course project that can survive a viva.

---

## 0. Context you must absorb before writing any code

### 0.1 What this repo currently is

A PySide6 GUI that **shells out to external binaries**:

| Concern | Who actually does it today |
|---|---|
| Key exchange, encryption, tunneling | `wireguard.exe` (kernel driver, not our code) |
| Kill switch / DNS block | `netsh advfirewall` via `subprocess` |
| Latency probing | `ping.exe` via `subprocess` |
| Routing | Windows routing table, set by WireGuard |

**Source of truth files:**
- `main.py` — CLI entry, UAC auto-elevation (`ctypes.windll.shell32.IsUserAnAdmin`), handler selection
- `vpn_core/real_windows_wireguard.py` (820 lines) — the only working path. Builds a `.conf`, calls `wireguard.exe /installtunnelservice`, applies firewall rules, parses `wg show`
- `vpn_core/wireguard_handler.py` — Linux/macOS `wg-quick` path
- `vpn_core/simple_vpn_handler.py` — fake handler, simulates connection
- `vpn_core/speedtest_utils.py` — `PingTester`, `ThreadPoolExecutor` fan-out
- `gui/main_window.py` — `ConnectionMonitor(QThread)` polling `get_connection_status()` every 3 s
- `gui/server_grid.py` — `PingTestThread(QThread)` running `ping.exe`

### 0.2 The problem this revamp solves

The project demonstrates **integration**, not **concepts**. The revamp moves the concepts *into* the codebase so each one is readable, runnable, and demonstrable on screen.

### 0.3 Non-negotiable constraints

1. **DO NOT rewrite, refactor, or "improve" `vpn_core/real_windows_wireguard.py`'s existing connect/disconnect/firewall flow.** It is the only path that produces a working VPN. All new work is **additive**, behind a mode switch. You may add new methods; you may not restructure existing ones.
2. **DO NOT commit any key, token, or credential.** Note `WARP_PRIVATE_KEY` is already hardcoded at `real_windows_wireguard.py:26` — leave it, but add nothing new of that kind.
3. **DO NOT touch Qt widgets from a non-GUI thread.** Every worker communicates via `Signal` only. This is already the pattern; keep it.
4. **Every module must run without an active VPN connection**, so it can be demoed on a laptop with no network privileges. Provide a loopback/offline mode for each.
5. **Prefer stdlib.** New third-party deps must be justified in `requirements.txt` with a comment. Allowed: `scapy`, `cryptography`, `psutil`, `pyqtgraph`. Nothing else without asking.
6. **Windows 11 is the primary target** (see §7 for platform traps that will otherwise waste your time).

### 0.4 Stop-and-verify protocol — MANDATORY

This plan is executed **with a reviewer in the loop**. You do not run it end to end.

At every gate marked `⛔ GATE n` you **stop, produce the listed evidence, and wait for an explicit "PASS — continue" from the reviewer.** Do not start the next task. Do not "continue while waiting". Do not self-approve.

**Three gate types:**

| Type | Meaning | Why it exists |
|---|---|---|
| **DESIGN** | Stop *before* writing the implementation. Produce the interface/spec only. | A wrong interface costs 500 lines of rework. A wrong protocol spec costs a phase. |
| **PROOF** | Stop *after* the work. Produce evidence the acceptance criteria are met. | Prevents "done" claims that are not true. |
| **RISK** | Stop before an action that can break the dev machine, escalate privilege, or touch the working VPN path. | These are hard to undo. |

**Standing stops — these fire at any time, in any phase, not only at numbered gates.** Stop and ask before you:

1. Modify **any existing method** in `vpn_core/real_windows_wireguard.py`, `wireguard_handler.py`, or `main.py`'s connect path. (Adding new methods/files is fine. Changing existing ones is not.)
2. Add a dependency not on the allowed list in §0.3 constraint 5.
3. Execute a **real** `netsh advfirewall` write, or any command that changes routing, adapters, or services on the dev machine.
4. Request elevation, or spawn an elevated child process.
5. Run `git commit`, `git push`, `git checkout -b`, `git reset`, or `git clean`.
6. Delete or overwrite any file you did not create in this plan — including anything under `system_design/`, `config/`, `keys/`, `logs/`.
7. Modify, weaken, skip, or `xfail` an acceptance test in order to make it pass.
8. Find that a phase's approach does not work as specified. Report it; do not silently substitute a different design.
9. Exceed ~400 lines in a single new file, or discover a phase needs more than ~3× its apparent scope.

**Evidence rules at every gate:**

- Paste terminal output **verbatim**. Do not summarise, trim, or retype it. If it is long, paste the full failure sections and the summary line.
- Never write "should work", "appears to", "presumably", or "this will". Either you ran it and have output, or you say you did not run it.
- State failures **first**, before successes.
- Cite code as `path/file.py:line`.
- For GUI work, attach an actual screenshot. A description is not evidence.
- If you attempted something twice and it still fails, **stop at that point** rather than trying a third approach.

**Gate index**

| Gate | Type | Phase | Blocks on |
|---|---|---|---|
| 0 | DESIGN | 0 | `PlatformOps` interface shape |
| 1 | PROOF | 0 | Foundation green, default path unchanged |
| 2 | DESIGN | 1 | Layer/FieldView model + one reference decoder |
| 3 | PROOF | 1 | Dissector correct against golden pcaps |
| 4 | DESIGN | 2 | Wire format + key schedule, before any implementation |
| 5 | PROOF | 2 | Replay filter + nonce/rekey, in isolation |
| 6 | PROOF | 2 | Tunnel end-to-end, tamper test, SOCKS5 |
| 7 | DESIGN | 3 | ARQ interface + impairment determinism |
| 8 | PROOF | 3 | Congestion traces reproducible |
| 9 | DESIGN | 4 | Audit of **existing** threads, before adding any lock |
| 10 | PROOF | 4 | Race/deadlock/Amdahl demos real, not simulated |
| 11 | RISK | 5 | Before the DNS leak test touches live network + firewall |
| 12 | PROOF | 5 | DNS wire format, transports, leak evidence |
| 13 | RISK | 6 | Raw ICMP socket approach, before traceroute is written |
| 14 | PROOF | 6 | Traceroute, PMTUD, longest-prefix match |
| 15 | RISK | 7 | Trust boundary + IPC auth, before any elevated daemon runs |
| 16 | PROOF | 7 | Split-privilege end to end |
| 17 | RISK | 8 | Before module J's signal handler / lock runs unmocked |
| 18 | PROOF | — | Final definition of done |

**Gate cadence:** roughly half the gates are DESIGN or RISK and come *before* the code they guard. If you find yourself writing implementation without having passed the DESIGN gate for it, you have skipped a gate — go back.

---

## 1. Concept coverage map

Each module is chosen to hit multiple syllabus topics at once. Build in tier order.

### Tier 1 — Core (do these first; they carry the viva)

| Module | Concepts demonstrated |
|---|---|
| **A. Packet dissector** | OSI/TCP-IP layering, encapsulation/decapsulation, header fields, port multiplexing, TTL, checksums, MTU |
| **B. Native tunnel (`onamvpn-native`)** | Sockets, datagram vs stream, ECDH key exchange, AEAD, replay protection, protocol design, client-server model |
| **C. Reliability + congestion layer** | ARQ (stop-and-wait / GBN / SR), sliding window, flow control, RTT estimation, RTO + Karn's algorithm, slow start, AIMD, fast retransmit, BDP |
| **G. Concurrency lab** | Race conditions, critical sections, mutex / semaphore / condition variable, bounded-buffer producer-consumer, deadlock (Coffman conditions, detection, recovery), thread pools, Amdahl's law |

### Tier 2 — Strong additions

| Module | Concepts demonstrated |
|---|---|
| **D. DNS stack from scratch** | DNS wire format, label encoding, record types, caching + TTL, recursive vs iterative, DoT/DoH, leak testing |
| **E. Path & routing lab** | IP forwarding, TTL/ICMP, traceroute, Path MTU Discovery, fragmentation + DF bit, CIDR, longest-prefix match, default-route splitting |
| **F. Privilege-separated daemon** | Process creation, privilege levels, least privilege, IPC (named pipes / UDS), message framing, marshalling |

### Tier 3 — If time allows

| Module | Concepts demonstrated |
|---|---|
| **H. Scheduler visualizer** | FCFS / SJF / RR / Priority, preemption, quantum, starvation, aging, Gantt, waiting/turnaround time |
| **I. Memory & buffer management** | Pooling/slab allocation, fragmentation, zero-copy (`memoryview`), `mmap`, virtual memory |
| **J. Resilience layer** | Signals, atomic writes, file locking, inter-process mutual exclusion, crash consistency |

---

## 2. Target repository layout

Create these; do not move existing files.

```
vpn_core/                       # EXISTING — leave intact
  real_windows_wireguard.py     # DO NOT RESTRUCTURE
  wireguard_handler.py
  simple_vpn_handler.py
  speedtest_utils.py
  logger.py

netlab/                         # NEW — all CN concept code
  __init__.py
  dissect/
    __init__.py
    capture.py                  # Npcap/Scapy capture source + offline pcap source
    headers.py                  # pure-Python Ethernet/IPv4/IPv6/TCP/UDP/ICMP decoders
    model.py                    # DecodedPacket dataclass, layer tree
  native/
    __init__.py
    protocol.py                 # wire format: handshake + data frame structs
    crypto.py                   # X25519 + HKDF + ChaCha20-Poly1305 wrappers
    replay.py                   # RFC-6479-style sliding-window replay filter
    client.py                   # OnamVPNNativeClient
    server.py                   # OnamVPNNativeServer
    socks5.py                   # SOCKS5 front-end (driver-free transport mode)
    tun_win.py                  # STRETCH: wintun.dll ctypes binding
  transport/
    __init__.py
    arq.py                      # StopAndWait / GoBackN / SelectiveRepeat
    rtt.py                      # SRTT/RTTVAR/RTO, Karn's algorithm
    congestion.py               # slow start, cong. avoidance, fast retransmit, AIMD
    impairment.py               # loss/delay/reorder/duplicate injection
    harness.py                  # loopback link runner producing reproducible traces
  dns/
    __init__.py
    wire.py                     # DNS message build/parse (no dnspython)
    resolver.py                 # UDP:53, DoT:853, DoH client
    cache.py                    # TTL-respecting cache with stats
    leaktest.py
  path/
    __init__.py
    traceroute.py               # raw ICMP, TTL walk
    pmtud.py                    # DF-bit binary search
    routing.py                  # routing-table parse + LPM simulator

oslab/                          # NEW — all OS concept code
  __init__.py
  ipc/
    __init__.py
    framing.py                  # length-prefixed JSON codec
    pipe_win.py                 # named pipe server/client
    uds_posix.py
    protocol.py                 # request/response schema + auth token
  daemon/
    __init__.py
    service.py                  # elevated helper process entry point
    ops.py                      # PlatformOps interface: real + fake impls
  concurrency/
    __init__.py
    ring.py                     # bounded buffer, mutex + condvar, unsafe toggle
    pool.py                     # instrumented thread pool
    deadlock.py                 # demo + wait-for-graph detector
  scheduling/
    __init__.py
    algorithms.py               # fcfs/sjf/rr/priority over real probe jobs
    gantt.py
  memory/
    __init__.py
    bufferpool.py               # slab allocator + stats
    pcaplog.py                  # mmap-backed circular pcap writer
  resilience/
    __init__.py
    signals.py
    atomicio.py                 # write-temp + os.replace
    singleton.py                # cross-process lock

gui/
  panels/                       # NEW — one tab per lab
    __init__.py
    dissector_panel.py
    transport_panel.py
    concurrency_panel.py
    dns_panel.py
    path_panel.py
    scheduler_panel.py
  labs_window.py                # NEW — "Labs" window hosting the panels

tests/                          # NEW
  test_headers.py
  test_native_protocol.py
  test_replay.py
  test_arq.py
  test_congestion.py
  test_dns_wire.py
  test_ring.py
  test_framing.py
  test_atomicio.py

docs/
  concepts/                     # NEW — one page per module, for the report
```

---

## 3. Phased implementation

Each phase ends with a commit and must pass its acceptance tests before the next begins.

---

### PHASE 0 — Foundation (no concepts yet, but everything depends on it)

**Goal:** make the new code testable without admin rights or a live network.

**Tasks**
1. Create `oslab/daemon/ops.py` defining a `PlatformOps` Protocol with methods:
   `run_firewall_rule()`, `install_tunnel_service()`, `uninstall_tunnel_service()`, `wg_show()`, `list_adapters()`, `read_routing_table()`.
   Provide `RealWindowsOps` (wraps the existing `subprocess` calls — **call into them, do not duplicate the logic**) and `FakeOps` (deterministic canned output, used by all tests).

> ### ⛔ GATE 0 — DESIGN — stop here
> Every later phase depends on this interface. Produce and wait:
> - Full contents of `oslab/daemon/ops.py` (signatures + docstrings; implementations may be stubs)
> - For each method: its return type, and what `FakeOps` will return
> - A list of **every** call site in the existing code you intend to route through this interface, as `file.py:line`
> - Confirmation that `RealWindowsOps` *delegates to* existing methods rather than reimplementing them
>
> Do not write `FakeOps` bodies or any test until this passes.

2. Add `pytest` + `pytest-qt` to `requirements.txt`. Create `tests/conftest.py` with a `fake_ops` fixture.
3. Add `oslab/resilience/atomicio.py`: `atomic_write_json(path, obj)` = write `path.tmp` → `os.replace`. Route **all** `config/settings.json` and `config/servers.json` writes through it.
4. Add `netlab/__init__.py`, `oslab/__init__.py` with version constants.
5. Add a `--labs` flag to `main.py` that opens `gui/labs_window.py` instead of `MainWindow`. Keep the default path byte-for-byte identical in behaviour.

**Acceptance**
- `pytest tests/ -q` runs green with zero admin rights and no network.
- `python main.py` (no flags) behaves exactly as before — verify by diffing `logs/` output on a connect/disconnect cycle against a pre-change run.
- Killing the process mid-`atomic_write_json` never leaves a truncated `settings.json` (test by injecting an exception between write and replace).

> ### ⛔ GATE 1 — PROOF — stop here
> - Verbatim `pytest tests/ -q` output — **including any warning blocks**, untrimmed
> - Verbatim `python main.py --labs --help`. (Plain `--help` cannot run unelevated: the elevation block executes at import, before argparse. `--labs` sets `_LABS_MODE`, skipping elevation, so argparse is reached and help prints.)
> - Verbatim **console** output of a launch → connect → disconnect → exit cycle. Do **not** ask for `logs/` here — `config/settings.json` ships `"log_to_file": false`, so no log file is produced. If you enable file logging to capture this, say so and revert it afterwards.
> - **The diff proving the default path is unchanged:** `git diff --stat` plus the full `git diff` of `main.py`, pasted as diff output, not described in prose. Note the repo has uncommitted pre-existing work, so this diff spans more than your phase — call out which hunks are yours.
> - `git status --porcelain`, **full and unfiltered**
> - **Integration proof for `atomic_write_json`:** the output of `grep -rn "json.dump" --include=*.py .` showing which writers you rerouted. Task 3 says *all* `settings.json` / `servers.json` writes go through it. Rerouting them edits existing methods, which is standing stop 1 — so **stop and ask before doing it**, and do not silently skip the task instead.
> - Line counts must be **measured** (`wc -l`), not estimated.
> - For any class whose methods are stubs or `NotImplementedError`, say so explicitly under FAILURES / UNRESOLVED.

---

### PHASE 1 — Module A: Packet Dissector

**Goal:** show live traffic decoded layer by layer, and show what the VPN actually hides.

**Tasks**
1. `netlab/dissect/headers.py` — **hand-written** decoders (this is the point; do not delegate to Scapy's parsers):
   - Ethernet II: dst/src MAC, EtherType
   - IPv4: version, IHL, DSCP/ECN, total length, ID, flags (DF/MF), fragment offset, TTL, protocol, header checksum **(verify it, and expose the computed vs received value)**, src/dst
   - IPv6: version, traffic class, flow label, payload length, next header, hop limit
   - TCP: ports, seq, ack, data offset, all 9 flag bits, window, checksum, urgent ptr, and parse options (MSS, SACK-permitted, timestamps, window scale)
   - UDP: ports, length, checksum
   - ICMP/ICMPv6: type, code, checksum, rest-of-header
   Each returns a `Layer` with `name`, `fields: dict[str, FieldView]` where `FieldView` carries `value`, `raw_bytes`, `bit_offset`, `bit_length`, `description`.

> ### ⛔ GATE 2 — DESIGN — stop here
> Write `model.py` and **only the IPv4 decoder** first. Six decoders built on a wrong field model is six rewrites. Produce and wait:
> - Full `netlab/dissect/model.py`
> - Full IPv4 decoder, including checksum verification
> - The decoded output for one real IPv4 packet, showing every field with its `bit_offset`/`bit_length`
> - Proof the model handles: sub-byte fields (IHL, flags), variable-length regions (options), and a field whose received value differs from the computed one (checksum)
>
> Do not write the other five decoders until this passes.

2. `netlab/dissect/capture.py` — two sources behind one interface:
   - `LiveCapture(adapter)` using Scapy's `sniff()` **only as a byte-delivery mechanism** (`lfilter`, raw `bytes(pkt)`); decoding is ours.
   - `PcapFileCapture(path)` for offline demo. **Ship 3 sample `.pcap` files in `docs/samples/`** so the panel works on any machine.
3. `gui/panels/dissector_panel.py`:
   - Left: live packet list (time, src→dst, proto, length, info summary)
   - Right top: collapsible layer tree (Ethernet → IP → TCP → payload)
   - Right bottom: hex dump with the selected field's bytes highlighted
   - Adapter selector + BPF filter box + pause/resume
4. **The money demo:** a "Tunnel Comparison" button that captures on the physical NIC for 5 s while a known HTTP request is made, with VPN off vs VPN on, and renders them side by side. VPN off → you see the destination IP, ports, SNI. VPN on → everything is one opaque `UDP :2408` flow to a Cloudflare IP.

**Acceptance**
- `pytest tests/test_headers.py` decodes every byte of the shipped pcaps and matches a golden JSON dump committed alongside.
- IPv4 checksum verification flags a deliberately corrupted packet in the test fixtures.
- The panel opens and shows the offline pcap with **zero** network access and **no** Npcap installed. (Live capture may be disabled with a clear message; the panel must not crash.)
- Tunnel Comparison screenshot shows destination IP visible in one pane and absent in the other.

> ### ⛔ GATE 3 — PROOF — stop here
> - Verbatim `pytest tests/test_headers.py -v`
> - The golden JSON for one pcap, next to an **independent** decoder's output for the same packet — field values must match. This is the only real check on a hand-written decoder; do not skip it by comparing against your own output.
>   - **Preferred:** `tshark -V -r <file>`. As of the Gate 2 review, tshark is **not installed** on this machine. Installing Wireshark solves this *and* trap §7.1 in one step, since the Wireshark installer bundles Npcap (choose "WinPcap API-compatible mode"), which Phase 1's live capture needs regardless. **This is a real install on the user's machine — ask before doing it.**
>   - **Fallback if Wireshark is not installed:** decode with `scapy.layers.inet.IP(bytes)` and diff field by field. Weaker than tshark (different implementation, but still Python) — acceptable, provided you say in the report which reference you used.
> - Output showing the corrupted-checksum fixture is detected
> - Screenshot of the panel running on the offline pcap
> - State explicitly whether Npcap is installed on the dev machine, and paste what the panel does when it is **not** (trap §7.1)

---

### PHASE 2 — Module B: OnamVPN Native tunnel

**Goal:** a VPN *you wrote*, with a real handshake and real encryption.

> **Transport decision — DECIDED 2026-09-17: SOCKS5 first. Wintun is a stretch goal only; do not start it without approval.**
>
> Build **SOCKS5 mode first**. It needs no kernel driver, no admin rights, works on Windows today, and is fully demonstrable (point a browser at `socks5://127.0.0.1:1080` and its traffic goes through your tunnel). TUN-based full-device capture is a **stretch goal**, §7.4.

**Tasks**
1. `netlab/native/protocol.py` — define and **document the wire format in a table in the module docstring**:

   ```
   Handshake Initiation  (type=1)
     0        1        2        4                    36                       52
     +--------+--------+--------+---------------------+------------------------+
     | type=1 | rsvd   | sender_idx (u32 LE)          | ephemeral pubkey (32B) |
     +--------+--------+------------------------------+------------------------+
     | encrypted_static (48B AEAD)                    | timestamp (12B TAI64N) |
     +------------------------------------------------+------------------------+
     | mac1 (16B)                                                              |
     +-------------------------------------------------------------------------+

   Handshake Response    (type=2)   ... mirror, carries responder ephemeral
   Data Frame            (type=4)
     +--------+--------+---------------------+---------------------+-----------+
     | type=4 | rsvd(3)| receiver_idx (u32)  | counter (u64 LE)    | ct + tag  |
     +--------+--------+---------------------+---------------------+-----------+
   Keepalive             (type=4 with empty plaintext)
   ```

   Use `struct` for pack/unpack. Every field gets a named constant for its offset.
2. `netlab/native/crypto.py` — use `cryptography` only:
   - `X25519PrivateKey` / `exchange()` for ECDH
   - `HKDF` (SHA-256) for the key chain: `(send_key, recv_key) = HKDF(shared_secret, info=b"onamvpn-v1")`
   - `ChaCha20Poly1305` for AEAD
   - **Nonce construction:** 12 bytes = `b"\x00"*4 + counter.to_bytes(8, "little")`. The counter is per-key and **must never repeat**. Assert on wraparound and force rekey.
   - Rekey after `2**20` messages or 120 s, whichever first. Log the rekey event — it is a demo point.

> ### ⛔ GATE 4 — DESIGN — stop here
> **Specification only. Write no client, server, or socket code yet.** A protocol bug found after the data path exists costs the whole phase. Produce and wait:
> - The complete wire-format table from `protocol.py`'s docstring, with every field's offset, width, and endianness
> - The `struct` format strings, and a hand-computed size for each message type that matches `struct.calcsize()`
> - The full key schedule written out: what goes into ECDH, what goes into HKDF (salt, info, output length), which half is send vs receive on each side, and how the two sides agree on that direction
> - The exact nonce construction, as bytes, for counter values 0, 1, and 2**32
> - What happens at rekey: state diagram covering counter reset, old-key retention window, and in-flight packets encrypted under the previous key
> - A statement of what your protocol does **not** defend against (this is a course project; being explicit about scope is a credit, not a gap)
>
> Name which parts you took from WireGuard's Noise_IK and which you designed. Do not present a simplified scheme as equivalent to the real one.

3. `netlab/native/replay.py` — sliding-window anti-replay, RFC 6479 style: a bitmap of the last 1024 sequence numbers.
   **Do NOT implement this as `if counter <= last_seen: drop`.** That incorrectly discards legitimately reordered packets and is the #1 thing a reviewer will catch.

> ### ⛔ GATE 5 — PROOF — stop here
> Replay and nonce handling are the two places where a VPN is silently, invisibly broken. Verify them **in isolation**, before they are buried under a socket layer. Produce and wait:
> - Full `netlab/native/replay.py`
> - Verbatim `pytest tests/test_replay.py -v`, with a named test for each of: in-order accept, reordered-within-window accept, exact duplicate reject, below-window reject, far-future slide, window boundary (exactly 1024 back), counter wraparound
> - A printed trace of the window bitmap across a 20-packet reordered sequence
> - Proof that a `(key, nonce)` pair can never repeat: paste the assertion and the test that fires it

4. `netlab/native/server.py` / `client.py` — asyncio or threaded UDP. Server maintains a peer table keyed by `sender_idx`. Handle: handshake, data, keepalive, rekey, peer timeout (wire the dead `keepalive_interval` setting here — default 25 s, matching WireGuard's NAT-binding refresh, and say so in a comment).
5. `netlab/native/socks5.py` — RFC 1928 SOCKS5 server on `127.0.0.1:1080`. `CONNECT` only, no auth (localhost). Each SOCKS connection becomes a stream ID multiplexed inside the tunnel.
6. Add a "Native (experimental)" entry to the GUI mode selector, alongside the existing WireGuard path.
7. `gui/panels/` — a handshake visualizer: animate the 4 messages, show the derived key material (truncated), show the counter advancing and the replay window filling.

**Acceptance**
- `pytest tests/test_native_protocol.py`: round-trip pack/unpack for every message type, including malformed input rejection.
- `pytest tests/test_replay.py`: accepts in-order; accepts reordered-within-window; **rejects a genuine duplicate**; rejects below-window; slides correctly on a far-future counter.
- Two processes on `127.0.0.1` complete a handshake and transfer 10 MB with byte-identical output (checksum both ends).
- Tamper test: flip one bit of a data frame's ciphertext in transit → receiver raises `InvalidTag` and drops it; the transfer still completes via retransmission.
- Browser configured to `socks5://127.0.0.1:1080` loads a page, and Module A's dissector shows **only** encrypted UDP frames to the tunnel endpoint on the wire.

> ### ⛔ GATE 6 — PROOF — stop here
> - Verbatim `pytest tests/test_native_protocol.py -v`
> - Terminal transcript of the two-process 10 MB transfer, with the SHA-256 of the input and output files shown side by side
> - The tamper test: the log line showing `InvalidTag`, and proof the transfer still completed
> - Screenshot of the browser loading a page through `socks5://127.0.0.1:1080`
> - A dissector capture from that session, showing **only** UDP frames to the tunnel endpoint — and confirm you checked for plaintext leaking alongside the tunnel
> - Measured throughput, and an honest note on how it compares to the real WireGuard path. It will be far slower. Say so; do not tune the benchmark to hide it.
> - Whether you attempted Wintun (trap §7.4). If yes, and it is not fully working, say so plainly rather than leaving a half-path in the tree.

---

### PHASE 3 — Module C: Reliability + congestion layer

**Goal:** the transport-layer chapter, made interactive. This is the strongest single viva module.

**Tasks**
1. `netlab/transport/impairment.py` — an in-path impairment shim with knobs: loss %, fixed + jitter delay, reorder %, duplicate %, and a bandwidth cap (token bucket). Deterministic given a seed.
2. `netlab/transport/arq.py` — three interchangeable senders/receivers sharing one interface:
   - `StopAndWait`
   - `GoBackN(window_size)` — cumulative ACK, single retransmit timer, retransmit from `base`
   - `SelectiveRepeat(window_size)` — per-packet timers, per-packet ACK, receiver buffer

> ### ⛔ GATE 7 — DESIGN — stop here
> Three protocols on a wrong interface is three rewrites; a non-deterministic impairment layer makes every later result unverifiable. Produce and wait:
> - The shared ARQ sender/receiver interface (signatures only), and how the timer, the channel, and the congestion controller plug into it
> - Full `impairment.py`
> - **Determinism proof:** run the same seed twice, diff the two event traces, show the diff is empty. Then run a different seed and show it differs.
> - Confirmation the clock is injectable (a test must be able to advance time without `sleep`), otherwise the test suite will be slow and flaky
> - `StopAndWait` implemented as the reference, with a passing test
>
> Do not write GBN or SR until this passes.

3. `netlab/transport/rtt.py` — Jacobson/Karels:
   `SRTT = (1-α)·SRTT + α·R`, `RTTVAR = (1-β)·RTTVAR + β·|SRTT−R|`, `RTO = SRTT + 4·RTTVAR`, clamped `[200 ms, 60 s]`.
   Implement **Karn's algorithm**: do not sample RTT from a retransmitted segment; double the RTO on timeout (exponential backoff) and only reset after a clean ACK.
4. `netlab/transport/congestion.py` — `cwnd`/`ssthresh` state machine: slow start (exponential), congestion avoidance (`cwnd += MSS²/cwnd` per ACK), fast retransmit on 3 dup-ACKs, fast recovery, timeout → `ssthresh = cwnd/2`, `cwnd = 1 MSS`. Emit a state-transition event on every change.
5. `netlab/transport/harness.py` — runs a transfer over the loopback link with a given ARQ + impairment config, records a trace of `(t, cwnd, ssthresh, inflight, rtt, event)`.
6. `gui/panels/transport_panel.py` — controls on the left (protocol, window, loss, delay, bandwidth, seed), live plots on the right via `pyqtgraph`:
   - cwnd + ssthresh vs time (the classic sawtooth)
   - RTT samples + SRTT + RTO envelope
   - sequence-number vs time ladder diagram with retransmissions marked red
   - a stats box: goodput, efficiency, retransmission rate, and **computed BDP vs configured window**, with a note when the window is the bottleneck

**Acceptance**
- `pytest tests/test_arq.py`: with 20 % loss and a fixed seed, all three protocols deliver the full payload in order, byte-identical; GBN shows more retransmissions than SR (assert this).
- `pytest tests/test_congestion.py`: a forced timeout drives `cwnd` to 1 MSS and halves `ssthresh`; three dup-ACKs trigger fast retransmit **without** collapsing `cwnd` to 1.
- Karn's algorithm test: an RTT sample from a retransmitted segment does not move `SRTT`.
- Same seed → byte-identical trace across runs (reproducibility is required for the demo).
- Visual: the cwnd plot shows a recognisable slow-start ramp followed by AIMD sawtooth.

> ### ⛔ GATE 8 — PROOF — stop here
> This is the module the viva will lean on hardest. Produce and wait:
> - Verbatim `pytest tests/test_arq.py tests/test_congestion.py -v`
> - The retransmission counts for GBN vs SR at identical seed and loss, with the assertion that GBN > SR
> - The Karn's-algorithm test: `SRTT` before and after an ambiguous retransmission sample, showing it did not move
> - Screenshot of the cwnd/ssthresh plot. **Label on the plot** where slow start ends, where fast retransmit fires, and where a timeout collapses `cwnd`.
> - The same run at the same seed, twice, with identical traces
> - A run where the configured window is below BDP, and the stats box correctly identifying the window as the bottleneck
>
> If the sawtooth does not look like the textbook figure, report that rather than adjusting the plot. A wrong-looking curve usually means a real state-machine bug.

---

### PHASE 4 — Module G: Concurrency lab

**Goal:** the OS-half centrepiece. Show the bugs, then show the fixes.

> ### ⛔ GATE 9 — DESIGN — stop here, **before writing any code in this phase**
> Task 5 (auditing the existing threads) is listed last but must be done **first**. Adding locks to live code on a guess can introduce a deadlock into the only working VPN path. Produce and wait:
> - For each existing thread — `ConnectionMonitor` (`gui/main_window.py:24`), `PingTestThread` (`gui/server_grid.py:19`), the `threading.Thread` at `vpn_core/real_windows_wireguard.py:717`, the `ThreadPoolExecutor` at `vpn_core/speedtest_utils.py:189`, the monitor thread at `speedtest_utils.py:404` — a table of: shared state it touches, read or write, and whether a real race exists
> - For each **real** race: the interleaving that triggers it, written out
> - For each place you decided **no** lock is needed: the reason (e.g. single atomic assignment under the GIL). This list matters as much as the first one.
> - Your proposed lock ordering, and why it cannot cycle
>
> Propose changes to existing files here; **do not apply them** until this gate passes (standing stop 1).

**Tasks**
1. `oslab/concurrency/ring.py` — bounded circular buffer, `threading.Lock` + two `Condition`s (`not_full`, `not_empty`). Constructor takes `safe: bool`; when `safe=False` it skips locking. Track `dropped`, `blocked_producer_ms`, `blocked_consumer_ms`.
2. `oslab/concurrency/pool.py` — instrumented thread pool. Record per-task submit/start/end. **Wire the dead `thread_count` setting to this** and use it for the server-ping fan-out in `speedtest_utils.py` (which currently hardcodes `max_workers`).
3. `oslab/concurrency/deadlock.py`:
   - `run_deadlock_demo()` — two threads, two locks, acquired in opposite order, with a configurable stagger that makes the deadlock reliably reproducible
   - `WaitForGraph` — tracks who holds what and who waits on what; `detect_cycle()` returns the cycle
   - Recovery: `lock.acquire(timeout=...)` → victim selection → release → retry with **lock ordering** (the prevention fix)
4. `gui/panels/concurrency_panel.py`:
   - **Race demo:** N producer threads increment a shared packet counter 100 000 times each. Unsafe mode → final value < expected, displayed in red against the expected value. Safe mode → exact. Run it live, on a button.
   - **Bounded buffer:** animated ring with producer/consumer rate sliders; show the producer blocking when full and the consumer blocking when empty.
   - **Deadlock:** a button that hangs two worker threads, a wait-for graph rendered as a cycle, a "Detect" button that names the cycle, and a "Recover" button.
   - **Amdahl:** run the real ping scan at pool sizes 1,2,4,8; plot measured speedup against the Amdahl prediction for the measured serial fraction.
5. Audit existing threads and document findings in `docs/concepts/concurrency.md`: `ConnectionMonitor` (`main_window.py:24`) and `PingTestThread` (`server_grid.py:19`) share handler state with no synchronisation. Add locks where a real race exists; **explicitly state in the doc where you decided no lock was needed and why** (e.g. GIL-atomic single assignment).

**Acceptance**
- The race demo produces a wrong total in unsafe mode on at least 8 of 10 runs (if it does not, raise the iteration count until it does — a race that never manifests demonstrates nothing).
- `pytest tests/test_ring.py`: producer blocks on full, consumer blocks on empty, no lost or duplicated items across 10 000 items with 4 producers and 4 consumers.
- `run_deadlock_demo()` deadlocks within 2 s, `detect_cycle()` returns both threads, recovery completes without deadlocking again.
- The Amdahl plot uses real measured times, not simulated ones.

> ### ⛔ GATE 10 — PROOF — stop here
> - Verbatim `pytest tests/test_ring.py -v`
> - **10 consecutive runs** of the race demo in unsafe mode, all results pasted, showing how many produced a wrong total. If fewer than 8, raise the iteration count and rerun — do not report a race that does not manifest.
> - The same 10 runs in safe mode, all exact
> - Terminal output of the deadlock demo hanging, the detected cycle, and successful recovery
> - The Amdahl table: pool size, **measured** wall time, speedup, predicted speedup, and the serial fraction you derived. Confirm these are measured, not computed from a formula.
> - The diff of any change you made to existing threaded code, matched against what GATE 9 approved

---

### PHASE 5 — Module D: DNS stack

> ### ⛔ GATE 11 — RISK — stop here, before task 4
> Tasks 1–3 (wire format, resolver, cache) are safe: build and test those first against loopback and captured responses. **Task 4, the leak test, is not** — it puts real queries on the wire and depends on live firewall rules. Before running it, produce and wait:
> - The exact commands the leak test will execute, in order
> - Which firewall rules must be active, and confirmation they are created by the **existing** code at `vpn_core/real_windows_wireguard.py:539`, not by new code
> - Your rollback procedure if the machine loses connectivity, tested **first** with `FakeOps`
> - Confirmation you have the manual escape from trap §7.8 to hand
>
> This gate covers standing stop 3. Do not run it without approval.

**Tasks**
1. `netlab/dns/wire.py` — build and parse DNS messages by hand (**no `dnspython`**): 12-byte header with ID/QR/Opcode/AA/TC/RD/RA/RCODE/counts; QNAME label-length encoding; **message-compression pointer (0xC0) handling on parse** — it will appear in real responses; A, AAAA, CNAME, MX, NS, TXT, SOA.
2. `netlab/dns/resolver.py` — three transports: plain UDP:53 (with TC→TCP:53 fallback), DoT (TLS to `1.1.1.1:853`, verify cert), DoH (`POST https://cloudflare-dns.com/dns-query`, `application/dns-message`).
3. `netlab/dns/cache.py` — TTL-honouring cache; expose hit/miss/eviction counters and show TTL counting down live.
4. `netlab/dns/leaktest.py` — resolve a known name via plain UDP while Module A captures port 53 on the physical NIC. VPN off + kill switch off → the query is visible in cleartext. VPN on + DNS leak protection on → the query does not appear on the physical NIC. **This empirically proves the firewall rules in `real_windows_wireguard.py:539` actually work** — currently nothing verifies that claim.
5. Wire the dead `custom_dns` / `primary_dns` / `secondary_dns` settings to the resolver.
6. `gui/panels/dns_panel.py` — query box, transport selector, decoded response table, cache view, latency comparison bar chart (UDP vs DoT vs DoH — DoH will be slowest; explain why in the panel text).

**Acceptance**
- `pytest tests/test_dns_wire.py`: parse a captured real response containing compression pointers; round-trip a query; reject a truncated message cleanly.
- All three transports resolve the same name to the same A record.
- Leak test produces two captures, one with the cleartext query present and one without, both saved as `.pcap` for the report.

> ### ⛔ GATE 12 — PROOF — stop here
> - Verbatim `pytest tests/test_dns_wire.py -v`
> - Your parse of a real response containing a compression pointer, next to Wireshark's decode of the same bytes
> - The A record for one name resolved via all three transports, identical
> - Both leak-test `.pcap` files, and the specific packet that is present in one and absent in the other. **If the query is still visible with protection on, report that** — it means the existing firewall rule does not work, which is a genuine finding worth more than a passing demo.
> - Confirmation the firewall state was restored afterwards

---

### PHASE 6 — Module E: Path & routing lab

> ### ⛔ GATE 13 — RISK — stop here, before writing task 1
> Raw ICMP sockets need elevation (standing stop 4), and trap §7.2 makes the Windows behaviour non-obvious. Produce and wait:
> - Exactly which socket type, family, and protocol you will open, and what elevation it requires
> - How you will handle the Windows case where `SOCK_RAW` cannot send a crafted IP header — state your plan for setting TTL (`IP_TTL` socket option, not a hand-built header)
> - How non-responding hops time out without hanging the UI thread
> - Confirmation the panel degrades with a clear message when run unelevated, rather than crashing

**Tasks**
1. `netlab/path/traceroute.py` — raw ICMP socket (`SOCK_RAW`, `IPPROTO_ICMP`), TTL 1..30, 3 probes per hop, parse `ICMP Time Exceeded` (type 11) vs `Echo Reply` (type 0), per-hop min/avg/max RTT, reverse-DNS each hop. Requires admin — the app already elevates.
2. `netlab/path/pmtud.py` — binary search over payload size with the DF bit set; detect `ICMP Fragmentation Needed` (type 3, code 4) and read the next-hop MTU from it. Run it against the WARP endpoint and **explain in the panel why the config uses MTU 1280** (`real_windows_wireguard.py:31`) — WireGuard overhead (60 B IPv6 + 8 UDP + 32 WG header/tag) on top of a possibly-1280 path.
3. `netlab/path/routing.py` — parse the OS routing table via `PlatformOps.read_routing_table()`; implement a longest-prefix-match lookup; let the user type a destination IP and watch which route wins. **Show the `0.0.0.0/1` + `128.0.0.0/1` split-default trick** that WireGuard installs for `AllowedIPs = 0.0.0.0/0` (`real_windows_wireguard.py:266`) and explain that it beats the real default route on prefix length without deleting it.
4. Wire the dead `mtu_size` setting into config generation.
5. `gui/panels/path_panel.py` — traceroute table with a hop-by-hop RTT bar, run before/after VPN and diff the paths side by side.

**Acceptance**
- Traceroute to `1.1.1.1` returns hops with plausible increasing RTTs; handles non-responding hops as `*` without hanging.
- PMTUD converges and reports a value in `[576, 1500]`.
- LPM simulator picks `128.0.0.0/1` over `0.0.0.0/0` for `8.8.8.8` when the tunnel is up — with the reasoning printed.
- Before/after traceroute shows a visibly different path when connected.

> ### ⛔ GATE 14 — PROOF — stop here
> - Traceroute to `1.1.1.1`, verbatim, next to the output of the system `tracert 1.1.1.1` for comparison
> - A traceroute to a host with non-responding hops, showing `*` and completing
> - PMTUD output with the converged value and the probe sequence that found it
> - The LPM lookup for `8.8.8.8` with the tunnel up, showing `128.0.0.0/1` winning and the reasoning printed
> - Before/after path diff, both captured
> - Confirm `mtu_size` is now read at config-generation time, with the `file.py:line` where it is consumed

---

### PHASE 7 — Module F: Privilege-separated daemon

> ### ⛔ GATE 15 — RISK — stop here, **before any code runs elevated**
> This phase creates a privilege boundary. A boundary with a flaw is worse than no boundary, and this is the one place a mistake becomes a security bug rather than a bug. Produce and wait:
> - A diagram of the trust boundary: which operations sit on the elevated side, which on the unprivileged side, and the complete list of messages that cross it
> - For **every** request type the daemon accepts: what an unprivileged caller could do with it if the token check were bypassed. Any request that lets a caller run an arbitrary command or write an arbitrary path is a design failure — redesign it before proceeding.
> - How the token is generated, passed to the daemon at spawn, stored, and compared (constant-time?)
> - Why the named pipe's ACL prevents another user's process from connecting
> - Confirmation the existing all-in-one elevated mode stays the default and is untouched
>
> Covers standing stops 1 and 4.

**Tasks**
1. `oslab/daemon/service.py` — an elevated helper process. It owns every privileged operation (firewall, tunnel service, raw sockets). Launched via `ShellExecuteW(runas)` — reuse the pattern already in `main.py:36`.
2. `oslab/ipc/framing.py` — length-prefixed codec: 4-byte big-endian length + UTF-8 JSON. Enforce a max frame size. Handle partial reads (a loop, not a single `read()`).
3. `oslab/ipc/pipe_win.py` — named pipe at `\\.\pipe\onamvpn` via `pywin32` or `ctypes`. `oslab/ipc/uds_posix.py` — Unix domain socket for the Linux path.
4. `oslab/ipc/protocol.py` — request/response schema, a per-session token generated by the launcher and passed to the daemon at spawn, validated on every request. Reject unauthenticated clients.
5. Refactor the GUI to run **unprivileged** and route privileged calls through the daemon. **Keep the existing all-in-one elevated mode as the default**; make daemon mode opt-in via `--split-privilege` until it is proven.

**Acceptance**
- `pytest tests/test_framing.py`: partial reads reassemble correctly; oversized frames are rejected; malformed JSON does not crash the server.
- GUI launched unprivileged + daemon elevated → connect/disconnect works end to end.
- A second process connecting to the pipe **without** the token is rejected; log the attempt.
- `docs/concepts/privilege.md` contains a diagram of the trust boundary and names which operations sit on which side.

> ### ⛔ GATE 16 — PROOF — stop here
> - Verbatim `pytest tests/test_framing.py -v`
> - Transcript of an unprivileged GUI + elevated daemon completing connect and disconnect
> - The rejection log from a process connecting without a valid token
> - Proof that a **malformed** and an **oversized** frame each leave the daemon alive and serving
> - Confirmation that `python main.py` with no flags still uses the original all-in-one path

---

### PHASE 8 — Tier 3 modules (H, I, J)

Build only if Phases 0–7 are complete and stable.

> ### ⛔ GATE 17 — RISK — stop here, before **any** part of module J runs unmocked
> Module J installs a signal handler whose job is to tear down firewall rules on exit, and a cross-process lock that gates tunnel ownership. Both fail dangerously: a handler that does not fire leaves the machine firewalled off, and a broken lock lets two instances fight over the tunnel. Produce and wait:
> - The teardown sequence the handler runs, and what happens if it is interrupted partway
> - Proof it was tested against `FakeOps` first, with output
> - How you will verify the handler actually fires under Qt on Windows (trap §7.10) — and note that pressing Ctrl+C by hand is the only real proof here
> - The lock's behaviour when a holder is killed with `SIGKILL`/`TerminateProcess` and never releases it
>
> Modules H and I carry no such risk; build and verify those first.

- **H. Scheduler** (`oslab/scheduling/`) — schedule the *real* server-probe jobs under FCFS / SJF / RR(quantum) / Priority, with aging to prevent starvation. Render a Gantt chart and a table of waiting + turnaround times per algorithm. The jobs must actually execute; do not simulate.
- **I. Memory** (`oslab/memory/`) — a slab pool of fixed-size packet buffers with `memoryview` zero-copy slicing; show allocation count, reuse rate, and fragmentation, benchmarked against naive per-packet `bytes()` allocation under `tracemalloc`. Plus an `mmap`-backed circular pcap log (write a valid pcap global header + per-packet headers so the file **opens in Wireshark** — this is the proof it works).
- **J. Resilience** (`oslab/resilience/`) — console-ctrl / signal handler that always tears down firewall rules, a cross-process singleton lock (`msvcrt.locking` on Windows / `fcntl.flock` on POSIX) so two instances cannot both own the tunnel, and a crash-recovery journal read at startup. This hardens the existing `cleanup_stale_configurations()` at `real_windows_wireguard.py:400`.

---

## 4. Wiring the six dead settings

These are currently written by `gui/settings_panel.py` and read by nothing. Each phase claims one:

| Setting | Phase | Where it becomes real |
|---|---|---|
| `keepalive_interval` | 2 | `netlab/native/client.py` keepalive timer |
| `thread_count` | 4 | `oslab/concurrency/pool.py`, used by the ping fan-out |
| `custom_dns`, `primary_dns`, `secondary_dns` | 5 | `netlab/dns/resolver.py` |
| `mtu_size` | 6 | config generation + PMTUD comparison |
| `connection_timeout` | 2 | native handshake + peer timeout |

When each is wired, add a line to `CHANGES.md`.

---

## 5. Documentation deliverables

For each module, `docs/concepts/<module>.md` containing:
1. The syllabus concepts it demonstrates, named explicitly
2. Where in the code each concept lives (`file.py:line`)
3. How to run the demo (exact command)
4. A screenshot of the panel
5. Expected output, and what a *wrong* result would look like

Also regenerate `system_design/` diagrams to include the new modules — the existing `.dot` sources are in `system_design/images/dot/`.

---

## 6. Definition of done

- [ ] `pytest tests/ -q` green, no admin, no network
- [ ] `python main.py` default path unchanged
- [ ] `python main.py --labs` opens all panels; every panel works offline
- [ ] All six dead settings wired
- [ ] Every module has a `docs/concepts/` page
- [ ] No new secrets committed; `.gitignore` still covers `keys/`, `config/*.conf`
- [ ] `CHANGES.md` updated per phase

> ### ⛔ GATE 18 — PROOF — final, stop here
> - Verbatim full `pytest tests/ -q` on a machine with **no admin rights and no network**
> - Screenshot of every panel, each running offline
> - `git diff --stat` for the whole effort, and the full diff of every **pre-existing** file that changed
> - `git status --porcelain` — confirm nothing was deleted
> - The six dead settings, each with the `file.py:line` that now reads it
> - Every acceptance criterion in this plan, listed as pass or fail. **Fails are expected and fine; a list with no fails will be assumed incomplete and audited line by line.**
> - Every trap in §7 you hit, and how you resolved it
> - Everything you did not build, and why

---

## 7. Platform traps — read before you write, these will cost you hours

These are known failure modes for this specific stack. The reviewer will check each.

### 7.1 Scapy on Windows requires Npcap, not raw sockets
Scapy's `sniff()` / `sendp()` need **Npcap** (WinPcap's successor), installed in "WinPcap API-compatible mode". Without it, L2 capture fails with an unhelpful error. Detect this at import and degrade to the offline-pcap source with a clear message. Do not let the panel crash.

### 7.2 `SOCK_RAW` + `SIO_RCVALL` is not a substitute
Python raw sockets on Windows give you **IP-layer, inbound-only** frames with no Ethernet header. If you write an Ethernet decoder on top of `SOCK_RAW` on Windows, it will parse garbage. Ethernet decoding requires Npcap. (The decoder itself should still handle Ethernet — for pcap files and Linux.)

### 7.3 Capturing on the Wintun adapter is unreliable
Npcap does not always enumerate Wintun virtual adapters. **Do not build the demo around capturing inside the tunnel.** Capture on the *physical* NIC and show the encrypted `UDP :2408` flow — this is the better demo anyway, since it proves the traffic is opaque.

### 7.4 There is no `pytun` on Windows
`python-pytun` is Linux-only. Writing a TUN device on Windows requires loading `wintun.dll` via `ctypes` (`WintunCreateAdapter`, `WintunStartSession`, `WintunReceivePacket`, `WintunAllocateSendPacket`) and handling its ring-buffer API. This is genuinely hard. **Do SOCKS5 mode first.** If you attempt Wintun, do it in `tun_win.py` behind a feature flag, and keep a Linux/WSL2 `/dev/net/tun` path as the fallback demo.

### 7.5 Anti-replay is not a comparison
`if counter <= last_seen: drop` is wrong — it discards legitimately reordered packets. Use a sliding-window bitmap. This is the most commonly botched part of a VPN implementation.

### 7.6 Nonce reuse destroys ChaCha20-Poly1305
Reusing a `(key, nonce)` pair leaks the keystream. The counter must be strictly monotonic per key, and rekeying must reset the counter **together with** the key, never separately. Assert loudly on wraparound.

### 7.7 Do not hand-roll crypto
Use `cryptography`'s `X25519`, `HKDF`, `ChaCha20Poly1305`. A from-scratch cipher is not a course-project win; it is a correctness liability. The *protocol* is yours; the *primitives* are not.

### 7.8 The kill switch will lock you out during development
If a crash leaves firewall rules applied, the dev machine loses internet. Before enabling the kill switch anywhere in new code, ensure the Phase-8 signal handler exists, and document the manual escape in `docs/`:
```
netsh advfirewall firewall delete rule name="OnamVPN-Killswitch-Block-All"
```
Test new firewall code with `FakeOps` first.

### 7.9 Existing bug — do not propagate it
`PingTester.ping_host()` (`speedtest_utils.py:32`) does a **TCP** `connect_ex` to the WireGuard endpoint's port — but WireGuard is **UDP**. That connect always fails; the "server online" result comes entirely from the ICMP fallback. Either remove the TCP probe or relabel it honestly. Do not reuse this function as a reachability primitive in new code.

### 7.10 SIGINT does not reliably fire under a Qt event loop on Windows
`signal.signal(SIGINT, ...)` in a PySide6 app often never runs, because the handler only executes between Python bytecodes and Qt blocks in C++. Fix with a `QTimer` firing every 200 ms to give the interpreter a chance to run handlers, or use `SetConsoleCtrlHandler` via `ctypes`. Verify the fix by actually pressing Ctrl+C.

### 7.11 Qt threading rule
`ConnectionMonitor` and `PingTestThread` already use `Signal` correctly. New workers must too. Calling `widget.setText()` from a worker thread will appear to work and then crash randomly under load.

### 7.12 Demo reproducibility
Anything demonstrated in a viva must not depend on live internet conditions. Every module needs a loopback or offline mode with a fixed random seed. The congestion-control plots in particular must be identical across runs for a given seed.

---

## 8. Reporting back

At **every gate** (§0.4), halt and output, in this order:

```
GATE <n> — <DESIGN|PROOF|RISK> — <phase>
STATUS: REQUESTING REVIEW

FAILURES / UNRESOLVED
  <what does not work, what you could not verify, what you skipped.
   Write "none" only if there genuinely are none.>

EVIDENCE
  <the specific artifacts this gate asks for, verbatim>

FILES
  <created / modified, with line counts; mark any pre-existing file with ⚠>

TRAPS HIT
  <any item from §7, and how you resolved it>

STANDING STOPS TRIGGERED
  <any of the 9 in §0.4 you hit, and what you did>

AWAITING: PASS — continue
```

Rules:

- **Failures come first.** A gate report that opens with successes will be read as hiding something.
- An acceptance test that fails gets **reported**, never adjusted, skipped, or `xfail`ed (standing stop 7).
- Do not begin the next task while awaiting review. "Continuing in the meantime" defeats the gate.
- If the reviewer returns findings, fix them and **re-submit the same gate**. Do not advance past a gate you have not been told passed.
- Never claim a thing works that you have not run. "Not yet verified" is an acceptable status; a false pass is not.
