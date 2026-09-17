# OnamVPN — Changes

## Phases 2-8 — the full CN + OS concept build (2026-09-17)

Everything below was built, tested and verified in one pass. All offline: no
admin rights, no capture driver, no network required.

### Phase 2 — OnamVPN Native: a VPN we wrote ourselves

`netlab/native/` — a working encrypted tunnel, not a wrapper around one.

- `protocol.py` — wire format specified in full: 132-byte handshake
  initiation, 76-byte response, 16-byte transport header. Sizes are asserted
  against the documented tables at import, so a format string and its
  documentation cannot drift apart.
- `crypto.py` — reduced Noise_IK: X25519 ECDH, a BLAKE2s chaining key, HKDF
  key schedule, ChaCha20-Poly1305 AEAD. The initiator's identity travels
  encrypted; a TAI64N timestamp defeats handshake replay; mac1 over the
  responder's public key rejects junk before any curve arithmetic.
- `replay.py` — RFC-6479 sliding-window filter. Accepts reordered packets,
  rejects genuine duplicates. Explicitly *not* `if counter <= last: drop`,
  which is the standard way to get this wrong.
- `session.py` — keys and counter rotate together, because changing one
  without the other reuses a nonce under a live key. The previous session is
  retained decrypt-only so in-flight packets survive a rekey.
- `socks5.py` / `runner.py` — RFC 1928 SOCKS5 front end and exit node, with
  stream multiplexing inside the tunnel.

Verified end to end: handshake, 200 KB transfer byte-identical, tamper test
(InvalidTag), replay test (an identical datagram sent twice is rejected as a
replay, not a forgery), four concurrent streams that do not cross.

**Three defects found and fixed while building it:**

- *Data loss on bulk transfers.* The relay read 16 KiB and framed it whole,
  producing a UDP datagram that IP-fragments into ~11 pieces; losing one
  destroyed the lot. 200 KB arrived as 134 KB. `chunk_payload` existed and was
  tested — and was never called from the send path.
- *A race between FRAME_OPEN and FRAME_DATA.* The exit node dialled the origin
  on a thread, and the client's first data frame routinely arrived before that
  dial returned, with nowhere to go. Early frames are now buffered until the
  socket exists.
- *Hard close discarded the response.* On FRAME_CLOSE the proxy closed the
  client socket immediately, destroying data the client had not yet read. Now
  a half-close, which is what TCP's independent directions are for.

Also: UDP socket buffers raised to 2 MiB. The default is small enough that a
descheduled receive thread loses datagrams on loopback under test load.

**Stated plainly in the protocol docstring:** no DoS defence (no cookie
mechanism), no traffic-analysis resistance, no formal verification, and — the
important one — no retransmission. The tunnel carries TCP *stream bytes*
rather than whole IP packets, so a dropped datagram removes bytes from the
middle of a stream with nothing to repair it. Phase 3 is the answer to that.

### Phase 3 — transport: ARQ and congestion control

`netlab/transport/` — the transport-layer chapter, made interactive.

- `impairment.py` — a deliberately bad link: loss, delay, jitter, reordering,
  duplication and a token-bucket bandwidth cap, all seeded. Runs on an
  injected virtual clock, so a 60-second transfer simulates in milliseconds
  and produces an identical trace every run.
- `arq.py` — Stop-and-Wait, Go-Back-N and Selective Repeat behind one
  interface, with cumulative and selective receivers.
- `rtt.py` — Jacobson/Karels SRTT/RTTVAR/RTO, including Karn's algorithm: an
  ACK for a retransmitted segment is ambiguous and must not move the estimate.
- `congestion.py` — TCP Reno: slow start, congestion avoidance, fast
  retransmit, fast recovery, and the asymmetry that matters — three duplicate
  ACKs halve the window, a timeout collapses it to one segment.

Measured, not asserted: Go-Back-N retransmits more than Selective Repeat at
10%, 20% and 30% loss; Stop-and-Wait is more than 3x slower on a long path.

**One defect fixed:** Selective Repeat was initially *slower* than Go-Back-N
despite retransmitting less, because a shared RTO was backed off on every
per-segment timeout, making the protocol progressively deaf. Backoff now fires
only when a segment that was already retransmitted expires again — which is
the situation Karn's algorithm actually describes.

### Phase 4 — concurrency

`oslab/concurrency/` — races, bounded buffers, deadlock, and the GIL.

- `ring.py` — bounded circular buffer with mutex and condition variables, plus
  a `safe=False` mode so the broken version is the same code with one flag
  flipped.
- `pool.py` — instrumented thread pool with per-task timing, Amdahl fitting,
  and a CPU-bound vs I/O-bound scaling comparison.
- `deadlock.py` — a reliable deadlock, a wait-for-graph cycle detector, and
  both standard fixes (lock ordering; timeout with backoff).

**Making the race actually manifest took real work, and the finding is itself
the lesson.** The naive version produced the correct answer 10 times out of
10. In CPython 3.12 the eval-breaker is only checked at call boundaries and
loop back-edges, so a load followed by a store inside one function body is
effectively atomic — an artefact of one interpreter, not a language guarantee.
With a realistic read-compute-write critical section and raised scheduling
pressure, the race appears in 10 runs out of 10; at the default 5 ms switch
interval it hides. That is precisely why races survive testing and appear
under production load.

**The GIL, measured:** at 8 workers, CPU-bound work reaches about 1.3x while
I/O-bound reaches 6.5-7.5x. Threads help exactly when work waits.

**One defect fixed:** the cycle detector reported a cycle for a simple chain —
a false-positive deadlock, which is worse than missing one, because it sends
you hunting a bug that does not exist.

### Phase 5 — DNS

`netlab/dns/` — wire format built and parsed by hand, no dnspython.

- `wire.py` — header, QNAME label encoding, and **compression pointers**,
  which appear in essentially every real response and which a parser that
  ignores them turns into garbage. Pointer loops are capped rather than
  followed forever.
- `resolver.py` — UDP :53 with TCP fallback on truncation, DoT :853 with
  certificate verification, DoH over HTTPS. A response-ID mismatch is rejected
  as the cache-poisoning signature it is.
- `cache.py` — TTL-honouring cache; expiry counts as a miss, because an
  expired answer is not usable.
- `leaktest.py` — resolves a unique random name while watching the physical
  adapter. This is the first thing in the project to actually *check* the
  DNS-leak claim in README.md rather than assert it.

### Phase 6 — path and routing

`netlab/path/` — traceroute, PMTU discovery, longest-prefix match.

- `traceroute.py` — TTL-walking probes built by hand, ICMP Time Exceeded
  parsed and matched to our own probes by identifier and sequence.
- `routing.py` — longest-prefix match with the reasoning preserved, and the
  **split-default trick** explained: `0.0.0.0/1` plus `128.0.0.0/1` cover the
  whole address space and beat `0.0.0.0/0` on prefix length, so all traffic
  enters the tunnel *without* deleting the route that reaches the VPN server.
  Verified: `162.159.192.1/32` correctly escapes via the physical gateway.
- `pmtud.py` — DF-bit binary search, ICMP black holes named, and the
  arithmetic behind the configured MTU of 1280 spelled out.

**One defect fixed:** `traceroute_available()` reported success while every
probe silently timed out. Windows lets an unelevated process *create* a raw
ICMP socket but not use it, so checking construction is a false positive. It
now checks elevation, and falls back to parsing the system `tracert`.

### Phases 7-8 — IPC, scheduling, memory, resilience

- `oslab/ipc/framing.py` — length-prefixed framing with partial-read
  reassembly and a size cap checked *before* allocating, so a peer announcing
  4 GB cannot make us try.
- `oslab/scheduling/algorithms.py` — FCFS, SJF, Round Robin and Priority over
  real measured probe durations, with Gantt rendering. SJF wins average
  waiting time, RR wins response time, FCFS shows the convoy effect, and aging
  rescues a starving job.
- `oslab/memory/bufferpool.py` — slab allocator with reuse and fragmentation
  statistics, plus a zero-copy `memoryview` comparison (116 MB copied versus
  zero).
- `oslab/resilience/singleton.py` — cross-process lock via `msvcrt.locking` /
  `flock`, released by the OS even on SIGKILL. **Fixed during testing:** the
  Windows lock was taken at byte 0, and because Windows locks are mandatory
  rather than advisory, that made the file's own diagnostics unreadable. The
  lock now sits at offset 4096.
- `oslab/resilience/signals.py` — ordered teardown where one failure does not
  stop the rest, Windows console-control handling, the Qt nudge timer that
  makes Ctrl+C work under an event loop, and a crash-recovery journal for the
  cases where nothing runs at all.

### The six dead settings are now live

Every one was written by the Settings dialog and read by nothing:

| Setting | Now controls |
|---|---|
| `thread_count` | pool size for the latency scan (`speedtest_utils.py`) |
| `keepalive_interval` | tunnel keepalive, clamped to 5-120 s |
| `connection_timeout` | handshake timeout, clamped to 1-60 s |
| `mtu_size` | inner payload per datagram, clamped to 576-1432 |
| `custom_dns` / `primary_dns` / `secondary_dns` | resolver upstream servers |

Each is clamped, because the dialog permits values that would break the tunnel
outright.

### GUI

`python main.py --labs` opens five tabs: Dissector, Network, Transport,
Concurrency, OS Lab. Panels are imported individually and guarded, so one
failing to construct costs its own tab rather than the whole window. Every
panel works offline; anything needing a driver, network or privileges degrades
with an explanation rather than an exception.

### Tests

155 to 448, all passing, with no admin rights and no network.

### Not done

- Documentation (`docs/concepts/`) — deferred by agreement, to be written last.
- Phase 7's privilege-separated daemon ships as the IPC framing layer only.
  The named-pipe transport and the elevated helper process are not built: that
  work creates a real privilege boundary and warranted review before running
  anything elevated.
- No panel screenshots. Headless Qt renders layout correctly but without
  fonts, so the images were worthless as evidence.
- **Wireshark did not install.** `winget install WiresharkFoundation.Wireshark`
  ran for several hours and then failed with MSI error 1603, "Install server
  not responding" — the installer needed an elevation prompt that nobody was
  awake to approve. Note that winget itself exited 0 despite the failure, so
  the exit code is not a reliable signal here.

  Consequences, none of them blocking:
  - `tshark` is still unavailable, so the dissector's independent cross-check
    continues to use Scapy 2.6.1 as its reference. That is weaker (both are
    Python) but genuinely independent of this codebase, and it is declared as
    such in `tests/test_capture.py`.
  - Npcap remains present but enumerates only `\Device\NPF_Loopback`, so live
    capture on a physical NIC still does not work and the Tunnel Comparison
    demo cannot run. Everything else in the dissector works from the committed
    `.pcap` fixtures.

  To fix, run this interactively and approve the prompt:

      winget install --id WiresharkFoundation.Wireshark -e

  choosing "Install Npcap in WinPcap API-compatible mode", then reboot.

---

## Phase 1 — capture layer, fixtures, panel (2026-09-17)

Completes the Gate 3 deliverables.

### New

- `netlab/dissect/capture.py` — `PcapFileCapture` (hand-written libpcap
  reader, stdlib only), `LiveCapture` (Scapy/Npcap, used only to deliver raw
  bytes — every header is still decoded by our own decoders), `write_pcap`,
  and `live_capture_available()`.
- `docs/samples/` — three committed `.pcap` fixtures plus their golden decodes
  and the scripts that regenerate both.
- `gui/panels/dissector_panel.py` — packet list, layer tree, and a hex dump
  that highlights exactly the bytes of the selected field via
  `FieldView.byte_offset` / `byte_length`.
- `tests/test_capture.py` — 43 tests: pcap format, golden decodes, and a
  field-by-field cross-check against Scapy.

### Why the pcap reader is hand-written

The libpcap format is itself part of the syllabus — the magic number carries
the writing host's byte order, and `incl_len < orig_len` is snaplen truncation
made visible. Parsing it by hand also keeps offline mode dependency-free, so
the panel works with no capture driver installed.

### Defect — fragmented TCP segments were flagged corrupt

A TCP checksum covers the whole reassembled segment, so it can never validate
against fragment 0 alone. The dispatcher was verifying it anyway, flagging
every fragmented datagram as corrupt. `decode_tcp` now takes
`checksum_verifiable`, and the field's description explains why verification
was skipped rather than silently showing nothing.

### Defect — the live-capture check was too optimistic

`live_capture_available()` reported "1 adapter(s) available" on this machine,
but `get_if_list()` returns only `\Device\NPF_Loopback` — no physical NIC. The
user would have discovered that mid-demo. It now distinguishes loopback-only
from genuinely usable and says what to do about it (plan trap §7.3).

### Fixture note

`make_samples.py` sets `proto=6` explicitly on the fragment fixtures. Scapy
defaults `IP.proto` to 0 when the payload is `Raw`, which made the
later-fragment test pass for the wrong reason — the chain stopped because the
protocol was unknown, not because the fragment check fired.

### Tests

112 → 155, all offline, no admin, no network.

### Not done

- **Panel screenshot.** Rendering under `QT_QPA_PLATFORM=offscreen` produces
  correct layout but no glyphs (no fonts in the headless environment), so the
  image was worthless as evidence and was deleted. Needs a desktop run:
  `python main.py --labs`.
- **tshark cross-check.** The Wireshark install did not complete (see below);
  Scapy 2.6.1 was used as the independent reference instead.
- **Tunnel Comparison demo.** Needs live capture on a physical NIC, which this
  machine cannot currently do.

---

## Phase 1 — dissector split by OSI layer + two decoder fixes (2026-09-17)

### Split

`headers.py` was 861 lines against the plan's ~400 ceiling. Split **by OSI
layer** rather than one file per protocol, so the file structure itself mirrors
the encapsulation model the module exists to teach:

| File | Layer | Contents | Lines |
|---|---|---|---|
| `tables.py` | — | protocol number → name lookups | 67 |
| `checksums.py` | — | RFC 1071 checksum, pseudo-headers | 40 |
| `_fields.py` | — | `_fv()` FieldView builder | 36 |
| `link.py` | L2 | Ethernet II, 802.1Q | 100 |
| `internet.py` | L3 | IPv4, IPv6, ICMP/ICMPv6 | 322 |
| `transport.py` | L4 | TCP (+options), UDP | 278 |
| `dispatch.py` | — | `decode_packet` chain | 130 |
| `headers.py` | — | facade re-exporting everything | 61 |

`headers.py` keeps every existing import path working; new code may import
from the layer module directly.

### Defect — every small TCP packet showed a false BAD CHECKSUM

TCP has no length field of its own, so the checksum's pseudo-header needs the
segment length from IP. The decoder used `len(hdr)` — "the rest of the buffer"
— instead. Ethernet pads frames to 60 bytes, so any segment under ~54 bytes
carries trailing padding that got folded into the checksum:

```
unpadded   is_bad = False
PADDED     is_bad = True     <- every SYN, ACK and FIN on a real capture
```

`decode_tcp()` now takes an explicit `transport_length`, supplied by the
dispatcher as `ip.total_length - ip.header_length`. UDP was already correct
(it has its own length field); ICMPv6 now receives the same treatment.

This would have been maximally confusing in a viva — the three-way handshake
is the first thing anyone captures, and all three packets would have been
flagged corrupt.

### Defect — literal `{hlen}` shown in the panel

The TCP `data_offset` description spanned two string literals and only the
first carried the `f` prefix, so the second rendered verbatim:

```
Data offset: 5×32-bit words = 20 B. Length of the TCP header; payload starts at byte {hlen}.
```

Fixed, with a test asserting no field description in any decoder contains `{`.

### Regression — RFC 3514 wording returned

The Gate 2 correction to the `reserved_flag` description was lost in the
rewrite and had reverted to presenting the April Fools' "evil bit" as the
normative definition. Restored.

### Tests

109 → 112. Added `TestEthernetPaddingChecksum` and
`TestDescriptionsAreRendered`. All six decoders re-verified against Scapy after
the split: Ethernet, VLAN, IPv4, IPv6, TCP (+options), UDP, ICMP, ICMPv6 — no
bad checksums on any valid packet.

---

## Phase 1 — Gate 3 review fixes (2026-09-17)

Cross-verified the six decoders against Scapy 2.6.1 as an independent
reference. Ethernet (incl. 802.1Q), IPv4, IPv6, TCP (options + pseudo-header
checksum), UDP and ICMP/ICMPv6 all decode correctly. Two defects found.

### Defect — `carries_transport_header()` was dead code

`decode_packet()` went straight from the IPv4 protocol field to
`decode_tcp`/`decode_udp`/`decode_icmp` without ever consulting it, so a
non-first fragment's raw payload was decoded as a transport header. A 20-byte
chunk of arbitrary payload parses as an entirely plausible TCP header, so the
panel would have shown invented ports and sequence numbers with no error.

This is the same defect raised at Gate 2. The helper was added then; nothing
ever called it.

Note on how it was missed: the Gate 2 hand-probe used `\xde\xad\xbe\xef` as the
fragment payload, which fails to decode as TCP on its own (its data-offset
nibble demands 52 bytes) — so the chain stopped for the wrong reason and the
probe looked like a pass. The regression test now uses a *valid* TCP header as
the fragment payload, which is the only version of the test that can fail.

### Defect — `notes` dropped from `Layer.to_dict()`

Fragmentation state decides whether a transport layer appears at all, so a
golden file omitting `notes` cannot distinguish "no TCP layer because this is a
fragment" from "no TCP layer because the decoder broke". Restored.

### Smaller correction

- `decode_packet` built the IPv6 source address twice: first by stripping
  colons from the display string (wrong — that cannot handle `::` compression),
  then immediately overwriting it with the correct `inet_pton` result. Removed
  the dead first assignment.

### Verified correct against Scapy, no change needed

- TCP checksum over the IPv4 pseudo-header, and ICMPv6 checksum over the IPv6
  pseudo-header — both easy to get wrong, both right.
- TCP options parser: MSS, Window Scale, SACK-Permitted, Timestamps, NOP, EOL.
  The `length < 2` guard correctly prevents the classic malformed-option
  infinite loop.
- UDP checksum of 0 on IPv4 is correctly *not* flagged bad (RFC 768: zero means
  the sender did not compute one).
- 802.1Q VLAN tag handling, including `payload_offset` extending 14 → 18.
- IPv6 `::` compression round-trips through the dispatcher.

### Tests

104 → 109. Added `TestUDPZeroChecksum`, `TestFragmentChaining`,
`TestNotesSerialisation`.

---

## Phase 1 — Gate 2 review fixes (2026-09-17)

Applied after cross-verification of the Gate 2 report (Layer/FieldView model +
IPv4 reference decoder).

### Defect — the three one-bit IPv4 flags highlighted the wrong bytes

`reserved_flag`, `df_flag` and `mf_flag` each live entirely inside header byte
6, but all three carried `hdr[6:8]` — the full two-byte flags+frag_offset word
— as `raw_bytes`. Their `bit_offset`/`bit_length` said one byte; `raw_bytes`
said two. The hex-dump panel highlights `len(raw_bytes)`, so DF would have
highlighted one byte too many with nothing to catch it. Only `frag_offset`
genuinely spans both bytes.

Root cause is that `raw_bytes` and `(bit_offset, bit_length)` were independent
descriptions of the same span with nothing tying them together. Added a
`FieldView.__post_init__` invariant requiring `len(raw_bytes) == byte_length`,
so a decoder cannot construct a disagreeing field at all.

### Defect — fragmented packets would decode into nonsense

Only fragment 0 carries the TCP/UDP header; fragments 1..n hold raw payload.
Nothing exposed this, so the decode chain (Phase 1 continuation) would have
handed a later fragment's bytes to `decode_tcp()` and produced convincing
garbage. Added `Layer.notes` plus `Layer.carries_transport_header()`, which the
chain must check before descending.

### Defect — Total Length was unvalidated

A header claiming `total_length` smaller than its own IHL-declared length
decoded happily and reported a negative payload size. Now rejected.
Deliberately *not* rejected: `total_length` shorter than the buffer, which is
legitimate — Ethernet pads frames to 60 bytes and snaplen truncates captures.

### Smaller corrections

- The `reserved_flag` description led with RFC 3514 (the April Fools' "evil
  bit") as though it were the normative definition. Now leads with RFC 791,
  which is what actually requires the bit to be zero, with 3514 marked as the
  joke it is. This text is read aloud in the viva.
- `Layer.payload_offset` docstring contradicted itself: it said "offset within
  raw_bytes" while `raw_bytes` holds the header only, making the value always
  equal to `len(raw_bytes)`. Reworded to describe its real use — locating the
  next layer in the frame buffer.
- Removed dead locals `byte0` / `byte1` and unused imports (`struct`, `asdict`
  in model.py; `Sequence` in headers.py).

### Verified as correct, no change needed

- IPv4 one's-complement checksum: hand-derived 0x1487 for the reference packet
  and confirmed a valid header checksums to 0.
- `_extract_bits` big-endian bit ordering, including the 13-bit `frag_offset`
  spanning two bytes.
- ECN codepoint mapping — `ECT(0)` is binary 10 and `ECT(1)` is binary 01,
  which is easy to get backwards and was right.
- Malformed-input rejection: short buffer, wrong version, IHL < 5, IHL beyond
  buffer.

### Tests

45 → 104. New `tests/test_headers.py` covers `_extract_bits`, the FieldView
invariant, checksum verification including a corrupted packet, all 15 IPv4
fields with their bit layout, IHL=6 variable-length options, six malformed
inputs, fragmentation, and JSON serialisation.

### Open — blocks Gate 3

`tshark` is not installed on this machine, so Gate 3's independent-decoder
cross-check has no reference. Installing Wireshark supplies both tshark and
Npcap (needed for Phase 1 live capture anyway). Plan updated with that and a
Scapy-based fallback.

---

## Phase 0 — Gate 1 review fixes (2026-09-17)

Applied after cross-verification of the Gate 1 report. Findings B1, N3, N4 and
N5 from that review.

### B1 — `atomic_write_json` is now actually used

It was written and unit-tested in Phase 0 but wired into nothing; all seven
production writers still wrote non-atomically. Rerouted (standing stop 1
waived for these call sites only):

- `gui/settings_panel.py` — settings save, config export, factory reset
- `vpn_core/real_windows_wireguard.py` — `_create_default_servers()`
- `vpn_core/simple_vpn_handler.py` — `_create_default_servers()`
- `vpn_core/wireguard_handler.py` — `_create_default_servers()`
- `setup.py` — `update_server_config()`

`grep -rn "json.dump(" --include=*.py .` now returns no production hits.

### N4 — durability, not just atomicity

`atomic_write_json()` wrote the temp file and immediately renamed it. That
gives atomicity (a reader never sees a torn file) but **not** durability: after
a power loss the rename can be recorded while the contents are still in the
page cache, leaving an atomically-renamed empty file. Added `flush()` +
`os.fsync()` before the replace, plus a best-effort parent-directory fsync
(POSIX only; no-op on Windows). The docstring previously implied the rename
alone gave both guarantees — corrected to distinguish them, since this is the
exact distinction Module J is meant to teach.

### N5 — unique temp filenames

The temp path was a fixed `<name>.tmp`, so two processes saving the same config
would share one temp file and clobber each other. Now
`<name>.<pid>.<random>.tmp`. The two tests that hardcoded the old name were
passing vacuously; they now glob for any leftover `*.tmp`.

### N3 — elevation guard now matches argparse

`_LABS_MODE = "--labs" in sys.argv` was an exact-string match, but argparse
accepts unambiguous prefixes. `python main.py --lab` therefore triggered UAC
elevation *and then* ran Labs mode with Administrator rights it does not need.
Replaced with `_labs_requested()`, which mirrors argparse's abbreviation rules
and stops at a `--` separator.

### Tests

32 → 45. Added `TestLabsElevationGuard`: 12 parametrised abbreviation cases
plus an end-to-end check that `main.py --labs --help` exits 0 and prints usage
without elevating.

Not code fixes, for the record: findings B2 (undisclosed `RealWindowsOps`
stubs), B3 (missing gate evidence) and N1 (line counts estimated rather than
measured) were reporting defects, not defects in the code.

---

## Phase 0 — Foundation (2026-09-17)

CN + OS Concept Revamp — foundation layer. All work is additive; no existing
VPN path code was restructured.

### New files
- `oslab/__init__.py` — OS-concept package root (`__version__ = "0.1.0"`)
- `oslab/daemon/__init__.py` — package marker
- `oslab/daemon/ops.py` — `PlatformOps` Protocol, `FakeOps` (canned/testable),
  stub `RealWindowsOps` (bodies deferred to Phase 7 / Module F)
- `oslab/resilience/__init__.py` — package marker
- `oslab/resilience/atomicio.py` — `atomic_write_json()`: write-temp-then-`os.replace`
- `netlab/__init__.py` — CN-concept package root (`__version__ = "0.1.0"`)
- `gui/labs_window.py` — stub `LabsWindow` (placeholder tab; panels added per phase)
- `gui/panels/__init__.py` — package marker
- `tests/__init__.py` — package marker
- `tests/conftest.py` — `fake_ops` pytest fixture
- `tests/test_foundation.py` — Phase 0 acceptance tests (Protocol, FakeOps,
  atomicio crash-safety, package imports)

### Modified files
- `main.py` — added `--labs` flag + `run_labs_mode()` + elevation bypass for
  `--labs` (offline demo requires no admin rights)
- `requirements.txt` — added `scapy>=2.5.0` (Phase 1 dissector) and
  `pyqtgraph>=0.13.0` (Phase 3 transport plots) with justification comments

### Settings wired this phase
_(none — settings are wired in their respective phases per the plan)_

---

# OnamVPN — Changes (2026-07-30)

This documents a cleanup pass over the codebase: dead code removal, bug fixes
that reconnect Settings options to actual behavior, git hygiene around
committed secrets, and a UI redesign with a proper light/dark theme system.

## Bug fixes

- **Crash on non-Windows platforms** (`main.py`) — the admin-elevation check
  called `ctypes.windll` unconditionally at import time, which doesn't exist
  off Windows. The app now only attempts UAC elevation when
  `platform.system() == 'Windows'`, so the Linux/macOS code paths that were
  previously unreachable can actually run.
- **Ping results were discarded** (`gui/server_grid.py`) — `PingTestThread`
  measured each server's real ping time but then overwrote the final
  `ping_complete` signal payload with `-1` for every server. It now emits the
  real measured times.
- **Kill switch / DNS leak protection ignored their checkboxes**
  (`vpn_core/real_windows_wireguard.py`) — `connect_to_server()` always
  enabled both firewall protections regardless of what the user chose in
  Settings. It now reads `config/settings.json` (`killswitch`,
  `dns_leak_protection`) and only enables what's turned on.
- **`log_to_file` / `log_level` settings had no effect** (`vpn_core/logger.py`,
  `main.py`) — logs were always written to disk at INFO level no matter what
  Settings said. `setup_logger()` now takes `log_to_file`, and `main.py` reads
  the saved log level/file preference from `config/settings.json` (with
  `--verbose` always forcing DEBUG).
- **`auto_connect` setting had no effect** (`gui/main_window.py`) — the app
  already auto-connected to the fastest pinged server on every launch,
  unconditionally, regardless of the "Auto-connect to last server" checkbox.
  `on_auto_connect_best()` now checks `self.settings["auto_connect"]` first.
  The dead `try_auto_connect()` method (defined, never called) was removed.
- **Settings dialog changes didn't stick until restart**
  (`gui/main_window.py`) — saving Settings applied the new theme/language but
  never updated `MainWindow.settings` in memory, so `auto_connect`,
  `show_notifications`, etc. stayed on their old values until the app was
  relaunched. `show_settings()` now refreshes `self.settings` on save.
- **Dark mode didn't reach server cards or the Settings dialog** — both hard
  coded their own light-mode colors, ignoring the selected theme. Fixed as
  part of the UI redesign (see below).
- **`wg set wg0 private-key <file>` misuse**
  (`vpn_core/wireguard_handler.py`) — the Windows branch passed a full
  generated `.conf` file to `wg set ... private-key`, which expects a file
  containing only the raw key. This code path was unreachable in practice
  (Windows always uses `RealWindowsWireGuard`), so it was removed rather than
  fixed; the class now always uses the correct `wg-quick` invocation, which is
  the actually-reachable path on Linux/macOS.
- Fixed a `SyntaxWarning: invalid escape sequence '\O'` in a docstring in
  `real_windows_wireguard.py` (`C:\OnamVPN` in a non-raw string).

## Dead code removed

- `vpn_core/encryption_utils.py` — `EncryptionManager`, `HashUtils`,
  `KeyGenerator`, `SecureConfig` (~360 lines). Never imported anywhere.
- `vpn_core/windows_wireguard.py` — `WindowsWireGuard`. Imported in
  `main.py` but never instantiated.
- `_load_or_create_client_keys`, `_load_or_create_server_keys`,
  `_update_server_peer_key`, `_read_private_key_from_conf` in
  `real_windows_wireguard.py` — defined, never called, and incompatible with
  the current design anyway (the app connects via a fixed, pre-registered
  Cloudflare WARP key; per-server generated keys would fail the WARP
  handshake).
- `try_auto_connect()` in `gui/main_window.py` — superseded by the (now
  correctly gated) `on_auto_connect_best()`.
- Duplicate theme/language application in `MainWindow.__init__` (theme and
  language were each applied twice via redundant file re-reads).
- Unused `ServerGrid._ping_results` / `_ping_remaining` attributes.
- The broken/unreachable Windows-specific `wg set` branches in
  `wireguard_handler.py` (see bug fix above).

## Git hygiene

- Added `.gitignore` (didn't exist before) covering `__pycache__/`, `venv/`,
  `keys/`, `config/client_keys/`, `config/server.key`, `config/*.conf`, and
  logs.
- Untracked from git (files remain locally, just no longer version controlled
  going forward):
  - `keys/client_private.key`, `keys/server_private.key` and their public
    counterparts — **real WireGuard private keys were committed to the
    repo**.
  - `config/OnamVPN-eu-frankfurt.conf`, `config/eu-frankfurt_client.conf` —
    generated tunnel configs that embedded a private key.
  - All `__pycache__/*.pyc` files.
- **Not done, needs your call:** this only stops *future* commits from
  including these files — the exposed keys are still present in the existing
  git history. Rewriting history is destructive and wasn't done without
  explicit sign-off. If this repo is ever pushed anywhere shared, treat those
  keys as compromised and regenerate them.

## UI redesign

Added `gui/theme.py` as the single source of truth for styling:

- Light/dark color palettes (background, surface, border, text, accent,
  success/warning/danger/info) instead of hex codes scattered across three
  files.
- `apply_qpalette()` sets a real `QPalette` on the `QApplication`, so native
  dialogs (`QMessageBox`, `QFileDialog`) also follow the theme, not just
  custom-styled widgets.
- `app_stylesheet()` is one QSS blob applied at the **`QApplication` level**
  (not per-window), so it automatically reaches the Settings dialog and any
  message boxes without each needing separate wiring.
- Semantic button variants (`primary`/`danger`/`info`/`ghost`) via a
  `variant` Qt property + `set_variant()` helper, instead of each button
  hardcoding its own inline stylesheet.
- `card_stylesheet()` / `ping_label_style()` for server cards, explicitly
  theme-aware (Qt doesn't cascade a widget's own inline stylesheet, so this
  needed explicit propagation — `ServerGrid.set_theme()` →
  `ServerCard.set_theme()` on every card).
- `main.py` now sets `QApplication.setStyle("Fusion")`, which is required for
  the QSS + QPalette combination to render consistently on Windows (the
  default native style ignores large parts of both).

Visible changes: indigo accent color, rounded server cards with a real
selected/hover state, a connection status "pill" that recolors by state
(connecting/connected/stale/disconnected/failed) while still respecting the
active theme, semantic button coloring, and a shield emoji in the header.
Switching Light ⇄ Dark in Settings now actually restyles every widget in the
app, including ones inside the Settings dialog itself.

## Verification

- `python -m py_compile` on all touched files — clean.
- Imported every touched module directly (`vpn_core.*`, `gui.*`) — no
  import-time errors.
- Ran an offscreen Qt smoke test: constructed `MainWindow` with
  `SimpleVPNHandler`, switched Dark → Light → Dark, opened the Settings
  dialog, selected a server card — no exceptions.
- Did not run `main.py` itself (it triggers a real UAC elevation prompt) or
  test against real WireGuard/Cloudflare WARP infrastructure.

## Known, intentionally unchanged

- `WARP_PRIVATE_KEY` in `real_windows_wireguard.py` is a single hardcoded key
  shared by every install of the app — every user connects to Cloudflare WARP
  as the same registered device. This is inherent to the current
  WARP-based design; a per-user identity would require a real registration
  flow (like `wgcf register`) and wasn't in scope for this pass.
