# 05 — Code and Architecture

Questions about how the code is organised, what each class does, and how the pieces fit
together. This is the "show me the code" section.

---

## A. Layout and structure

**Q1. What are the top-level packages and what does each contain?**

| Package | Contents |
|---|---|
| `netlab/` | Computer Networks modules — `dissect`, `native`, `transport`, `dns`, `path` |
| `oslab/` | OS modules — `concurrency`, `scheduling`, `memory`, `resilience`, `ipc`, `daemon` |
| `vpn_core/` | The original WireGuard client: handlers, logger, speedtest |
| `gui/` | Qt UI — main window, labs window, five panels, server grid, settings, theme |
| `config/` | `servers.json`, `settings.json` |
| `docs/` | `concepts/` (9 pages), `samples/` (pcaps + goldens), `brand/`, `qna/` |
| `tests/` | 457 tests across 9 files |
| `system_design/` | 8 architecture diagrams as `.dot`, `.svg`, `.png`, `.pdf` |

**Q2. Why is `netlab/dissect` split into `link.py` / `internet.py` / `transport.py`?**
So the file structure is itself the lesson — the files are named for the OSI layer they
decode. Encapsulation is visible in the directory listing before you open a file.

**Q3. What is `headers.py` for if the decoders live elsewhere?**
It is a **facade** re-exporting everything, so callers have one import surface while the
implementation stays split by layer.

**Q4. What is `_fields.py`?**
A private helper (`_fv`) that builds a `FieldView` from a header buffer plus a bit offset
and length — the single place that keeps `raw_bytes` and the bit span consistent.

---

## B. The dissector's data model

**Q5. What are the three model types?**
- `FieldView` — one decoded field: value, description, `raw_bytes`, and `(bit_offset, bit_length)`.
- `Layer` — one protocol header: a named, ordered collection of `FieldView`s.
- `DecodedPacket` — the chain of layers produced from one frame.

**Q6. What invariant does `FieldView.__post_init__` enforce, and why?**
`len(raw_bytes) == byte_length`. Without it, the hex-dump highlight can drift away from the
decoded value with nothing to catch it.

**Q7. What does `model._extract_bits` do?**
Pulls an integer out of an arbitrary bit range — used for sub-byte fields such as the IPv4
version/IHL nibbles and the three fragment flags.

**Q8. How does `dispatch.decode_packet` work?**
It takes a frame and an `l2` flag, decodes Ethernet (or starts at L3 if `l2=False`), then
chains: EtherType → `decode_ipv4` / `decode_ipv6`, IP protocol number → `decode_tcp` /
`decode_udp` / `decode_icmp`, guarding against descending into a later IP fragment.

**Q9. What is `tables.py`?**
Protocol-number → name lookups: EtherTypes, IP protocol numbers, ICMP types and codes, TCP
flag names.

**Q10. What does `capture.py` provide?**
`PcapFileCapture` (offline replay), `LiveCapture` (Npcap-backed), `write_pcap`,
`live_capture_available()` and `list_adapters()`, plus `CaptureBackendUnavailable`. It also
defines a `PacketSource` `Protocol`, so offline and live sources are interchangeable.

**Q11. Why is `PacketSource` a `typing.Protocol` rather than a base class?**
Structural typing — anything with the right methods is a valid source, so the panel does not
care whether bytes come from a file, Npcap, or a test fixture.

---

## C. The native tunnel's modules

**Q12. What does each file in `netlab/native/` do?**

| File | Responsibility |
|---|---|
| `protocol.py` | The wire format only: constants, byte layout, pack/unpack. **No crypto, no sockets.** |
| `crypto.py` | X25519, HKDF chaining, ChaCha20-Poly1305, the handshake key schedule |
| `replay.py` | The RFC 6479 sliding-window replay filter |
| `session.py` | Keys, send/receive counters, rekey policy, `PeerState` |
| `endpoint.py` | UDP client and server sockets, the receive loop |
| `socks5.py` | The SOCKS5 front end (TCP) |
| `runner.py` | Wires client + server together for the end-to-end demo |
| `settings.py` | Tunnel configuration |

**Q13. Why does `protocol.py` deliberately contain no crypto and no sockets?**
So the specification is separable from the implementation: the byte layout can be read,
tested and asserted on its own, and a change to the crypto cannot silently change the wire
format.

**Q14. How does `protocol.py` prevent its documentation from drifting?**
`SIZE_INIT = struct.calcsize(FMT_INIT)` and friends are asserted against the documented
sizes at **import time** — 132, 76, 16, 7 bytes.

**Q15. Name the main protocol constants.**
```
PROTOCOL_NAME  = b"OnamVPN-v1 X25519 ChaCha20Poly1305 BLAKE2s"
PROLOGUE       = b"OnamVPN native tunnel"
MSG_HANDSHAKE_INIT = 1   MSG_HANDSHAKE_RESP = 2
MSG_COOKIE_REPLY   = 3   (reserved, not implemented)
MSG_TRANSPORT_DATA = 4
KEY_SIZE = 32   TAG_SIZE = 16   MAC_SIZE = 16
NONCE_SIZE = 12  TIMESTAMP_SIZE = 12  HASH_SIZE = 32
MAX_TUNNEL_PAYLOAD = 1280      MAX_FRAME_PAYLOAD = 0xFFFF
KEEPALIVE_SECONDS = 25
REKEY_AFTER_MESSAGES  = 2**20  REJECT_AFTER_MESSAGES = 2**24
REKEY_AFTER_SECONDS   = 120    REJECT_AFTER_SECONDS  = 180
HANDSHAKE_TIMEOUT_SECONDS = 5  REPLAY_WINDOW_BITS = 1024
```

**Q16. What are the four inner frame kinds?**
`FRAME_OPEN = 1` (payload is `host:port`), `FRAME_DATA = 2`, `FRAME_CLOSE = 3` (half or full
close), `FRAME_KEEPALIVE = 4`.

---

## D. The transport lab's modules

**Q17. What does each file in `netlab/transport/` do?**

| File | Responsibility |
|---|---|
| `impairment.py` | `Clock` (virtual), `ImpairedLink` (loss, delay, jitter, bandwidth, reorder, duplicate), `LinkStats` |
| `arq.py` | `ArqSender` ABC + `StopAndWait`, `GoBackN`, `SelectiveRepeat`; `CumulativeReceiver`, `SelectiveReceiver` |
| `rtt.py` | `RttEstimator` — SRTT, RTTVAR, RTO, Karn, backoff |
| `congestion.py` | `RenoController`, `CongestionState`, `CongestionEvent`, `bandwidth_delay_product` |
| `harness.py` | `TransferConfig`, `TransferResult`, `run_transfer`, `compare_protocols` |

**Q18. Why is `ArqSender` an abstract base class?**
The three protocols differ only in windowing, ACK handling and timer policy. Putting the
shared transfer loop in the ABC makes the *differences* the readable part.

**Q19. Why is `Clock` injected rather than imported?**
So nothing calls `time.time()`. That is what makes a 60-second transfer simulate in
milliseconds, never flake on a loaded machine, and produce a byte-identical trace per seed.

**Q20. What does `compare_protocols` do?**
Runs all three ARQ protocols over an **identical** link (same seed, same impairments) so the
comparison is like for like.

---

## E. The DNS and path modules

**Q21. What does each file in `netlab/dns/` do?**
`wire.py` — encode/decode of the RFC 1035 message format (`encode_name`, `decode_name`,
`build_query`, `parse_message`, `Message`, `Question`, `Record`).
`resolver.py` — `Resolver` with UDP/TCP/DoT/DoH, `Answer`, `configured_servers()`.
`cache.py` — `DnsCache`, `CacheEntry` with TTL expiry and capacity eviction.
`leaktest.py` — `run_leak_test`, `unique_query_name`, `compare_plain_and_encrypted`.

**Q22. What are the DNS defaults?**
`DEFAULT_SERVERS = ("1.1.1.1", "1.0.0.1")`, `DOH_URL =
"https://cloudflare-dns.com/dns-query"`, `DOT_HOST = "1.1.1.1"`, `DOT_PORT = 853`,
`DOT_SERVER_NAME = "cloudflare-dns.com"`.

**Q23. What does each file in `netlab/path/` do?**
`traceroute.py` — `checksum`, `build_echo_request`, `Hop`, `TracerouteResult`,
`traceroute()`, `system_traceroute()`, `traceroute_auto()`, `traceroute_available()`.
`routing.py` — `Route`, `LookupResult`, `parse_windows_route_print`,
`longest_prefix_match`, `describe_split_default`.
`pmtud.py` — `discover_path_mtu`, `tunnel_overhead`, `recommended_tunnel_mtu`,
`explain_mtu_choice`.

**Q24. What is `traceroute_auto` for?**
It picks the raw-socket path when elevated and falls back to parsing the system `tracert`
when not — so the panel works either way and the mechanism demonstrated is identical.

**Q25. What are the PMTUD constants?**
`IPV4_HEADER = 20`, `IPV6_HEADER = 40`, `UDP_HEADER = 8`, `ICMP_HEADER = 8`,
`WIREGUARD_OVERHEAD = 32`, `MIN_PROBE = 576` (RFC 791 minimum every IPv4 host must accept),
`MAX_PROBE = 1500`, `IPV6_MIN_MTU = 1280`, `CODE_FRAGMENTATION_NEEDED = 4`.

---

## F. The OS lab's modules

**Q26. What does each file in `oslab/` do?**

| File | Key symbols |
|---|---|
| `concurrency/ring.py` | `BoundedRing`, `SharedCounter`, `RingStats` |
| `concurrency/pool.py` | `InstrumentedPool`, `amdahl_speedup`, `estimate_serial_fraction`, `measure_scaling`, `compare_workload_scaling`, `cpu_bound_task`, `io_bound_task` |
| `concurrency/deadlock.py` | `WaitForGraph`, `run_deadlock_demo`, `run_ordered_demo`, `run_timeout_recovery_demo` |
| `scheduling/algorithms.py` | `Job`, `Slice`, `ScheduleResult`, `schedule_fcfs/sjf/round_robin/priority`, `compare_algorithms`, `jobs_from_measurements` |
| `memory/bufferpool.py` | `BufferPool`, `Buffer`, `PoolStats`, `PoolExhausted`, `compare_allocation_strategies`, `demonstrate_zero_copy` |
| `resilience/singleton.py` | `SingleInstance`, `AlreadyRunning` |
| `resilience/signals.py` | `TeardownRegistry`, `TeardownHandler`, `install_handlers`, `install_qt_nudge`, `Journal` |
| `resilience/atomicio.py` | `atomic_write_json` |
| `ipc/framing.py` | `encode_frame`, `decode_frame`, `read_exactly`, `read_frame`, `FrameBuffer`, `FramingError` |
| `daemon/ops.py` | `PlatformOps`, `FakeOps`, `RealWindowsOps` (stubbed) |

**Q27. Why does the scheduler take `jobs_from_measurements`?**
So the job set comes from **real measured probe durations** rather than invented numbers —
which is what makes the comparison a measurement rather than an illustration.

---

## G. The VPN client

**Q28. What are the three handlers and when is each chosen?**

| Handler | Platform | Chosen when |
|---|---|---|
| `RealWindowsWireGuard` | Windows | `test_wireguard_installation()` succeeds |
| `WireGuardHandler` | Linux / macOS | `test_wireguard_installation()` succeeds |
| `SimpleVPNHandler` | Any | Fallback — WireGuard missing or handler construction raised |

**Q29. Write the selection logic.**
```python
if platform.system() == 'Windows':
    try:
        handler = RealWindowsWireGuard()
        vpn_handler = handler if handler.test_wireguard_installation() else SimpleVPNHandler()
    except Exception:
        vpn_handler = SimpleVPNHandler()
else:
    try:
        handler = WireGuardHandler()
        vpn_handler = handler if handler.test_wireguard_installation() else SimpleVPNHandler()
    except Exception:
        vpn_handler = SimpleVPNHandler()
```

**Q30. What design pattern is that, and what does it buy?**
Polymorphism behind a common interface. `MainWindow` never branches on platform — it calls
`connect()`, `disconnect()`, `get_connection_status()` and the handler decides how.

**Q31. What is `SimpleVPNHandler` for?**
A demo/fallback handler requiring no WireGuard install — simulated VPN behaviour so the GUI
is demonstrable on any machine.

**Q32. What are the connection states?**
```python
class ConnectionState(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING   = "connecting"
    CONNECTED    = "connected"
    IDLE         = "idle"
    DISCONNECTING = "disconnecting"
    ERROR        = "error"
```

**Q33. Give the state transitions and their durations.**

| From | To | Trigger | Duration |
|---|---|---|---|
| DISCONNECTED | CONNECTING | `connect()` | < 1 s |
| CONNECTING | CONNECTED | Success | 10–30 s |
| CONNECTING | ERROR | Failure | 1–30 s |
| CONNECTED | IDLE | Inactivity | 5 min+ |
| IDLE | CONNECTED | Activity | < 1 s |
| CONNECTED/IDLE | DISCONNECTING | `disconnect()` | < 1 s |
| DISCONNECTING | DISCONNECTED | Complete | 5–10 s |
| ERROR | DISCONNECTED | Reset/Retry | < 1 s |

**Q34. Walk through a connection.**
1–3: user clicks Connect, server validated, WireGuard checked (< 1 s).
4–6: keypair generated (`wg genkey`), config written with Interface and Peer sections, saved
with 0600 permissions (2–5 s).
7–9: background thread started, `wg-quick up` executed — creates the TUN interface,
configures routes, establishes the peer, persistent keepalive 25 s (10–30 s).
10–12: `is_connected = True`, UI refreshed, status shown (< 1 s).

**Q35. What happens on disconnect?**
`wg-quick down <config>`, delete temporary keys, update UI state, log completion — 5–10 s.

---

## H. Threading and the GUI

**Q36. What threads exist in the client?**
The Qt main thread (event loop), `ConnectionMonitor` (QThread, 2-second poll), the VPN
connection thread (`threading.Thread`, runs the blocking `wg-quick up`), and a
`ThreadPoolExecutor` for concurrent ping tests.

**Q37. How do worker threads talk to the UI safely?**
Qt signal/slot. A signal emitted from a non-GUI thread is **queued** to the main thread,
which guarantees ordering and avoids touching widgets off-thread.

**Q38. Why must `wg-quick up` not run on the main thread?**
It blocks for 10–30 seconds. Blocking the Qt event loop freezes the window — which is
exactly the bug that was found and fixed.

**Q39. How was that fix measured?**
By counting event-loop ticks during connect: **1 tick before, 64 after**. The UI freeze went
from 4–10 seconds to none.

**Q40. Why does the ping scan use threads rather than processes?**
It is I/O-bound — the workers spend their time waiting on the network, where the GIL is
released. Measured: **6.23 s → 1.11 s, a 5.6× speedup**. Module G is the lab that explains
why this works here and would not help encryption.

**Q41. Why is `Fusion` forced as the Qt style?**
Native styles like `windowsvista` ignore large parts of QSS and QPalette, so the theme would
render differently per platform. Fusion renders the custom theming identically everywhere.

**Q42. What are the GUI files?**
`main_window.py` (client), `labs_window.py` (the five-tab labs window), `server_grid.py`,
`settings_panel.py`, `theme.py`, and `panels/` — `dissector_panel.py`, `transport_panel.py`,
`concurrency_panel.py`, `netlab_panel.py`, `oslab_panel.py`.

---

## I. Logging and configuration

**Q43. How is logging configured?**
`vpn_core/logger.py::setup_logger(level, log_to_file)` — console plus a
`RotatingFileHandler` (10 MB, 5 backups) under `%APPDATA%\OnamVPN\logs\`.

**Q44. How does `main.py` decide the log level?**
`_load_logging_settings(verbose)` reads `log_level` and `log_to_file` from
`config/settings.json`; `--verbose` forces DEBUG regardless of the saved setting. A malformed
settings file falls back to INFO rather than crashing.

**Q45. What was the file-logging defect?**
Handlers were attached to a logger named `"OnamVPN"` while every module logged through
`get_logger(__name__)` — a different logger. **Every log file was 0 bytes since October
2025** and nobody noticed, because the console output still worked.

**Q46. Why did that bug hide for so long?**
Console logging came from a different handler and kept working. The failure was silent, in a
subsystem whose only job is to tell you when things fail.

**Q47. Where are secrets kept now?**
In `.env`, which is git-ignored. The hardcoded WARP key in
`vpn_core/real_windows_wireguard.py` is the remaining exception and is the leading suspect in
the open tunnel issue.

---

## J. Tests

**Q48. How are the tests organised?**
By module: `test_headers.py` and `test_capture.py` (dissector), `test_native.py` (tunnel),
`test_transport.py`, `test_dns.py`, `test_path.py`, `test_concurrency.py`, `test_oslab.py`,
and `test_foundation.py` for shared infrastructure.

**Q49. Give three tests that are unusual and say why.**
- *"A forged packet does not poison the replay window"* — asserts an **ordering** property
  (authenticate before recording the counter), not a value.
- *"The default switch interval often hides the race"* — asserts that a bug is **invisible**,
  which is the module's actual finding.
- *"A stale lock file does not block startup"* — asserts that the *file's existence* is not
  what enforces exclusion.

**Q50. Which tests are skipped offline?**
The live DNS comparison across four transports, live traceroute, and anything needing a
capture backend. They skip rather than fail, so the offline suite is still 457 green.

**Q51. What does `tests/conftest.py` provide?**
Shared fixtures — sample frames, pcap paths, seeded links and clocks — so tests do not
re-derive setup.

**Q52. How would you demonstrate that the test suite is meaningful rather than decorative?**
Point at the defects section: three modules were written, unit-tested, and never called by
anything. Unit tests do not catch *"nothing calls this"* — only an integration test does.
That is why the suite now includes end-to-end runs (the tunnel demo, the transfer harness)
rather than unit tests alone.

---

## K. Diagrams and generated assets

**Q53. What is in `system_design/`?**
Eight diagrams, each as `.dot` source rendered to `.svg`, `.png` and `.pdf`: architecture
overview, startup control flow, VPN connection sequence, module dependencies, connection
state machine, threading model, handler polymorphism, and file-system structure. Plus
`architecture_warp.dot/.svg`.

**Q54. Why keep the `.dot` sources in the repository?**
The diagram is generated from text, so it can be reviewed in a diff and regenerated rather
than redrawn — the same argument as keeping `docs/samples/make_samples.py` alongside the
committed `.pcap` fixtures.

**Q55. How are the sample captures regenerated?**
```bash
python docs/samples/make_samples.py
python docs/samples/make_goldens.py
```
Rarely needed — the fixtures are committed so the tests are deterministic and offline.
