# 01 — Basics

Foundational questions about what OnamVPN is, why it exists, and how to run it.

---

## A. The project itself

**Q1. What is OnamVPN in one sentence?**
A VPN client built on WireGuard, plus eight laboratory modules that reimplement — in
readable Python — the Computer Networks and Operating Systems mechanisms that the
client depends on.

**Q2. Why does the project have two halves?**
The project began as a GUI wrapper around `wireguard.exe`. Every concept it claimed to
demonstrate — key exchange, tunnelling, routing, congestion control — actually happened
inside binaries nobody here wrote, which made *"show me where you implement that"*
unanswerable. The labs move those concepts into the repository.

**Q3. Are the client and the labs two separate projects?**
No. The labs explain the client. Each lab maps to something the real client does:

| The client does this | The lab that explains it |
|---|---|
| Sends WireGuard UDP to `162.159.193.1:2408` | `netlab/dissect` decodes exactly those frames |
| Installs `0.0.0.0/1` + `128.0.0.0/1` routes | `netlab/path/routing.py` |
| Claims DNS cannot leak | `netlab/dns/leaktest.py` — the first thing that *tests* the claim |
| Uses WireGuard's Noise_IK handshake | `netlab/native/crypto.py` — a reduction of it |
| Sets `MTU = 1280` | `netlab/path/pmtud.py` — derives that number |

**Q4. What is the technology stack?**
Python 3.12, PySide6 (Qt) for the GUI, `cryptography` for X25519 / HKDF /
ChaCha20-Poly1305, `pyqtgraph` for live plots, `scapy` only as a byte-delivery source
for live capture, `pytest` for tests. JSON for configuration.

**Q5. How big is the project?**

| Package | Lines of Python |
|---|---|
| `netlab/` | 6,956 |
| `oslab/` | 2,671 |
| `gui/` | 3,694 |
| `tests/` | 3,888 |
| **Total** | **19,245** |

**Q6. How many tests are there and how long do they take?**
457 tests, roughly 57 seconds, fully offline — no network, no admin, no capture driver.

**Q7. What licence is the project under?**
MIT.

---

## B. Running it

**Q8. How do you set it up?**
```bash
python -m venv venv && venv\Scripts\activate
pip install -r requirements.txt
```

**Q9. How do you open the labs?**
```bash
python main.py --labs
```
No Administrator rights required.

**Q10. How do you run the real VPN client?**
```bash
python main.py
```
This requires Administrator rights on Windows — managing a WireGuard tunnel service
needs them.

**Q11. How does the app get Administrator rights?**
`main.py` checks `ctypes.windll.shell32.IsUserAnAdmin()` at import time. If not
elevated, it calls `ShellExecuteW(..., "runas", ...)` to trigger the UAC dialog,
relaunches itself, and exits.

**Q12. Why is elevation skipped for `--labs`?**
The labs are offline demonstrations that need no privileges. Elevating them would grant
Administrator rights to code that does not need them — an unnecessary privilege.

**Q13. There is a subtle bug avoided in the elevation check. What is it?**
The elevation decision happens *before* argparse runs, so it has to match argparse's own
parsing — including **prefix abbreviation**, where `--lab` and `--la` are both accepted
as `--labs`. A plain `"--labs" in sys.argv` would miss those, elevate anyway, and then
run Labs mode with Administrator rights it does not need. `_labs_requested()` in
`main.py` handles the abbreviation and the `--labs=x` form.

**Q14. What command-line modes exist?**

| Flag | Effect |
|---|---|
| *(none)* | GUI client mode |
| `--labs` | CN+OS Concept Labs window, no admin |
| `--mode server` | Run as a VPN server |
| `--port N` | Server port (default 51820) |
| `--speedtest` | Ping/speed test every configured server |
| `--enable-tcp` | Dummy TCP server for GUI online detection |
| `--verbose` / `-v` | Force DEBUG logging |

**Q15. How do you run the tests?**
```bash
python -m pytest tests/ -q
```

**Q16. Why does `main.py` reconfigure stdout to UTF-8 at import time?**
Windows consoles default to a legacy code page (cp1252 here). Several startup messages
begin with an emoji, so printing one raised `UnicodeEncodeError` and killed the app
*before any window appeared*. `reconfigure(encoding="utf-8", errors="replace")` keeps
the messages where the console supports them and degrades to a replacement character
where it does not. Losing a decorative glyph is acceptable; refusing to start is not.

---

## C. The five panels

**Q17. What are the five panels in the Labs window?**
Dissector, Transport, Concurrency, Network, and OS Lab.

**Q18. What does the Dissector panel do?**
Runs six hand-written protocol decoders (Ethernet/802.1Q, IPv4, IPv6, TCP with options,
UDP, ICMP/ICMPv6) over committed `.pcap` files. Selecting a field highlights exactly the
bytes it occupies in the hex dump.

**Q19. What does the Transport panel do?**
Runs Stop-and-Wait, Go-Back-N and Selective Repeat over a seeded impairment link under
TCP Reno congestion control, and plots the cwnd sawtooth with congestion events
annotated — **green** for fast retransmit, **red** for timeout.

**Q20. What does the Concurrency panel do?**
Demonstrates a race condition, a bounded buffer, deadlock (plus two fixes), and measures
the GIL's effect on CPU-bound versus I/O-bound thread scaling — by running the broken
code and watching it break.

**Q21. What does the Network panel do?**
Runs the native tunnel end to end (handshake, round trip, 100 KB bulk transfer over
SOCKS5), resolves DNS four ways (UDP/TCP/DoT/DoH), and demonstrates traceroute,
longest-prefix match and MTU arithmetic.

**Q22. What does the OS Lab panel do?**
Compares FCFS / SJF / Round Robin / Priority schedulers over real measured probe
durations with Gantt charts, measures a slab allocator and zero-copy parsing, and
demonstrates the single-instance lock, ordered teardown and crash journal.

---

## D. The eight modules

**Q23. Name the modules and their letters.**

| Module | Name | Location |
|---|---|---|
| A | Packet Dissector | `netlab/dissect/` |
| B | OnamVPN Native tunnel | `netlab/native/` |
| C | Transport: ARQ + congestion | `netlab/transport/` |
| D | DNS | `netlab/dns/` |
| E | Path and Routing | `netlab/path/` |
| F | IPC framing *(partial)* | `oslab/ipc/` |
| G | Concurrency | `oslab/concurrency/` |
| H, I, J | Scheduling, Memory, Resilience | `oslab/scheduling/`, `oslab/memory/`, `oslab/resilience/` |

**Q24. Which module is described as "the strongest single module for a viva"?**
Module C (Transport). Almost every transport-layer exam question has a knob in that
panel that answers it visually.

**Q25. Which module is only partially built, and why?**
Module F. Only the message-framing layer exists. The named-pipe transport and the
elevated helper process were deliberately not built, because *a privilege boundary with
a flaw is worse than no boundary* — the plan gated that work behind design review.

---

## E. Configuration and data

**Q26. What is in `config/servers.json`?**
Four server entries, all Cloudflare WARP endpoints: `cloudflare-warp` (anycast),
`eu-frankfurt` (`162.159.193.1:2408`), `us-newyork` (`162.159.192.1:2408`) and
`india-mumbai` (`162.159.195.1:2408`). Each carries a public key, client address
`172.16.0.2/32`, DNS `1.1.1.1, 1.0.0.1` and `mtu: 1280`. The default server is
`eu-frankfurt`.

**Q27. What is in `config/settings.json`?**
Theme, language, `start_minimized`, `auto_connect`, notifications, custom DNS,
`connection_timeout` (30 s), `keepalive_interval` (25 s), `killswitch`,
`dns_leak_protection`, `log_level`, `log_to_file`, `mtu_size` and `thread_count`.

**Q28. Which settings does `main.py` actually read at startup?**
`log_level` and `log_to_file`, via `_load_logging_settings()`. `--verbose` overrides
both by forcing DEBUG.

**Q29. Where do logs go?**
`%APPDATA%\OnamVPN\logs\onamvpn_<date>.log` on Windows, via a `RotatingFileHandler`
(10 MB per file, 5 backups).

**Q30. What are the three sample captures?**

| File | Contents |
|---|---|
| `01_tcp_handshake.pcap` | Full three-way handshake, HTTP GET + response, FIN exchange — 7 packets |
| `02_sharp_edges.pcap` | 6 packets, each of which once produced a wrong answer. Exactly one is genuinely corrupt |
| `03_mixed_protocols.pcap` | One packet per decoder, including a WireGuard-shaped flow to a WARP endpoint |

---

## F. Verification and evidence

**Q31. How are the decoders verified?**
Cross-checked field by field against **Scapy 2.6.1** in
`tests/test_capture.py::TestScapyCrossCheck`. Scapy is a separate implementation by
different authors, so agreement is meaningful evidence rather than self-confirmation.

**Q32. Why are golden files not enough on their own?**
A golden file records a wrong answer just as happily as a right one. It pins the
decoders against *themselves* — it catches unintended change but proves no correctness.
The Scapy comparison is the real check.

**Q33. Why is the Scapy cross-check weaker than `tshark`?**
Both are Python, and both could in principle share a misreading of an RFC. `tshark`
would be an independent implementation in a different language. It is not installed on
this machine (Wireshark install failed with MSI error 1603).

**Q34. How many tests per file?**

| File | Tests | File | Tests |
|---|---|---|---|
| `test_native.py` | 80 | `test_capture.py` | 43 |
| `test_headers.py` | 67 | `test_path.py` | 37 |
| `test_oslab.py` | 58 | `test_dns.py` | 37 |
| `test_transport.py` | 57 | `test_concurrency.py` | 33 |
| `test_foundation.py` | 45 | | |

**Q35. Why is reproducibility emphasised so heavily?**
Every result has to be explainable in a viva. The transport link uses an injected
virtual `Clock` (nothing calls `time.time()`) and a seeded PRNG, so the same seed
produces a byte-identical trace every run. *A congestion graph that changes between runs
cannot be explained.*

---

## G. Honesty and limits

**Q36. What is the project's stated position on limitations?**
Every module documents what it does *not* do, in its docstring and its doc page. The
rationale: a demonstration that hides its boundaries teaches the wrong thing, and an
examiner who finds an unstated limit will reasonably wonder what else is unstated.

**Q37. What is the single biggest open problem?**
🔴 The WARP tunnel connects, then disappears. The service shows `RUNNING`, then vanishes;
no Wintun adapter appears; traffic never leaves via the tunnel. Documented in
`docs/OPEN_ISSUE_tunnel.md`.

**Q38. What is the leading hypothesis for that bug?**
`WARP_PRIVATE_KEY` is hardcoded at `vpn_core/real_windows_wireguard.py:27` and committed.
Cloudflare WARP requires a key registered to an account via their device-registration
API. A key registered once and then shared by every copy of the project is likely
deregistered, rate-limited or expired — so the peer gets no handshake response, the
interface comes up, never handshakes, and the tunnel is torn down. Still a hypothesis.

**Q39. How would you confirm it?**
While the tunnel is briefly up, run `wg.exe show`. `latest handshake` never being set
confirms the key hypothesis. `wireguard.exe /dumplog` (elevated) gives WireGuard's own
reason for stopping.

**Q40. Should anyone use this for real privacy?**
No. Use WireGuard for anything real. The native tunnel exists to make the mechanism
legible, not to secure traffic — it has no retransmission, no DoS defence, no
traffic-analysis resistance, is not constant-time, and is not formally verified.

**Q41. What does not work on the development machine?**
Live packet capture (Npcap enumerates only `\Device\NPF_Loopback`), the DNS leak test
(needs live capture on a physical NIC), PMTU discovery unelevated, and DoT/DoH
(`cloudflare-dns.com` does not resolve on this network).

**Q42. The DoT/DoH failure is itself instructive. Why?**
TCP opens on `:853` but TLS times out, while ordinary HTTPS returns 200. That is a
middlebox blocking encrypted DNS — which is *precisely* the argument for running DoH on
port 443, where it is indistinguishable from ordinary web traffic.

---

## H. Getting oriented in the repository

**Q43. What is the repository layout?**
```
netlab/                         Computer Networks modules
  dissect/   model · tables · checksums · link(L2) · internet(L3) ·
             transport(L4) · dispatch · capture        ← grouped by OSI layer
  native/    protocol · crypto · replay · session · endpoint · socks5 · runner
  transport/ impairment · arq · rtt · congestion · harness
  dns/       wire · resolver · cache · leaktest
  path/      traceroute · routing · pmtud
oslab/                          Operating Systems modules
  concurrency/ ring · pool · deadlock
  scheduling/  algorithms          memory/    bufferpool
  resilience/  atomicio · signals · singleton
  ipc/         framing             daemon/    ops
vpn_core/                       the original WireGuard client
gui/panels/                     five Qt panels + Labs window
docs/concepts/                  9 pages, one per module
docs/samples/                   3 committed .pcap fixtures + golden decodes
tests/                          457 tests
```

**Q44. Why are the dissector files named after OSI layers?**
So the file structure is itself the lesson: `link.py` is L2, `internet.py` is L3,
`transport.py` is L4, and `dispatch.py` chains them. Encapsulation is visible in the
directory listing before you open a file.

**Q45. Where is the per-module documentation?**
`docs/concepts/` — nine pages, one per module. Each contains the concepts mapped to
`file.py:line`, how to run it, expected output, **what a wrong result looks like**, and
what the module does not do.
