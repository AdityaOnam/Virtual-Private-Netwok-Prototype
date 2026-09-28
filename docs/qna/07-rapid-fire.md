# 07 — Rapid Fire

One-line answers, every number worth memorising, and the commands. Read this last.

---

## A. One-liners — Networking

| Question | Answer |
|---|---|
| What layer is Ethernet? | L2 — `netlab/dissect/link.py` |
| What layer is IPv4? | L3 — `internet.py` |
| What layer is TCP? | L4 — `transport.py` |
| Which field selects the L3 decoder? | EtherType |
| Which field selects the L4 decoder? | IP protocol number |
| What is EtherType 0x0800? | IPv4 |
| What is EtherType 0x86DD? | IPv6 |
| What is EtherType 0x8100? | 802.1Q VLAN tag |
| IP protocol 6? | TCP |
| IP protocol 17? | UDP |
| IP protocol 1? | ICMP |
| Minimum Ethernet frame? | 60 bytes (padded) — the cause of the checksum bug |
| IPv4 header, no options? | 20 bytes (IHL = 5) |
| IHL = 6 means? | 24-byte header — 4 bytes of options |
| IPv6 fixed header? | 40 bytes |
| UDP header? | 8 bytes |
| TCP header, no options? | 20 bytes |
| ICMP header? | 8 bytes |
| ICMP type 8 / 0? | Echo request / Echo reply |
| ICMP type 11? | Time Exceeded — what traceroute reads |
| ICMP type 3 code 4? | Fragmentation Needed — the PMTUD signal |
| Checksum RFC? | RFC 1071 |
| A verified-whole checksum equals? | Zero |
| Is UDP checksum 0 legal? | Yes on IPv4 (RFC 768); mandatory on IPv6 |
| What does a Time Exceeded carry back? | The first 8 bytes of the original datagram |
| What does `*` mean in traceroute? | ICMP suppressed or rate-limited — not a broken router |
| Socket option used to set TTL? | `IP_TTL` |
| Longest-prefix match tie-breaker? | Route metric |
| Does table order matter? | No — specificity decides |
| `0.0.0.0/0` matches? | Everything, and therefore always loses |
| Split-default pair? | `0.0.0.0/1` + `128.0.0.0/1` |
| Why not just `0.0.0.0/0`? | Deleting the real default kills the route to the VPN server |
| What keeps tunnel traffic out of the tunnel? | A `/32` to the endpoint via the physical gateway |

## B. One-liners — DNS

| Question | Answer |
|---|---|
| DNS message RFC? | RFC 1035 |
| Header size? | 12 bytes |
| Four sections? | Question, Answer, Authority, Additional |
| Max label length? | 63 bytes |
| Max name length? | 255 bytes |
| Are there dots on the wire? | No — length-prefixed labels, zero-terminated |
| Compression pointer marker? | Both high bits set, `≥ 0xC0` |
| `0xC0 0x0C` means? | "The rest of this name is at byte 12" |
| Why byte 12? | Where the question section starts |
| After a pointer, parsing resumes where? | After the **pointer** (2 bytes), not the target |
| Pointer-loop defence? | `MAX_POINTER_JUMPS = 64` |
| TC bit means? | Truncated — retry over TCP :53 |
| DNS over TCP framing? | 2-byte length prefix |
| DoT port? | 853 |
| DoH port? | 443, `application/dns-message` |
| Why DoH over DoT? | Indistinguishable from HTTPS — unblockable by port |
| Is cert verification on for DoT? | Yes — off would be worse than plaintext |
| Expired cache entry counts as? | A **miss** |
| Record type 1 / 28? | A / AAAA |
| Record type 5 / 15 / 16? | CNAME / MX / TXT |
| Default resolvers here? | `1.1.1.1`, `1.0.0.1` |
| Why a unique leak-test name? | A cache anywhere could answer without a packet leaving |
| Leak test searches for? | The **wire form** — length-prefixed labels |

## C. One-liners — Transport

| Question | Answer |
|---|---|
| Stop-and-Wait window? | 1 |
| Go-Back-N ACK type? | Cumulative |
| Go-Back-N timers? | One |
| Selective Repeat ACK type? | Per segment |
| Selective Repeat timers? | Per segment |
| GBN vs SR trade? | Receiver memory vs wasted bandwidth |
| Why did TCP start as GBN? | Memory was expensive; SACK came when it got cheap |
| Slow start growth? | ×2 per RTT (+1 MSS per ACK) |
| Congestion avoidance growth? | +1 MSS per RTT (`MSS²/cwnd` per ACK) |
| Fast retransmit trigger? | 3 duplicate ACKs |
| After fast retransmit, cwnd? | `ssthresh + 3` — **not** 1 |
| After a timeout, cwnd? | **1 MSS**, back to slow start |
| Why the asymmetry? | Dup ACKs mean packets still arrive; a timeout means nothing does |
| RTO formula? | `SRTT + 4·RTTVAR` |
| Whose algorithm? | Jacobson/Karels |
| Karn's rule? | Never sample RTT from a retransmitted segment |
| On timeout instead? | Double the RTO (exponential backoff) |
| BDP formula? | bandwidth × RTT |
| Window < BDP means? | Window-limited — the link can never be filled |
| MSS used here? | 1460 bytes |
| Variant implemented? | Reno (not CUBIC, not BBR) |
| Green line on the plot? | Fast retransmit |
| Red line on the plot? | Timeout |

## D. One-liners — VPN / crypto

| Question | Answer |
|---|---|
| Key exchange? | X25519 (ECDH over Curve25519) |
| KDF? | HKDF with a running chaining key |
| AEAD? | ChaCha20-Poly1305 |
| Hash / MAC? | BLAKE2s-256 / BLAKE2s-128 keyed |
| Handshake pattern? | Noise_IK (a reduction of it) |
| Key size? | 32 bytes |
| Tag size? | 16 bytes |
| Nonce size? | 12 bytes |
| Nonce construction? | 4 zero bytes ‖ u64 LE counter |
| Timestamp format / size? | TAI64N, 12 bytes |
| Handshake Initiation size? | 132 bytes (type 1) |
| Handshake Response size? | 76 bytes (type 2) |
| Transport Data header? | 16 bytes (type 4) |
| Message type 3? | Cookie Reply — **reserved, not implemented** |
| Inner frame header? | 7 bytes — kind(1) ‖ stream_id(4 LE) ‖ length(2 LE) |
| Byte order? | Little-endian throughout (opposite of IP/TCP) |
| Replay window size? | 1024 bits |
| Replay RFC? | RFC 6479 |
| Keepalive interval? | 25 seconds |
| Keepalive size on the wire? | 32 bytes |
| Rekey after? | 2²⁰ messages / 120 s |
| Reject after? | 2²⁴ messages / 180 s |
| Handshake timeout? | 5 seconds |
| Max tunnel payload? | 1280 bytes |
| What does mac1 stop? | Junk from peers that don't know the server's public key |
| What would mac2 stop? | A DoS flood from peers that do |
| Front end? | SOCKS5 on `127.0.0.1:1080` |
| What it tunnels? | Applications configured to use the proxy — not the device |

## E. One-liners — OS

| Question | Answer |
|---|---|
| Race demo threads / expected total? | 8 threads, 400,000 |
| Roughly how many lost? | ~270,000 |
| Why did the first version never fail? | CPython 3.12 checks the eval-breaker only at call boundaries and loop back-edges |
| What made it observable? | A function call in the critical section + `setswitchinterval(1e-6)` |
| Default switch interval? | 5 ms — where the race hides |
| Coffman conditions? | Mutual exclusion, hold-and-wait, no preemption, circular wait |
| Prevention used in real systems? | Lock ordering (breaks circular wait) |
| Recovery shown here? | Timeout and back off, with randomised delay |
| Why randomise the delay? | Otherwise both threads back off in lockstep — livelock |
| GIL, CPU-bound 8 workers? | 1.31× |
| GIL, I/O-bound 8 workers? | 6.50× |
| Conclusion? | Threads help exactly when the work waits |
| CPU-bound answer in Python? | Processes |
| Amdahl fit method? | Karp-Flatt from the two-worker point |
| SJF is optimal for? | Average waiting time — provably |
| SJF's catch? | Unimplementable — needs durations known in advance |
| Large quantum makes RR into? | FCFS, exactly |
| Starvation fix? | Aging |
| Metric interactive users feel? | Response time |
| Slab allocator eliminates? | External fragmentation |
| Slab allocator creates? | Internal fragmentation — deliberately |
| Acquire/release cost? | O(1) both |
| Bytes copied by memoryview in the demo? | Zero (vs 116,000,000 by slicing) |
| Cross-process lock mechanism? | Advisory file lock — `msvcrt.locking` / `fcntl.flock` |
| Why not a mutex? | A mutex lives in one process's address space |
| Why not a PID file? | Survives a crash; PIDs are recycled |
| What releases the lock on SIGKILL? | The OS closing the descriptor |
| Teardown order? | Reverse registration — a stack |
| What can't be caught? | SIGKILL, TerminateProcess, power loss |
| Defence against those? | A journal replayed at startup |
| `os.replace` gives? | Atomicity, not durability |
| Durability needs? | `flush()` + `fsync()` **before** the replace |
| Console close event? | `CTRL_CLOSE_EVENT` — needs `SetConsoleCtrlHandler`, ~5 s to clean up |
| Why Ctrl+C fails under Qt? | Python handlers run only between bytecodes; Qt's loop is C++ |
| Fix? | A QTimer nudge a few times a second |
| IPC frame format? | 4-byte BE length + UTF-8 JSON |
| `MAX_FRAME`? | 1 MiB, checked **before** allocating |
| Why must reads loop? | `recv(n)` returns *up to* n |

---

## F. Every number worth memorising

### Project
| | |
|---|---|
| Tests | 457, ~57 s, offline |
| Total Python | 19,245 lines |
| `netlab/` / `oslab/` / `gui/` / `tests/` | 6,956 / 2,671 / 3,694 / 3,888 |
| Defects found and fixed | 20 |
| Concept doc pages | 9 |
| Panels | 5 |
| Sample pcaps | 3 |
| Native tunnel size | ~1400 lines |

### Wire sizes
| | |
|---|---|
| Ethernet header / min frame | 14 / 60 bytes |
| IPv4 / IPv6 header | 20 / 40 bytes |
| TCP / UDP / ICMP header | 20 / 8 / 8 bytes |
| WireGuard overhead | 32 bytes (16 header + 16 tag) |
| Available inner MTU on a 1500 path | 1440 bytes |
| Configured tunnel MTU | **1280** |
| IPv6 minimum MTU (RFC 8200 §5) | 1280 |
| RFC 791 minimum IPv4 host MTU | 576 |
| DNS header | 12 bytes |

### Measured results
| | |
|---|---|
| Startup latency scan | 6.23 s → 1.11 s (5.6×) |
| Event-loop ticks during connect | 1 → 64 |
| 200 KB transfer before the chunking fix | arrived as 134 KB |
| Bytes copied, slicing vs memoryview | 116,000,000 vs 0 |
| GIL CPU-bound speedup at 8 workers | 1.31× (Amdahl 1.38×) |
| GIL I/O-bound speedup at 8 workers | 6.50× (Amdahl 6.31×) |
| Scheduler probes | frankfurt 0.30 s, mumbai 0.05 s, newyork 0.20 s, warp 0.08 s |
| SJF avg waiting / RR response | 0.128 s / 0.075 s |
| RR context switches vs FCFS | 12 vs 3 |

### ARQ at 100 segments, window 8
| loss | protocol | retransmitted | efficiency |
|---|---|---|---|
| 20% | go-back-n | 81 | 0.55 |
| 20% | selective-repeat | 69 | 0.59 |
| 30% | go-back-n | 121 | 0.45 |
| 30% | selective-repeat | 101 | 0.50 |

### Configuration
| | |
|---|---|
| WireGuard endpoints | `162.159.192.1` (NY), `.193.1` (FRA), `.195.1` (BOM), port **2408** |
| Default server | `eu-frankfurt` |
| Client address | `172.16.0.2/32` |
| DNS | `1.1.1.1, 1.0.0.1` |
| Server mode port | 51820 |
| SOCKS5 port | 1080 |
| Keepalive | 25 s |
| Connection timeout | 30 s |
| Log rotation | 10 MB × 5 backups |

---

## G. Commands

```bash
# Setup
python -m venv venv && venv\Scripts\activate
pip install -r requirements.txt

# The labs — no admin, no network, no capture driver
python main.py --labs

# The real VPN client — requires Administrator
python main.py

# Other modes
python main.py --mode server --port 51820
python main.py --speedtest
python main.py --verbose

# Tests
python -m pytest tests/ -q
python -m pytest tests/test_oslab.py -k "Framing or FrameBuffer" -v
python -m pytest tests/test_capture.py::TestScapyCrossCheck -v

# Regenerate the sample captures (rarely needed — they are committed)
python docs/samples/make_samples.py
python docs/samples/make_goldens.py

# Diagnosing the open tunnel issue
sc query WireGuardTunnel$wgcf-profile
"C:\Program Files\WireGuard\wg.exe" show
"C:\Program Files\WireGuard\wireguard.exe" /dumplog      # needs elevation

# If Wireshark is installed, the stronger cross-check
tshark -V -r docs/samples/01_tcp_handshake.pcap
```

---

## H. The five sentences to have ready

1. **What it is.** "A WireGuard VPN client, plus eight lab modules that reimplement the CN
   and OS mechanisms the client depends on — so that 'show me where you implement that' has
   an answer."

2. **Why the rewrite.** "Everything used to happen inside binaries nobody here wrote. The
   labs move those concepts into the repository."

3. **The best single demo.** "Transport — three ARQ protocols under TCP Reno on a seeded
   virtual link, where a red line always collapses cwnd and a green one never does."

4. **The most honest thing in it.** "Every module documents what it does *not* do. The
   tunnel has no retransmission, no DoS defence and no formal verification, and the WARP
   tunnel currently connects and then disappears."

5. **What it proves about testing.** "Three separate defects were the same shape — a module
   written, unit-tested, and never called by anything. Unit tests do not catch 'nothing
   calls this'."
