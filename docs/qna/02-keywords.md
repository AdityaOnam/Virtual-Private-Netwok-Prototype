# 02 — Keyword Index

Every term an examiner might point at, with a one-or-two-line answer and the place in
this repository where it is implemented. Use this when the question is *"what is X?"*
followed by *"show me."*

---

## A. Networking fundamentals

| Keyword | Answer | Where |
|---|---|---|
| **OSI model** | Seven-layer reference model. This project implements L2–L4 decoding and names its files for the layers. | `netlab/dissect/link.py`, `internet.py`, `transport.py` |
| **TCP/IP model** | Four-layer practical model: link, internet, transport, application. | `netlab/dissect/` |
| **Encapsulation** | Each layer wraps the layer above in its own header. Decoding is the reverse: peel one header, use a field in it to decide what is next. | `dispatch.py:39` |
| **Demultiplexing** | Choosing the next decoder from a field: EtherType → IP protocol number → port. | `dispatch.py:39` |
| **Network byte order** | Big-endian, the convention of the IP suite. Not a law — the native tunnel is little-endian, matching WireGuard. | `netlab/dissect/*` vs `netlab/native/protocol.py` |
| **MTU** | Maximum Transmission Unit — largest payload a link will carry. Typical Ethernet 1500. | `netlab/path/pmtud.py` |
| **MSS** | Maximum Segment Size — TCP payload per segment; `MSS = 1460` here. | `netlab/transport/congestion.py:58` |
| **TTL / hop limit** | A counter decremented by every router; zero means discard and report. Traceroute exploits it. | `internet.py`, `netlab/path/traceroute.py` |
| **Checksum (RFC 1071)** | Ones-complement sum of 16-bit words, then complemented. Verifying a packet including its own checksum yields zero. | `netlab/dissect/checksums.py:19` |
| **Pseudo-header** | Fake header (src IP, dst IP, protocol, length) folded into TCP/UDP checksums so a misdelivered segment is detected. | `checksums.py:29` |
| **Fragmentation** | Splitting a datagram too large for a link. Controlled by DF/MF flags and fragment offset. | `internet.py` |
| **DF bit** | Don't Fragment. Set it and an oversized packet is dropped with ICMP Fragmentation Needed — the basis of PMTUD. | `netlab/path/pmtud.py` |
| **MF bit** | More Fragments. Set on every fragment but the last. | `internet.py` |
| **IHL** | IPv4 Internet Header Length in 32-bit words. `IHL > 5` means options are present and the payload does not start at byte 20. | `internet.py` |
| **EtherType** | 16-bit field in the Ethernet header naming the L3 protocol (0x0800 IPv4, 0x86DD IPv6, 0x8100 VLAN). | `link.py`, `tables.py` |
| **802.1Q** | VLAN tagging — a 4-byte tag inserted before the EtherType. | `link.py` |
| **Port multiplexing** | Source/destination ports let one host run many conversations over one IP. | `transport.py` |
| **Snapshot length** | pcap capture limit; `incl_len < orig_len` means the frame was truncated. | `capture.py` |
| **libpcap magic number** | First 4 bytes of a `.pcap` file; its byte order tells the reader the file's endianness. | `capture.py` |

---

## B. TCP and transport

| Keyword | Answer | Where |
|---|---|---|
| **ARQ** | Automatic Repeat reQuest — reliability by acknowledgement and retransmission. | `netlab/transport/arq.py` |
| **Stop-and-Wait** | Window of 1. Correct and trivial, but one segment per RTT regardless of bandwidth. | `arq.py:193` |
| **Go-Back-N** | Window N, cumulative ACK, **one** timer. Receiver discards out-of-order, so one loss resends that segment and everything after. Cheap receiver, expensive recovery. | `arq.py:245` |
| **Selective Repeat** | Window N, per-segment ACK, per-segment timer. Receiver buffers out-of-order, so only the lost segment is resent. Expensive receiver, cheap recovery. | `arq.py:315` |
| **Sliding window** | `base`, `next_seq`, and `effective_window()` — the sender may have up to N unacknowledged segments outstanding. | `arq.py` |
| **Cumulative ACK** | "Everything up to here arrived." | `CumulativeReceiver`, `arq.py:412` |
| **Selective ACK** | "This specific segment arrived." | `SelectiveReceiver`, `arq.py:436` |
| **Flow control** | Protects the *receiver* from being overrun — the advertised receiver window. | `congestion.py` — `window_bytes(receiver_window)` |
| **Congestion control** | Protects the *network* from being overrun — cwnd. Distinct from flow control; the sender uses `min(cwnd, rwnd)`. | `congestion.py` |
| **cwnd** | Congestion window — the sender's own estimate of what the path can take. | `RenoController`, `congestion.py:78` |
| **ssthresh** | Slow-start threshold. Below it, slow start; above it, congestion avoidance. | `congestion.py` |
| **Slow start** | +1 MSS per ACK → cwnd **doubles** every RTT. Exponential, and despite the name the fastest phase. | `congestion.py` |
| **Congestion avoidance** | `+MSS²/cwnd` per ACK → **+1 MSS per RTT**. Linear probing. | `congestion.py` |
| **AIMD** | Additive Increase, Multiplicative Decrease — the sawtooth. | the cwnd plot |
| **Fast retransmit** | Three duplicate ACKs → resend the missing segment without waiting for a timeout. | `congestion.py` |
| **Fast recovery** | After fast retransmit: `ssthresh = cwnd/2`, `cwnd = ssthresh + 3`. cwnd does **not** collapse to 1. | `congestion.py` |
| **Timeout (RTO expiry)** | `ssthresh = cwnd/2`, `cwnd = 1 MSS`, back to slow start. The harsh signal. | `congestion.py` |
| **Duplicate ACK** | Receiver re-acknowledges the last in-order byte — evidence that something arrived out of order. | `arq.py` |
| **RTT** | Round-trip time. | `netlab/transport/rtt.py` |
| **SRTT / RTTVAR** | Jacobson/Karels smoothed RTT and its variation. | `rtt.py:45` |
| **RTO** | Retransmission timeout, `SRTT + 4·RTTVAR`. The `4·RTTVAR` term is why a jittery path gets a wider timer than a steady one with the same mean. | `rtt.py` |
| **Karn's algorithm** | Never sample RTT from a retransmitted segment — the ACK is ambiguous. Double the RTO on timeout instead, and resume sampling after a clean ACK. | `rtt.py` |
| **Exponential backoff** | `back_off()` doubles the RTO on each successive timeout. | `rtt.py` |
| **BDP** | Bandwidth-Delay Product = bandwidth × RTT — bytes needed in flight to fill the link. | `bandwidth_delay_product()`, `congestion.py:204` |
| **Window-limited vs link-limited** | If window < BDP the link can never be filled however clean it is. On a throughput graph that looks exactly like congestion. | the harness bottleneck report |
| **Token bucket** | Rate-limiting model producing queueing delay in the impairment link. | `impairment.py` |
| **Reno** | The congestion-control variant implemented here — the textbook sawtooth. Modern Linux defaults to CUBIC and increasingly BBR. | `congestion.py` |

---

## C. VPN, cryptography, tunnel

| Keyword | Answer | Where |
|---|---|---|
| **VPN** | Virtual Private Network — an encrypted tunnel that carries traffic as if it originated at the far end. | whole project |
| **WireGuard** | Modern VPN protocol: UDP, Noise_IK handshake, ChaCha20-Poly1305, tiny codebase. | `vpn_core/` |
| **Noise_IK** | The Noise-protocol handshake pattern WireGuard uses: **I**nitiator static key transmitted, responder static **K**nown in advance. | `netlab/native/crypto.py` — a reduction of it |
| **X25519** | Elliptic-curve Diffie-Hellman over Curve25519. 32-byte keys. | `crypto.py` |
| **ECDH** | Two parties derive a shared secret from their own private key and the other's public key, without transmitting the secret. | `crypto.py` |
| **HKDF** | HMAC-based key derivation; used here with a running chaining key. | `crypto.py` |
| **Chaining key (C)** | A value that absorbs every DH result in sequence; the transport keys fall out of the final C. | `crypto.py` |
| **Transcript hash (H)** | Absorbs everything sent or received and is used as AEAD associated data — so tampering anywhere in the transcript makes the next decryption fail. | `crypto.py` |
| **AEAD** | Authenticated Encryption with Associated Data — confidentiality *and* integrity in one operation. | ChaCha20-Poly1305, `crypto.py` |
| **ChaCha20-Poly1305** | Stream cipher + MAC. Fails catastrophically if a `(key, nonce)` pair repeats. | `crypto.py`, `session.py` |
| **Poly1305 tag** | 16-byte authentication tag appended to the ciphertext. | `TAG_SIZE = 16` |
| **Nonce** | Number used once. Here: 4 zero bytes ‖ 64-bit little-endian counter. | `session.py` |
| **Nonce reuse** | The one fatal mistake: the keystream repeats and both plaintexts leak. Prevented by `NonceExhausted` and by rotating key+counter together. | `session.py` |
| **Forward secrecy** | Ephemeral keys mixed into the chain, so compromising a static key later does not decrypt past sessions. | `crypto.py` |
| **Identity hiding** | The initiator's *static* public key travels encrypted, so an observer cannot tell who is connecting. | `crypto.py` |
| **TAI64N timestamp** | 12-byte monotonic timestamp in the initiation; the responder keeps the greatest per peer and rejects anything not strictly greater — handshake replay defence. | `protocol.py` |
| **mac1** | `MAC(HASH(LABEL ‖ S_r), message)` — a peer that does not already know the server's public key cannot produce it, so junk is discarded before any curve arithmetic. | `protocol.py` |
| **mac2 / cookie reply** | WireGuard's DoS mitigation (message type 3). **Not implemented here** — stated as a limit. | `MSG_COOKIE_REPLY = 3`, reserved |
| **Replay attack** | Re-sending a captured valid packet. Defeated by a sliding window over the counter. | `netlab/native/replay.py` |
| **Sliding-window replay filter (RFC 6479)** | 1024-bit bitmap over recent counters: above window → accept and slide; inside and unset → accept (legitimate reorder); inside and set → reject (replay); below window → reject (too old to judge). | `replay.py` |
| **Rekey** | `install_keys()` replaces both keys **and** resets the counter in one call. There is deliberately no setter for keys alone. | `session.py` |
| **`PeerState.previous`** | The retired session kept decrypt-only, so packets already in flight when the rekey happened still arrive. | `session.py` |
| **Keepalive** | An empty-plaintext transport packet (32 bytes on the wire) sent every 25 s to refresh NAT bindings. | `KEEPALIVE_SECONDS = 25` |
| **SOCKS5** | A proxy protocol. Used as the tunnel's front end because it needs no driver and no admin rights — but it tunnels *applications configured to use the proxy*, not the whole device. | `netlab/native/socks5.py` |
| **TUN adapter** | A virtual network interface that captures every packet the machine sends. What a real VPN uses. On Windows that means driving `wintun.dll` through `ctypes`. | not implemented; discussed in `native-tunnel.md` |
| **Kill switch** | Firewall rules blocking all traffic outside the tunnel, so a tunnel failure does not silently expose traffic. | `config/settings.json`, `oslab/resilience/` |
| **Split-default route** | `0.0.0.0/1` + `128.0.0.0/1` — together they cover the whole address space, each beats the real `/0` default on specificity, **without deleting it**. | `netlab/path/routing.py` |

---

## D. DNS

| Keyword | Answer | Where |
|---|---|---|
| **RFC 1035** | The DNS message format: 12-byte header + four sections (question, answer, authority, additional). | `netlab/dns/wire.py` |
| **QNAME encoding** | Length-prefixed labels ending in a zero byte. `www.example.com` → `03 www 07 example 03 com 00`. There are no dots on the wire. | `encode_name`, `wire.py:97` |
| **Label** | One component of a name, max 63 bytes — which leaves the two high bits of a length byte free. | `MAX_LABEL = 63` |
| **Compression pointer** | A length byte ≥ `0xC0` is not a label: it is a 14-bit offset from the start of the *message*. `0xC0 0x0C` means "the rest is at byte 12". | `decode_name`, `wire.py:117` |
| **Pointer loop** | A pointer to itself, or two pointing at each other. A naive parser follows them forever; `MAX_POINTER_JUMPS = 64` caps it. | `wire.py:63` |
| **Where parsing resumes** | After following a pointer, the next record starts after the **pointer** (2 bytes), not after wherever it led. Getting this wrong shifts every subsequent record. | `decode_name` |
| **TC bit** | Truncation. A UDP response too large comes back with TC set and no useful answer; the resolver must retry over TCP :53. The oldest fallback in the protocol. | `resolver.py` |
| **RD / RA** | Recursion Desired / Recursion Available. | `wire.py` |
| **RCODE** | Response code — NOERROR, NXDOMAIN, SERVFAIL, etc. | `RCODE_NAMES`, `wire.py:83` |
| **RDATA / RDLENGTH** | The record's payload and its length. An RDLENGTH error after a pointer produces NOERROR with no addresses. | `_decode_rdata`, `wire.py:280` |
| **Record types** | A (1), NS (2), CNAME (5), SOA (6), PTR (12), MX (15), TXT (16), AAAA (28). | `wire.py:66-73` |
| **DoT** | DNS over TLS, port 853. Same messages inside TLS with a 2-byte length prefix (TLS is a stream, DNS needs framing). Encrypted, but obviously DNS — blockable by port. | `resolver.py` |
| **DoH** | DNS over HTTPS, port 443, POSTed as `application/dns-message`. Slowest, and speed is not the point: it is indistinguishable from ordinary web traffic. | `DOH_URL`, `resolver.py:53` |
| **Certificate verification** | **On** for DoT. Turning it off would defeat the purpose — an attacker redirecting :853 could answer every query, which is worse than plaintext because it looks secure. | `resolver.py` |
| **TTL** | Time to live on a record. Honouring it is how an operator moves a service: lower the TTL, wait, change the record, traffic follows. | `netlab/dns/cache.py` |
| **Expiry counts as a miss** | In `cache.py`, an expired entry is a **miss**, not a hit — the answer existed but is no longer usable. | `cache.py` |
| **Cache poisoning signature** | A response whose ID does not match the query. | `resolver.py` |
| **DNS leak** | The tunnel is encrypted but the OS resolver keeps sending plaintext queries to the ISP over the physical adapter, so an observer learns every site visited. The most common way a VPN leaks. | `netlab/dns/leaktest.py` |
| **Why a unique query name** | Resolving `example.com` proves nothing — a cache anywhere may answer without a packet leaving the machine, and that absence would look like success. | `unique_query_name`, `leaktest.py:73` |
| **Searched in wire form** | The leak test looks for the *length-prefixed* name in captured bytes, not the dotted string, because that is what appears on the wire. | `leaktest.py` |
| **Stub resolver** | Asks a recursive server and reads the answer; does not walk the hierarchy from the root. What this is. | `resolver.py` |
| **Negative caching (RFC 2308)** | Caching NXDOMAIN using the SOA minimum as TTL. **Not implemented** — named rather than hidden. | limit |

---

## E. Routing, path, ICMP

| Keyword | Answer | Where |
|---|---|---|
| **ICMP** | Internet Control Message Protocol — the error and diagnostic channel of IP. | `internet.py`, `traceroute.py` |
| **Time Exceeded (type 11)** | Sent by a router that decremented TTL to zero. Traceroute assembles the whole path from these error messages. | `_classify`, `traceroute.py:351` |
| **Destination Unreachable (type 3), code 4** | Fragmentation Needed — the PMTUD signal. | `pmtud.py` |
| **Echo request / reply (types 8 / 0)** | Ping. | `build_echo_request`, `traceroute.py:69` |
| **Traceroute** | There is no "tell me the path" message in IP. Send TTL=1, 2, 3… and read the source address of each Time Exceeded. | `traceroute.py` |
| **Matching replies to probes** | A Time Exceeded carries the first 8 bytes of the original datagram, so our identifier and sequence are recoverable — that is how our probes are told apart from every other ICMP message on the machine. | `_classify` |
| **Why `*` appears** | Not a broken router. Many operators rate-limit or suppress ICMP errors; the hop forwards perfectly while declining to announce itself. | `traceroute.py` |
| **`IP_TTL`** | The socket option used to set TTL. Portable, and what system `tracert` does. Crafting the IP header by hand needs `IP_HDRINCL` and behaves inconsistently across Windows versions. | `traceroute.py` |
| **CIDR / prefix length** | `a.b.c.d/n` — n bits of network. | `Route.prefix_length`, `routing.py:43` |
| **Longest-prefix match** | Of all routes that match a destination, the most specific (longest mask) wins — **regardless of order in the table**. | `longest_prefix_match`, `routing.py:159` |
| **Default route** | `0.0.0.0/0` matches everything and therefore always loses to anything else that matches — which is exactly what makes it useful. | `routing.py` |
| **Why the /32 matters** | The route to the VPN endpoint stays `/32` via the physical gateway, and `/32` beats `/1`, so tunnel traffic escapes the tunnel. Without it the tunnel deadlocks on its own traffic. | `describe_split_default`, `routing.py:210` |
| **PMTUD (RFC 1191)** | Binary-search the path MTU by sending DF-set probes and reading Fragmentation Needed errors. | `pmtud.py` |
| **ICMP black hole** | A network that blocks all ICMP gives the sender no Fragmentation Needed at all: large packets vanish silently while small ones succeed, so a connection handshakes and then hangs. Notoriously hard to diagnose. | `pmtud.py` |
| **Why MTU 1280** | 1500 − 20 (IPv4) − 8 (UDP) − 32 (WireGuard header + tag) = 1440 available. 1280 is chosen instead because it is the minimum MTU every IPv6 link must support (RFC 8200 §5), so the tunnel survives almost any path. ~11% payload efficiency traded for not debugging an ICMP black hole. | `explain_mtu_choice`, `pmtud.py:116` |

---

## F. Operating systems — concurrency

| Keyword | Answer | Where |
|---|---|---|
| **Race condition** | Two threads' interleaving changes the result. Demonstrated with 8 threads incrementing a shared counter; expected 400,000, roughly 270,000 updates lost. | `SharedCounter`, `ring.py:215` |
| **Critical section** | The read-compute-write region that must not interleave. | `ring.py` |
| **Mutex** | `threading.Lock` — mutual exclusion inside one process. | `ring.py` |
| **Condition variable** | `not_full` / `not_empty` — wait until a predicate holds, without spinning. | `BoundedRing`, `ring.py:72` |
| **Bounded buffer / producer-consumer** | Fixed-capacity queue where producers block when full and consumers block when empty. | `BoundedRing` |
| **GIL** | Global Interpreter Lock — only one thread executes Python bytecode at a time. | measured in `pool.py` |
| **Eval-breaker** | The point where CPython checks whether to switch threads. **As of 3.12 that is at call boundaries and loop back-edges, not between arbitrary bytecodes** — which is why the first race demo produced the correct answer 10/10 times. | `concurrency.md` |
| **`sys.setswitchinterval`** | The scheduler-pressure knob. Lowered to 1e-6 to raise exposure of the race. Does **not** fabricate the bug — the code is equally broken either way. | `ring.py` |
| **Amdahl's law** | Speedup is bounded by the serial fraction. Measured against prediction here. | `amdahl_speedup`, `pool.py:218` |
| **Karp-Flatt metric** | Estimating the serial fraction from a measured two-worker speedup. | `estimate_serial_fraction`, `pool.py:225` |
| **Deadlock** | Two or more threads each holding a resource the other needs. | `oslab/concurrency/deadlock.py` |
| **Coffman conditions** | Mutual exclusion, hold-and-wait, no preemption, circular wait. All four must hold simultaneously — break any one and deadlock cannot occur. | `deadlock.py` |
| **Wait-for graph** | Directed graph of "thread A waits for a resource held by thread B". A cycle means deadlock. | `WaitForGraph.detect_cycle()`, `deadlock.py:52` |
| **Lock ordering** | Deadlock **prevention**: always take L1 before L2, so no cycle can form and no detection machinery is needed. What real systems use. | `run_ordered_demo()`, `deadlock.py:182` |
| **Timeout and back off** | Deadlock **recovery**: break hold-and-wait after the fact. Wastes work already done and can livelock if both threads back off in lockstep — which is why the retry delay is randomised. | `run_timeout_recovery_demo()`, `deadlock.py:229` |
| **Livelock** | Threads keep running and keep yielding to each other, making no progress. | `deadlock.py` |
| **Thread pool** | A fixed set of workers consuming a task queue. | `InstrumentedPool`, `pool.py:84` |

---

## G. Operating systems — scheduling, memory, resilience

| Keyword | Answer | Where |
|---|---|---|
| **FCFS** | First Come First Served. Simple; suffers the **convoy effect** — one long job delays everything behind it. | `schedule_fcfs`, `algorithms.py:148` |
| **SJF** | Shortest Job First. Provably optimal for average waiting time, and **unimplementable in general** because it needs to know durations in advance. | `schedule_sjf`, `algorithms.py:166` |
| **Round Robin** | Each job gets a quantum, then goes to the back of the queue. Wins response time, loses turnaround, costs 4× the context switches here. | `schedule_round_robin`, `algorithms.py:197` |
| **Quantum** | The RR time slice. A large enough quantum makes RR degenerate to FCFS **exactly** — asserted in the tests. | `algorithms.py` |
| **Priority scheduling** | Highest-priority runnable job first. Risks **starvation**. | `schedule_priority`, `algorithms.py:251` |
| **Starvation** | A low-priority job never runs because higher-priority jobs keep arriving. | `algorithms.py` |
| **Aging** | Raise a waiting job's effective priority over time, guaranteeing it eventually runs. | `schedule_priority(aging=...)` |
| **Waiting time** | `turnaround − service` — time spent not running. | `ScheduleResult.metrics()` |
| **Turnaround time** | `completion − arrival` — total time in the system. | `metrics()` |
| **Response time** | `first run − arrival` — time until *anything* happens. The one interactive users feel. | `metrics()` |
| **Gantt chart** | Time-ordered rendering of which job held the CPU when. | `ScheduleResult.gantt()` |
| **Context-switch cost** | Modelled by the `switch_cost` parameter. | `algorithms.py` |
| **Slab allocation** | Pre-allocate an arena of fixed-size blocks and hand them out forever; steady-state allocation becomes **zero**. | `BufferPool`, `bufferpool.py:134` |
| **Free list** | Singly-linked list of available blocks. `acquire()` pops the head, `release()` pushes it back — both O(1). | `BufferPool._free` |
| **Internal fragmentation** | Waste *inside* a block — a 64-byte ACK in a 2048-byte block wastes 1984 bytes. The trade a slab allocator makes deliberately. | `PoolStats.internal_fragmentation` |
| **External fragmentation** | Free memory stranded in unusably small gaps between allocations. Fixed-size blocks eliminate it. | `bufferpool.py` |
| **Backpressure** | `PoolExhausted` — refusing work rather than allocating without bound. | `bufferpool.py:49` |
| **Zero-copy** | `memoryview` slices without copying. Measured over 20,000 four-layer parses: **116,000,000 bytes copied by slicing, zero by memoryview.** | `Buffer.view()`, `demonstrate_zero_copy` |
| **Single-instance lock** | Cross-process mutual exclusion via an advisory file lock (`msvcrt.locking` / `fcntl.flock`). A `threading.Lock` cannot do this — a mutex lives in one process's address space. | `SingleInstance`, `singleton.py:65` |
| **Why descriptor, not PID file** | The lock is held by the **file descriptor**, so when a process dies — even SIGKILL — the OS closes its descriptors and the lock releases. A PID file survives a crash (blocking the next start) and PIDs are recycled. | `singleton.py` |
| **Ordered teardown** | Handlers run in **reverse** registration order — a stack — and each is individually guarded, so one raising does not prevent the rest. | `TeardownRegistry`, `signals.py:62` |
| **Signal handling** | SIGINT, SIGTERM, SIGBREAK. | `install_handlers`, `signals.py:124` |
| **`SetConsoleCtrlHandler`** | Closing a console window sends CTRL_CLOSE_EVENT, which is **not a signal** and never reaches Python's signal module. Windows then gives ~5 seconds before killing the process. | `_install_console_handler`, `signals.py:166` |
| **Qt nudge** | Python signal handlers only run between bytecodes; while Qt is blocked in its C++ event loop no Python runs, so a Ctrl+C just sits there. A QTimer firing a few times a second returns control to Python briefly. | `install_qt_nudge`, `signals.py:205` |
| **Crash journal** | Record the intent before acting, clear it after, and on the next launch clean up whatever is still recorded. The only defence against SIGKILL and power loss, which run nothing. | `Journal`, `signals.py:229` |
| **Atomic write** | `os.replace` — a reader sees either the old file or the new one, never a torn one. | `atomic_write_json`, `atomicio.py:52` |
| **Atomicity ≠ durability** | After a power loss the rename can be recorded while the data is still in the page cache, giving an atomically-renamed **empty** file. So: `flush()` + `os.fsync()` *before* the replace, plus best-effort parent-directory fsync on POSIX. | `atomicio.py` |

---

## H. IPC and framing

| Keyword | Answer | Where |
|---|---|---|
| **Stream vs message** | A pipe or TCP connection is a byte stream with no message boundaries. Write three messages and the reader may see one read or seven. The protocol must supply the boundaries. | `oslab/ipc/framing.py` |
| **Delimiter framing** | Terminate with a byte that cannot appear in the payload — simple, but requires escaping, which is where bugs live. | `framing.py` docstring |
| **Fixed-length framing** | Every message the same size — wasteful and inflexible. | `framing.py` |
| **Length-prefix framing** | Send the length, then that many bytes. Used here: 4-byte big-endian length + UTF-8 JSON. Also what DNS-over-TCP, TLS records, and this project's own tunnel header do. | `encode_frame`, `framing.py:55` |
| **`recv` returns *up to* n** | Reads must loop. Treating one read as one message works in testing and fails in production under load. | `read_exactly`, `framing.py:74` |
| **Attacker-controlled length** | A peer claiming 4 GB makes a naive reader allocate 4 GB and die — a one-line DoS. `MAX_FRAME` (1 MiB) caps it, and **the cap is checked before any allocation**. | `framing.py:48` |
| **`FrameBuffer`** | Handles several frames in one chunk, one frame split across chunks, and keeps the remainder for the next feed. | `framing.py:109` |
| **`PlatformOps`** | The interface both sides of the (unbuilt) privileged daemon would use; `FakeOps` works for tests, `RealWindowsOps` is stubbed. | `oslab/daemon/ops.py` |

---

## I. GUI, Qt and the client

| Keyword | Answer | Where |
|---|---|---|
| **PySide6 / Qt** | The GUI framework. `Fusion` style is forced so QSS + QPalette theming renders identically across platforms. | `main.py::setup_application` |
| **Qt event loop** | Single-threaded UI loop. Blocking it freezes the window — which is exactly the bug that was fixed (4–10 s frozen UI, measured **1 event-loop tick**, now **64**). | `gui/main_window.py` |
| **Signal / slot** | Qt's thread-safe message passing: a signal emitted from a worker thread is **queued** to the main thread. | `ConnectionMonitor` |
| **QThread** | Qt-aware thread. `ConnectionMonitor` polls handler status every 2 s and emits a queued signal. | `gui/main_window.py:24` |
| **`ThreadPoolExecutor`** | Used for concurrent server latency probing — I/O-bound, so threads help. Startup scan went **6.23 s → 1.11 s (5.6×)**. | `vpn_core/speedtest_utils.py:215` |
| **Handler polymorphism** | Three interchangeable handlers behind one interface: `RealWindowsWireGuard`, `WireGuardHandler` (Linux/macOS), `SimpleVPNHandler` (demo fallback). | `vpn_core/` |
| **`ConnectionState`** | DISCONNECTED → CONNECTING → CONNECTED → IDLE → DISCONNECTING → DISCONNECTED, plus ERROR. | `vpn_core/wireguard_handler.py` |
| **`wg-quick up`** | Brings up the tunnel: creates the TUN interface, configures routes, establishes the peer. Blocks 10–30 s, so it runs on a background thread. | `wireguard_handler.py` |
| **`RotatingFileHandler`** | 10 MB per file, 5 backups. | `vpn_core/logger.py` |
| **`get_logger(__name__)`** | The idiom that broke file logging: handlers were attached to the logger named `"OnamVPN"` while modules logged under their own module names, so **every log file was 0 bytes since Oct 2025**. | `vpn_core/logger.py` |
