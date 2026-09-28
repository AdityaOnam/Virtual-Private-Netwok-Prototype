# 03 — Computer Networks Concepts

Concept-specific questions for Modules A (Dissector), B (Native Tunnel), C (Transport),
D (DNS) and E (Path & Routing).

---

# Module A — Packet Dissector

**Q1. What does the dissector actually do?**
Decodes raw frames into a layered `DecodedPacket`, field by field, with every field
carrying both its raw bytes and its bit span. Nothing delegates parsing to a library —
the point is that every field is extracted by code you can read.

**Q2. Which decoders exist?**
Ethernet II and 802.1Q (L2), IPv4, IPv6 and ICMP/ICMPv6 (L3), TCP with options and UDP
(L4).

**Q3. How is encapsulation implemented in code?**
`dispatch.decode_packet()` chains the decoders: EtherType selects the L3 decoder, the IP
protocol number selects the L4 decoder. Each step reads one field from the header it just
parsed to decide what to parse next.

**Q4. What is the `FieldView` invariant and why does it matter?**
Every field carries both `raw_bytes` and a `(bit_offset, bit_length)` span. These are two
descriptions of the same thing; if they disagree, the hex-dump highlight drifts away from
the decoded value. `FieldView.__post_init__` enforces `len(raw_bytes) == byte_length`, so
a decoder that gets it wrong raises immediately instead of producing a misleading display.

**Q5. Give the real bug that invariant catches.**
The first IPv4 decoder passed the two-byte flags+fragment word as `raw_bytes` for each of
the three one-bit flags, all of which live entirely inside the *first* of those bytes. The
bit offsets were right; the highlight was one byte too wide, with nothing to catch it.

**Q6. How are sub-byte fields extracted?**
`model._extract_bits(data, bit_offset, bit_length)` — used for the IPv4 version/IHL
nibbles and the three flag bits.

**Q7. Explain the Internet checksum.**
RFC 1071: sum the data as 16-bit big-endian words with end-around carry, then take the
ones-complement. Verifying a packet *including* its own checksum field yields zero if it
is intact. Implemented once in `checksums.py:19` and reused by `netlab/path/traceroute.py`.

**Q8. Why does TCP's checksum cover IP addresses?**
Through a **pseudo-header** (source IP, destination IP, protocol, TCP length). It binds
the segment to the addresses it was sent between, so a segment misdelivered to the wrong
host fails its checksum instead of being accepted.

**Q9. TCP has no length field of its own. Why is that a problem?**
The segment length has to come from IP (`total_length − IHL·4`). If you instead compute
the checksum over "the rest of the buffer", you fold in whatever follows — which is
exactly the padding bug below.

**Q10. Describe the Ethernet-padding defect.**
Ethernet pads frames shorter than 60 bytes. A 60-byte padded TCP SYN has trailing zeros
after the TCP header. Computing the checksum over "the rest of the buffer" folded that
padding in, so **every SYN, ACK and FIN reported BAD CHECKSUM** — the first packets
anyone captures.

**Q11. What is `carries_transport_header()` and what went wrong with it?**
It answers "does this IP datagram carry a transport header, or is it a later fragment
carrying raw payload?" It was written and never called, so the dispatcher descended into
later fragments and **invented ports and sequence numbers** from arbitrary bytes — a
20-byte chunk of anything parses as a plausible TCP header.

**Q12. Why can a first fragment's TCP checksum not be verified?**
A first fragment (MF=1, offset 0) carries a real TCP header, and must be decoded — but its
checksum covers the whole *reassembled* segment, so it cannot be verified from that
fragment alone. The field says so rather than flagging it bad.

**Q13. Is a UDP checksum of zero an error?**
No. On IPv4, RFC 768 says zero means the sender did not compute one. Flagging it corrupt
shows a false error on ordinary traffic. (On IPv6 the UDP checksum is mandatory.)

**Q14. What does IHL=6 mean?**
The IPv4 header is 6 × 4 = 24 bytes: 20 fixed + 4 bytes of options. The payload does not
start at byte 20 — a variable-length-header case that a fixed-offset parser gets wrong.

**Q15. In `02_sharp_edges.pcap`, which packet is genuinely corrupt?**
Packet 5 — a corrupted IPv4 checksum. The other five are legitimate traffic that *looks*
wrong to a naive decoder.

**Q16. Why is the IPv4 checksum of packet 5 at frame bytes `[24:26]`?**
14 (Ethernet header) + 10 (IPv4 checksum offset) = 24, and the field is 2 bytes.

**Q17. Which TCP options are parsed?**
MSS, Window Scale, SACK-permitted/SACK blocks, and Timestamps, in
`transport._parse_tcp_options`.

**Q18. How does the pcap reader know the file's byte order?**
From the libpcap **magic number** in the first 4 bytes. Its byte order tells the reader
the endianness of every field that follows — a file format carrying its own byte order.

**Q19. What does `incl_len < orig_len` mean in a pcap record?**
The frame was truncated at capture time by the **snapshot length** — the capture saw more
bytes on the wire than it stored.

**Q20. Why is Scapy in `requirements.txt` if decoding is hand-written?**
Scapy is used **only as a byte-delivery source** for live capture (`sniff()` returning raw
bytes) — and separately as an independent reference implementation in the cross-check
tests. All decoding is hand-written.

**Q21. Why can't Ethernet decoding be built on raw sockets on Windows?**
Python's `SOCK_RAW` on Windows delivers IP-layer, inbound-only frames with **no link-layer
header**. An Ethernet decoder built on it parses garbage. Ethernet capture needs Npcap.

**Q22. What does the dissector *not* do?**
No IPv6 extension-header chain decoding (the fixed 40-byte header and `next_header` are
parsed, the chain is left to the caller), and **no reassembly** — fragments are identified
and handled correctly, but the original datagram is never rebuilt.

**Q23. What wrong results should you watch for?**
Any packet in `01_tcp_handshake.pcap` flagged bad (the padding bug is back); packet 2 of
`02_sharp_edges.pcap` showing a TCP layer (the fragment check is being skipped); a field
description containing a literal `{` (an unrendered f-string — one shipped, in the TCP
`data_offset` text).

---

# Module B — The Native Tunnel

**Q24. What is OnamVPN Native?**
A VPN written in this repository — roughly 1400 lines — where every byte on the wire is
produced by code here: X25519 → HKDF → ChaCha20-Poly1305, with an RFC 6479 replay filter
and a SOCKS5 front end.

**Q25. What are the four message types?**
Handshake Initiation (type 1, 132 bytes), Handshake Response (type 2, 76 bytes), Cookie
Reply (type 3, **reserved, not implemented**), and Transport Data (type 4, 16-byte header
+ ciphertext + tag).

**Q26. Lay out the Handshake Initiation.**
```
offset  size  field
  0       1   type = 1
  1       3   reserved (zero)
  4       4   sender_index          u32 LE
  8      32   ephemeral public key  X25519
 40      48   encrypted_static      32 B key + 16 B tag
 88      28   encrypted_timestamp   12 B TAI64N + 16 B tag
116      16   mac1                  BLAKE2s-128 keyed
```

**Q27. Lay out the Transport Data header.**
```
  0   1  type = 4
  1   3  reserved
  4   4  receiver_index  u32 LE
  8   8  counter         u64 LE — the AEAD nonce
 16   n  ciphertext + 16 B Poly1305 tag
```

**Q28. How is the protocol kept honest about its own sizes?**
The `struct` format strings are `struct.calcsize()`d and asserted against the documented
tables **at import time**, so a format string and its documentation cannot drift apart.

**Q29. Why is the counter little-endian when IP headers are big-endian?**
To match WireGuard. It is worth pointing at: "network byte order" is a convention of the
IP suite, not a property of protocols in general — `netlab/dissect` reads big-endian
headers a few files away.

**Q30. Walk through the key schedule.**
```
C = HASH(PROTOCOL_NAME)
H = HASH(C ‖ PROLOGUE) ; H = HASH(H ‖ S_r)

message 1:  e_i,E_i = keygen
            C = KDF1(C, E_i) ; H = HASH(H ‖ E_i)
            C,k = KDF2(C, DH(e_i, S_r))
            enc_S_i = AEAD(k, 0, S_i, aad=H)        ← identity, hidden
            C,k = KDF2(C, DH(s_i, S_r))
            enc_ts  = AEAD(k, 0, TAI64N(now), aad=H) ← handshake replay defence

message 2:  e_r,E_r = keygen
            C = KDF1(C, E_r) ; H = HASH(H ‖ E_r)
            C = KDF1(C, DH(e_r, E_i))               ← forward secrecy
            C = KDF1(C, DH(e_r, S_i))
            enc_none = AEAD(k, 0, b"", aad=H)       ← key confirmation

both:       T1, T2 = KDF2(C, b"")
            initiator: send=T1 recv=T2
            responder: send=T2 recv=T1
```

**Q31. How do the two sides agree which key is which?**
The KDF emits an **ordered pair** and the roles are fixed by who initiated. Nothing is
negotiated, so nothing can get out of step.

**Q32. What are C and H, and why two values?**
`C` (chaining key) absorbs every *secret* — the DH results. `H` (transcript hash) absorbs
everything *sent or received* and is used as AEAD associated data, so tampering anywhere
in the transcript makes the next decryption fail.

**Q33. What provides forward secrecy?**
The ephemeral-ephemeral DH — `C = KDF1(C, DH(e_r, E_i))`. Ephemeral keys are discarded
after the handshake, so a later compromise of a static key does not decrypt past sessions.

**Q34. What provides identity hiding?**
The initiator's *static* public key is transmitted encrypted (`encrypted_static`), under a
key derived from `DH(e_i, S_r)` — which only the real responder can compute.

**Q35. Why is there a timestamp in the initiation?**
Without it, an attacker who records a valid initiation can replay it forever and force the
responder to redo the expensive half of the handshake. The responder keeps the greatest
TAI64N timestamp per peer and rejects anything not strictly greater.

**Q36. What is mac1 for?**
`MAC(HASH(LABEL ‖ S_r), message)`. A peer that does not already know the server's public
key cannot compute it, so junk is discarded **before any curve arithmetic happens**.

**Q37. Why is nonce discipline critical?**
ChaCha20-Poly1305 fails catastrophically if a `(key, nonce)` pair repeats — the keystream
is reused and both plaintexts leak (XOR of the two plaintexts is recoverable).

**Q38. How is the nonce constructed?**
`4 zero bytes ‖ counter as u64 little-endian`:
```
counter 0      → 00 00 00 00 | 00 00 00 00 00 00 00 00
counter 1      → 00 00 00 00 | 01 00 00 00 00 00 00 00
counter 2**32  → 00 00 00 00 | 00 00 00 00 01 00 00 00
```

**Q39. What two rules enforce nonce safety?**
`encrypt()` raises `NonceExhausted` past `REJECT_AFTER_MESSAGES` (2²⁴) rather than
wrapping; and `needs_rekey()` goes true far earlier (`REKEY_AFTER_MESSAGES` = 2²⁰), so a
healthy session rotates long before the hard limit.

**Q40. Why is there no setter for the keys alone?**
`install_keys()` replaces both keys **and** resets the counter in one call. Changing either
without the other reuses a nonce under a live key — the one thing this construction does
not tolerate. Removing the ability to do it is the enforcement.

**Q41. What is `PeerState.previous` for?**
It keeps the retired session **decrypt-only** after a rekey, so packets already in flight
when the rekey happened still arrive.

**Q42. Why is the naive replay check wrong?**
```python
if counter <= highest_seen: drop
```
UDP reorders. That discards legitimate reordering. A receiver must accept a counter lower
than one already seen, while rejecting one it has seen *before*.

**Q43. How does the sliding-window replay filter work?**
A 1024-bit bitmap over the most recent counters:
```
state: highest=10, window covers 3..10, seen {10, 9, 7}
  recv 11  → above window   → accept, slide
  recv  8  → inside, unset  → accept   (legitimate reorder)
  recv  9  → inside, set    → REJECT   (replay)
  recv  2  → below window   → REJECT   (too old to judge)
```

**Q44. "Below window → reject" can drop legitimate packets. Why is that acceptable?**
Because they are too old to prove innocent. It is a deliberate trade of **bounded memory**
against dropping badly-delayed packets — the same trade every real implementation makes.

**Q45. Why must authentication happen before the counter is recorded?**
Otherwise a forged packet with a plausible counter would poison the replay window, and the
*genuine* packet with that counter would then be dropped as a replay. This is asserted in
the tests.

**Q46. How do the tests distinguish a replay from a forgery?**
By sending an identical datagram twice: the Poly1305 tag is valid both times, so only the
window can tell them apart — it must be rejected as a **replay**, not a forgery.

**Q47. Why SOCKS5 instead of a TUN adapter?**
A TUN adapter captures every packet the machine sends — what a real VPN does — but on
Windows that means loading `wintun.dll` through `ctypes` and driving its ring-buffer API
(`python-pytun` is Linux-only). SOCKS5 needs no driver, no admin rights, and is
demonstrable immediately: point a browser at `127.0.0.1:1080`.

**Q48. What is the cost of that choice?**
It tunnels **applications configured to use the proxy**, not the whole device. Anything
else still goes out in the clear.

**Q49. What is the inner frame format and why does it exist?**
`kind (1) ‖ stream_id u32 LE (4) ‖ length u16 LE (2) ‖ payload` — 7-byte header. It exists
because we tunnel SOCKS5 *connections*, so several TCP streams must be multiplexed inside
one tunnel. Frame kinds: OPEN (payload = `host:port`), DATA, CLOSE, KEEPALIVE.

**Q50. What is `MAX_TUNNEL_PAYLOAD` and why?**
1280 bytes — so a tunnel datagram fits inside the minimum MTU every IPv6 link must
support, avoiding IP fragmentation.

**Q51. Describe the `chunk_payload` defect.**
`chunk_payload` was written and unit-tested but **never called** in the relay loops. A
16 KiB read was framed whole, producing a datagram that IP-fragmented; losing one fragment
killed the whole datagram, so **200 KB arrived as 134 KB** — silently.

**Q52. Why is a keepalive needed, and why 25 seconds?**
NAT bindings expire after a period of silence, after which the server cannot reach the
client. `KEEPALIVE_SECONDS = 25` refreshes the binding; an empty-plaintext transport
packet costs 16 + 16 = 32 bytes.

**Q53. What does "no retransmission" mean here, precisely, and why is it the important limit?**
WireGuard tunnels whole **IP packets**, so a dropped datagram costs an inner TCP segment
and the inner TCP retransmits it. We tunnel SOCKS5 **stream bytes**, so a dropped datagram
removes bytes from the middle of a TCP stream with nothing to notice or repair it. On
loopback this effectively never happens; on a lossy path it would corrupt transfers.
`netlab/transport` is the layer that would fix it, and the two are not wired together.

**Q54. What else is the tunnel not defended against?**
No DoS defence (no cookie mechanism, therefore no mac2 — each initiation costs two X25519
operations and an attacker can force them); no traffic-analysis resistance (packet sizes
and timing unpadded, so the *shape* of a session is visible even though its content is
not); no roaming (a peer's endpoint is fixed at handshake time); not constant-time; not
formally verified.

**Q55. What does the end-to-end demo print, and what would be wrong?**
```
handshakes : 1 | byte-identical : True | send counter : 84
replay accepted : 81 | replay rejected : 0 | forgeries dropped: 0
```
`byte-identical: False` means data loss (check `chunk_payload`). `forgeries dropped`
climbing during normal use means something is corrupting packets or a session is being
decrypted with the wrong key. `replay rejected` climbing means the window is too small for
the reordering on this path, or the counter is being double-counted.

---

# Module C — Transport: ARQ and Congestion Control

**Q56. Compare the three ARQ protocols.**

| | Window | ACK | Timers | Receiver | Recovery |
|---|---|---|---|---|---|
| Stop-and-Wait | 1 | per segment | 1 | trivial | trivial, but 1 segment/RTT |
| Go-Back-N | N | cumulative | **one** | discards out-of-order | resend the lost segment **and everything after** |
| Selective Repeat | N | per segment | **per segment** | buffers out-of-order | resend only the lost segment |

**Q57. What is the fundamental trade between GBN and SR?**
Receiver memory against wasted bandwidth. It is why real TCP started as Go-Back-N and grew
SACK once memory got cheap and bandwidth-delay products got large.

**Q58. Give the measured comparison.**
At 100 segments, window 8:

| loss | protocol | retransmitted | efficiency |
|---|---|---|---|
| 20% | go-back-n | 81 | 0.55 |
| 20% | selective-repeat | 69 | 0.59 |
| 30% | go-back-n | 121 | 0.45 |
| 30% | selective-repeat | 101 | 0.50 |

**Q59. Why is the simulation reproducible, and why does that matter?**
An injected virtual `Clock` (nothing calls `time.time()`) plus a seeded PRNG: the same seed
produces a byte-identical trace every run, tested in `TestReproducibility`. A 60-second
transfer simulates in milliseconds and never flakes on a loaded machine. **A congestion
graph that changes between runs cannot be explained in a viva.**

**Q60. Draw the Reno state machine.**
```
              cwnd < ssthresh
        ┌──────────────────────────────┐
        │        SLOW START            │
        │  cwnd += 1 MSS per ACK       │  → doubles per RTT
        └──────────────────────────────┘
                    │ cwnd >= ssthresh
                    ▼
        ┌──────────────────────────────┐
        │     CONGESTION AVOIDANCE     │
        │  cwnd += MSS²/cwnd per ACK   │  → +1 MSS per RTT
        └──────────────────────────────┘
           │                      │
           │ 3 dup ACKs           │ timeout
           ▼                      ▼
     ┌──────────────┐      ssthresh = cwnd/2
     │FAST RECOVERY │      cwnd     = 1 MSS
     │cwnd = ssthresh+3    → SLOW START
     └──────────────┘
```

**Q61. Explain the asymmetry between the two loss signals — the single most important point on the graph.**
Three duplicate ACKs mean packets are *still arriving*: the path works, one segment was
lost, so halving cwnd is proportionate. A timeout means **nothing has arrived for a whole
RTO**: every assumption about the path is stale, so the sender drops to one segment and
re-probes from scratch. On the plot, a red (timeout) line always collapses cwnd to the
floor; a green (fast retransmit) line never does.

**Q62. Why is "slow start" a misleading name?**
It is the *fastest* phase — exponential growth. The name is historical: it is slow compared
to the original TCP, which blasted the receiver's whole advertised window on the first RTT
and collapsed the early internet.

**Q63. Why is congestion avoidance `MSS²/cwnd` per ACK?**
Because roughly `cwnd/MSS` ACKs arrive per RTT, so `cwnd/MSS × MSS²/cwnd = MSS` — exactly
one extra segment per RTT. That is the additive increase of AIMD expressed per-ACK.

**Q64. Distinguish flow control from congestion control.**
Flow control protects the **receiver** (advertised receiver window). Congestion control
protects the **network** (cwnd). The sender is limited by `min(cwnd, rwnd)` — implemented
as `window_bytes(receiver_window)`.

**Q65. How is the RTO computed?**
Jacobson/Karels: `RTO = SRTT + 4·RTTVAR`. The `4·RTTVAR` term is why a jittery path gets a
wider RTO than a steady one with the same mean — asserted in the tests.

**Q66. Explain Karn's algorithm and the failure it prevents.**
When a segment is retransmitted and an ACK arrives, the ACK is ambiguous — it may be for
the original or the retransmission, and the two have very different elapsed times.
Measuring it corrupts SRTT in the dangerous direction: if the ACK was for the original, the
measured time is far too short, which shortens the RTO, which causes more spurious
retransmissions, which shortens it further. Karn's rule: do not sample RTT from a
retransmitted segment at all; double the RTO on each timeout instead, and only resume
sampling after a clean ACK.

**Q67. What is the bandwidth-delay product and what does the bottleneck report say?**
BDP = bandwidth × RTT: the bytes that must be in flight to keep the link busy. The panel
computes both and names the binding limit:
```
window-limited: 46720 B window < 50000 B BDP  — the link cannot be filled regardless of loss
link-limited:   93440 B window >= 50000 B BDP — the window is not the constraint
```
A sender whose window is below the BDP sends a window and then waits an RTT. On a
throughput graph that looks exactly like congestion.

**Q68. What wrong results should you watch for?**
`delivered intact: False` (ARQ is broken — the whole point is that the byte stream survives
a lossy link); Selective Repeat retransmitting *more* than Go-Back-N (the per-segment timer
logic has regressed — this happened: a shared RTO was backed off on every per-segment
timeout, making the protocol progressively deaf); cwnd collapsing to 1 MSS on a fast
retransmit (the two loss signals have been conflated); a different trace on a rerun with
the same seed (reproducibility is broken and no graph can be trusted).

**Q69. What are the module's limits?**
Reno only, not CUBIC or BBR. No real SACK option blocks — Selective Repeat uses per-segment
ACKs. Not wired to the native tunnel. 64-bit sequence numbers that never wrap: real
Selective Repeat needs the window to be at most **half** the sequence space or it cannot
distinguish a retransmission from a new segment reusing the number, and a non-wrapping
counter sidesteps that.

---

# Module D — DNS

**Q70. Describe the DNS header.**
12 bytes: ID (16), flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE), then QDCOUNT, ANCOUNT,
NSCOUNT, ARCOUNT — one 16-bit count per section.

**Q71. How is a name encoded on the wire?**
Length-prefixed labels ending in a zero byte. `www.example.com` becomes:
```
03 'w''w''w' 07 'e''x''a''m''p''l''e' 03 'c''o''m' 00
```
**There are no dots on the wire.**

**Q72. Why is a label limited to 63 bytes?**
Because that leaves the two high bits of a length byte free — and that is exactly what
compression uses.

**Q73. Explain compression pointers.**
A length byte with both high bits set (`≥ 0xC0`) is not a label: it is a 14-bit offset from
the start of the *message*. `0xC0 0x0C` means "the rest of this name is at byte 12" — and
byte 12 is where the question section starts, so almost every answer in a real response
points there rather than repeating the name.

**Q74. Can you avoid implementing compression by not using it?**
No. The **server** decides whether to compress. A parser that ignores it produces garbage
on real traffic, and asking politely does not help. (We never *emit* compression — a query
has one name, so there is nothing to compress — but we must still parse it.)

**Q75. What are the two subtleties of pointer handling?**
(1) **Where parsing resumes**: after following a pointer, the next record starts after the
*pointer* (2 bytes), not after wherever it led — getting this wrong shifts every subsequent
record and produces plausible-looking nonsense. (2) **Pointer loops**: a broken or
malicious server can emit a pointer to itself, or two pointing at each other; a naive
parser follows them forever. `MAX_POINTER_JUMPS = 64` caps it, which is what every real
resolver does.

**Q76. Compare the three (four) transports.**

| Transport | Port | Property |
|---|---|---|
| UDP | 53 | The original. Fast, unencrypted — your ISP sees every name you look up even when the page is HTTPS |
| TCP | 53 | The truncation fallback; message prefixed with its 2-byte length |
| DoT | 853 | Same messages inside TLS with a 2-byte length prefix. Encrypted, but **obviously DNS** — blockable by port |
| DoH | 443 | The same bytes POSTed as `application/dns-message`. Slowest, and speed is not the point: **indistinguishable from ordinary web traffic**, so it cannot be blocked without blocking HTTPS |

**Q77. Why does DoT need a 2-byte length prefix when UDP DNS does not?**
A UDP datagram carries its own boundary. TLS is a **stream**, so DNS has to supply framing
— the same length-prefix idea as `oslab/ipc/framing.py` and the tunnel's transport header.

**Q78. Why is certificate verification left on for DoT?**
Turning it off would defeat the entire purpose: an attacker who can redirect port 853 could
then answer every query — worse than plaintext, because it *looks* secure.

**Q79. What is the TC bit and what must happen next?**
Truncation. A UDP response too large for the negotiated size comes back with TC set and no
useful answer; the resolver must retry over TCP :53 with the same message. This is the
oldest fallback in the protocol.

**Q80. Why does the cache count an expired entry as a miss?**
The answer existed but is no longer usable, which is the whole point of the TTL. Counting
it as a hit would inflate the hit rate and hide the fact that a query still had to go out.

**Q81. Why is honouring TTL not just politeness?**
It is how an operator moves a service: lower the TTL, wait for the old one to expire
everywhere, change the record, and traffic follows. A resolver that ignores TTL keeps
sending users to a decommissioned address.

**Q82. Why is DNS in a VPN project at all?**
Because DNS is the most common way a VPN leaks. The tunnel can be perfectly encrypted while
the OS resolver keeps sending plaintext queries to the ISP's server over the physical
adapter — so an observer learns every site visited without seeing any content.

**Q83. How does the leak test work?**
Start a capture on the physical NIC filtered to UDP :53, resolve a **unique random** name,
then look for that name in the captured bytes.

**Q84. Why must the query name be unique?**
Resolving `example.com` proves nothing — the OS resolver, the router, or the ISP may answer
from cache without a packet leaving the machine, and that absence of traffic would look
exactly like success.

**Q85. Why search for the name in wire form?**
Because length-prefixed labels are what actually appear on the wire; a dotted string never
does.

**Q86. What was significant about `leaktest.py` existing at all?**
`README.md` had always claimed OnamVPN blocks port 53 on every adapter except the tunnel.
**Nothing in the project ever checked that claim.** `leaktest.py` is the first thing that
tests it.

**Q87. What is the DNS-leak firewall defect?**
Windows evaluates **Block before Allow**. A blanket block rule plus a tunnel-scoped allow
rule therefore blocked *all* DNS, not just the leaking path.

**Q88. What are the module's limits?**
No negative caching (RFC 2308 — a real resolver caches NXDOMAIN using the SOA minimum, so a
typo'd domain does not hammer the authority); no recursion (this is a **stub** resolver, it
asks a recursive server rather than walking the hierarchy from the root); no DNSSEC; we
never *emit* compression; and the leak test cannot run on this machine because Npcap
enumerates only loopback — it degrades to comparing transports and **says so in its own
output** rather than implying otherwise.

---

# Module E — Path and Routing

**Q89. How does traceroute work, given that IP has no "tell me the path" message?**
It abuses TTL. Every router that forwards a packet decrements TTL; a router that decrements
it to zero discards the packet and reports it with ICMP Time Exceeded. Send TTL=1, 2, 3…
and each hop identifies itself by the source address of its ICMP error, until the
destination replies Echo Reply instead. **The path is assembled entirely from error
messages.**

**Q90. How are replies matched to probes?**
A Time Exceeded carries the first 8 bytes of the original datagram inside it, so the
identifier and sequence we sent are recoverable — that is how our probes are distinguished
from every other ICMP message on the machine.

**Q91. Why does `*` appear for some hops?**
Not a broken router. Many operators rate-limit or suppress ICMP errors, and some firewalls
drop them entirely. The hop forwards packets perfectly while declining to announce itself.

**Q92. Why use the `IP_TTL` socket option rather than crafting the IP header?**
Crafting one by hand needs `IP_HDRINCL` and behaves inconsistently across Windows versions.
`IP_TTL` is portable and is what the system `tracert` does.

**Q93. Describe the `traceroute_available()` trap.**
It originally reported success while every probe timed out, producing 30 rows of `* * *`.
**Windows lets an unelevated process create a raw ICMP socket but not send or receive on
it**, so checking that the socket constructs is a false positive. The check now verifies
elevation explicitly and falls back to parsing the system `tracert` when privileges are
missing — the panel works either way, and the mechanism being demonstrated is identical.

**Q94. Explain longest-prefix match.**
A destination usually matches several routes; the winner is the one with the most specific
prefix — the longest netmask — **regardless of the order routes appear in the table**.
`0.0.0.0/0` matches everything and therefore always loses to anything else that matches at
all, which is exactly what makes it a useful default.

**Q95. Explain the split-default trick — the best single thing in the module.**
WireGuard's `AllowedIPs = 0.0.0.0/0` does **not** replace the default route. It installs
two:
```
0.0.0.0/1     → tunnel    covers   0.0.0.0 – 127.255.255.255
128.0.0.0/1   → tunnel    covers 128.0.0.0 – 255.255.255.255
```
Together they cover the whole address space, and each `/1` beats the real default's `/0` on
specificity. So all traffic goes to the tunnel **without deleting the original default
route**.

**Q96. Why does not deleting the default route matter so much?**
The original route is how packets reach the VPN server itself. Delete it and the tunnel
cannot carry its own traffic — the classic self-inflicted outage.

**Q97. How does the VPN's own traffic escape the tunnel?**
The route to the VPN endpoint stays a `/32` through the physical gateway, and `/32` beats
`/1`. Three prefix lengths do three different jobs, decided entirely by longest-prefix
match:
```
8.8.8.8        → 0.0.0.0/1        via 10.8.0.1     (tunnel)
200.1.2.3      → 128.0.0.0/1      via 10.8.0.1     (tunnel)
162.159.192.1  → 162.159.192.1/32 via 192.168.1.1  (physical — the VPN server)
192.168.1.7    → 192.168.1.0/24   on-link          (LAN)
```

**Q98. Derive the MTU arithmetic.**
```
1500   typical Ethernet MTU
-  20  outer IPv4 header    (40 if the path is IPv6)
-   8  outer UDP header
-  32  WireGuard data header + Poly1305 tag
=1440  available to the inner packet
```

**Q99. So why is the configured MTU 1280 and not 1440?**
1280 is the minimum MTU every IPv6 link must support (RFC 8200 §5), so a tunnel at 1280
survives almost any path — including one that is itself tunnelled — without fragmenting.
Trading about 11% of payload efficiency for not having to debug an ICMP black hole is a
good trade.

**Q100. What is an ICMP black hole and why is it hard to diagnose?**
Some networks block all ICMP, believing it to be "just ping". The sender then gets no
Fragmentation Needed error at all: large packets vanish silently while small ones succeed,
so a connection completes its handshake and then hangs on the first big transfer. The
symptom looks like anything *but* MTU.

**Q101. What wrong results should you watch for?**
Every hop `* * *` (running unelevated with the raw-socket path selected — the availability
check should have caught this and fallen back); RTTs not generally increasing with hop
count (probes are being mismatched to replies); the VPN endpoint routing via the tunnel
gateway rather than the physical one (the `/32` is missing, and the tunnel is about to
deadlock on its own traffic).

**Q102. What are the module's limits?**
PMTU discovery cannot run unelevated (and returns a result carrying the reason rather than
raising); IPv4 only (IPv6 traceroute needs ICMPv6 and a different socket family); no Paris
traceroute, so load-balanced paths can report hops that are not actually on one path; and
the before/after VPN comparison is manual.
