# 06 — Constructive & Critical Questions

The hard ones. Defects and how they were found, design trade-offs defended, limits stated
plainly, and what you would do next. These are the questions where a rehearsed answer shows
and an honest one lands.

---

## A. Defects found and fixed

**Q1. How many defects were found, and why does the project count them?**
Twenty. The count matters less than *how* they were found — a defect discovered by an
integration test says something different from one discovered by a unit test.

**Q2. List the most instructive ones.**

| Defect | Consequence |
|---|---|
| TCP checksum computed over Ethernet padding | **Every SYN, ACK and FIN reported BAD CHECKSUM** — the first packets anyone captures |
| `carries_transport_header()` added, never called | Later IP fragments decoded as TCP, **inventing ports from raw payload** |
| DNS-leak firewall rules | Windows evaluates **Block before Allow**, so a blanket block plus a tunnel-scoped allow blocked *all* DNS |
| `chunk_payload` written, tested, never called | **200 KB arrived as 134 KB** — oversized datagrams IP-fragmented, one lost fragment killed each |
| File logging never worked | Every log 0 bytes since Oct 2025 — handlers attached to `"OnamVPN"` while modules used `get_logger(__name__)` |
| Connect blocked the Qt event loop | 4–10 s frozen UI — measured **1 event-loop tick**, now **64** |
| Startup latency scan was serial | **6.23 s → 1.11 s** (5.6×) |
| Deadlock cycle detector | **False positive** on a simple chain — worse than a miss |
| `FieldView` bit span vs raw bytes | IPv4 flag highlights one byte too wide, with nothing to catch it |
| Windows lock taken at byte 0 | Mandatory locking made the file's own diagnostics unreadable — moved to offset 4096 |
| Selective Repeat shared RTO | Backed off on every per-segment timeout, making SR **slower than Go-Back-N** despite retransmitting less |
| `traceroute_available()` false positive | 30 rows of `* * *` — Windows lets you *create* a raw socket unelevated but not use it |
| `atomic_write_json` without fsync | Atomic rename of data still in the page cache — an atomically-renamed empty file |
| Unrendered f-string in a field description | The TCP `data_offset` text literally read "payload starts at byte {hlen}" |

**Q3. What is the pattern worth noticing across these?**
Three were the **same shape**: a module written, unit-tested, and never wired to anything —
`carries_transport_header`, `chunk_payload`, and the file-logging handlers. **Unit tests do
not catch *"nothing calls this"*; only an integration test does.**

**Q4. What is the second pattern?**
Several defects produced *plausible* wrong output rather than a crash: invented TCP ports
from fragment payload, NOERROR with no addresses after a pointer error, a false-positive
deadlock. Silent plausible wrongness is harder to find than a traceback, which is why the
concept docs all include a "what a wrong result looks like" section.

**Q5. Why is a false-positive deadlock detection worse than a missed one?**
Because it sends you hunting a bug that does not exist. A miss costs you the bug you already
had; a false positive costs you the bug you did not.

**Q6. The padding bug affected "the first packets anyone captures". Why does that matter more than the bug's size?**
Because it destroys trust in the tool immediately. A decoder that flags every SYN as corrupt
is not a decoder with a bug — it is a decoder nobody will use.

---

## B. Design trade-offs, defended

**Q7. Why SOCKS5 rather than a TUN adapter, and what does it cost you?**
A TUN adapter is what a real VPN uses, but on Windows it means loading `wintun.dll` through
`ctypes` and driving its ring-buffer API (`python-pytun` is Linux-only). SOCKS5 needs no
driver, no admin rights, and is demonstrable in seconds. The cost is real and stated: it
tunnels **applications configured to use the proxy**, not the whole device.

**Q8. Why implement Reno rather than CUBIC or BBR?**
Reno is what the textbook describes and what the sawtooth comes from. CUBIC and BBR are what
modern Linux actually runs — a fair criticism, and it is named as a limit rather than
implied away.

**Q9. Why a virtual clock rather than real timing?**
Because every result must be explainable. A 60-second transfer simulates in milliseconds,
never flakes on a loaded machine, and produces a byte-identical trace per seed. A congestion
graph that changes between runs cannot be explained.

**Q10. Isn't a simulated link a weaker demonstration than a real one?**
It is a different demonstration. A real link cannot be held constant while you vary one
parameter, so it cannot answer "what does 20% loss do to Go-Back-N specifically?" The
simulation is the controlled experiment; the WireGuard client is the real system.

**Q11. Why 1280 MTU instead of the computed 1440?**
1440 is what the arithmetic allows on a clean 1500-byte path. 1280 is the minimum every IPv6
link must support (RFC 8200 §5), so a tunnel at 1280 survives almost any path — including
one that is itself tunnelled. Trading ~11% payload efficiency for not debugging an ICMP
black hole is a good trade.

**Q12. Why lower `sys.setswitchinterval` in the race demo? Isn't that cheating?**
No. The code is equally broken at either setting — the change raises **exposure**, not
brokenness, the way a loaded production machine does. And the default-interval run is kept
and asserted precisely so the contrast is visible: *the bug is constant, the exposure is
not.*

**Q13. Why does the replay window reject packets below the window, when some are legitimate?**
They are too old to prove innocent. Keeping unbounded history to judge them would make
memory an attacker-controlled quantity. It is a deliberate trade of bounded memory against
dropping badly-delayed packets, and every real implementation makes it.

**Q14. Why is there deliberately no setter for the session keys alone?**
Because changing either key without resetting the counter reuses a nonce under a live key —
the one thing ChaCha20-Poly1305 does not tolerate. Removing the ability to do it is stronger
than documenting that you should not.

**Q15. Why does the cache count an expired entry as a miss rather than a hit?**
Counting it as a hit would inflate the hit rate and hide the fact that a query still had to
leave the machine. The TTL exists precisely so that answer stops being usable.

**Q16. Why was Module F stopped halfway?**
Because the phase creates a real privilege boundary, and **a boundary with a flaw is worse
than no boundary**. A request type that lets an unprivileged caller run an arbitrary command
or write an arbitrary path is a security bug, not a bug. The plan gated the work behind
design review so the trust boundary and authentication scheme would be examined before
anything ran elevated.

**Q17. Isn't "we didn't build it" just an excuse?**
The test is whether the stopping point was chosen or stumbled into. `PlatformOps` is defined,
`FakeOps` works and is tested, `RealWindowsOps` is stubbed with `NotImplementedError`, and
the delegation targets it names all exist — so the remaining work is wiring rather than
design. That is a deliberate stop.

**Q18. Why keep the original WireGuard client at all once the labs exist?**
Because it is the thing that actually works. The labs exist to explain a real system, not to
replace it — and "use WireGuard for anything real" is stated in the README.

---

## C. Limits, stated plainly

**Q19. What does the native tunnel not do?**
No retransmission (the important one), no DoS defence (no cookie, therefore no mac2), no
traffic-analysis resistance, no roaming, not constant-time, not formally verified.

**Q20. Explain the "no retransmission" limit precisely.**
WireGuard tunnels whole **IP packets**, so a dropped datagram costs an inner TCP segment and
the inner TCP retransmits it. We tunnel SOCKS5 **stream bytes**, so a dropped datagram
removes bytes from the middle of a TCP stream with nothing to notice or repair it. On
loopback this effectively never happens; on a lossy path it would corrupt transfers.

**Q21. You built an entire ARQ module. Why isn't it wired to the tunnel?**
It is exactly the layer that would fix the gap, and connecting them is left undone — stated
rather than implied. Honest answer: it is the single most obvious next piece of work in the
project.

**Q22. What does the dissector not do?**
No IPv6 extension-header chain decoding, no reassembly (fragments are identified and handled
correctly, but the original datagram is never rebuilt), and no live capture on this machine.

**Q23. What does the DNS module not do?**
No negative caching (RFC 2308), no recursion (stub resolver only), no DNSSEC, and it never
*emits* compression — though it must and does parse it.

**Q24. What does the path module not do?**
PMTUD cannot run unelevated (returns a result carrying the reason rather than raising), IPv4
only, no Paris traceroute (so load-balanced paths can report hops not actually on one path),
and the before/after VPN comparison is manual.

**Q25. What does the OS lab not do?**
Single-CPU scheduling only; non-preemptive SJF and Priority (no SRTF); the buffer pool is not
lock-free; no mmap-backed circular pcap log; and **the signal handlers are not installed in
the running app** — the machinery is built and tested but not wired into `main.py`.

**Q26. Why state all of this out loud?**
Because a demonstration that hides its boundaries teaches the wrong thing, and an examiner
who finds an unstated limit will reasonably wonder what else is unstated.

---

## D. The open tunnel issue

**Q27. State the symptom precisely.**
The app reports `Connected! Cloudflare WARP tunnel active.` and the tunnel service briefly
shows `STATE : 4 RUNNING`. Minutes later the `WireGuardTunnel$wgcf-profile` service no longer
exists, no Wintun adapter is present, the only default route is `0.0.0.0/0 → Wi-Fi` (no
split-default pair, so nothing is being tunnelled), and the public IP is the ISP's.

**Q28. What evidence was gathered?**
```
sc query WireGuardTunnel$wgcf-profile   RUNNING, then "does not exist" 4 min later
Get-NetAdapter                          Wi-Fi, Bluetooth, Sophos TAP, PANGP — no wgcf-profile
Get-NetRoute 0.0.0.0/0                  NextHop 192.170.0.1, InterfaceAlias Wi-Fi
curl api.ipify.org                      139.5.9.101  (ISP, not Cloudflare)
```
The generated config at `C:\OnamVPN\wgcf-profile.conf` is well-formed: correct
`AllowedIPs = 0.0.0.0/0, ::/0`, endpoint `162.159.193.1:2408`, `MTU = 1280`.

**Q29. What is the leading hypothesis?**
`WARP_PRIVATE_KEY` is hardcoded at `vpn_core/real_windows_wireguard.py:27` and committed to
the repository. Cloudflare WARP requires a key **registered to an account** via their
device-registration API. A key registered once and shared by every copy of this project is
likely deregistered, rate-limited or expired. A WireGuard peer whose key the server does not
recognise gets no handshake response — the interface comes up, never completes a handshake,
and the tunnel is torn down. That matches the observed sequence exactly.

**Q30. How would you confirm or refute it?**
1. Let the app auto-connect; file logging now works, so the full sequence lands in
   `%APPDATA%\OnamVPN\logs\onamvpn_<date>.log`.
2. While the tunnel is briefly up: `wg.exe show`. **`latest handshake` never being set
   confirms the key hypothesis.**
3. `wireguard.exe /dumplog` (elevated) gives WireGuard's own reason for stopping.

**Q31. What is the worst thing about this bug, independent of its cause?**
**The UI claims success while no traffic goes through the tunnel.** A VPN that reports
"Connected" when it is not is worse than one that reports failure — the user acts on a
guarantee that does not exist.

**Q32. What would you change about the UI regardless of the root cause?**
Gate the "Connected" state on evidence rather than on the service starting: require a
`latest handshake` timestamp from `wg show`, and require the split-default route pair to be
present. Both are already things the project knows how to check — `netlab/path/routing.py`
reads the live table.

**Q33. What does this bug say about the project's own claims?**
It is the reason `leaktest.py` exists in the form it does. The lesson generalises: a claim
nothing tests is not a feature, it is a hope.

---

## E. Security critique

**Q34. Is hardcoding a private key in a repository acceptable?**
No, and the project says so. It is committed, it is the leading suspect in the open issue,
and the right fix is device registration at runtime with the key stored outside version
control (the `.env` mechanism already exists and is git-ignored).

**Q35. What attack does the missing cookie mechanism enable?**
Each handshake initiation costs the responder two X25519 operations. Without a cookie
reply (and therefore mac2), an attacker can force those at will — a computational
denial-of-service. mac1 stops *unauthenticated junk*; only mac2 stops a flood from someone
who knows the server's public key.

**Q36. What does "no traffic-analysis resistance" actually leak?**
Packet sizes and timing are unpadded, so the **shape** of a session is visible even though
its content is not — request/response boundaries, transfer sizes, idle periods, and often
enough to fingerprint a site.

**Q37. Why does "not constant-time" matter?**
Timing differences correlated with secret data leak the secret. Python is not constant-time
and cannot easily be made so, which is one of several reasons this is a teaching
implementation and not a product.

**Q38. Why is turning off DoT certificate verification worse than plaintext DNS?**
Because it *looks* secure. An attacker who can redirect port 853 can then answer every query
with full confidence from the user that they are protected. A known-plaintext channel at
least sets expectations correctly.

**Q39. What is the security argument for DoH on port 443?**
It is indistinguishable from ordinary web traffic, so it cannot be blocked without blocking
HTTPS. This project measured the argument accidentally: on this network,
`cloudflare-dns.com` does not resolve and TCP :853 opens but TLS times out, while ordinary
HTTPS returns 200 — a middlebox blocking encrypted DNS by port.

**Q40. The GUI runs fully elevated. Why is that a problem, and what is the fix?**
Every line of GUI code — including UI event handling and JSON parsing — runs with
Administrator rights, so any bug anywhere is a privilege-escalation bug. The fix is Module
F's privilege-separated daemon: a small elevated helper exposing a narrow, authenticated set
of operations, with the GUI unprivileged. The framing layer for it exists; the boundary does
not.

---

## F. Methodology and evidence

**Q41. Why is cross-checking against Scapy stronger than golden files?**
A golden file records a wrong answer just as happily as a right one — it pins the decoders
against **themselves**. Scapy is a separate implementation by different authors, so agreement
is evidence rather than self-confirmation.

**Q42. Why is the Scapy cross-check still not the strongest possible check?**
Both are Python, and both could in principle share a misreading of an RFC. An independent
implementation in a different language — `tshark` — would be stronger. It is not installed
here (Wireshark failed with MSI error 1603), and the doc says to prefer
`tshark -V -r docs/samples/01_tcp_handshake.pcap` if you install it.

**Q43. What is the role of `02_sharp_edges.pcap`?**
It is a **regression corpus of real wrong answers**: six packets, each of which produced a
wrong answer during development, exactly one of which is genuinely corrupt. It encodes the
bugs so they cannot come back silently.

**Q44. Why do the concept docs all include "what a wrong result looks like"?**
Because several defects produced plausible wrong output rather than a crash. If you do not
know what wrong looks like, you cannot tell that the demo has regressed.

**Q45. Give an example of a test asserting something unusual.**
`test_default_switch_interval_often_hides_the_race` — it asserts that a bug is **invisible**
at the default setting. The finding being tested is not "the code is correct" but "the
exposure varies", which is the module's actual contribution.

**Q46. How do you know the replay window is tested properly and not just exercised?**
Two tests draw the distinction: an identical datagram sent twice must be rejected as a
**replay, not a forgery** (the tag is valid both times, so only the window can tell them
apart); and a forged packet must not poison the window, which asserts an **ordering**
property — authenticate before recording the counter.

**Q47. What would you add to the test suite if you had one more day?**
Integration tests for the wiring gaps, since that is the defect shape that recurred three
times: assert that the relay loop actually calls `chunk_payload`, that the dispatcher
actually calls `carries_transport_header`, and that a log line written through
`get_logger(__name__)` reaches the file handler.

---

## G. What next

**Q48. What is the single highest-value next piece of work?**
Fix the WARP tunnel — or, if the key hypothesis holds, replace the hardcoded key with proper
device registration. Everything else is a lab; that is the part users touch.

**Q49. What is the second?**
Wire `netlab/transport` to `netlab/native`, giving the tunnel retransmission. It closes the
project's most-stated limit with a module that already exists and is tested.

**Q50. And the third?**
Install the resilience signal handlers in `main.py`, so the kill-switch teardown and crash
journal actually protect the running app rather than only the test suite.

**Q51. How would you make the tunnel resist DoS?**
Implement the cookie reply (message type 3) and mac2: under load the responder replies with
a cookie instead of doing the DH, and only an initiator that can echo the cookie back —
proving it can receive at its claimed address — gets the expensive work done for it.

**Q52. How would you extend the dissector meaningfully?**
IPv6 extension-header chain walking and actual fragment reassembly. Reassembly would also let
the TCP checksum be verified on fragmented segments, closing the "cannot be verified from one
fragment" case honestly rather than by annotation.

**Q53. How would you make the DNS module production-plausible?**
Negative caching per RFC 2308 (using the SOA minimum), and DNSSEC validation. Recursion from
the root is a larger project and arguably not worth it for a stub resolver.

**Q54. What would make the concurrency lab stronger?**
Process-based comparison alongside threads, to complete the argument — currently the module
concludes "use processes for CPU-bound work" without measuring that claim. And an Amdahl fit
over more than two points.

**Q55. What would you do about live capture?**
Either fix the Npcap installation so a physical adapter enumerates, or test on a machine
where it does. Without it the DNS leak test cannot prove what left the machine, and the
Tunnel Comparison demo (VPN off vs on, watching the destination address disappear) cannot
run at all.

**Q56. If you had to remove one thing from the project, what would it be?**
Nothing structural — but the hardcoded WARP key should be deleted from history, not just
from the working tree, since a committed secret stays in the git objects.

---

## H. Meta questions

**Q57. What did you learn that you did not expect?**
That a bug's *exposure* and a bug's *existence* are independent. The race demo produced the
correct answer 10/10 times while being completely broken, and understanding why — CPython
3.12's eval-breaker only checks at call boundaries and loop back-edges — was more valuable
than the race itself.

**Q58. What was the hardest part?**
Making the broken code break reliably. Both the race and the deadlock initially *worked*,
because the windows were too narrow. A demo that only fails sometimes teaches nothing, and
widening the window without fabricating the bug is a genuine design problem.

**Q59. What single decision most improved the project?**
Moving the concepts into the repository. Before that, "show me where you implement key
exchange" had no answer; afterwards there is a file, a line number, and a test.

**Q60. If an examiner accuses the project of being two unrelated things bolted together, what is the answer?**
Point at the mapping table: `netlab/dissect` decodes the WireGuard traffic the real tunnel
produces; `netlab/path/routing.py` explains the split-default routes the real tunnel
installs; `netlab/dns/leaktest.py` tests the DNS-leak claim the real tunnel makes;
`netlab/native` is the real tunnel's mechanism rebuilt small enough to read. The labs are not
a second project — they are the client's own mechanisms, made legible.
