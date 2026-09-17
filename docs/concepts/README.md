# OnamVPN — CN + OS Concept Modules

This directory documents what each module demonstrates, where the code is, and
how to run it.

## Running everything

```bash
python main.py --labs
```

Five tabs, all working offline — no Administrator rights, no capture driver,
no network. Anything that needs one of those says so and degrades rather than
failing.

```bash
python -m pytest tests/ -q      # 457 tests, same requirements
```

## The modules

| Doc | Module | Tab | Core concepts |
|---|---|---|---|
| [dissector.md](dissector.md) | A | Dissector | layering, encapsulation, header fields, checksums, fragmentation |
| [native-tunnel.md](native-tunnel.md) | B | Network | key exchange, AEAD, replay windows, protocol design, SOCKS5 |
| [transport.md](transport.md) | C | Transport | ARQ, sliding windows, RTT estimation, congestion control |
| [dns.md](dns.md) | D | Network | DNS wire format, compression, DoT/DoH, caching and TTL |
| [path-routing.md](path-routing.md) | E | Network | TTL and ICMP, traceroute, PMTU, longest-prefix match |
| [concurrency.md](concurrency.md) | G | Concurrency | races, mutexes, condition variables, deadlock, the GIL |
| [os-lab.md](os-lab.md) | H, I, J | OS Lab | CPU scheduling, slab allocation, crash resilience |
| [ipc.md](ipc.md) | F (partial) | — | message framing over a byte stream |

## How this project changed

OnamVPN began as a GUI wrapper around `wireguard.exe`. Every networking and OS
concept — crypto, handshakes, tunnelling, routing — happened inside binaries
nobody here wrote, which made "show me where you implement X" unanswerable.

The modules above move those concepts into the codebase. The original
WireGuard path still exists and still works; it is what you use to actually
browse. The labs are what you point at when explaining how any of it works.

The two halves meet in a few places worth knowing about:

- `netlab/dissect` decodes the WireGuard traffic the real tunnel produces.
- `netlab/path/routing.py` explains the split-default routes the real tunnel
  installs.
- `netlab/dns/leaktest.py` tests the DNS-leak claim the real tunnel makes.
- `netlab/native` is the real tunnel's mechanism, rebuilt small enough to read.

## A note on honesty

Several modules document what they do **not** do. That is deliberate.

The native tunnel has no retransmission, no DoS defence and no formal
verification. The dissector cannot capture on a physical NIC on this machine.
Traceroute falls back to the system command when unelevated. The scheduler's
SJF needs job durations known in advance, which is impossible in general.

Each of those limits is stated in the module's docstring and in its doc page.
A demonstration that hides its boundaries teaches the wrong thing, and an
examiner who finds an unstated limit will reasonably wonder what else is
unstated.
