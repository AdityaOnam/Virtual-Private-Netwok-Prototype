# Module E — Path and Routing

Traceroute built from ICMP primitives, Path MTU Discovery, and the
longest-prefix match that decides where every packet goes.

## Concepts demonstrated

| Concept | Where |
|---|---|
| TTL and hop limiting | `traceroute.py` — the whole mechanism |
| ICMP Time Exceeded (type 11) | `traceroute.py` — `_classify` |
| ICMP Destination Unreachable (type 3) | `pmtud.py` — code 4, Fragmentation Needed |
| Internet checksum | `traceroute.py` — `checksum`, same algorithm as the dissector |
| Path MTU Discovery (RFC 1191) | `pmtud.py` |
| DF bit and fragmentation | `pmtud.py` |
| Tunnel overhead arithmetic | `pmtud.py` — `explain_mtu_choice` |
| CIDR and netmasks | `routing.py` — `Route.prefix_length` |
| Longest-prefix match | `routing.py` — `longest_prefix_match` |
| Default routes and specificity | `routing.py` — `describe_split_default` |

## Traceroute: the trick

There is no "tell me the path" message in IP. Traceroute discovers the path by
abusing TTL.

Every router that forwards a packet decrements TTL. A router that decrements
it to zero discards the packet and reports the fact with ICMP Time Exceeded.
So:

```
TTL=1  → first router replies Time Exceeded   → hop 1
TTL=2  → second router replies                → hop 2
...
until the destination replies Echo Reply instead
```

Each hop identifies itself by the source address of its ICMP error. **The path
is assembled entirely from error messages.**

**Matching replies to probes.** A Time Exceeded carries the first 8 bytes of
the original datagram inside it, so the identifier and sequence we sent are
recoverable. That is how our probes are distinguished from every other ICMP
message on the machine.

**Why `*` appears.** A `*` is not a broken router. Many operators rate-limit or
suppress ICMP errors, and some firewalls drop them entirely. The hop forwards
packets perfectly while declining to announce itself.

**Setting TTL.** We use the `IP_TTL` socket option and let the kernel build the
IP header. Crafting one by hand needs `IP_HDRINCL` and behaves inconsistently
across Windows versions. `IP_TTL` is portable and is what the system `tracert`
does.

## A trap worth knowing

`traceroute_available()` originally reported success while every probe timed
out, producing 30 rows of `* * *`.

**Windows lets an unelevated process create a raw ICMP socket but not send or
receive on it.** Checking that the socket constructs is a false positive. The
check now verifies elevation explicitly, and falls back to parsing the system
`tracert` when privileges are missing — so the panel works either way, and the
mechanism being demonstrated is identical.

## Longest-prefix match

A destination usually matches several routes. The winner is the one with the
most specific prefix — the longest netmask — regardless of the order routes
appear in the table.

`0.0.0.0/0` matches everything and therefore always loses to anything else
that matches at all. That is exactly what makes it a useful default.

## The split-default trick

This is the best single thing in the module, because it explains a real design
decision in the VPN sitting next to it.

WireGuard's `AllowedIPs = 0.0.0.0/0` **does not replace the default route**. It
installs two:

```
0.0.0.0/1      →  tunnel     covers   0.0.0.0 – 127.255.255.255
128.0.0.0/1    →  tunnel     covers 128.0.0.0 – 255.255.255.255
```

Together they cover the whole address space, and each /1 beats the real default
route's /0 on specificity. So all traffic goes to the tunnel **without deleting
the original default route**.

That matters enormously: the original route is how packets reach the VPN server
itself. Delete it and the tunnel cannot carry its own traffic — the classic
self-inflicted outage.

Meanwhile the route to the VPN endpoint stays a /32 through the physical
gateway, and /32 beats /1, so tunnel traffic escapes the tunnel.

**Three prefix lengths doing three different jobs, decided entirely by
longest-prefix match:**

```
8.8.8.8          → 0.0.0.0/1          via 10.8.0.1      (tunnel)
200.1.2.3        → 128.0.0.0/1        via 10.8.0.1      (tunnel)
162.159.192.1    → 162.159.192.1/32   via 192.168.1.1   (physical — the VPN server)
192.168.1.7      → 192.168.1.0/24     on-link           (LAN)
```

## Path MTU and why 1280

`config/servers.json` sets MTU 1280 for the WireGuard tunnel. The arithmetic:

```
1500   typical Ethernet MTU
-  20  outer IPv4 header      (40 if the path is IPv6)
-   8  outer UDP header
-  32  WireGuard data header + Poly1305 tag
=1440  available to the inner packet
```

1280 sits below that, and is chosen rather than 1440 because it is the minimum
MTU every IPv6 link must support (RFC 8200 §5). A tunnel at 1280 survives
almost any path — including one that is itself tunnelled — without
fragmenting.

Trading about 11% of payload efficiency for not having to debug an ICMP black
hole is a good trade.

**The ICMP black hole.** Some networks block all ICMP, believing it to be "just
ping". The sender then gets no Fragmentation Needed error at all: large packets
vanish silently while small ones succeed, so a connection completes its
handshake and then hangs on the first big transfer. The symptom looks like
anything but MTU, which is why these are notoriously hard to diagnose.

## Running it

```bash
python main.py --labs        # Network tab → Path and routing
```

**Traceroute** traces the destination, reporting whether it used raw sockets or
the system fallback. **Routing table and MTU** reads the live table, runs
longest-prefix match on four destinations with the reasoning printed, and
shows the MTU arithmetic.

## Expected output

```
 1  192.170.0.1     3.0 ms   8.0 ms   2.0 ms
 2  10.16.4.1      16.0 ms  15.0 ms   4.0 ms
 3  172.29.1.21     3.0 ms   4.0 ms   2.0 ms
...

8.8.8.8          → 0.0.0.0/1
  0.0.0.0/1 (/1) beats 0.0.0.0/0 (/0) because a longer prefix is more
  specific — order in the table is irrelevant. This is a VPN split-default
  route: /1 beats the real default /0 without deleting it, so the route to
  the VPN server itself survives.
```

**Wrong results to watch for:**

- Every hop `* * *` — running unelevated with the raw-socket path selected.
  The availability check should have caught this and fallen back.
- RTTs not generally increasing with hop count — probes are being mismatched
  to replies.
- The VPN endpoint routing via the tunnel gateway rather than the physical one
  — the /32 is missing, and the tunnel is about to deadlock on its own traffic.

## Verification

`tests/test_path.py`, 37 tests:

- split-default beats the real default; the /32 to the VPN server beats both
- table order is irrelevant to the result; metric breaks ties between equals
- `windows route print` parsing on a real sample
- the ICMP echo request checksums to zero when verified whole
- MTU arithmetic: 1500 − 60 = 1440 available, 1280 configured
- unelevated Windows is reported unavailable rather than silently failing
- live traceroute finds a path and does not hang on unresponsive hops

## Limits

- **PMTU discovery cannot run unelevated**, and returns a result carrying the
  reason rather than raising.
- **IPv4 only.** IPv6 traceroute needs ICMPv6 and a different socket family.
- **No Paris traceroute.** Load-balanced paths can report hops that are not
  actually on one path; varying the flow identifier would fix that.
- **The before/after VPN comparison is manual.** The helper packages a single
  trace; toggling the tunnel between runs is left to the operator.
