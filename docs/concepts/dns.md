# Module D — DNS

The DNS wire format, built and parsed by hand. No `dnspython`.

DNS is the oldest widely-used binary protocol most people meet, and it shows
two ideas that keep recurring: length-prefixed labels, and back-references for
compression.

## Concepts demonstrated

| Concept | Where |
|---|---|
| DNS message format (RFC 1035) | `wire.py` — 12-byte header, four sections |
| Length-prefixed label encoding | `wire.py` — `encode_name` |
| Message compression pointers | `wire.py` — `decode_name`, the `0xC0` case |
| Record types and RDATA | `wire.py` — A, AAAA, CNAME, MX, NS, TXT, SOA |
| Truncation and TCP fallback | `resolver.py` — the TC bit |
| Encrypted transports | `resolver.py` — DoT :853, DoH :443 |
| Caching and TTL | `cache.py` |
| Cache poisoning signature | `resolver.py` — response-ID mismatch |
| DNS leakage | `leaktest.py` |

## The wire format

```
Header (12 bytes, fixed)
┌────────────────────────────────┬────────────────────────────────┐
│              ID (16)           │ QR│Opcode│AA│TC│RD│RA│Z │RCODE │
├────────────────────────────────┼────────────────────────────────┤
│            QDCOUNT (16)        │            ANCOUNT (16)        │
├────────────────────────────────┼────────────────────────────────┤
│            NSCOUNT (16)        │            ARCOUNT (16)        │
└────────────────────────────────┴────────────────────────────────┘
```

**QNAME encoding.** `www.example.com` becomes length-prefixed labels ending in
a zero byte:

```
03 'w''w''w' 07 'e''x''a''m''p''l''e' 03 'c''o''m' 00
```

There are no dots on the wire. A label is at most 63 bytes, which leaves the
two high bits of a length byte free — and that is what compression uses.

## Compression pointers

A length byte with both high bits set (`>= 0xC0`) is not a label. It is a
14-bit offset from the start of the *message* to where the rest of the name
already appears.

```
0xC0 0x0C  →  "the rest of this name is at byte 12"
```

Byte 12 is where the question section starts, so almost every answer in a real
response points there rather than repeating the name.

**A parser that ignores this produces garbage on real traffic**, and it cannot
be avoided by asking politely — the server decides whether to compress.

Two subtleties both of which are easy to get wrong:

- **Where parsing resumes.** After following a pointer, the next record starts
  after the *pointer* (2 bytes), not after wherever it led. Getting this wrong
  shifts every subsequent record and produces plausible-looking nonsense.
- **Pointer loops.** A malicious or broken server can emit a pointer to
  itself, or two that point at each other. A naive parser follows them
  forever. `MAX_POINTER_JUMPS` caps it, which is what every real resolver does.

## The three transports

```
UDP :53    The original. Fast, unencrypted, readable by anyone on the path.
           Your ISP sees every name you look up even when the page itself is
           HTTPS.

DoT :853   DNS over TLS. Same messages, wrapped in TLS with a 2-byte length
           prefix because TLS is a stream and DNS needs framing.
           Encrypted, but obviously DNS — so it can be blocked by port.

DoH :443   The same bytes POSTed as application/dns-message. Slowest of the
           three, and speed is not the point: it is indistinguishable from
           ordinary web traffic, so it cannot be blocked without blocking
           HTTPS.
```

Certificate verification is **on** for DoT. Turning it off would defeat the
entire purpose: an attacker who can redirect port 853 could then answer every
query, which is worse than plaintext because it looks secure.

**Truncation.** A UDP response too large for the negotiated size comes back
with the TC bit set and no useful answer. The resolver must retry over TCP :53
— same message, prefixed with its 2-byte length. This is the oldest fallback in
the protocol.

## Caching and TTL

Caching is what makes DNS survive its own load. Without it every page view
would re-query the root servers.

Honouring TTL is not politeness — it is how an operator moves a service. They
lower the TTL, wait for the old one to expire everywhere, change the record,
and traffic follows. A resolver that ignores TTL keeps sending users to a
decommissioned address.

In `cache.py`, expiry counts as a **miss**, not a hit: the answer existed but
is no longer usable, which is the whole point of the TTL.

## Why this is in a VPN project

DNS is the most common way a VPN leaks. The tunnel can be perfectly encrypted
while the OS resolver keeps sending plaintext queries to the ISP's server over
the physical adapter — so an observer learns every site visited without seeing
any content.

`README.md` has always claimed OnamVPN blocks port 53 on every adapter except
the tunnel. Nothing in the project ever checked that claim. `leaktest.py` does.

**Method.** Start a capture on the physical NIC filtered to UDP :53, resolve a
unique random name, then look for that name in the captured bytes.

The name has to be unique. Resolving `example.com` proves nothing — the OS
resolver, the router, or the ISP may answer from cache without a packet
leaving the machine, and an absence of traffic would look like success.

The name is searched for in its **wire form** (length-prefixed labels), not as
a dotted string, because that is what actually appears on the wire.

## Running it

```bash
python main.py --labs        # Network tab → DNS section
```

Enter a name, pick "compare all", and the panel resolves it four ways with
timings side by side, then demonstrates the cache.

## Expected output

```
  transport       time  rcode      addresses
  udp            18.4ms  NOERROR    1.1.1.1, 1.0.0.1
  tcp            31.2ms  NOERROR    1.1.1.1, 1.0.0.1
  dot            94.7ms  NOERROR    1.1.1.1, 1.0.0.1
  doh           142.3ms  NOERROR    1.1.1.1, 1.0.0.1

  all transports agreed: True
```

The extra time on DoT and DoH is the TLS handshake, not the lookup.

**Wrong results to watch for:**

- Transports disagreeing — one of them is parsing incorrectly.
- A parse failure on a real response — almost certainly compression pointers.
- `NOERROR` with no addresses on a name that exists — the answer section is
  being mis-parsed, likely an RDLENGTH or offset error after a pointer.

## Verification

`tests/test_dns.py`, 37 tests:

- `encode_name("www.example.com")` byte-for-byte against the RFC's example
- a response containing a real compression pointer parses correctly
- `decode_name` returns the offset after the *pointer*, not the target
- pointer loops and out-of-range pointers are rejected
- expired cache entries count as misses; TTL 0 is not stored
- capacity eviction removes the oldest
- live: all four transports return the same A records (skipped offline)

## Limits

- **No negative caching (RFC 2308).** A real resolver caches NXDOMAIN using
  the SOA minimum as the TTL, so a typo'd domain does not hammer the
  authority on every retry. Not implemented; named rather than hidden.
- **No recursion.** This is a stub resolver — it asks a recursive server and
  reads the answer. It does not walk the hierarchy from the root itself.
- **No DNSSEC.** Records are not validated.
- **We never emit compression.** A query has one name, so there is nothing to
  compress. We must still *parse* it, and do.
- **The leak test cannot run on this machine.** It needs live capture on a
  physical NIC, and Npcap here enumerates only loopback. Without a capture
  backend it degrades to comparing transports, which shows the difference in
  principle but does not prove what left the machine — and it says so in its
  own output rather than implying otherwise.
