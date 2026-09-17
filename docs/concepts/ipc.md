# Module F (partial) — IPC Message Framing

Length-prefixed framing over a byte stream. This is the foundation the
privilege-separated daemon would sit on; the transport and the elevated helper
are **not built** (see Limits).

## Concepts demonstrated

| Concept | Where |
|---|---|
| Stream vs message boundaries | `framing.py` |
| Length-prefix framing | `encode_frame` / `read_frame` |
| Partial reads and reassembly | `read_exactly`, `FrameBuffer` |
| Denial of service via declared length | `MAX_FRAME`, checked before allocating |
| Marshalling | JSON payloads |

## The problem

A pipe or a TCP connection is a byte stream, not a message stream. Write three
messages and the reader may see them as one read, or as seven:

```
sender:    [msg A][msg B][msg C]
receiver:  [msg A + first half of B]  ...then...  [rest of B][msg C]
```

There are no boundaries in the medium, so the protocol has to supply them.

Three standard answers:

```
delimiter      terminate with a byte that cannot appear in the payload —
               simple, but requires escaping, which is where bugs live
fixed length   every message the same size — wasteful and inflexible
length prefix  send the length first, then that many bytes    ← used here
```

Length prefixing is what almost every binary protocol uses. DNS over TCP, TLS
records, and `netlab/native`'s transport header all do exactly this — which
makes it a useful thing to point at across three modules.

```
┌────────────────┬──────────────────────────┐
│ length (4 B BE)│ UTF-8 JSON payload       │
└────────────────┴──────────────────────────┘
```

## Two things that are easy to get wrong

**Reads must loop.** `recv(n)` returns *up to* n bytes, not exactly n. Treating
one read as one message works in testing, where messages are small and arrive
intact, and fails in production under load. `read_exactly` loops until
satisfied.

**The length field is attacker-controlled.** A peer that claims 4 GB will make
a naive reader allocate 4 GB and die — a one-line denial of service.
`MAX_FRAME` caps it, and **the cap is checked before any allocation happens**,
not after.

## Running it

There is no panel for this module; it is exercised entirely through tests.

```bash
python -m pytest tests/test_oslab.py -k "Framing or FrameBuffer" -v
```

## Verification

`tests/test_oslab.py`, 14 tests:

- a frame dribbled in four uneven chunks reassembles correctly
- a peer announcing 4,000,000,000 bytes is rejected without allocating
- zero-length frames, malformed JSON and non-object bodies are all rejected
- a truncated stream reports how far it got
- `FrameBuffer` handles several frames in one chunk, one frame split across
  chunks, and keeps the remainder for the next feed

## Limits — what Module F does not include

This is the framing layer only. The rest of the privilege-separated daemon
described in the original plan is **not built**:

- No named-pipe transport (`\\.\pipe\onamvpn`) or Unix-domain-socket
  equivalent.
- No elevated helper process.
- No per-session authentication token.
- The GUI still runs elevated as a whole, exactly as before.

That was a deliberate stop rather than an oversight. The phase creates a real
privilege boundary, and a boundary with a flaw is worse than no boundary — a
request type that lets an unprivileged caller run an arbitrary command or
write an arbitrary path is a security bug, not a bug. The plan gated this work
behind design review specifically so the trust boundary and the authentication
scheme would be examined before anything ran elevated.

`oslab/daemon/ops.py` defines the `PlatformOps` interface that both sides
would use, with a working `FakeOps` for tests. `RealWindowsOps` is stubbed —
every method raises `NotImplementedError` — and the delegation targets it names
(`_run_ps`, `_create_wireguard_interface`, `_remove_wireguard_interface` in
`vpn_core/real_windows_wireguard.py`) all exist, so the remaining work is
wiring rather than design.
