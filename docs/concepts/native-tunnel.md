# Module B — OnamVPN Native

A VPN written here, rather than a wrapper around one. Roughly 1400 lines, and
every byte on the wire is produced by code in this repository.

## Concepts demonstrated

| Concept | Where |
|---|---|
| Protocol design: framing, versioning, type bytes | `protocol.py` |
| Byte order as a convention, not a law | `protocol.py` — little-endian, the opposite of IP/TCP |
| Elliptic-curve Diffie-Hellman | `crypto.py` — X25519 |
| Key derivation and chaining | `crypto.py` — HKDF with a running chaining key |
| Authenticated encryption (AEAD) | `crypto.py` — ChaCha20-Poly1305 |
| Nonce discipline | `session.py` — counter as nonce, never repeats under a key |
| Forward secrecy | `crypto.py` — ephemeral keys mixed into the chain |
| Identity hiding | `crypto.py` — the initiator's static key travels encrypted |
| Replay attacks and sliding windows | `replay.py` |
| Key rotation | `session.py` — keys and counter rotate together |
| Datagram vs stream sockets | `endpoint.py` UDP, `socks5.py` TCP |
| Stream multiplexing | `protocol.py` — `stream_id` in the inner frame |
| NAT binding lifetime | `protocol.py` — `KEEPALIVE_SECONDS = 25` |
| MTU and fragmentation | `protocol.py` — `chunk_payload`, `MAX_TUNNEL_PAYLOAD` |

## Wire format

Four message types. Sizes are asserted against the documented tables at import
time, so a `struct` format string and its documentation cannot drift apart.

```
Handshake Initiation — type 1 — 132 bytes
  0    type=1        8   ephemeral pubkey (32)
  1    reserved(3)   40  encrypted_static (48 = 32 key + 16 tag)
  4    sender_index  88  encrypted_timestamp (28 = 12 TAI64N + 16 tag)
                     116 mac1 (16)

Handshake Response — type 2 — 76 bytes
Transport Data — type 4 — 16-byte header + ciphertext + tag
```

The counter in the transport header is **little-endian**, matching WireGuard.
This is worth pointing at: "network byte order" is a convention of the IP
suite, not a property of protocols in general. `netlab/dissect` reads
big-endian headers a few files away.

## The key schedule

A Noise-style chaining key. Two values evolve through the handshake: `C`
absorbs every secret, `H` absorbs everything sent or received and is used as
AEAD associated data — so tampering anywhere in the transcript makes the next
decryption fail.

```
C = HASH(PROTOCOL_NAME)
H = HASH(C || PROLOGUE) ; H = HASH(H || S_r)

message 1:  e_i,E_i = keygen
            C = KDF1(C, E_i) ; H = HASH(H || E_i)
            C,k = KDF2(C, DH(e_i, S_r))
            enc_S_i = AEAD(k, 0, S_i, aad=H)      ← identity, hidden
            C,k = KDF2(C, DH(s_i, S_r))
            enc_ts = AEAD(k, 0, TAI64N(now), aad=H)   ← handshake replay defence

message 2:  e_r,E_r = keygen
            C = KDF1(C, E_r) ; H = HASH(H || E_r)
            C = KDF1(C, DH(e_r, E_i))             ← forward secrecy
            C = KDF1(C, DH(e_r, S_i))
            enc_none = AEAD(k, 0, b"", aad=H)     ← key confirmation

both:       T1, T2 = KDF2(C, b"")
            initiator: send=T1 recv=T2
            responder: send=T2 recv=T1
```

That last step answers "how do the two sides agree which key is which": the
KDF emits an ordered pair and the roles are fixed by who initiated. Nothing is
negotiated, so nothing can get out of step.

**Why the timestamp.** Without it, an attacker who records a valid initiation
can replay it forever and force the responder to redo the expensive half of
the handshake. The responder keeps the greatest timestamp per peer and rejects
anything not strictly greater.

**Why mac1.** A peer that does not already know the server's public key cannot
compute `MAC(HASH(LABEL || S_r), message)`, so junk is discarded before any
curve arithmetic happens.

## Nonce safety

ChaCha20-Poly1305 fails catastrophically if a `(key, nonce)` pair repeats —
the keystream is reused and both plaintexts leak. The nonce is the send
counter, so the counter must never repeat under one key.

```
nonce = 4 zero bytes || counter as u64 little-endian

counter 0      → 00 00 00 00 00 00 00 00 00 00 00 00
counter 1      → 00 00 00 00 01 00 00 00 00 00 00 00
counter 2**32  → 00 00 00 00 00 00 00 00 01 00 00 00
```

Two rules enforce it. `encrypt()` raises `NonceExhausted` past
`REJECT_AFTER_MESSAGES` rather than wrapping. And `needs_rekey()` goes true far
earlier, so a healthy session rotates long before the hard limit.

`install_keys()` replaces both keys **and** resets the counter in one call.
There is deliberately no setter for the keys alone: changing either without
the other reuses a nonce under a live key, which is the one thing this
construction does not tolerate.

`PeerState.previous` keeps the retired session decrypt-only, so packets
already in flight when the rekey happened still arrive.

## Anti-replay

The naive version is wrong:

```python
if counter <= highest_seen:
    drop            # ← discards legitimate reordering
```

UDP reorders. A receiver must accept a counter lower than one already seen,
while rejecting one it has seen before. `replay.py` keeps a 1024-bit bitmap:

```
state: highest=10, window covers 3..10, seen {10, 9, 7}

  recv 11  → above window   → accept, slide
  recv  8  → inside, unset  → accept          (legitimate reorder)
  recv  9  → inside, set    → REJECT          (replay)
  recv  2  → below window   → REJECT          (too old to judge)
```

"Below window" rejects packets that may be perfectly legitimate — they are
simply too old to prove innocent. That is a deliberate trade of bounded memory
against dropping badly-delayed packets.

## Transport: why SOCKS5

A TUN adapter captures every packet the machine sends, which is what a real
VPN does. On Windows that means loading `wintun.dll` through `ctypes` and
driving its ring-buffer API; `python-pytun` is Linux-only.

SOCKS5 needs no driver, no admin rights, and is demonstrable immediately —
point a browser at `127.0.0.1:1080` and its traffic goes through the tunnel.

The trade is real and worth stating: this tunnels **applications configured to
use the proxy**, not the whole device. Anything else still goes out in the
clear.

## Running it

```bash
python main.py --labs        # Network tab → "Run tunnel end to end"
```

Brings up client and server on loopback, completes a handshake, pushes a round
trip and a 100 KB bulk transfer through SOCKS5, and prints the session
counters including the replay window filling in.

## Expected output

```
handshakes       : 1
byte-identical   : True
send counter     : 84      (the AEAD nonce — never repeats under one key)
replay accepted  : 81
replay rejected  : 0
replay window    : ################################
forgeries dropped: 0
```

**Wrong results to watch for:**

- `byte-identical: False` — data loss. Check `chunk_payload` is being used in
  the relay loops; framing a 16 KiB read whole produces a datagram that
  IP-fragments, and losing one fragment truncates the stream silently.
- `forgeries dropped` climbing during normal use — something is corrupting
  packets, or a session is being decrypted with the wrong key.
- `replay rejected` climbing during normal use — the window is too small for
  the reordering on this path, or the counter is being double-counted.

## Verification

`tests/test_native.py`, 80 tests:

- every message type round-trips; malformed input rejected
- the handshake derives matching keys, and the direction agreement holds
- a tampered ciphertext raises `InvalidTag`
- a forged packet does **not** poison the replay window — authentication
  happens before the counter is recorded, or a forgery with a plausible
  counter would cause the genuine packet to be dropped as a replay
- an identical datagram sent twice is rejected as a **replay**, not a forgery:
  the tag is valid both times, so only the window can tell them apart
- 200 KB transfers byte-identical; four concurrent streams do not cross
- after a rekey the counter restarts at 0 and the ciphertext differs, proving
  the key moved with it

## Limits — stated so nobody assumes otherwise

- **No retransmission.** This is the important one. WireGuard tunnels whole IP
  packets, so a dropped datagram costs an inner TCP segment and the inner TCP
  retransmits it. We tunnel SOCKS5 *stream bytes*, so a dropped datagram
  removes bytes from the middle of a TCP stream with nothing to notice or
  repair it. On loopback this effectively never happens; on a lossy path it
  would corrupt transfers. `netlab/transport` is the layer that would fix it,
  and the two are not wired together.
- **No denial-of-service defence.** No cookie mechanism, therefore no mac2.
  Each initiation costs two X25519 operations and an attacker can force them.
- **No traffic-analysis resistance.** Packet sizes and timing are unpadded, so
  the shape of a session is visible even though its content is not.
- **No roaming.** A peer's endpoint is fixed at handshake time.
- **Not constant-time.** Python is not, and this is a teaching implementation.
- **Not formally verified.** Real Noise_IK has machine-checked proofs. This is
  a reduction of it, and small changes to a Noise pattern can break its
  security properties in ways that are not locally obvious.

Use WireGuard for anything real. This exists to make the mechanism legible.
