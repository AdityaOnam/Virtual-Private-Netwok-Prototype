# Module C — Transport: ARQ and Congestion Control

The transport-layer chapter, made interactive. Three ARQ protocols and TCP
Reno, running over a link whose loss, delay, jitter and bandwidth you control.

This is the strongest single module for a viva: almost every transport-layer
exam question has a knob here that answers it visually.

## Concepts demonstrated

| Concept | Where |
|---|---|
| Automatic Repeat reQuest | `arq.py` — Stop-and-Wait, Go-Back-N, Selective Repeat |
| Sliding windows | `arq.py` — `base`, `next_seq`, `effective_window()` |
| Cumulative vs selective acknowledgement | `arq.py` — `CumulativeReceiver`, `SelectiveReceiver` |
| Flow control vs congestion control | `congestion.py` — `window_bytes(receiver_window)` |
| RTT estimation | `rtt.py` — Jacobson/Karels SRTT and RTTVAR |
| Retransmission timeout | `rtt.py` — `RTO = SRTT + 4·RTTVAR` |
| Karn's algorithm | `rtt.py` — ambiguous samples discarded |
| Exponential backoff | `rtt.py` — `back_off()` |
| Slow start | `congestion.py` — one segment per ACK, doubling per RTT |
| Congestion avoidance | `congestion.py` — `MSS²/cwnd` per ACK, linear per RTT |
| Fast retransmit and fast recovery | `congestion.py` — three duplicate ACKs |
| AIMD | the sawtooth in the panel |
| Bandwidth-delay product | `congestion.py` — `bandwidth_delay_product()` |
| Queueing delay | `impairment.py` — token bucket |

## Why it is reproducible

Every result has to be explainable in a viva, so the link cannot depend on the
real internet.

- **Virtual clock.** `impairment.Clock` is injected; nothing calls
  `time.time()`. A 60-second transfer simulates in milliseconds and never
  flakes on a loaded machine.
- **Seeded PRNG.** The same seed produces a byte-identical trace, every run.
  Tested explicitly in `TestReproducibility`.

A congestion graph that changes between runs cannot be explained.

## The three protocols

```
Stop-and-Wait    window 1. Correct, trivial, hopeless on a long path:
                 one segment per RTT regardless of bandwidth.

Go-Back-N        window N, cumulative ACK, ONE timer. The receiver discards
                 anything out of order, so one loss forces the sender to
                 resend that segment and everything after it.
                 Cheap receiver, expensive recovery.

Selective Repeat window N, per-segment ACK, per-segment timer. The receiver
                 buffers out-of-order segments, so only the lost one is
                 resent. Expensive receiver, cheap recovery.
```

The trade is receiver memory against wasted bandwidth. It is why real TCP
started as Go-Back-N and grew SACK once memory got cheap and bandwidth-delay
products got large.

Measured at 100 segments, window 8:

| loss | protocol | retransmitted | efficiency |
|---|---|---|---|
| 20% | go-back-n | 81 | 0.55 |
| 20% | selective-repeat | 69 | 0.59 |
| 30% | go-back-n | 121 | 0.45 |
| 30% | selective-repeat | 101 | 0.50 |

## Congestion control

```
                cwnd < ssthresh
┌──────────────────────────────────────────┐
│              SLOW START                  │
│   cwnd += 1 MSS per ACK  → doubles/RTT   │
└──────────────────────────────────────────┘
                │ cwnd >= ssthresh
                ▼
┌──────────────────────────────────────────┐
│          CONGESTION AVOIDANCE            │
│   cwnd += MSS²/cwnd per ACK  → +1/RTT    │
└──────────────────────────────────────────┘
      │                          │
      │ 3 duplicate ACKs         │ timeout
      ▼                          ▼
┌──────────────┐          ssthresh = cwnd/2
│ FAST RECOVERY│          cwnd     = 1 MSS
│ cwnd = ssthresh + 3     → SLOW START
└──────────────┘
```

**The asymmetry is the thing to be able to explain.** Three duplicate ACKs mean
packets are *still arriving* — the path works, one segment was lost, so halving
is proportionate. A timeout means nothing has arrived for a whole RTO: every
assumption about the path is stale, so the sender drops to one segment and
re-probes from scratch.

**"Slow start" is the fastest phase.** The name is historical — it is slow
compared to the original TCP, which blasted the receiver's whole advertised
window on the first RTT and collapsed the early internet.

## Karn's algorithm

When a segment is retransmitted and an ACK arrives, the ACK is ambiguous: it
may be for the original or the retransmission, and the two have very different
elapsed times.

Measuring it corrupts SRTT in the dangerous direction. If the ACK was really
for the original, the measured time is far too short, which shortens the RTO,
which causes more spurious retransmissions, which shortens it further.

Karn's rule: do not sample RTT from a retransmitted segment at all. Double the
RTO on each timeout instead, and only resume sampling after a clean ACK.

## Running it

```bash
python main.py --labs        # Transport tab
```

Set loss, delay, window and seed; click **Run transfer**. Or **Compare all
three protocols** to run them over an identical link.

A good demonstration configuration:

```
protocol  go-back-n      loss 0.02      delay 25 ms
window    64             bandwidth 8000 kbit/s      seed 5
```

## Expected output

```
delivered intact : True
segments sent    : 377        retransmitted : 77
efficiency       : 79.6%
timeouts         : 7          fast retransmits : 10
bottleneck: window-limited: 46720 B window < 50000 B BDP
```

The cwnd plot shows a slow-start ramp, then AIMD sawtooth. Dotted vertical
lines mark congestion events — green for fast retransmit, red for timeout. A
red line always drops cwnd to the floor; a green one does not.

**Wrong results to watch for:**

- `delivered intact: False` — ARQ is broken. The whole point is that the byte
  stream survives a lossy link.
- Selective Repeat retransmitting *more* than Go-Back-N — the per-segment
  timer logic has regressed. This happened during development: a shared RTO
  was backed off on every per-segment timeout, making the protocol
  progressively deaf and slower than Go-Back-N despite retransmitting less.
- `cwnd` collapsing to 1 MSS on a fast retransmit — the two loss signals have
  been conflated.
- A different trace on a rerun with the same seed — reproducibility is broken
  and no graph can be trusted.

## The bottleneck report

A sender whose window is below the bandwidth-delay product can never fill the
link, however clean it is: it sends a window, then waits an RTT for the ACK.
On a throughput graph that looks exactly like congestion.

The panel computes both and says which limit is binding:

```
window-limited: 46720 B window < 50000 B BDP
                — the link cannot be filled regardless of loss
link-limited:   93440 B window >= 50000 B BDP
                — the window is not the constraint
```

## Verification

`tests/test_transport.py`, 57 tests:

- all three protocols deliver a complete ordered stream at 20% loss
- Go-Back-N retransmits more than Selective Repeat at seeds 3, 7 and 11
- Stop-and-Wait is more than 3x slower on a long path
- a timeout drives cwnd to exactly 1 MSS; three duplicate ACKs do not
- Karn: an RTT sample from a retransmitted segment does not move SRTT
- a jittery path gets a wider RTO than a steady one with the same mean
- same seed → identical trace; different seed → different trace
- reordering and duplication do not corrupt the stream

## Limits

- **Reno, not CUBIC or BBR.** Modern Linux defaults to CUBIC and increasingly
  BBR. Reno is what the textbook describes and what the sawtooth comes from.
- **No SACK.** Selective Repeat here uses per-segment ACKs rather than TCP's
  actual SACK option blocks.
- **Not wired to the native tunnel.** This layer would fix Module B's lack of
  retransmission; connecting them is left undone and stated rather than
  implied.
- **64-bit sequence numbers.** Real Selective Repeat needs the window to be at
  most half the sequence space or it cannot distinguish a retransmission from
  a new segment reusing the number. A counter that never wraps sidesteps that,
  and saying so is better than silently depending on it.
