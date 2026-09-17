"""
netlab.native.replay — sliding-window anti-replay filter (RFC 6479 style).

The problem
───────────
UDP reorders.  A receiver must therefore accept a packet whose counter is
*lower* than one already seen — but must reject a counter it has seen before,
or an attacker can capture a packet and re-send it forever.

The naive version is wrong:

    if counter <= highest_seen:
        drop                      # ← throws away legitimate reordering

That discards every packet that arrives even slightly out of order, which on a
real path is a lot of them.  It is the single most commonly botched piece of a
VPN implementation.

The fix
───────
Keep a bitmap of the last N counters.  A counter is accepted if:

  - it is greater than the highest seen                     → slide the window
  - it is inside the window and its bit is not yet set      → set the bit
  - otherwise                                               → replay, drop

Worked example with an 8-bit window (the real one is 1024 bits):

    state: highest=10, bitmap covers 3..10, seen {10, 9, 7}

      recv 11  → above window   → accept, slide to 4..11
      recv  8  → inside, unset  → accept, set bit          (legitimate reorder)
      recv  9  → inside, set    → REJECT                   (replay)
      recv  2  → below window   → REJECT                   (too old to judge)
      recv 99  → far above      → accept, window resets

"Below window" rejects a packet that might be perfectly legitimate — it is
simply too old for us to prove it is not a replay, and the trade is deliberate:
bounded memory in exchange for dropping badly-delayed packets.  Making the
window larger shifts that trade, and REPLAY_WINDOW_BITS is where it is set.
"""

from __future__ import annotations

from .protocol import REPLAY_WINDOW_BITS


class ReplayWindow:
    """
    Sliding-window replay filter over a monotonically-issued 64-bit counter.

    Not thread-safe by design: one instance belongs to one session, and the
    session serialises access.  Sharing one across threads without a lock
    would corrupt the bitmap — see oslab.concurrency for that lesson.
    """

    __slots__ = ("window_bits", "_highest", "_bitmap", "accepted", "rejected")

    def __init__(self, window_bits: int = REPLAY_WINDOW_BITS) -> None:
        if window_bits < 8:
            raise ValueError(f"window must be at least 8 bits, got {window_bits}")
        self.window_bits = window_bits
        self._highest = -1          # no packet seen yet
        self._bitmap = 0            # bit i set ⇒ counter (_highest - i) seen
        self.accepted = 0
        self.rejected = 0

    # ── query ────────────────────────────────────────────────────────────────

    @property
    def highest_seen(self) -> int:
        """Greatest counter accepted so far, or -1 if none."""
        return self._highest

    def would_accept(self, counter: int) -> bool:
        """Test without mutating — used by tests and the panel."""
        if counter < 0:
            return False
        if self._highest < 0 or counter > self._highest:
            return True
        offset = self._highest - counter
        if offset >= self.window_bits:
            return False
        return not (self._bitmap >> offset) & 1

    # ── update ───────────────────────────────────────────────────────────────

    def check_and_update(self, counter: int) -> bool:
        """
        Accept *counter* exactly once.  Returns True if it was fresh.

        This both tests and records, so a caller must not call it twice for
        the same packet — the second call reports a replay of the first.
        """
        if counter < 0:
            self.rejected += 1
            return False

        if self._highest < 0:
            self._highest = counter
            self._bitmap = 1
            self.accepted += 1
            return True

        if counter > self._highest:
            shift = counter - self._highest
            if shift >= self.window_bits:
                self._bitmap = 1            # everything older falls off
            else:
                self._bitmap = ((self._bitmap << shift) | 1) & self._mask()
            self._highest = counter
            self.accepted += 1
            return True

        offset = self._highest - counter
        if offset >= self.window_bits:
            self.rejected += 1              # below the window: cannot judge
            return False

        if (self._bitmap >> offset) & 1:
            self.rejected += 1              # already seen: replay
            return False

        self._bitmap |= 1 << offset         # in-window reorder: fine
        self.accepted += 1
        return True

    def _mask(self) -> int:
        return (1 << self.window_bits) - 1

    # ── introspection, for the panel ─────────────────────────────────────────

    def bitmap_str(self, width: int = 32) -> str:
        """
        Render the newest *width* bits, newest on the left.

        '#' = seen, '.' = not seen.  Used by the handshake visualiser to show
        the window filling in real time.
        """
        if self._highest < 0:
            return "." * width
        bits = []
        for offset in range(min(width, self.window_bits)):
            bits.append("#" if (self._bitmap >> offset) & 1 else ".")
        return "".join(bits)

    def __repr__(self) -> str:
        return (
            f"ReplayWindow(highest={self._highest}, "
            f"accepted={self.accepted}, rejected={self.rejected})"
        )
