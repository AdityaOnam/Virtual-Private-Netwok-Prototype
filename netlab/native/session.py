"""
netlab.native.session — transport session: keys, counter, rekey, replay.

A Session owns everything that must stay consistent for one direction pair of
one peer: the two transport keys, the send counter, and the replay window.

Nonce safety
────────────
ChaCha20-Poly1305 fails catastrophically if a (key, nonce) pair repeats — the
keystream is reused and both plaintexts leak.  The nonce here is the send
counter, so the counter must never repeat under one key.  Two rules enforce it:

  1. `encrypt()` refuses outright past REJECT_AFTER_MESSAGES.  It raises
     rather than wrapping; there is no safe way to continue.
  2. `needs_rekey()` goes true far earlier (REKEY_AFTER_MESSAGES, or
     REKEY_AFTER_SECONDS), so a healthy session rotates long before the hard
     limit is anywhere near.

Rekeying replaces the keys and resets the counter **together**, in one
operation, because doing either alone reuses a nonce under a live key.  That
is what `install_keys()` is for — there is deliberately no setter for the keys
alone.

    ┌──────────┐  handshake   ┌─────────┐  counter > REKEY_AFTER_MESSAGES
    │   NEW    │─────────────▶│ CURRENT │──────────────or age > REKEY_AFTER──┐
    └──────────┘              └─────────┘                                    │
                                   ▲                                         ▼
                                   │                                  ┌─────────────┐
                                   │       new handshake completes    │  REKEYING   │
                                   └─────────────────────────────────-│ (old kept)  │
                                                                      └─────────────┘
                                                                             │
                              old session stays decrypt-only until           │
                              REJECT_AFTER_SECONDS, so packets already       │
                              in flight under the previous key still ────────┘
                              arrive intact

That retention window is why `previous` exists on PeerState: drop the old key
the instant you rekey and every packet the peer sent in the last RTT is lost.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .crypto import InvalidTag, aead_decrypt, aead_encrypt
from .protocol import (
    REJECT_AFTER_MESSAGES,
    REJECT_AFTER_SECONDS,
    REKEY_AFTER_MESSAGES,
    REKEY_AFTER_SECONDS,
)
from .replay import ReplayWindow


class NonceExhausted(RuntimeError):
    """Raised when the send counter reaches the hard limit for a key."""


class SessionExpired(RuntimeError):
    """Raised when a session is too old to use."""


@dataclass
class Session:
    """One set of transport keys plus the counters that go with them."""

    send_key: bytes
    recv_key: bytes
    local_index: int
    remote_index: int
    is_initiator: bool
    created_at: float = field(default_factory=time.monotonic)
    send_counter: int = 0
    replay: ReplayWindow = field(default_factory=ReplayWindow)
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    rekeys: int = 0

    # ── lifecycle ────────────────────────────────────────────────────────────

    def age(self) -> float:
        return time.monotonic() - self.created_at

    def needs_rekey(self) -> bool:
        """True once the session should be replaced, well before it must be."""
        return (
            self.send_counter >= REKEY_AFTER_MESSAGES
            or self.age() >= REKEY_AFTER_SECONDS
        )

    def is_expired(self) -> bool:
        """True once the session must not be used at all."""
        return (
            self.send_counter >= REJECT_AFTER_MESSAGES
            or self.age() >= REJECT_AFTER_SECONDS
        )

    def install_keys(self, send_key: bytes, recv_key: bytes) -> None:
        """
        Replace both keys and reset the counter and replay window atomically.

        Keys and counter must move together: changing one without the other
        reuses a nonce under a live key, which is the one failure mode
        ChaCha20-Poly1305 does not tolerate.
        """
        self.send_key = send_key
        self.recv_key = recv_key
        self.send_counter = 0
        self.replay = ReplayWindow()
        self.created_at = time.monotonic()
        self.rekeys += 1

    # ── data path ────────────────────────────────────────────────────────────

    def encrypt(self, plaintext: bytes) -> tuple[int, bytes]:
        """
        Encrypt and return (counter_used, ciphertext).

        Raises NonceExhausted rather than letting the counter wrap.
        """
        if self.send_counter >= REJECT_AFTER_MESSAGES:
            raise NonceExhausted(
                f"send counter reached {REJECT_AFTER_MESSAGES}; "
                "the session must rekey before sending again"
            )
        counter = self.send_counter
        ciphertext = aead_encrypt(self.send_key, counter, plaintext, b"")
        self.send_counter += 1
        self.packets_sent += 1
        self.bytes_sent += len(ciphertext)
        return counter, ciphertext

    def decrypt(self, counter: int, ciphertext: bytes) -> bytes | None:
        """
        Authenticate, decrypt, and record the counter.

        Returns the plaintext, or None if the packet was a replay.  Raises
        InvalidTag if the ciphertext was tampered with.

        Order matters: authenticate *before* touching the replay window, so a
        forged packet carrying a plausible counter cannot poke holes in the
        window and cause later genuine packets to be dropped.
        """
        plaintext = aead_decrypt(self.recv_key, counter, ciphertext, b"")
        if not self.replay.check_and_update(counter):
            return None
        self.packets_received += 1
        self.bytes_received += len(ciphertext)
        return plaintext


@dataclass
class PeerState:
    """
    A peer's current session plus the one it just replaced.

    `previous` stays decrypt-only for REJECT_AFTER_SECONDS so packets already
    in flight under the old key are not lost at the moment of rekey.
    """

    current: Session | None = None
    previous: Session | None = None
    endpoint: tuple[str, int] | None = None
    last_handshake_timestamp: bytes | None = None
    last_received: float = 0.0
    last_sent: float = 0.0

    def promote(self, session: Session) -> None:
        """Make *session* current, retiring the old one to decrypt-only."""
        if self.current is not None:
            self.previous = self.current
        self.current = session

    def expire_previous(self) -> None:
        """Drop the retired session once nothing can still be in flight."""
        if self.previous is not None and self.previous.age() >= REJECT_AFTER_SECONDS:
            self.previous = None

    def decrypt_any(self, local_index: int, counter: int,
                    ciphertext: bytes) -> bytes | None:
        """
        Try the session matching *local_index*, current first.

        Returns plaintext, or None for a replay.  Raises InvalidTag if no
        session can authenticate the packet.
        """
        for session in (self.current, self.previous):
            if session is not None and session.local_index == local_index:
                return session.decrypt(counter, ciphertext)
        raise InvalidTag(f"no session with local index {local_index}")

    def stats(self) -> dict:
        """Counters for the GUI panel."""
        session = self.current
        if session is None:
            return {"state": "no session"}
        return {
            "state": "expired" if session.is_expired()
                     else ("rekey due" if session.needs_rekey() else "established"),
            "age_s": round(session.age(), 1),
            "send_counter": session.send_counter,
            "packets_sent": session.packets_sent,
            "packets_received": session.packets_received,
            "bytes_sent": session.bytes_sent,
            "bytes_received": session.bytes_received,
            "replay_accepted": session.replay.accepted,
            "replay_rejected": session.replay.rejected,
            "replay_window": session.replay.bitmap_str(),
            "rekeys": session.rekeys,
            "has_previous": self.previous is not None,
        }
