"""
netlab.native.crypto — key exchange, key schedule and AEAD.

Primitives come from `cryptography`; the *protocol* is ours.  Hand-rolling a
cipher would be a correctness liability and teaches nothing the protocol does
not already teach.

    X25519              Elliptic-curve Diffie-Hellman
    BLAKE2s             hash (32 B) and keyed MAC (16 B)
    HKDF-SHA256         key derivation
    ChaCha20-Poly1305   AEAD

The key schedule
────────────────
A Noise-style chaining key.  Two values evolve through the handshake:

    C  the chaining key   — all secret material mixes into this
    H  the handshake hash — everything sent or received mixes into this, and
                            it is used as AEAD associated data, so any
                            tampering anywhere in the transcript makes the
                            next decryption fail

    KDF_n(C, input) = HKDF-SHA256(salt=C, ikm=input, info=b"", L=32n)
                      split into n 32-byte outputs

Initiator (i) holds static (s_i, S_i); responder (r) holds (s_r, S_r).
The initiator must know S_r in advance — that is the "K" in Noise_IK.

    C = HASH(PROTOCOL_NAME)
    H = HASH(C || PROLOGUE)
    H = HASH(H || S_r)

    -- message 1, initiator → responder --
    e_i, E_i = keygen()
    C        = KDF1(C, E_i)
    H        = HASH(H || E_i)
    C, k     = KDF2(C, DH(e_i, S_r))
    enc_S_i  = AEAD(k, 0, S_i, aad=H)              ← initiator identity, hidden
    H        = HASH(H || enc_S_i)
    C, k     = KDF2(C, DH(s_i, S_r))
    enc_ts   = AEAD(k, 0, TAI64N(now), aad=H)      ← handshake replay defence
    H        = HASH(H || enc_ts)

    -- message 2, responder → initiator --
    e_r, E_r = keygen()
    C        = KDF1(C, E_r)
    H        = HASH(H || E_r)
    C        = KDF1(C, DH(e_r, E_i))               ← forward secrecy
    C        = KDF1(C, DH(e_r, S_i))
    C, t, k  = KDF3(C, PSK)                        ← PSK is zeros if unused
    H        = HASH(H || t)
    enc_none = AEAD(k, 0, b"", aad=H)              ← key confirmation
    H        = HASH(H || enc_none)

    -- both sides --
    T1, T2 = KDF2(C, b"")
    initiator: send = T1, recv = T2
    responder: send = T2, recv = T1

That last step answers "how do the two sides agree which key is which": the
KDF emits an ordered pair, and the roles are fixed by who initiated.  No
negotiation, nothing to get out of step.

Why the timestamp
─────────────────
Without it, an attacker who records a valid handshake initiation can replay it
forever and force the responder to redo the expensive half of the handshake.
The responder stores the greatest timestamp seen per peer and rejects anything
not strictly greater.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .protocol import (
    HASH_SIZE,
    KEY_SIZE,
    LABEL_MAC1,
    MAC_SIZE,
    PROLOGUE,
    PROTOCOL_NAME,
    TIMESTAMP_SIZE,
    nonce_for,
)

__all__ = [
    "InvalidTag",
    "KeyPair",
    "aead_decrypt",
    "aead_encrypt",
    "dh",
    "generate_keypair",
    "hash_",
    "kdf",
    "mac",
    "tai64n",
    "HandshakeState",
]


# ── Primitives ───────────────────────────────────────────────────────────────

def hash_(*chunks: bytes) -> bytes:
    """BLAKE2s-256 over the concatenation of *chunks*."""
    digest = hashes.Hash(hashes.BLAKE2s(HASH_SIZE))
    for chunk in chunks:
        digest.update(chunk)
    return digest.finalize()


def mac(key: bytes, data: bytes) -> bytes:
    """Keyed BLAKE2s truncated to 16 bytes — used for mac1."""
    digest = hashes.Hash(hashes.BLAKE2s(HASH_SIZE))
    digest.update(key)
    digest.update(data)
    return digest.finalize()[:MAC_SIZE]


def kdf(chaining_key: bytes, input_material: bytes, outputs: int) -> list[bytes]:
    """
    HKDF-SHA256 with the chaining key as salt, split into *outputs* 32-byte
    values.  This is the Noise KDF_n construction.
    """
    if not 1 <= outputs <= 3:
        raise ValueError(f"kdf supports 1-3 outputs, got {outputs}")
    blob = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE * outputs,
        salt=chaining_key,
        info=b"",
    ).derive(input_material)
    return [blob[i * KEY_SIZE:(i + 1) * KEY_SIZE] for i in range(outputs)]


@dataclass(frozen=True)
class KeyPair:
    """An X25519 keypair.  `public` is the 32-byte wire encoding."""

    private: X25519PrivateKey
    public: bytes

    @classmethod
    def generate(cls) -> "KeyPair":
        priv = X25519PrivateKey.generate()
        return cls(priv, _public_bytes(priv))

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> "KeyPair":
        priv = X25519PrivateKey.from_private_bytes(raw)
        return cls(priv, _public_bytes(priv))

    def private_bytes(self) -> bytes:
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )
        return self.private.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )


def _public_bytes(priv: X25519PrivateKey) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def generate_keypair() -> KeyPair:
    return KeyPair.generate()


def dh(private: X25519PrivateKey, peer_public: bytes) -> bytes:
    """X25519 shared secret.  Raises ValueError on a malformed peer key."""
    if len(peer_public) != KEY_SIZE:
        raise ValueError(f"public key must be {KEY_SIZE} B, got {len(peer_public)}")
    return private.exchange(X25519PublicKey.from_public_bytes(peer_public))


def aead_encrypt(key: bytes, counter: int, plaintext: bytes, aad: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(nonce_for(counter), plaintext, aad)


def aead_decrypt(key: bytes, counter: int, ciphertext: bytes, aad: bytes) -> bytes:
    """Raises cryptography.exceptions.InvalidTag if authentication fails."""
    return ChaCha20Poly1305(key).decrypt(nonce_for(counter), ciphertext, aad)


def tai64n(when: float | None = None) -> bytes:
    """
    12-byte TAI64N timestamp: 8 bytes of seconds, 4 of nanoseconds.

    Used as a monotonic handshake counter rather than as a clock — the
    responder only ever compares it to the last value it saw from that peer.
    """
    now = time.time() if when is None else when
    seconds = int(now)
    nanos = int((now - seconds) * 1e9)
    return (0x400000000000000A + seconds).to_bytes(8, "big") + nanos.to_bytes(4, "big")


# ── Handshake state machine ──────────────────────────────────────────────────

class HandshakeState:
    """
    Carries (C, H) through a handshake and produces the transport keys.

    One instance handles one handshake attempt for one side.  The class does no
    I/O: the caller feeds it bytes and sends whatever it returns.
    """

    def __init__(self, responder_static_public: bytes,
                 preshared_key: bytes | None = None) -> None:
        self.chaining_key = hash_(PROTOCOL_NAME)
        self.handshake_hash = hash_(self.chaining_key, PROLOGUE)
        self.handshake_hash = hash_(self.handshake_hash, responder_static_public)
        self.responder_static_public = responder_static_public
        self.preshared_key = preshared_key or b"\x00" * KEY_SIZE
        self.ephemeral: KeyPair | None = None
        self.remote_ephemeral: bytes | None = None
        self.remote_static: bytes | None = None

    # ── helpers ──────────────────────────────────────────────────────────────

    def _mix_key(self, material: bytes) -> None:
        (self.chaining_key,) = kdf(self.chaining_key, material, 1)

    def _mix_key_and_derive(self, material: bytes) -> bytes:
        self.chaining_key, key = kdf(self.chaining_key, material, 2)
        return key

    def _mix_hash(self, data: bytes) -> None:
        self.handshake_hash = hash_(self.handshake_hash, data)

    def mac1(self, message_without_mac: bytes) -> bytes:
        """
        mac1 = MAC(HASH(LABEL_MAC1 || S_r), message so far).

        A peer that does not already know the responder's public key cannot
        compute this, so unauthenticated junk is discarded before any
        expensive curve operation.
        """
        key = hash_(LABEL_MAC1, self.responder_static_public)
        return mac(key, message_without_mac)

    # ── initiator side ───────────────────────────────────────────────────────

    def write_initiation(self, static: KeyPair) -> tuple[bytes, bytes, bytes]:
        """
        Produce (ephemeral_public, encrypted_static, encrypted_timestamp).

        The caller assembles these into a HandshakeInit and appends mac1.
        """
        self.ephemeral = KeyPair.generate()
        self._mix_key(self.ephemeral.public)
        self._mix_hash(self.ephemeral.public)

        key = self._mix_key_and_derive(
            dh(self.ephemeral.private, self.responder_static_public)
        )
        encrypted_static = aead_encrypt(key, 0, static.public, self.handshake_hash)
        self._mix_hash(encrypted_static)

        key = self._mix_key_and_derive(
            dh(static.private, self.responder_static_public)
        )
        encrypted_timestamp = aead_encrypt(key, 0, tai64n(), self.handshake_hash)
        self._mix_hash(encrypted_timestamp)

        return self.ephemeral.public, encrypted_static, encrypted_timestamp

    def read_response(self, remote_ephemeral: bytes, encrypted_empty: bytes,
                      static: KeyPair) -> tuple[bytes, bytes]:
        """
        Consume the responder's reply and return (send_key, recv_key).

        Raises InvalidTag if the transcript was tampered with.
        """
        assert self.ephemeral is not None, "write_initiation must run first"
        self.remote_ephemeral = remote_ephemeral
        self._mix_key(remote_ephemeral)
        self._mix_hash(remote_ephemeral)
        self._mix_key(dh(self.ephemeral.private, remote_ephemeral))
        self._mix_key(dh(static.private, remote_ephemeral))

        self.chaining_key, temp, key = kdf(self.chaining_key, self.preshared_key, 3)
        self._mix_hash(temp)
        aead_decrypt(key, 0, encrypted_empty, self.handshake_hash)
        self._mix_hash(encrypted_empty)

        send_key, recv_key = kdf(self.chaining_key, b"", 2)
        return send_key, recv_key

    # ── responder side ───────────────────────────────────────────────────────

    def read_initiation(self, remote_ephemeral: bytes, encrypted_static: bytes,
                        encrypted_timestamp: bytes,
                        static: KeyPair) -> tuple[bytes, bytes]:
        """
        Consume an initiation and return (initiator_static_public, timestamp).

        Raises InvalidTag if either ciphertext fails to authenticate.
        """
        self.remote_ephemeral = remote_ephemeral
        self._mix_key(remote_ephemeral)
        self._mix_hash(remote_ephemeral)

        key = self._mix_key_and_derive(dh(static.private, remote_ephemeral))
        remote_static = aead_decrypt(key, 0, encrypted_static, self.handshake_hash)
        self._mix_hash(encrypted_static)
        self.remote_static = remote_static

        key = self._mix_key_and_derive(dh(static.private, remote_static))
        timestamp = aead_decrypt(key, 0, encrypted_timestamp, self.handshake_hash)
        self._mix_hash(encrypted_timestamp)

        return remote_static, timestamp

    def write_response(self) -> tuple[bytes, bytes, bytes, bytes]:
        """
        Produce (ephemeral_public, encrypted_empty, send_key, recv_key).

        Note the key order is swapped relative to the initiator: the KDF's
        first output is the initiator's send key, so it is the responder's
        receive key.
        """
        assert self.remote_ephemeral is not None and self.remote_static is not None
        self.ephemeral = KeyPair.generate()
        self._mix_key(self.ephemeral.public)
        self._mix_hash(self.ephemeral.public)
        self._mix_key(dh(self.ephemeral.private, self.remote_ephemeral))
        self._mix_key(dh(self.ephemeral.private, self.remote_static))

        self.chaining_key, temp, key = kdf(self.chaining_key, self.preshared_key, 3)
        self._mix_hash(temp)
        encrypted_empty = aead_encrypt(key, 0, b"", self.handshake_hash)
        self._mix_hash(encrypted_empty)

        initiator_send, initiator_recv = kdf(self.chaining_key, b"", 2)
        return self.ephemeral.public, encrypted_empty, initiator_recv, initiator_send
