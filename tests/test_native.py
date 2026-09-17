"""
tests/test_native.py — Phase 2: the OnamVPN Native tunnel.

Covers the wire format, the key schedule, the anti-replay window, session
rekey/nonce safety, and an end-to-end tunnel over loopback including a
tamper test and a bulk transfer.

All offline: the tunnel runs client and server in one process on 127.0.0.1.
"""

from __future__ import annotations

import hashlib
import socket
import struct
import threading
import time

import pytest

from netlab.native import protocol as P
from netlab.native.crypto import (
    HandshakeState,
    InvalidTag,
    KeyPair,
    aead_decrypt,
    aead_encrypt,
    dh,
    hash_,
    kdf,
    tai64n,
)
from netlab.native.replay import ReplayWindow
from netlab.native.runner import LocalTunnel, chunk_payload
from netlab.native.session import NonceExhausted, PeerState, Session


# ─────────────────────────────────────────────────────────────────────────────
# Wire format
# ─────────────────────────────────────────────────────────────────────────────

class TestWireFormat:
    def test_documented_sizes(self) -> None:
        """struct.calcsize must match the hand-computed table in the docstring."""
        assert P.SIZE_INIT == 132
        assert P.SIZE_RESP == 76
        assert P.SIZE_DATA_HEADER == 16
        assert P.SIZE_INNER_FRAME == 7

    def test_mac1_offsets(self) -> None:
        assert P.MAC1_OFFSET_INIT == 116
        assert P.MAC1_OFFSET_RESP == 60

    def test_init_round_trip(self) -> None:
        message = P.HandshakeInit(
            sender_index=0xDEADBEEF,
            ephemeral=bytes(range(32)),
            encrypted_static=bytes(48),
            encrypted_timestamp=bytes(28),
            mac1=bytes(16),
        )
        blob = P.pack_init(message)
        assert len(blob) == P.SIZE_INIT
        assert blob[0] == P.MSG_HANDSHAKE_INIT
        assert P.unpack_init(blob) == message

    def test_response_round_trip(self) -> None:
        message = P.HandshakeResponse(1, 2, bytes(range(32)), bytes(16), bytes(16))
        blob = P.pack_response(message)
        assert len(blob) == P.SIZE_RESP
        assert P.unpack_response(blob) == message

    def test_data_round_trip(self) -> None:
        message = P.TransportData(0x11223344, 2 ** 40, b"c" * 64)
        blob = P.pack_data(message)
        assert len(blob) == P.SIZE_DATA_HEADER + 64
        assert P.unpack_data(blob) == message

    def test_little_endian_on_the_wire(self) -> None:
        """Counter is LE — the opposite of IP/TCP network byte order."""
        blob = P.pack_data(P.TransportData(0, 1, b"\x00" * 16))
        assert blob[8:16] == b"\x01\x00\x00\x00\x00\x00\x00\x00"

    @pytest.mark.parametrize("bad", [b"", b"\x01", b"\x01" * 131, b"\x01" * 133])
    def test_malformed_init_rejected(self, bad: bytes) -> None:
        with pytest.raises(ValueError):
            P.unpack_init(bad)

    def test_wrong_type_rejected(self) -> None:
        blob = bytearray(P.pack_init(P.HandshakeInit(1, bytes(32), bytes(48),
                                                     bytes(28), bytes(16))))
        blob[0] = P.MSG_HANDSHAKE_RESP
        with pytest.raises(ValueError, match="expected type"):
            P.unpack_init(bytes(blob))

    def test_data_shorter_than_tag_rejected(self) -> None:
        with pytest.raises(ValueError, match="at least"):
            P.unpack_data(b"\x04" + b"\x00" * 20)

    def test_inner_frame_round_trip(self) -> None:
        blob = P.pack_inner(P.FRAME_DATA, 7, b"payload")
        kind, stream_id, payload, consumed = P.unpack_inner(blob)
        assert (kind, stream_id, payload) == (P.FRAME_DATA, 7, b"payload")
        assert consumed == len(blob)

    def test_inner_frames_pack_back_to_back(self) -> None:
        blob = P.pack_inner(P.FRAME_DATA, 1, b"aa") + P.pack_inner(P.FRAME_DATA, 2, b"bbb")
        kind, sid, payload, consumed = P.unpack_inner(blob)
        assert (sid, payload) == (1, b"aa")
        kind, sid, payload, _ = P.unpack_inner(blob[consumed:])
        assert (sid, payload) == (2, b"bbb")

    def test_inner_frame_truncated_rejected(self) -> None:
        blob = P.pack_inner(P.FRAME_DATA, 1, b"aaaa")[:-2]
        with pytest.raises(ValueError, match="claims"):
            P.unpack_inner(blob)


class TestNonce:
    @pytest.mark.parametrize(
        "counter, expected",
        [
            (0, "00 00 00 00 00 00 00 00 00 00 00 00"),
            (1, "00 00 00 00 01 00 00 00 00 00 00 00"),
            (2 ** 32, "00 00 00 00 00 00 00 00 01 00 00 00"),
            (2 ** 64 - 1, "00 00 00 00 ff ff ff ff ff ff ff ff"),
        ],
    )
    def test_construction(self, counter: int, expected: str) -> None:
        assert P.nonce_for(counter).hex(" ") == expected

    def test_length_is_always_12(self) -> None:
        for counter in (0, 1, 2 ** 31, 2 ** 63):
            assert len(P.nonce_for(counter)) == P.NONCE_SIZE

    def test_never_repeats_across_range(self) -> None:
        seen = {P.nonce_for(c) for c in range(1000)}
        assert len(seen) == 1000

    @pytest.mark.parametrize("bad", [-1, 2 ** 64])
    def test_out_of_range_rejected(self, bad: int) -> None:
        with pytest.raises(ValueError, match="out of range"):
            P.nonce_for(bad)


# ─────────────────────────────────────────────────────────────────────────────
# Anti-replay window — the most commonly botched part of a VPN
# ─────────────────────────────────────────────────────────────────────────────

class TestReplayWindow:
    def test_in_order_all_accepted(self) -> None:
        window = ReplayWindow()
        assert all(window.check_and_update(i) for i in range(500))
        assert window.rejected == 0

    def test_exact_duplicate_rejected(self) -> None:
        window = ReplayWindow()
        assert window.check_and_update(5) is True
        assert window.check_and_update(5) is False
        assert window.rejected == 1

    def test_reordered_within_window_accepted(self) -> None:
        """
        The whole point: a lower counter is not automatically a replay.
        `if counter <= highest: drop` fails this test.
        """
        window = ReplayWindow()
        for counter in (10, 9, 7, 8, 6):
            assert window.check_and_update(counter) is True, counter
        assert window.rejected == 0

    def test_replay_of_reordered_packet_rejected(self) -> None:
        window = ReplayWindow()
        window.check_and_update(10)
        window.check_and_update(8)
        assert window.check_and_update(8) is False

    def test_below_window_rejected(self) -> None:
        window = ReplayWindow(window_bits=8)
        window.check_and_update(100)
        assert window.check_and_update(50) is False

    def test_window_boundary_exact(self) -> None:
        """The oldest counter still inside the window must be accepted."""
        window = ReplayWindow(window_bits=16)
        window.check_and_update(100)
        assert window.check_and_update(100 - 15) is True
        assert window.check_and_update(100 - 16) is False

    def test_far_future_resets_window(self) -> None:
        window = ReplayWindow(window_bits=16)
        for counter in range(5):
            window.check_and_update(counter)
        assert window.check_and_update(10_000) is True
        assert window.check_and_update(3) is False     # now far below
        assert window.check_and_update(9_999) is True  # still in window

    def test_first_packet_may_be_any_counter(self) -> None:
        window = ReplayWindow()
        assert window.check_and_update(12345) is True

    def test_negative_rejected(self) -> None:
        assert ReplayWindow().check_and_update(-1) is False

    def test_would_accept_does_not_mutate(self) -> None:
        window = ReplayWindow()
        window.check_and_update(5)
        assert window.would_accept(6) is True
        assert window.would_accept(6) is True
        assert window.check_and_update(6) is True
        assert window.would_accept(6) is False

    def test_reordered_trace(self) -> None:
        """A 20-packet shuffled-but-unique stream loses nothing."""
        order = [0, 3, 1, 2, 7, 5, 4, 6, 11, 8, 10, 9, 15, 12, 14, 13, 19, 16, 18, 17]
        window = ReplayWindow()
        assert all(window.check_and_update(c) for c in order)
        assert window.accepted == 20 and window.rejected == 0

    def test_bitmap_render(self) -> None:
        window = ReplayWindow()
        window.check_and_update(4)
        window.check_and_update(2)
        assert window.bitmap_str(6) == "#.#..."

    def test_rejects_tiny_window(self) -> None:
        with pytest.raises(ValueError, match="at least 8"):
            ReplayWindow(window_bits=4)


# ─────────────────────────────────────────────────────────────────────────────
# Key schedule
# ─────────────────────────────────────────────────────────────────────────────

class TestCrypto:
    def test_dh_is_symmetric(self) -> None:
        a, b = KeyPair.generate(), KeyPair.generate()
        assert dh(a.private, b.public) == dh(b.private, a.public)

    def test_kdf_outputs_are_distinct_and_sized(self) -> None:
        outputs = kdf(b"\x01" * 32, b"material", 3)
        assert len(outputs) == 3
        assert all(len(o) == 32 for o in outputs)
        assert len(set(outputs)) == 3

    def test_kdf_is_deterministic(self) -> None:
        assert kdf(b"\x02" * 32, b"x", 2) == kdf(b"\x02" * 32, b"x", 2)

    def test_kdf_rejects_bad_count(self) -> None:
        with pytest.raises(ValueError, match="1-3"):
            kdf(b"\x00" * 32, b"", 4)

    def test_aead_round_trip(self) -> None:
        key = b"\x07" * 32
        blob = aead_encrypt(key, 3, b"secret", b"aad")
        assert aead_decrypt(key, 3, blob, b"aad") == b"secret"

    def test_aead_rejects_wrong_aad(self) -> None:
        key = b"\x07" * 32
        blob = aead_encrypt(key, 0, b"secret", b"aad")
        with pytest.raises(InvalidTag):
            aead_decrypt(key, 0, blob, b"different")

    def test_aead_rejects_wrong_counter(self) -> None:
        key = b"\x07" * 32
        blob = aead_encrypt(key, 0, b"secret", b"")
        with pytest.raises(InvalidTag):
            aead_decrypt(key, 1, blob, b"")

    def test_tai64n_is_monotonic_and_sized(self) -> None:
        first = tai64n(1000.0)
        second = tai64n(1000.5)
        assert len(first) == P.TIMESTAMP_SIZE
        assert second > first

    def test_keypair_round_trips_through_bytes(self) -> None:
        original = KeyPair.generate()
        restored = KeyPair.from_private_bytes(original.private_bytes())
        assert restored.public == original.public

    def test_handshake_derives_matching_keys(self) -> None:
        """
        The full handshake, with no sockets involved.

        Both sides must end with the initiator's send key equal to the
        responder's receive key, and vice versa — the direction agreement.
        """
        initiator_static = KeyPair.generate()
        responder_static = KeyPair.generate()

        initiator = HandshakeState(responder_static.public)
        ephemeral, enc_static, enc_ts = initiator.write_initiation(initiator_static)

        responder = HandshakeState(responder_static.public)
        remote_static, _timestamp = responder.read_initiation(
            ephemeral, enc_static, enc_ts, responder_static
        )
        assert remote_static == initiator_static.public

        r_ephemeral, enc_empty, r_send, r_recv = responder.write_response()
        i_send, i_recv = initiator.read_response(
            r_ephemeral, enc_empty, initiator_static
        )

        assert i_send == r_recv, "initiator send must equal responder receive"
        assert i_recv == r_send, "initiator receive must equal responder send"
        assert i_send != i_recv, "the two directions must use different keys"

    def test_handshake_hides_initiator_identity(self) -> None:
        """S_i travels encrypted, so a passive observer cannot see who dialled."""
        initiator_static = KeyPair.generate()
        responder_static = KeyPair.generate()
        state = HandshakeState(responder_static.public)
        _, enc_static, _ = state.write_initiation(initiator_static)
        assert initiator_static.public not in enc_static

    def test_handshake_fails_against_wrong_responder_key(self) -> None:
        initiator_static = KeyPair.generate()
        responder_static = KeyPair.generate()
        impostor = KeyPair.generate()

        initiator = HandshakeState(impostor.public)
        ephemeral, enc_static, enc_ts = initiator.write_initiation(initiator_static)

        responder = HandshakeState(responder_static.public)
        with pytest.raises(InvalidTag):
            responder.read_initiation(ephemeral, enc_static, enc_ts, responder_static)

    def test_tampered_initiation_rejected(self) -> None:
        initiator_static = KeyPair.generate()
        responder_static = KeyPair.generate()
        initiator = HandshakeState(responder_static.public)
        ephemeral, enc_static, enc_ts = initiator.write_initiation(initiator_static)

        corrupted = bytearray(enc_static)
        corrupted[0] ^= 0xFF

        responder = HandshakeState(responder_static.public)
        with pytest.raises(InvalidTag):
            responder.read_initiation(ephemeral, bytes(corrupted), enc_ts,
                                      responder_static)

    def test_mac1_requires_knowing_the_server_key(self) -> None:
        real = KeyPair.generate()
        other = KeyPair.generate()
        message = b"\x01" * 116
        assert (HandshakeState(real.public).mac1(message)
                != HandshakeState(other.public).mac1(message))


# ─────────────────────────────────────────────────────────────────────────────
# Session: nonce safety and rekey
# ─────────────────────────────────────────────────────────────────────────────

def _session(**kwargs) -> Session:
    defaults = dict(send_key=b"\x01" * 32, recv_key=b"\x02" * 32,
                    local_index=1, remote_index=2, is_initiator=True)
    defaults.update(kwargs)
    return Session(**defaults)


class TestSession:
    def test_counter_increments_per_packet(self) -> None:
        session = _session()
        assert [session.encrypt(b"x")[0] for _ in range(4)] == [0, 1, 2, 3]

    def test_round_trip(self) -> None:
        a = _session()
        b = _session(send_key=a.recv_key, recv_key=a.send_key, is_initiator=False)
        counter, ciphertext = a.encrypt(b"payload")
        assert b.decrypt(counter, ciphertext) == b"payload"

    def test_replay_returns_none(self) -> None:
        a = _session()
        b = _session(send_key=a.recv_key, recv_key=a.send_key)
        counter, ciphertext = a.encrypt(b"once")
        assert b.decrypt(counter, ciphertext) == b"once"
        assert b.decrypt(counter, ciphertext) is None

    def test_tampered_ciphertext_raises(self) -> None:
        a = _session()
        b = _session(send_key=a.recv_key, recv_key=a.send_key)
        counter, ciphertext = a.encrypt(b"payload")
        corrupted = bytearray(ciphertext)
        corrupted[0] ^= 0xFF
        with pytest.raises(InvalidTag):
            b.decrypt(counter, bytes(corrupted))

    def test_forgery_does_not_poison_replay_window(self) -> None:
        """
        Authenticate before recording the counter.

        Otherwise a forged packet with a plausible counter marks that slot
        used, and the genuine packet that follows is dropped as a replay.
        """
        a = _session()
        b = _session(send_key=a.recv_key, recv_key=a.send_key)
        counter, ciphertext = a.encrypt(b"genuine")
        forged = bytes(len(ciphertext))
        with pytest.raises(InvalidTag):
            b.decrypt(counter, forged)
        assert b.decrypt(counter, ciphertext) == b"genuine"

    def test_refuses_to_exhaust_nonce(self) -> None:
        session = _session()
        session.send_counter = P.REJECT_AFTER_MESSAGES
        with pytest.raises(NonceExhausted):
            session.encrypt(b"x")

    def test_needs_rekey_on_message_count(self) -> None:
        session = _session()
        assert session.needs_rekey() is False
        session.send_counter = P.REKEY_AFTER_MESSAGES
        assert session.needs_rekey() is True

    def test_install_keys_resets_counter_and_window(self) -> None:
        """Keys and counter must move together or a nonce repeats."""
        session = _session()
        for _ in range(10):
            session.encrypt(b"x")
        assert session.send_counter == 10
        session.install_keys(b"\x09" * 32, b"\x0a" * 32)
        assert session.send_counter == 0
        assert session.replay.highest_seen == -1
        assert session.rekeys == 1

    def test_rekey_lets_counters_repeat_safely(self) -> None:
        """
        After a rekey the counter restarts at 0 — which is only safe because
        the key changed at the same instant.
        """
        session = _session()
        first_counter, first = session.encrypt(b"same plaintext")
        session.install_keys(b"\x09" * 32, b"\x0a" * 32)
        second_counter, second = session.encrypt(b"same plaintext")
        assert first_counter == second_counter == 0
        assert first != second, "identical ciphertext would mean keystream reuse"


class TestPeerState:
    def test_previous_session_still_decrypts(self) -> None:
        """In-flight packets must survive a rekey."""
        sender = _session()
        receiver = _session(send_key=sender.recv_key, recv_key=sender.send_key,
                            local_index=7)
        peer = PeerState()
        peer.promote(receiver)

        counter, ciphertext = sender.encrypt(b"in flight")

        newer = _session(local_index=8)
        peer.promote(newer)
        assert peer.previous is receiver

        assert peer.decrypt_any(7, counter, ciphertext) == b"in flight"

    def test_unknown_index_raises(self) -> None:
        peer = PeerState()
        peer.promote(_session(local_index=1))
        with pytest.raises(InvalidTag, match="no session"):
            peer.decrypt_any(99, 0, b"\x00" * 32)


# ─────────────────────────────────────────────────────────────────────────────
# End to end over loopback
# ─────────────────────────────────────────────────────────────────────────────

class _Origin:
    """A trivial echo server the tunnel's exit node can reach."""

    def __init__(self) -> None:
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.address = self._sock.getsockname()
        self._running = True
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while self._running:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        buffer = b""
        while b"\n" not in buffer:
            chunk = conn.recv(65536)
            if not chunk:
                break
            buffer += chunk
        try:
            conn.sendall(b"ECHO:" + buffer)
        except OSError:
            pass
        conn.close()

    def stop(self) -> None:
        self._running = False
        self._sock.close()


def _socks_connect(proxy: tuple[str, int], target: tuple[str, int],
                   timeout: float = 15) -> socket.socket:
    sock = socket.create_connection(proxy, timeout=timeout)
    sock.sendall(b"\x05\x01\x00")
    assert sock.recv(2) == b"\x05\x00"
    sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(target[0])
                 + struct.pack("!H", target[1]))
    reply = sock.recv(10)
    assert reply[1] == 0, f"SOCKS5 reply code {reply[1]}"
    return sock


def _drain(sock: socket.socket, timeout: float = 8) -> bytes:
    sock.settimeout(timeout)
    out = b""
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            out += chunk
    except socket.timeout:
        pass
    return out


@pytest.fixture
def tunnel():
    t = LocalTunnel()
    assert t.start(timeout=10), "tunnel handshake failed"
    yield t
    t.stop()


@pytest.fixture
def origin():
    o = _Origin()
    yield o
    o.stop()


class TestEndToEnd:
    def test_handshake_completes(self, tunnel) -> None:
        assert tunnel.stats()["server"]["handshakes_completed"] == 1
        assert tunnel.stats()["client"]["state"] == "established"

    def test_round_trip_through_socks5(self, tunnel, origin) -> None:
        sock = _socks_connect(tunnel.proxy_address, origin.address)
        sock.sendall(b"hello through the tunnel\n")
        assert _drain(sock, timeout=5) == b"ECHO:hello through the tunnel\n"
        sock.close()

    def test_bulk_transfer_is_byte_identical(self, tunnel, origin) -> None:
        """200 KB, which spans many datagrams and exercises chunking."""
        payload = b"x" * 200_000 + b"\n"
        expected = b"ECHO:" + payload
        sock = _socks_connect(tunnel.proxy_address, origin.address)
        sock.sendall(payload)
        received = _drain(sock, timeout=30)
        sock.close()
        assert len(received) == len(expected), (
            f"got {len(received)} B, expected {len(expected)} B"
        )
        assert hashlib.sha256(received).hexdigest() == \
               hashlib.sha256(expected).hexdigest()

    def test_no_replays_or_forgeries_on_a_clean_run(self, tunnel, origin) -> None:
        sock = _socks_connect(tunnel.proxy_address, origin.address)
        sock.sendall(b"clean\n")
        _drain(sock, timeout=5)
        sock.close()
        stats = tunnel.stats()["server"]
        assert stats["replays_dropped"] == 0
        assert stats["forgeries_dropped"] == 0

    def test_concurrent_streams_do_not_cross(self, tunnel, origin) -> None:
        """Stream ids must keep multiplexed connections separate."""
        results: dict[int, bytes] = {}

        def run(index: int) -> None:
            sock = _socks_connect(tunnel.proxy_address, origin.address)
            sock.sendall(f"stream-{index}\n".encode())
            results[index] = _drain(sock, timeout=8)
            sock.close()

        threads = [threading.Thread(target=run, args=(i,)) for i in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)

        assert len(results) == 4
        for index, data in results.items():
            assert data == f"ECHO:stream-{index}\n".encode(), (index, data)

    def test_forged_datagram_is_dropped(self, tunnel) -> None:
        """Random noise aimed at the server must not be accepted."""
        before = tunnel.server.stats()["forgeries_dropped"]
        attacker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        index = tunnel.server.peer_indices()[0]
        forged = P.pack_data(P.TransportData(index, 99999, b"\x00" * 48))
        attacker.sendto(forged, tunnel.server.address)
        attacker.close()
        time.sleep(0.4)
        assert tunnel.server.stats()["forgeries_dropped"] > before

    def test_replayed_datagram_is_dropped(self, tunnel) -> None:
        """
        Send one genuine packet twice.

        The AEAD authenticates both copies — the ciphertext is untouched and
        the tag is valid — so nothing but the replay window can tell them
        apart. This is precisely the attack `if counter <= highest: drop`
        catches by accident and a correct sliding window catches on purpose.
        """
        session = tunnel.client.peer.current
        assert session is not None

        counter, ciphertext = session.encrypt(P.pack_inner(P.FRAME_KEEPALIVE, 0, b""))
        datagram = P.pack_data(
            P.TransportData(session.remote_index, counter, ciphertext)
        )

        before = tunnel.server.stats()["replays_dropped"]
        attacker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        attacker.sendto(datagram, tunnel.server.address)   # genuine
        time.sleep(0.3)
        attacker.sendto(datagram, tunnel.server.address)   # byte-identical replay
        attacker.close()
        time.sleep(0.4)

        after = tunnel.server.stats()
        assert after["replays_dropped"] == before + 1, (
            "the second, identical datagram must be rejected as a replay"
        )
        assert after["forgeries_dropped"] == 0, (
            "a replay is not a forgery — the tag was valid both times"
        )


class TestChunking:
    def test_large_payload_splits_under_mtu(self) -> None:
        """
        Frames must fit the *configured* payload size, not the compiled-in
        default — chunk_payload reads mtu_size from config/settings.json.
        """
        from netlab.native.settings import tunnel_payload_size

        size = tunnel_payload_size()
        frames = chunk_payload(P.FRAME_DATA, 1, b"y" * 5000)
        assert len(frames) == -(-5000 // size)      # ceiling division
        for frame in frames:
            assert len(frame) <= size + P.SIZE_INNER_FRAME

    def test_explicit_size_overrides_settings(self) -> None:
        frames = chunk_payload(P.FRAME_DATA, 1, b"y" * 5000, size=500)
        assert len(frames) == 10
        for frame in frames:
            assert len(frame) <= 500 + P.SIZE_INNER_FRAME

    def test_chunks_reassemble_in_order(self) -> None:
        original = bytes(range(256)) * 20
        rebuilt = b""
        for frame in chunk_payload(P.FRAME_DATA, 1, original):
            _, _, payload, _ = P.unpack_inner(frame)
            rebuilt += payload
        assert rebuilt == original

    def test_empty_payload_still_produces_one_frame(self) -> None:
        assert len(chunk_payload(P.FRAME_CLOSE, 1, b"")) == 1


# ─────────────────────────────────────────────────────────────────────────────
# Settings wiring — six values the GUI wrote and nothing read
# ─────────────────────────────────────────────────────────────────────────────

class TestSettingsWiring:
    """
    Each of these settings was written by the Settings dialog and consumed
    nowhere. They now change real behaviour, and are clamped because the
    dialog permits values that would break the tunnel.
    """

    def _write(self, tmp_path, monkeypatch, **values) -> None:
        import json
        config = tmp_path / "config"
        config.mkdir(exist_ok=True)
        (config / "settings.json").write_text(json.dumps(values), encoding="utf-8")
        monkeypatch.chdir(tmp_path)

    def test_keepalive_is_read(self, tmp_path, monkeypatch) -> None:
        from netlab.native.settings import keepalive_interval
        self._write(tmp_path, monkeypatch, keepalive_interval=42)
        assert keepalive_interval() == 42

    def test_keepalive_is_clamped(self, tmp_path, monkeypatch) -> None:
        """A 1-second keepalive is pure overhead; 9999 stops refreshing NAT."""
        from netlab.native.settings import keepalive_interval
        self._write(tmp_path, monkeypatch, keepalive_interval=1)
        assert keepalive_interval() == 5
        self._write(tmp_path, monkeypatch, keepalive_interval=9999)
        assert keepalive_interval() == 120

    def test_connection_timeout_is_read(self, tmp_path, monkeypatch) -> None:
        from netlab.native.settings import connection_timeout
        self._write(tmp_path, monkeypatch, connection_timeout=12)
        assert connection_timeout() == 12.0

    def test_mtu_is_read_and_clamped(self, tmp_path, monkeypatch) -> None:
        from netlab.native.settings import tunnel_payload_size
        self._write(tmp_path, monkeypatch, mtu_size=1000)
        assert tunnel_payload_size() == 1000
        self._write(tmp_path, monkeypatch, mtu_size=9000)
        assert tunnel_payload_size() == 1432, "must not exceed a 1500-byte path"
        self._write(tmp_path, monkeypatch, mtu_size=100)
        assert tunnel_payload_size() == 576, "IPv4 minimum every host accepts"

    def test_mtu_changes_chunking(self, tmp_path, monkeypatch) -> None:
        """The setting must actually change how payloads are split."""
        self._write(tmp_path, monkeypatch, mtu_size=600)
        frames = P.chunk_payload(P.FRAME_DATA, 1, b"z" * 3000)
        assert len(frames) == 5
        for frame in frames:
            _, _, payload, _ = P.unpack_inner(frame)
            assert len(payload) <= 600

    def test_missing_settings_fall_back(self, tmp_path, monkeypatch) -> None:
        from netlab.native.settings import (
            connection_timeout,
            keepalive_interval,
            tunnel_payload_size,
        )
        monkeypatch.chdir(tmp_path)
        assert keepalive_interval() == P.KEEPALIVE_SECONDS
        assert connection_timeout() == float(P.HANDSHAKE_TIMEOUT_SECONDS)
        assert tunnel_payload_size() == P.MAX_TUNNEL_PAYLOAD

    def test_corrupt_settings_fall_back(self, tmp_path, monkeypatch) -> None:
        config = tmp_path / "config"
        config.mkdir(exist_ok=True)
        (config / "settings.json").write_text("{not json", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        from netlab.native.settings import keepalive_interval
        assert keepalive_interval() == P.KEEPALIVE_SECONDS

    def test_thread_count_is_read(self) -> None:
        from vpn_core.speedtest_utils import SpeedTestManager
        assert 1 <= SpeedTestManager._configured_worker_count() <= 32
