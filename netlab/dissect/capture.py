"""
netlab.dissect.capture — packet sources for the dissector.

Two sources behind one interface:

    PcapFileCapture(path)     replay a .pcap file      — no dependencies
    LiveCapture(adapter)      sniff a live adapter     — needs Npcap + Scapy

Both yield DecodedPacket objects.  The panel treats them identically, so the
whole dissector works on a machine with no capture driver and no network.

The pcap reader is hand-written rather than delegated to Scapy, for the same
reason the header decoders are: the file format is itself part of the subject.

libpcap file layout
───────────────────
    Global header (24 B, once at the start of the file)
    ┌────────────┬──────┬───────────────────────────────────────────────┐
    │ magic      │ u32  │ 0xA1B2C3D4 µs-resolution, 0xA1B23C4D ns       │
    │            │      │ Byte-swapped value ⇒ file written on a host   │
    │            │      │ of the opposite endianness. This is how a     │
    │            │      │ format carries its own byte order.            │
    │ ver_major  │ u16  │ 2                                             │
    │ ver_minor  │ u16  │ 4                                             │
    │ thiszone   │ i32  │ GMT offset, virtually always 0                │
    │ sigfigs    │ u32  │ timestamp accuracy, virtually always 0        │
    │ snaplen    │ u32  │ bytes captured per packet; a packet longer    │
    │            │      │ than this is truncated — orig_len > incl_len  │
    │ network    │ u32  │ LINKTYPE: 1 = Ethernet, 101 = raw IP          │
    └────────────┴──────┴───────────────────────────────────────────────┘

    Per-packet record (16 B header, then incl_len bytes of frame)
    ┌────────────┬──────┬───────────────────────────────────────────────┐
    │ ts_sec     │ u32  │ capture time, seconds since epoch             │
    │ ts_usec    │ u32  │ microseconds (or nanoseconds if ns magic)     │
    │ incl_len   │ u32  │ bytes present in the file                     │
    │ orig_len   │ u32  │ bytes on the wire                             │
    └────────────┴──────┴───────────────────────────────────────────────┘

    incl_len < orig_len means the capture was truncated by snaplen — the
    dissector will decode the layers that survived and stop.

Concepts demonstrated (Module A)
─────────────────────────────────
  - File formats carrying their own byte order (magic-number endianness)
  - Snapshot length and truncated capture
  - Link-layer types: the same decoder chain fed L2 frames or bare IP
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Protocol

from .dispatch import decode_packet
from .model import DecodedPacket

# ── libpcap constants ────────────────────────────────────────────────────────

PCAP_MAGIC_US = 0xA1B2C3D4   # timestamps in microseconds
PCAP_MAGIC_NS = 0xA1B23C4D   # timestamps in nanoseconds
_GLOBAL_HEADER_LEN = 24
_RECORD_HEADER_LEN = 16

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW_IP = 101
LINKTYPE_NULL = 0

#: Link types whose frames start at L2 rather than at the IP header.
_L2_LINKTYPES = {LINKTYPE_ETHERNET}


@dataclass
class CaptureInfo:
    """Metadata describing where a packet stream came from."""

    source: str
    link_type: int
    snaplen: int = 0
    is_live: bool = False

    @property
    def is_l2(self) -> bool:
        """True if frames include a link-layer header (and so an Ethernet one)."""
        return self.link_type in _L2_LINKTYPES

    @property
    def link_type_name(self) -> str:
        return {
            LINKTYPE_ETHERNET: "Ethernet",
            LINKTYPE_RAW_IP: "Raw IP",
            LINKTYPE_NULL: "Null/Loopback",
        }.get(self.link_type, f"LINKTYPE {self.link_type}")


class PacketSource(Protocol):
    """Common interface the panel consumes."""

    info: CaptureInfo

    def packets(self) -> Iterator[DecodedPacket]:
        """Yield decoded packets until the source is exhausted or stopped."""
        ...


# ─────────────────────────────────────────────────────────────────────────────
# Offline: .pcap file replay
# ─────────────────────────────────────────────────────────────────────────────

class PcapFileCapture:
    """
    Replay a libpcap-format capture file.

    Pure stdlib — works on any machine, with no capture driver, no admin
    rights and no network.  This is the source the panel falls back to, and the
    one the tests use.

    Raises
    ------
    FileNotFoundError
        If *path* does not exist.
    ValueError
        If the file is not a libpcap capture or is truncated mid-header.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if not self.path.exists():
            raise FileNotFoundError(f"pcap file not found: {self.path}")

        raw = self.path.read_bytes()
        if len(raw) < _GLOBAL_HEADER_LEN:
            raise ValueError(
                f"{self.path.name}: too short to be a pcap file "
                f"({len(raw)} B, need at least {_GLOBAL_HEADER_LEN})"
            )

        # The magic number encodes the writing host's byte order: read it both
        # ways and see which one matches.
        magic_be = struct.unpack_from(">I", raw, 0)[0]
        magic_le = struct.unpack_from("<I", raw, 0)[0]
        if magic_be in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
            self._endian = ">"
            self._nanos = magic_be == PCAP_MAGIC_NS
        elif magic_le in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
            self._endian = "<"
            self._nanos = magic_le == PCAP_MAGIC_NS
        else:
            raise ValueError(
                f"{self.path.name}: not a libpcap file "
                f"(magic 0x{magic_be:08X} / 0x{magic_le:08X})"
            )

        _, vmaj, vmin, _, _, snaplen, link_type = self._parse_global_header(raw)
        self.version = (vmaj, vmin)

        self._raw = raw
        self.info = CaptureInfo(
            source=self.path.name,
            link_type=link_type,
            snaplen=snaplen,
            is_live=False,
        )

    def _parse_global_header(self, raw: bytes) -> tuple:
        """Return (magic, vmaj, vmin, tz, sigfigs, snaplen, linktype)."""
        magic, vmaj, vmin, tz, sigfigs, snaplen, link_type = struct.unpack_from(
            f"{self._endian}IHHiIII", raw, 0
        )
        return magic, vmaj, vmin, tz, sigfigs, snaplen, link_type

    def packets(self) -> Iterator[DecodedPacket]:
        """Yield each packet in the file, decoded."""
        offset = _GLOBAL_HEADER_LEN
        raw = self._raw
        divisor = 1e9 if self._nanos else 1e6

        while offset + _RECORD_HEADER_LEN <= len(raw):
            ts_sec, ts_frac, incl_len, orig_len = struct.unpack_from(
                f"{self._endian}IIII", raw, offset
            )
            offset += _RECORD_HEADER_LEN

            if incl_len > len(raw) - offset:
                # Truncated final record — stop rather than yield a partial frame.
                break

            frame = raw[offset: offset + incl_len]
            offset += incl_len

            yield decode_packet(
                frame,
                l2=self.info.is_l2,
                capture_source=self.info.source,
                timestamp=ts_sec + ts_frac / divisor,
            )

    def __len__(self) -> int:
        """Number of complete packet records in the file."""
        return sum(1 for _ in self._record_offsets())

    def _record_offsets(self) -> Iterator[int]:
        offset = _GLOBAL_HEADER_LEN
        raw = self._raw
        while offset + _RECORD_HEADER_LEN <= len(raw):
            incl_len = struct.unpack_from(f"{self._endian}I", raw, offset + 8)[0]
            if incl_len > len(raw) - offset - _RECORD_HEADER_LEN:
                break
            yield offset
            offset += _RECORD_HEADER_LEN + incl_len


# ─────────────────────────────────────────────────────────────────────────────
# pcap writing — used to build the sample fixtures
# ─────────────────────────────────────────────────────────────────────────────

def write_pcap(path: str | Path, frames: list[bytes],
               link_type: int = LINKTYPE_ETHERNET,
               snaplen: int = 65535) -> None:
    """
    Write *frames* to a libpcap file at *path*.

    Used to generate the sample captures in docs/samples/ and, later, by
    Module I's mmap-backed packet log — a file written here opens in Wireshark.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    out = bytearray()
    out += struct.pack("<IHHiIII", PCAP_MAGIC_US, 2, 4, 0, 0, snaplen, link_type)
    for i, frame in enumerate(frames):
        out += struct.pack("<IIII", 1_700_000_000 + i, i * 1000, len(frame), len(frame))
        out += frame
    path.write_bytes(bytes(out))


# ─────────────────────────────────────────────────────────────────────────────
# Live capture — requires Npcap (Windows) or libpcap (Linux/macOS) + Scapy
# ─────────────────────────────────────────────────────────────────────────────

class CaptureBackendUnavailable(RuntimeError):
    """Raised when live capture is requested but the driver/library is missing."""


def live_capture_available() -> tuple[bool, str]:
    """
    Report whether live capture can work on this machine, without raising.

    Returns
    -------
    (available, reason)
        *reason* is a message suitable for display in the panel when
        *available* is False.

    Trap §7.1 in the plan: on Windows, Scapy needs **Npcap** (installed in
    "WinPcap API-compatible mode"), not raw sockets.  Without it, sniffing
    fails with an unhelpful error deep inside Scapy, so we check up front and
    let the panel degrade to offline pcap replay instead of crashing.
    """
    try:
        from scapy.arch import get_if_list  # noqa: F401
    except ImportError:
        return False, (
            "Scapy is not installed. Live capture is unavailable; "
            "offline .pcap replay still works."
        )

    try:
        from scapy.arch import get_if_list
        interfaces = get_if_list()
    except Exception as exc:  # Scapy raises various driver-specific errors
        return False, (
            f"No capture driver found ({exc.__class__.__name__}). "
            "On Windows install Npcap in WinPcap API-compatible mode "
            "(bundled with Wireshark). Offline .pcap replay still works."
        )

    if not interfaces:
        return False, (
            "No capture-capable adapters found. On Windows this usually means "
            "Npcap is missing. Offline .pcap replay still works."
        )

    # Plan trap §7.3: Npcap can be installed and still enumerate only the
    # loopback adapter — which is useless for the Tunnel Comparison demo, since
    # that needs the physical NIC.  Report that honestly instead of saying
    # "N adapters available" and letting the user discover it mid-demo.
    physical = [i for i in interfaces if "loopback" not in i.lower()]
    if not physical:
        return False, (
            "Npcap is present but only the loopback adapter is visible — no "
            "physical NIC. Reinstall Npcap with 'Support raw 802.11' and "
            "WinPcap API-compatible mode, or reboot after installing. "
            "Offline .pcap replay still works."
        )
    return True, f"{len(physical)} adapter(s): " + ", ".join(
        i.split("\\")[-1] for i in physical[:3]
    )


def list_adapters() -> list[str]:
    """Return capture-capable adapter names, or [] if the backend is missing."""
    ok, _ = live_capture_available()
    if not ok:
        return []
    from scapy.arch import get_if_list
    return list(get_if_list())


class LiveCapture:
    """
    Sniff a live adapter.

    Scapy is used only to deliver raw bytes (`lfilter` + `bytes(pkt)`); every
    header is decoded by our own decoders.  That keeps the pedagogical point
    intact — Scapy is the driver, not the dissector.

    Raises
    ------
    CaptureBackendUnavailable
        If no capture driver is present.  Callers should check
        live_capture_available() first and fall back to PcapFileCapture.
    """

    def __init__(self, adapter: str, bpf_filter: str = "", count: int = 0) -> None:
        available, reason = live_capture_available()
        if not available:
            raise CaptureBackendUnavailable(reason)

        self.adapter = adapter
        self.bpf_filter = bpf_filter
        self.count = count
        self._stop = False
        self.info = CaptureInfo(
            source=adapter,
            link_type=LINKTYPE_ETHERNET,
            is_live=True,
        )

    def stop(self) -> None:
        """Ask the capture loop to finish after the current packet."""
        self._stop = True

    def packets(self) -> Iterator[DecodedPacket]:
        """Yield decoded packets as they arrive until stop() is called."""
        from scapy.sendrecv import sniff

        queue: list[DecodedPacket] = []

        def handle(pkt) -> None:
            queue.append(
                decode_packet(
                    bytes(pkt),
                    l2=True,
                    capture_source=self.adapter,
                    timestamp=float(pkt.time),
                )
            )

        sniff(
            iface=self.adapter,
            filter=self.bpf_filter or None,
            prn=handle,
            count=self.count,
            store=False,
            stop_filter=lambda _: self._stop,
        )
        yield from queue
