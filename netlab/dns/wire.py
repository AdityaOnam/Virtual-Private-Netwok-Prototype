"""
netlab.dns.wire — DNS message format, built and parsed by hand.

No dnspython.  The wire format is the lesson: DNS is the oldest widely-used
binary protocol most people meet, and it shows two ideas that keep recurring —
length-prefixed labels, and back-references for compression.

Message layout (RFC 1035)
─────────────────────────
    Header (12 bytes, fixed)
    ┌────────────────────────────────┬────────────────────────────────┐
    │              ID (16)           │ QR│Opcode│AA│TC│RD│RA│Z │RCODE │
    ├────────────────────────────────┼────────────────────────────────┤
    │            QDCOUNT (16)        │            ANCOUNT (16)        │
    ├────────────────────────────────┼────────────────────────────────┤
    │            NSCOUNT (16)        │            ARCOUNT (16)        │
    └────────────────────────────────┴────────────────────────────────┘
    Question  × QDCOUNT:  QNAME, QTYPE(16), QCLASS(16)
    Answer    × ANCOUNT:  NAME, TYPE(16), CLASS(16), TTL(32), RDLENGTH(16), RDATA
    Authority × NSCOUNT
    Additional× ARCOUNT

QNAME encoding
──────────────
"www.example.com" becomes a sequence of length-prefixed labels ending in a
zero byte:

    03 'w' 'w' 'w' 07 'e' 'x' 'a' 'm' 'p' 'l' 'e' 03 'c' 'o' 'm' 00

There are no dots on the wire. A label is at most 63 bytes, which is why the
two high bits of a length byte are free — and that is what compression uses.

Compression pointers
────────────────────
A name whose length byte has both high bits set (0b11xxxxxx, i.e. >= 0xC0) is
not a label: it is a 14-bit offset from the start of the *message* to where
the rest of the name already appears.

    0xC0 0x0C  →  "the rest of this name is at byte 12"

Byte 12 is where the question section starts, so almost every answer in a real
response points there rather than repeating the name. Any parser that ignores
this produces garbage on real traffic — and it cannot be avoided by asking
nicely, because the server decides whether to compress.

Pointer loops
─────────────
A malicious or broken server can emit a pointer that points at itself, or two
pointers that point at each other. A naive parser follows them forever. The
parser below caps the number of jumps, which is what every real resolver does.
"""

from __future__ import annotations

import random
import struct
from dataclasses import dataclass, field

HEADER_SIZE = 12
MAX_LABEL = 63
MAX_NAME = 255
POINTER_MASK = 0xC0
MAX_POINTER_JUMPS = 64      # defence against pointer loops

# Record types
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_PTR = 12
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28

TYPE_NAMES = {
    TYPE_A: "A", TYPE_NS: "NS", TYPE_CNAME: "CNAME", TYPE_SOA: "SOA",
    TYPE_PTR: "PTR", TYPE_MX: "MX", TYPE_TXT: "TXT", TYPE_AAAA: "AAAA",
}
NAME_TO_TYPE = {v: k for k, v in TYPE_NAMES.items()}

CLASS_IN = 1

RCODE_NAMES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL",
    3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
}


class DnsParseError(ValueError):
    """Raised on a malformed DNS message."""


# ─────────────────────────────────────────────────────────────────────────────
# Names
# ─────────────────────────────────────────────────────────────────────────────

def encode_name(name: str) -> bytes:
    """Encode a domain name as length-prefixed labels ending in a zero byte."""
    if name in ("", "."):
        return b"\x00"
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna") if any(ord(c) > 127 for c in label) \
            else label.encode("ascii")
        if not 1 <= len(raw) <= MAX_LABEL:
            raise ValueError(
                f"label {label!r} is {len(raw)} bytes; must be 1-{MAX_LABEL}"
            )
        out.append(len(raw))
        out += raw
    out.append(0)
    if len(out) > MAX_NAME:
        raise ValueError(f"name {name!r} encodes to {len(out)} bytes, max {MAX_NAME}")
    return bytes(out)


def decode_name(message: bytes, offset: int) -> tuple[str, int]:
    """
    Decode a name at *offset*, following compression pointers.

    Returns (name, offset_after_the_name_in_this_record).

    The second value is subtle: when a pointer is followed, parsing continues
    after the *pointer*, not after wherever it led. Getting this wrong shifts
    every subsequent record and produces plausible-looking nonsense.
    """
    labels: list[str] = []
    jumps = 0
    position = offset
    after_pointer: int | None = None

    while True:
        if position >= len(message):
            raise DnsParseError(f"name at {offset} runs past end of message")

        length = message[position]

        if length == 0:
            position += 1
            break

        if length & POINTER_MASK == POINTER_MASK:
            if position + 1 >= len(message):
                raise DnsParseError("truncated compression pointer")
            pointer = struct.unpack_from("!H", message, position)[0] & 0x3FFF
            if after_pointer is None:
                after_pointer = position + 2
            jumps += 1
            if jumps > MAX_POINTER_JUMPS:
                raise DnsParseError(
                    "compression pointer loop (exceeded "
                    f"{MAX_POINTER_JUMPS} jumps)"
                )
            if pointer >= len(message):
                raise DnsParseError(f"pointer to {pointer} is past end of message")
            position = pointer
            continue

        if length > MAX_LABEL:
            raise DnsParseError(f"label length {length} exceeds {MAX_LABEL}")

        position += 1
        if position + length > len(message):
            raise DnsParseError("label runs past end of message")
        labels.append(message[position:position + length].decode("ascii", "replace"))
        position += length

    return ".".join(labels), (after_pointer if after_pointer is not None else position)


# ─────────────────────────────────────────────────────────────────────────────
# Records
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Question:
    name: str
    qtype: int = TYPE_A
    qclass: int = CLASS_IN

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self.qtype, str(self.qtype))

    def encode(self) -> bytes:
        return encode_name(self.name) + struct.pack("!HH", self.qtype, self.qclass)


@dataclass
class Record:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes
    value: str = ""

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self.rtype, str(self.rtype))

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.type_name,
            "ttl": self.ttl,
            "value": self.value,
        }


@dataclass
class Message:
    ident: int
    is_response: bool = False
    opcode: int = 0
    authoritative: bool = False
    truncated: bool = False
    recursion_desired: bool = True
    recursion_available: bool = False
    rcode: int = 0
    questions: list[Question] = field(default_factory=list)
    answers: list[Record] = field(default_factory=list)
    authorities: list[Record] = field(default_factory=list)
    additionals: list[Record] = field(default_factory=list)

    @property
    def rcode_name(self) -> str:
        return RCODE_NAMES.get(self.rcode, f"RCODE{self.rcode}")

    def flags_word(self) -> int:
        flags = 0
        if self.is_response:
            flags |= 0x8000
        flags |= (self.opcode & 0xF) << 11
        if self.authoritative:
            flags |= 0x0400
        if self.truncated:
            flags |= 0x0200
        if self.recursion_desired:
            flags |= 0x0100
        if self.recursion_available:
            flags |= 0x0080
        flags |= self.rcode & 0xF
        return flags

    def encode(self) -> bytes:
        header = struct.pack(
            "!HHHHHH", self.ident, self.flags_word(),
            len(self.questions), len(self.answers),
            len(self.authorities), len(self.additionals),
        )
        # We never emit compression pointers ourselves: a query has one name,
        # so there is nothing to compress, and writing a correct compressor is
        # a lot of machinery for zero saving here. We must still *parse* them.
        return header + b"".join(q.encode() for q in self.questions)

    def a_records(self) -> list[str]:
        return [r.value for r in self.answers if r.rtype == TYPE_A]

    def summary(self) -> str:
        question = self.questions[0].name if self.questions else "?"
        return (
            f"{question} {self.rcode_name} "
            f"{len(self.answers)} answer(s)"
        )


def build_query(name: str, qtype: int = TYPE_A,
                ident: int | None = None,
                recursion_desired: bool = True) -> Message:
    """Build a standard recursive query."""
    return Message(
        ident=random.randint(0, 0xFFFF) if ident is None else ident,
        is_response=False,
        recursion_desired=recursion_desired,
        questions=[Question(name, qtype)],
    )


def _decode_rdata(rtype: int, rdata: bytes, message: bytes, offset: int) -> str:
    """Render RDATA as text.  Names inside RDATA may themselves be compressed."""
    import socket

    if rtype == TYPE_A and len(rdata) == 4:
        return socket.inet_ntoa(rdata)
    if rtype == TYPE_AAAA and len(rdata) == 16:
        return socket.inet_ntop(socket.AF_INET6, rdata)
    if rtype in (TYPE_CNAME, TYPE_NS, TYPE_PTR):
        name, _ = decode_name(message, offset)
        return name
    if rtype == TYPE_MX and len(rdata) >= 3:
        preference = struct.unpack_from("!H", rdata, 0)[0]
        exchange, _ = decode_name(message, offset + 2)
        return f"{preference} {exchange}"
    if rtype == TYPE_TXT and rdata:
        parts, index = [], 0
        while index < len(rdata):
            length = rdata[index]
            parts.append(rdata[index + 1:index + 1 + length].decode("utf-8", "replace"))
            index += 1 + length
        return " ".join(parts)
    if rtype == TYPE_SOA:
        primary, next_offset = decode_name(message, offset)
        mailbox, next_offset = decode_name(message, next_offset)
        if next_offset + 20 <= len(message):
            serial, refresh, retry, expire, minimum = struct.unpack_from(
                "!IIIII", message, next_offset
            )
            return f"{primary} {mailbox} {serial} {refresh} {retry} {expire} {minimum}"
        return f"{primary} {mailbox}"
    return rdata.hex(" ")


def _parse_record(message: bytes, offset: int) -> tuple[Record, int]:
    name, offset = decode_name(message, offset)
    if offset + 10 > len(message):
        raise DnsParseError("record header runs past end of message")
    rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", message, offset)
    offset += 10
    if offset + rdlength > len(message):
        raise DnsParseError(
            f"RDLENGTH {rdlength} runs past end of message"
        )
    rdata = message[offset:offset + rdlength]
    value = _decode_rdata(rtype, rdata, message, offset)
    return Record(name, rtype, rclass, ttl, rdata, value), offset + rdlength


def parse_message(raw: bytes) -> Message:
    """Parse a complete DNS message, following compression pointers."""
    if len(raw) < HEADER_SIZE:
        raise DnsParseError(
            f"message is {len(raw)} bytes; header alone needs {HEADER_SIZE}"
        )

    ident, flags, qdcount, ancount, nscount, arcount = struct.unpack_from(
        "!HHHHHH", raw, 0
    )
    message = Message(
        ident=ident,
        is_response=bool(flags & 0x8000),
        opcode=(flags >> 11) & 0xF,
        authoritative=bool(flags & 0x0400),
        truncated=bool(flags & 0x0200),
        recursion_desired=bool(flags & 0x0100),
        recursion_available=bool(flags & 0x0080),
        rcode=flags & 0xF,
    )

    offset = HEADER_SIZE
    for _ in range(qdcount):
        name, offset = decode_name(raw, offset)
        if offset + 4 > len(raw):
            raise DnsParseError("question runs past end of message")
        qtype, qclass = struct.unpack_from("!HH", raw, offset)
        offset += 4
        message.questions.append(Question(name, qtype, qclass))

    for count, bucket in ((ancount, message.answers),
                          (nscount, message.authorities),
                          (arcount, message.additionals)):
        for _ in range(count):
            record, offset = _parse_record(raw, offset)
            bucket.append(record)

    return message
