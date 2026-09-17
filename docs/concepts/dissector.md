# Module A — Packet Dissector

Hand-written protocol decoders. Nothing here delegates parsing to a library:
the point is that every field is extracted by code you can read.

## Concepts demonstrated

| Concept | Where |
|---|---|
| OSI / TCP-IP layering | `netlab/dissect/` — files named for the layer they decode |
| Encapsulation and demultiplexing | `dispatch.py:39` — EtherType → IP protocol → transport |
| Bit-level header layout | `model.py:288` `_extract_bits` |
| Sub-byte fields | `internet.py` — IPv4 version/IHL nibbles, the 3 flag bits |
| Variable-length headers | `internet.py` — IHL > 5 means options present |
| Internet checksum (RFC 1071) | `checksums.py:19` |
| IP fragmentation | `internet.py` — DF/MF flags, fragment offset |
| Port multiplexing | `transport.py` — TCP/UDP source and destination ports |
| TTL and hop limiting | `internet.py` — also the mechanism traceroute exploits |
| TCP options | `transport.py:29` `_parse_tcp_options` — MSS, WScale, SACK, timestamps |
| Transport pseudo-headers | `checksums.py:29` — why TCP's checksum covers IP addresses |
| File formats carrying byte order | `capture.py` — the libpcap magic number |
| Snapshot length and truncation | `capture.py` — `incl_len < orig_len` |

## Layout

The decoders are grouped by OSI layer, so the file structure is itself the
lesson:

```
netlab/dissect/
  model.py       Layer / FieldView / DecodedPacket, and _extract_bits
  tables.py      protocol number → name lookups
  checksums.py   RFC 1071 checksum + pseudo-headers
  link.py        L2   Ethernet II, 802.1Q VLAN
  internet.py    L3   IPv4, IPv6, ICMP / ICMPv6
  transport.py   L4   TCP (with options), UDP
  dispatch.py         chains them into a DecodedPacket
  capture.py          libpcap reader + live capture
  headers.py          facade re-exporting everything
```

## The FieldView invariant

Every field carries both `raw_bytes` and a `(bit_offset, bit_length)` span.
These are two descriptions of the same thing, and if they may disagree the
hex-dump highlight drifts away from the decoded value.

`FieldView.__post_init__` enforces `len(raw_bytes) == byte_length`. A decoder
that gets it wrong raises immediately instead of producing a misleading
display.

This was not theoretical. The first IPv4 decoder passed the two-byte
flags+fragment word as `raw_bytes` for each of the three one-bit flags, all of
which live entirely inside the first of those bytes. The bit offsets were
right; the highlight was one byte too wide, with nothing to catch it.

## Running it

```bash
python main.py --labs        # Dissector tab
```

Pick one of the three committed captures in `docs/samples/`, click a packet,
expand a layer, click a field. The hex dump marks exactly the bytes that field
occupies.

Regenerating the fixtures (rarely needed — they are committed):

```bash
python docs/samples/make_samples.py
python docs/samples/make_goldens.py
```

## The sample captures

**`01_tcp_handshake.pcap`** — a full three-way handshake, an HTTP GET and its
response, then the FIN exchange. Seven packets. Use this to show the flag bits
changing meaningfully: SYN, SYN-ACK, ACK, PSH-ACK, FIN-ACK.

**`02_sharp_edges.pcap`** — six packets, each of which produced a wrong answer
at some point during development. Exactly one is genuinely corrupt.

| # | Packet | What broke |
|---|---|---|
| 0 | 60-byte padded TCP SYN | The checksum was computed over "the rest of the buffer". Ethernet pads short frames to 60 bytes, so the padding was folded in and **every SYN, ACK and FIN reported BAD CHECKSUM**. TCP has no length field of its own; the segment length has to come from IP. |
| 1 | First fragment (MF=1) | Carries a real TCP header, and must be decoded. Its TCP checksum covers the whole reassembled segment, so it cannot be verified from this fragment alone — the field says so rather than flagging it bad. |
| 2 | Later fragment (offset 3) | Carries raw payload, not a header. The dispatcher descended into it anyway and **invented ports and sequence numbers** out of arbitrary bytes. A 20-byte chunk of anything parses as a plausible TCP header. |
| 3 | UDP with checksum 0 | Legal on IPv4 — RFC 768 says zero means the sender did not compute one. Flagging it corrupt shows a false error on ordinary traffic. |
| 4 | IPv4 with options (IHL=6) | Variable-length header; the payload does not start at byte 20. |
| 5 | Corrupted IPv4 checksum | The only genuinely bad packet. Must be flagged. |

**`03_mixed_protocols.pcap`** — one packet per decoder: VLAN-tagged IPv4/UDP,
ICMP echo request and reply, ICMP Time Exceeded (what traceroute receives),
IPv6/TCP, IPv6/ICMPv6, and a WireGuard-shaped UDP flow to a Cloudflare WARP
endpoint — which is what OnamVPN's own traffic looks like on the wire.

## Expected output, and what wrong looks like

Selecting the IPv4 checksum on packet 5 of `02_sharp_edges.pcap`:

```
received=0x91CA, computed=0x6ECA        ← flagged, in red
selected: bytes [24:26]  (2 bytes)  =  91 ca
```

Byte 24 is 14 (Ethernet header) + 10 (IPv4 checksum offset). If the highlight
shows a different range, the FieldView invariant has been violated somewhere.

**Wrong results to watch for:**

- Any packet in `01_tcp_handshake.pcap` flagged bad — the padding bug is back.
- Packet 2 of `02_sharp_edges.pcap` showing a TCP layer — the fragment check
  is being skipped.
- A field description containing a literal `{` — an unrendered f-string. One
  shipped: the TCP `data_offset` text said "payload starts at byte {hlen}".

## Verification

The decoders are cross-checked field by field against **Scapy 2.6.1** in
`tests/test_capture.py::TestScapyCrossCheck`. Scapy is a separate
implementation by different authors, so agreement is meaningful evidence.

It is weaker than `tshark` — both are Python, and both could in principle
share a misreading of an RFC. `tshark` is not installed on this machine (the
Wireshark install failed with MSI error 1603; see `CHANGES.md`). If you install
Wireshark, prefer `tshark -V -r docs/samples/01_tcp_handshake.pcap` as the
reference.

Golden decodes in `docs/samples/*.golden.json` catch unintended change, but
only pin the decoders against themselves — a golden file records a wrong answer
just as happily as a right one. The Scapy comparison is the real check.

## Limits

- **Live capture does not work on this machine.** Npcap is present but
  enumerates only `\Device\NPF_Loopback`. The panel says so and falls back to
  pcap replay. The Tunnel Comparison demo (VPN off vs on, watching the
  destination address disappear) needs a physical NIC and cannot run.
- **Ethernet decoding needs Npcap, not raw sockets.** Python's `SOCK_RAW` on
  Windows delivers IP-layer, inbound-only frames with no link-layer header. An
  Ethernet decoder built on it parses garbage.
- **IPv6 extension headers are not decoded.** The fixed 40-byte header is
  parsed and `next_header` is read, but a chain of extension headers is left
  to the caller.
- **No reassembly.** Fragments are identified and handled correctly, but the
  original datagram is never rebuilt.
