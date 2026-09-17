#!/usr/bin/env python3
"""
docs/samples/make_goldens.py — regenerate golden decode files.

    python docs/samples/make_goldens.py

Writes <name>.golden.json next to each sample .pcap.  tests/test_capture.py
asserts the decoders still reproduce them byte for byte, so an unintended
change to any decoder shows up as a diff rather than silently altering what
the panel displays.

A golden file only pins behaviour against *itself*.  The independent check —
diffing against Scapy, a separate implementation — lives in
tests/test_capture.py::TestScapyCrossCheck.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from netlab.dissect.capture import PcapFileCapture  # noqa: E402

SAMPLES_DIR = Path(__file__).resolve().parent


def golden_for(pcap: Path) -> dict:
    cap = PcapFileCapture(pcap)
    return {
        "source": pcap.name,
        "link_type": cap.info.link_type,
        "snaplen": cap.info.snaplen,
        "packets": [p.to_dict() for p in cap.packets()],
    }


def main() -> int:
    for pcap in sorted(SAMPLES_DIR.glob("*.pcap")):
        out = pcap.with_suffix(".golden.json")
        out.write_text(
            json.dumps(golden_for(pcap), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"  wrote {out.name:32} ({out.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
