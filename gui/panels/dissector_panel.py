"""
gui/panels/dissector_panel.py — Module A: the packet dissector panel.

Layout
──────
    ┌──────────────────────────── source bar ────────────────────────────┐
    ├───────────────────────┬────────────────────────────────────────────┤
    │  packet list          │  layer tree (Ethernet → IP → TCP → …)      │
    │  (one row per frame)  ├────────────────────────────────────────────┤
    │                       │  hex dump, selected field highlighted      │
    └───────────────────────┴────────────────────────────────────────────┘

Selecting a packet fills the layer tree; selecting a field highlights exactly
the bytes that field occupies in the hex dump, using FieldView.byte_offset and
FieldView.byte_length.  Those two are guaranteed consistent with the field's
bit span by the FieldView invariant, so the highlight cannot drift from the
decoded value.

Offline by default
──────────────────
The panel opens on a committed .pcap from docs/samples/ and needs no capture
driver, no admin rights and no network.  Live capture appears only when a
backend is present; when it is not, the reason is shown in the status line
rather than raising (plan trap §7.1).
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPlainTextEdit,
    QSplitter,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from netlab.dissect.capture import PcapFileCapture, live_capture_available
from netlab.dissect.model import DecodedPacket, FieldView

SAMPLES_DIR = Path(__file__).resolve().parents[2] / "docs" / "samples"

# Role used to stash the FieldView on a tree item without showing it.
_FIELD_ROLE = Qt.ItemDataRole.UserRole + 1

_BAD_COLOUR = QColor("#c0392b")
_HIGHLIGHT_BG = QColor("#ffe08a")


class DissectorPanel(QWidget):
    """Live/offline packet dissector with a byte-accurate hex view."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._packets: list[DecodedPacket] = []
        self._build_ui()
        self._populate_sources()

    # ── UI construction ──────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(8)

        # Source bar
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Capture:"))
        self.source_combo = QComboBox()
        self.source_combo.setMinimumWidth(280)
        self.source_combo.currentIndexChanged.connect(self._on_source_changed)
        bar.addWidget(self.source_combo)
        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        bar.addWidget(self.status_label, stretch=1)
        root.addLayout(bar)

        # Split: packet list | (layer tree over hex dump)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        self.packet_tree = QTreeWidget()
        self.packet_tree.setHeaderLabels(["#", "Time", "Protocols", "Len", "Summary"])
        self.packet_tree.setRootIsDecorated(False)
        self.packet_tree.setAlternatingRowColors(True)
        self.packet_tree.currentItemChanged.connect(self._on_packet_selected)
        header = self.packet_tree.header()
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        splitter.addWidget(self.packet_tree)

        right = QSplitter(Qt.Orientation.Vertical)

        self.layer_tree = QTreeWidget()
        self.layer_tree.setHeaderLabels(["Field", "Value", "Bits"])
        self.layer_tree.currentItemChanged.connect(self._on_field_selected)
        right.addWidget(self.layer_tree)

        self.hex_view = QPlainTextEdit()
        self.hex_view.setReadOnly(True)
        mono = QFont("Consolas")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        mono.setPointSize(10)
        self.hex_view.setFont(mono)
        right.addWidget(self.hex_view)
        right.setSizes([420, 280])

        splitter.addWidget(right)
        splitter.setSizes([460, 700])
        root.addWidget(splitter, stretch=1)

        self.detail_label = QLabel("Select a field to see what it means.")
        self.detail_label.setWordWrap(True)
        self.detail_label.setMinimumHeight(48)
        self.detail_label.setAlignment(
            Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft
        )
        root.addWidget(self.detail_label)

    def _populate_sources(self) -> None:
        """List the committed sample captures, then report live availability."""
        self.source_combo.blockSignals(True)
        for pcap in sorted(SAMPLES_DIR.glob("*.pcap")):
            self.source_combo.addItem(f"[file] {pcap.name}", str(pcap))
        self.source_combo.blockSignals(False)

        available, reason = live_capture_available()
        if available:
            self.status_label.setText(f"Live capture: {reason}")
        else:
            self.status_label.setText(f"Offline only — {reason}")

        if self.source_combo.count():
            self._on_source_changed(0)

    # ── Loading ──────────────────────────────────────────────────────────────

    def _on_source_changed(self, index: int) -> None:
        path = self.source_combo.itemData(index)
        if not path:
            return
        try:
            capture = PcapFileCapture(path)
            self._packets = list(capture.packets())
        except (OSError, ValueError) as exc:
            self._packets = []
            self.status_label.setText(f"Could not read capture: {exc}")
            return
        self._fill_packet_list()

    def _fill_packet_list(self) -> None:
        self.packet_tree.clear()
        first = self._packets[0].timestamp if self._packets else 0.0
        for i, packet in enumerate(self._packets):
            protocols = "/".join(layer.name for layer in packet.layers) or "—"
            item = QTreeWidgetItem([
                str(i),
                f"{packet.timestamp - first:.6f}",
                protocols,
                str(len(packet.raw_frame)),
                packet.summary(),
            ])
            if any(f.is_bad for layer in packet.layers for f in layer.fields.values()):
                for column in range(item.columnCount()):
                    item.setForeground(column, _BAD_COLOUR)
            self.packet_tree.addTopLevelItem(item)

        for column in range(4):
            self.packet_tree.resizeColumnToContents(column)
        if self._packets:
            self.packet_tree.setCurrentItem(self.packet_tree.topLevelItem(0))

    # ── Selection ────────────────────────────────────────────────────────────

    def _current_packet(self) -> DecodedPacket | None:
        item = self.packet_tree.currentItem()
        if item is None:
            return None
        index = self.packet_tree.indexOfTopLevelItem(item)
        if 0 <= index < len(self._packets):
            return self._packets[index]
        return None

    def _on_packet_selected(self, *_args) -> None:
        packet = self._current_packet()
        self.layer_tree.clear()
        if packet is None:
            self.hex_view.setPlainText("")
            return

        for layer in packet.layers:
            layer_item = QTreeWidgetItem([
                layer.name,
                f"{len(layer.raw_bytes)} bytes",
                "",
            ])
            font = layer_item.font(0)
            font.setBold(True)
            layer_item.setFont(0, font)

            for name, field in layer.fields.items():
                value = field.value
                text = value if isinstance(value, str) else repr(value)
                child = QTreeWidgetItem([
                    name,
                    text if len(text) <= 60 else text[:57] + "…",
                    f"{field.bit_offset}+{field.bit_length}",
                ])
                child.setData(0, _FIELD_ROLE, field)
                if field.is_bad:
                    for column in range(child.columnCount()):
                        child.setForeground(column, _BAD_COLOUR)
                    child.setText(1, f"{text}  ✗ expected {field.computed_value}")
                layer_item.addChild(child)

            self.layer_tree.addTopLevelItem(layer_item)
            layer_item.setExpanded(True)

        self.layer_tree.resizeColumnToContents(0)
        self._render_hex(packet)

    def _on_field_selected(self, *_args) -> None:
        packet = self._current_packet()
        item = self.layer_tree.currentItem()
        if packet is None or item is None:
            return
        field = item.data(0, _FIELD_ROLE)
        if not isinstance(field, FieldView):
            self.detail_label.setText("Select a field to see what it means.")
            self._render_hex(packet)
            return

        self.detail_label.setText(field.description)
        layer_start = self._layer_start_offset(packet, item)
        self._render_hex(
            packet,
            highlight=(layer_start + field.byte_offset, field.byte_length),
        )

    def _layer_start_offset(self, packet: DecodedPacket, field_item: QTreeWidgetItem) -> int:
        """
        Byte offset of the selected field's layer within the whole frame.

        FieldView.bit_offset is relative to its layer, so the hex highlight has
        to add back the offsets of every preceding layer.
        """
        parent = field_item.parent()
        if parent is None:
            return 0
        index = self.layer_tree.indexOfTopLevelItem(parent)
        return sum(layer.payload_offset for layer in packet.layers[:index])

    # ── Hex dump ─────────────────────────────────────────────────────────────

    def _render_hex(self, packet: DecodedPacket,
                    highlight: tuple[int, int] | None = None) -> None:
        """
        Render the frame as a classic offset / hex / ASCII dump.

        *highlight* is (byte_offset, byte_length); those bytes are wrapped in
        brackets and the block is marked, so the selected field is visible
        without relying on rich-text selection.
        """
        data = packet.raw_frame
        lo, hi = (-1, -1)
        if highlight:
            lo = highlight[0]
            hi = lo + highlight[1]

        lines: list[str] = []
        for base in range(0, len(data), 16):
            chunk = data[base: base + 16]
            hex_parts: list[str] = []
            for i, byte in enumerate(chunk):
                absolute = base + i
                marker = "·" if lo <= absolute < hi else " "
                hex_parts.append(f"{byte:02x}{marker}")
                if i == 7:
                    hex_parts.append(" ")
            ascii_part = "".join(
                chr(b) if 32 <= b < 127 else "." for b in chunk
            )
            lines.append(f"{base:04x}  {''.join(hex_parts):<52} |{ascii_part}|")

        if highlight:
            lines.append("")
            lines.append(
                f"selected: bytes [{lo}:{hi}]  "
                f"({highlight[1]} byte{'s' if highlight[1] != 1 else ''}, "
                f"marked with ·)  =  {data[lo:hi].hex(' ')}"
            )

        self.hex_view.setPlainText("\n".join(lines))
