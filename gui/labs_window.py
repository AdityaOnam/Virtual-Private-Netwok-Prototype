"""
gui/labs_window.py — the Concept Labs window.

Opened with:  python main.py --labs

Every panel works offline, with no capture driver, no network and no
Administrator rights — anything that needs one of those degrades with an
explanation rather than failing. That is deliberate: the whole point is to be
demonstrable on an arbitrary machine.

    Dissector    Module A   packet decoding, layer by layer
    Network      Modules B, D, E   native tunnel, DNS transports, path
    Transport    Module C   ARQ and congestion control
    Concurrency  Module G   races, deadlock, the GIL
    OS Lab       Modules H, I, J   scheduling, memory, resilience

Panels are imported individually and guarded, so one failing to construct
costs its own tab rather than the whole window.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QLabel,
    QMainWindow,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

#: (import path, class name, tab label, one-line description)
PANELS = [
    ("gui.panels.dissector_panel", "DissectorPanel", "Dissector",
     "Module A — hand-written protocol decoders"),
    ("gui.panels.netlab_panel", "NetLabPanel", "Network",
     "Modules B, D, E — tunnel, DNS, path"),
    ("gui.panels.transport_panel", "TransportPanel", "Transport",
     "Module C — ARQ and congestion control"),
    ("gui.panels.concurrency_panel", "ConcurrencyPanel", "Concurrency",
     "Module G — races, deadlock, the GIL"),
    ("gui.panels.oslab_panel", "OsLabPanel", "OS Lab",
     "Modules H, I, J — scheduling, memory, resilience"),
]


class LabsWindow(QMainWindow):
    """Hosts every CN + OS concept panel as a tab."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("OnamVPN — Concept Labs")
        self.setMinimumSize(1200, 780)
        self.load_errors: list[str] = []
        self._build_ui()

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        header = QLabel("OnamVPN Concept Labs")
        font = QFont()
        font.setPointSize(16)
        font.setBold(True)
        header.setFont(font)
        layout.addWidget(header)

        subtitle = QLabel(
            "Computer Networks and Operating Systems concepts, implemented and "
            "measured. Everything here runs offline — no capture driver, no "
            "network and no Administrator rights required."
        )
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        layout.addWidget(self.tabs, stretch=1)

        for module_path, class_name, label, description in PANELS:
            self._add_panel(module_path, class_name, label, description)

        if self.tabs.count() == 0:
            self.tabs.addTab(self._placeholder(
                "No panels could be loaded.\n\n"
                + "\n".join(self.load_errors)
            ), "Error")

    def _add_panel(self, module_path: str, class_name: str,
                   label: str, description: str) -> None:
        try:
            module = __import__(module_path, fromlist=[class_name])
            panel = getattr(module, class_name)()
            self.tabs.addTab(panel, label)
            self.tabs.setTabToolTip(self.tabs.count() - 1, description)
        except Exception as exc:
            # A panel that will not construct costs its own tab, not the
            # window. The message is kept so the failure is visible rather
            # than the tab silently missing.
            message = f"{label}: {type(exc).__name__}: {exc}"
            self.load_errors.append(message)
            self.tabs.addTab(self._placeholder(
                f"{label} failed to load.\n\n{message}"
            ), f"{label} ⚠")

    @staticmethod
    def _placeholder(text: str) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        label = QLabel(text)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setWordWrap(True)
        layout.addWidget(label)
        return widget
