"""
gui/panels/transport_panel.py — Module C: ARQ and congestion control.

Left: the knobs. Right: what they did.

    cwnd / ssthresh vs time    the AIMD sawtooth, with events annotated
    sequence vs time           the ladder diagram; retransmissions in red
    summary                    goodput, efficiency, and which limit is binding

Everything runs on a virtual clock with a seeded PRNG, so the same settings
always produce the same picture. That matters for a demo: a graph that changes
between runs cannot be explained.

Plots use pyqtgraph when it is installed and fall back to a text rendering when
it is not, so the panel is never simply blank.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from netlab.transport.harness import TransferConfig, compare_protocols, run_transfer

try:
    import pyqtgraph as pg
    HAVE_PYQTGRAPH = True
except ImportError:
    pg = None
    HAVE_PYQTGRAPH = False


class TransferWorker(QThread):
    """
    Runs the simulation off the GUI thread.

    A 400-segment lossy transfer takes a noticeable fraction of a second, and
    blocking the event loop for that long makes the window visibly freeze.
    Results come back by signal — never by touching a widget from here.
    """

    finished_ok = Signal(object)
    failed = Signal(str)

    def __init__(self, config: TransferConfig, compare: bool = False) -> None:
        super().__init__()
        self.config = config
        self.compare = compare

    def run(self) -> None:
        try:
            if self.compare:
                self.finished_ok.emit(compare_protocols(
                    segments=self.config.segments,
                    window=self.config.window,
                    loss=self.config.loss,
                    delay_ms=self.config.delay_ms,
                    jitter_ms=self.config.jitter_ms,
                    bandwidth_bps=self.config.bandwidth_bps,
                    seed=self.config.seed,
                ))
            else:
                self.finished_ok.emit(run_transfer(self.config))
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class TransportPanel(QWidget):
    """Interactive ARQ + congestion-control laboratory."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._worker: TransferWorker | None = None
        self._result = None
        self._build_ui()

    # ── UI ───────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QHBoxLayout(self)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        splitter.addWidget(self._controls())
        splitter.addWidget(self._output())
        splitter.setSizes([320, 900])
        root.addWidget(splitter)

    def _controls(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)

        protocol_box = QGroupBox("Protocol")
        protocol_form = QFormLayout(protocol_box)
        self.protocol = QComboBox()
        self.protocol.addItems(["go-back-n", "selective-repeat", "stop-and-wait"])
        protocol_form.addRow("ARQ:", self.protocol)
        self.window = QSpinBox()
        self.window.setRange(1, 256)
        self.window.setValue(32)
        protocol_form.addRow("Window (segments):", self.window)
        self.segments = QSpinBox()
        self.segments.setRange(10, 2000)
        self.segments.setValue(300)
        protocol_form.addRow("Segments to send:", self.segments)
        self.congestion = QCheckBox("Congestion control (Reno)")
        self.congestion.setChecked(True)
        protocol_form.addRow(self.congestion)
        layout.addWidget(protocol_box)

        link_box = QGroupBox("Link")
        link_form = QFormLayout(link_box)
        self.loss = QDoubleSpinBox()
        self.loss.setRange(0.0, 0.9)
        self.loss.setSingleStep(0.01)
        self.loss.setValue(0.02)
        link_form.addRow("Loss probability:", self.loss)
        self.delay = QDoubleSpinBox()
        self.delay.setRange(0.0, 500.0)
        self.delay.setValue(25.0)
        link_form.addRow("One-way delay (ms):", self.delay)
        self.jitter = QDoubleSpinBox()
        self.jitter.setRange(0.0, 200.0)
        self.jitter.setValue(0.0)
        link_form.addRow("Jitter (ms):", self.jitter)
        self.bandwidth = QSpinBox()
        self.bandwidth.setRange(0, 1_000_000)
        self.bandwidth.setValue(8000)
        self.bandwidth.setSuffix(" kbit/s  (0 = unlimited)")
        link_form.addRow("Bandwidth:", self.bandwidth)
        self.seed = QSpinBox()
        self.seed.setRange(0, 99999)
        self.seed.setValue(5)
        link_form.addRow("Random seed:", self.seed)
        layout.addWidget(link_box)

        self.run_button = QPushButton("Run transfer")
        self.run_button.clicked.connect(lambda: self._run(compare=False))
        layout.addWidget(self.run_button)

        self.compare_button = QPushButton("Compare all three protocols")
        self.compare_button.clicked.connect(lambda: self._run(compare=True))
        layout.addWidget(self.compare_button)

        self.status = QLabel("Ready.")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        layout.addStretch(1)
        return panel

    def _output(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)

        if HAVE_PYQTGRAPH:
            pg.setConfigOptions(antialias=True)
            self.cwnd_plot = pg.PlotWidget(title="Congestion window vs time")
            self.cwnd_plot.setLabel("left", "segments")
            self.cwnd_plot.setLabel("bottom", "time (s)")
            self.cwnd_plot.addLegend()
            layout.addWidget(self.cwnd_plot, stretch=2)

            self.seq_plot = pg.PlotWidget(title="Sequence number vs time")
            self.seq_plot.setLabel("left", "sequence")
            self.seq_plot.setLabel("bottom", "time (s)")
            layout.addWidget(self.seq_plot, stretch=2)
        else:
            self.cwnd_plot = None
            self.seq_plot = None
            note = QLabel("pyqtgraph is not installed — showing text output only.")
            note.setWordWrap(True)
            layout.addWidget(note)

        self.summary = QPlainTextEdit()
        self.summary.setReadOnly(True)
        layout.addWidget(self.summary, stretch=1)
        return panel

    # ── running ──────────────────────────────────────────────────────────────

    def _config(self) -> TransferConfig:
        bandwidth = self.bandwidth.value()
        return TransferConfig(
            protocol=self.protocol.currentText(),
            segments=self.segments.value(),
            window=self.window.value(),
            loss=self.loss.value(),
            delay_ms=self.delay.value(),
            jitter_ms=self.jitter.value(),
            bandwidth_bps=(bandwidth * 1000) if bandwidth else None,
            congestion_control=self.congestion.isChecked(),
            seed=self.seed.value(),
        )

    def _run(self, compare: bool) -> None:
        if self._worker is not None and self._worker.isRunning():
            return
        self.run_button.setEnabled(False)
        self.compare_button.setEnabled(False)
        self.status.setText("Running…")

        self._worker = TransferWorker(self._config(), compare=compare)
        self._worker.finished_ok.connect(
            self._show_comparison if compare else self._show_result
        )
        self._worker.failed.connect(self._show_error)
        self._worker.finished.connect(self._reenable)
        self._worker.start()

    def _reenable(self) -> None:
        self.run_button.setEnabled(True)
        self.compare_button.setEnabled(True)

    def _show_error(self, message: str) -> None:
        self.status.setText(message)
        self.summary.setPlainText(message)

    # ── rendering ────────────────────────────────────────────────────────────

    def _show_result(self, result) -> None:
        self._result = result
        summary = result.summary()

        lines = [
            f"{summary['protocol']}   seed {result.config.seed}",
            "",
            f"  delivered intact : {summary['delivered_ok']}",
            f"  elapsed          : {summary['elapsed_s']} s",
            f"  segments sent    : {summary['segments_sent']}",
            f"  retransmitted    : {summary['retransmitted']}",
            f"  efficiency       : {summary['efficiency']:.1%}",
            f"  timeouts         : {summary['timeouts']}",
            f"  fast retransmits : {summary['fast_retransmits']}",
            f"  goodput          : {summary['goodput_bps'] / 1000:.1f} kbit/s",
            "",
            f"  bottleneck: {summary['bottleneck']}",
        ]

        if result.congestion_events:
            lines += ["", "Congestion events:"]
            for event in result.congestion_events[:14]:
                lines.append(
                    f"  t={event.t:6.3f}  {event.kind:20} "
                    f"cwnd={event.cwnd / 1460:5.1f}  {event.note}"
                )
        self.summary.setPlainText("\n".join(lines))
        self.status.setText(
            f"Done — {summary['segments_sent']} sent, "
            f"{summary['retransmitted']} retransmitted."
        )
        self._plot(result)

    def _plot(self, result) -> None:
        if not HAVE_PYQTGRAPH:
            return

        self.cwnd_plot.clear()
        acks = [p for p in result.trace if p["event"] == "ack"]
        if acks:
            times = [p["t"] for p in acks]
            self.cwnd_plot.plot(
                times, [p["cwnd_segments"] for p in acks],
                pen=pg.mkPen("#2d7ff9", width=2), name="cwnd",
            )
            ssthresh = [p["ssthresh_segments"] for p in acks]
            if any(value is not None for value in ssthresh):
                self.cwnd_plot.plot(
                    times, [v if v is not None else 0 for v in ssthresh],
                    pen=pg.mkPen("#e67e22", width=1, style=Qt.PenStyle.DashLine),
                    name="ssthresh",
                )

        for event in result.congestion_events:
            colour = "#c0392b" if event.kind == "timeout" else "#27ae60"
            self.cwnd_plot.addItem(
                pg.InfiniteLine(pos=event.t, angle=90,
                                pen=pg.mkPen(colour, width=1,
                                             style=Qt.PenStyle.DotLine))
            )

        self.seq_plot.clear()
        sends = [p for p in result.trace if p["event"] == "send"]
        retransmits = [p for p in result.trace if p["event"] == "retransmit"]
        if sends:
            self.seq_plot.plot(
                [p["t"] for p in sends], [p["seq"] for p in sends],
                pen=None, symbol="o", symbolSize=3,
                symbolBrush="#2d7ff9", name="sent",
            )
        if retransmits:
            self.seq_plot.plot(
                [p["t"] for p in retransmits], [p["seq"] for p in retransmits],
                pen=None, symbol="x", symbolSize=7,
                symbolBrush="#c0392b", name="retransmitted",
            )

    def _show_comparison(self, results: dict) -> None:
        lines = ["Same link, same seed, three protocols:", ""]
        lines.append(f"  {'protocol':18} {'time':>8} {'sent':>6} "
                     f"{'rtx':>6} {'eff':>7}")
        for name, result in results.items():
            summary = result.summary()
            lines.append(
                f"  {name:18} {summary['elapsed_s']:8.3f} "
                f"{summary['segments_sent']:6} {summary['retransmitted']:6} "
                f"{summary['efficiency']:7.1%}"
            )
        lines += [
            "",
            "Go-Back-N resends the whole window after a loss; Selective Repeat",
            "resends only what was lost, so it retransmits less at the cost of",
            "a receiver that must buffer out-of-order segments.",
            "Stop-and-Wait sends one segment per round trip regardless of how",
            "fast the link is — which is why windowing exists at all.",
        ]
        self.summary.setPlainText("\n".join(lines))
        self.status.setText("Comparison complete.")

        if HAVE_PYQTGRAPH:
            self.cwnd_plot.clear()
            colours = {"go-back-n": "#2d7ff9", "selective-repeat": "#27ae60",
                       "stop-and-wait": "#e67e22"}
            for name, result in results.items():
                acks = [p for p in result.trace if p["event"] == "ack"]
                if acks:
                    self.cwnd_plot.plot(
                        [p["t"] for p in acks],
                        [p["cwnd_segments"] for p in acks],
                        pen=pg.mkPen(colours.get(name, "#888"), width=2),
                        name=name,
                    )
