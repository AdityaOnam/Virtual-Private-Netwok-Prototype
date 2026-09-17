"""
gui/panels/oslab_panel.py — Modules H, I, J: scheduling, memory, resilience.

Three smaller demonstrations sharing one tab, because each is a single
measurement rather than an interactive laboratory:

    Scheduler   FCFS / SJF / RR / Priority over the same job set, with a text
                Gantt chart and the waiting/turnaround/response table
    Memory      pooled vs naive allocation, and memoryview vs slicing
    Resilience  the single-instance lock and the crash-recovery journal
"""

from __future__ import annotations

from PySide6.QtCore import QThread, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QDoubleSpinBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from oslab.memory.bufferpool import (
    compare_allocation_strategies,
    demonstrate_zero_copy,
)
from oslab.resilience.signals import Journal, TeardownRegistry
from oslab.resilience.singleton import AlreadyRunning, SingleInstance
from oslab.scheduling.algorithms import Job, compare_algorithms


class _Worker(QThread):
    output = Signal(str)

    def __init__(self, job) -> None:
        super().__init__()
        self.job = job

    def run(self) -> None:
        try:
            self.output.emit(self.job())
        except Exception as exc:
            self.output.emit(f"{type(exc).__name__}: {exc}")


class OsLabPanel(QWidget):
    """Scheduling, memory management and crash resilience."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._worker: _Worker | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        root = QHBoxLayout(self)

        controls = QWidget()
        controls.setMaximumWidth(340)
        layout = QVBoxLayout(controls)

        scheduler_box = QGroupBox("CPU scheduling")
        scheduler_form = QFormLayout(scheduler_box)
        scheduler_form.addRow(QLabel(
            "Four algorithms over the same job set — durations taken from "
            "real server probes."
        ))
        self.quantum = QDoubleSpinBox()
        self.quantum.setRange(0.005, 1.0)
        self.quantum.setSingleStep(0.01)
        self.quantum.setValue(0.05)
        self.quantum.setSuffix(" s")
        scheduler_form.addRow("RR quantum:", self.quantum)
        button = QPushButton("Compare schedulers")
        button.clicked.connect(self._run_scheduler)
        scheduler_form.addRow(button)
        layout.addWidget(scheduler_box)

        memory_box = QGroupBox("Memory")
        memory_layout = QVBoxLayout(memory_box)
        memory_layout.addWidget(QLabel(
            "Slab pool vs an allocation per packet, and memoryview vs slicing."
        ))
        button = QPushButton("Measure allocation and copying")
        button.clicked.connect(self._run_memory)
        memory_layout.addWidget(button)
        layout.addWidget(memory_box)

        resilience_box = QGroupBox("Resilience")
        resilience_layout = QVBoxLayout(resilience_box)
        resilience_layout.addWidget(QLabel(
            "Cross-process locking and the journal that survives a kill."
        ))
        button = QPushButton("Demonstrate lock and journal")
        button.clicked.connect(self._run_resilience)
        resilience_layout.addWidget(button)
        layout.addWidget(resilience_box)

        layout.addStretch(1)
        root.addWidget(controls)

        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        mono = QFont("Consolas")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self.output.setFont(mono)
        root.addWidget(self.output, stretch=1)

    def _start(self, job) -> None:
        if self._worker is not None and self._worker.isRunning():
            return
        self.output.setPlainText("Running…")
        self._worker = _Worker(job)
        self._worker.output.connect(self.output.setPlainText)
        self._worker.start()

    # ── demonstrations ───────────────────────────────────────────────────────

    def _run_scheduler(self) -> None:
        quantum = self.quantum.value()

        def job() -> str:
            jobs = [
                Job(0, "frankfurt", 0.30),
                Job(1, "mumbai", 0.05),
                Job(2, "newyork", 0.20),
                Job(3, "warp", 0.08),
            ]
            comparison = compare_algorithms(jobs, quantum=quantum)
            lines = [
                "Four jobs, durations measured from real server probes:",
                "  frankfurt 0.30s   mumbai 0.05s   newyork 0.20s   warp 0.08s",
                "",
                f"  {'algorithm':14} {'waiting':>9} {'turnaround':>11} "
                f"{'response':>9} {'switches':>9}",
            ]
            for metrics in comparison["metrics"].values():
                lines.append(
                    f"  {metrics['algorithm']:14} {metrics['avg_waiting']:>9.3f} "
                    f"{metrics['avg_turnaround']:>11.3f} "
                    f"{metrics['avg_response']:>9.3f} "
                    f"{metrics['context_switches']:>9}"
                )
            lines += [
                "",
                f"  best average waiting  : {comparison['best_avg_waiting']}",
                f"  best average response : {comparison['best_avg_response']}",
                "",
            ]
            for result in comparison["results"].values():
                lines.append(result.gantt(52))
                lines.append("")
            lines += [
                "SJF is provably optimal for average waiting time, and equally",
                "impossible to implement honestly — it needs each job's duration",
                "before running it. Here the durations were measured first,",
                "which is the cheat that makes the comparison possible.",
                "",
                "Round Robin loses on turnaround and wins on response time. That",
                "is the trade every interactive scheduler makes: users notice",
                "the wait before anything happens, not the total.",
                "",
                "FCFS shows the convoy effect — one long job at the front delays",
                "everything behind it.",
            ]
            return "\n".join(lines)

        self._start(job)

    def _run_memory(self) -> None:
        def job() -> str:
            allocation = compare_allocation_strategies(packets=20_000)
            zero_copy = demonstrate_zero_copy()
            return "\n".join([
                f"Allocating {allocation['packets']:,} packet buffers:",
                "",
                f"  naive (one bytearray each)",
                f"    peak memory : {allocation['naive']['peak_bytes']:,} B",
                f"    elapsed     : {allocation['naive']['seconds']}s",
                "",
                f"  pooled (slab allocator, {allocation['pooled']['capacity']} blocks)",
                f"    peak memory : {allocation['pooled']['peak_bytes']:,} B",
                f"    elapsed     : {allocation['pooled']['seconds']}s",
                f"    reuse rate  : {allocation['pooled']['reuse_rate']:.1%}",
                f"    fresh allocations: {allocation['pooled']['fresh_allocations']}",
                f"    internal fragmentation: "
                f"{allocation['pooled']['internal_fragmentation']:.1%}",
                "",
                f"  peak memory ratio: {allocation['peak_ratio']}x",
                "",
                "The pool allocates its blocks once and reuses them forever, so",
                "the steady-state allocation count is zero and the collector has",
                "nothing to walk. The cost is internal fragmentation: a 64-byte",
                "ACK still occupies a whole block.",
                "",
                "─" * 60,
                "",
                f"Peeling {zero_copy['layers']} headers off a packet, "
                f"{zero_copy['iterations']:,} times:",
                "",
                f"  slicing bytes   : {zero_copy['slicing_seconds']}s, "
                f"{zero_copy['bytes_copied_by_slicing']:,} bytes copied",
                f"  memoryview      : {zero_copy['memoryview_seconds']}s, "
                f"{zero_copy['bytes_copied_by_memoryview']} bytes copied",
                f"  speedup         : {zero_copy['speedup']}x",
                "",
                "Slicing bytes copies the remainder every time, so a four-layer",
                "dissector copies the payload four times. A memoryview is a",
                "window onto the same memory — which is why the dissector in",
                "netlab.dissect passes offsets around instead of re-slicing.",
            ])

        self._start(job)

    def _run_resilience(self) -> None:
        def job() -> str:
            import os
            import tempfile

            directory = tempfile.mkdtemp(prefix="onamvpn-demo-")
            lines = ["Cross-process single-instance lock:", ""]

            first = SingleInstance("demo", directory)
            first.acquire()
            lines.append(f"  first instance acquired : {first.acquired}")
            lines.append(f"  lock file               : {first.lock_path.name}")
            lines.append(f"  recorded pid            : "
                         f"{first.holder_info().get('pid')} "
                         f"(this process is {os.getpid()})")

            try:
                SingleInstance("demo", directory).acquire()
                lines.append("  second instance         : ACQUIRED — this is a bug")
            except AlreadyRunning:
                lines.append("  second instance         : refused, as it should be")

            first.release()
            lines.append(f"  after release, available: "
                         f"{SingleInstance.is_available('demo', directory)}")
            lines += [
                "",
                "A threading.Lock cannot do this — it lives inside one process's",
                "address space and a second process never sees it. The file lock",
                "is held by the descriptor, so the OS releases it even when the",
                "process is killed outright with no chance to clean up.",
                "",
                "─" * 60,
                "",
                "Teardown ordering:",
                "",
            ]

            registry = TeardownRegistry()
            done: list[str] = []
            registry.register("socket", lambda: done.append("socket"))
            registry.register("broken",
                              lambda: (_ for _ in ()).throw(RuntimeError("boom")))
            registry.register("firewall", lambda: done.append("firewall"))
            results = registry.run("demo")
            for entry in results:
                state = "ok" if entry["ok"] else f"FAILED ({entry.get('error')})"
                lines.append(f"  {entry['name']:10} {state}")
            lines += [
                "",
                "  Handlers run in reverse registration order, and one failing",
                "  does not stop the rest. The firewall rules must come off even",
                "  if an earlier step threw — a teardown that aborts halfway is",
                "  how a machine ends up with no internet and no explanation.",
                "",
                "─" * 60,
                "",
                "Crash-recovery journal:",
                "",
            ]

            journal_path = os.path.join(directory, "recovery.json")
            journal = Journal.open(journal_path)
            journal.begin("killswitch", {"rule": "OnamVPN-Killswitch-Block-All"})
            lines.append("  wrote intent, then simulated a crash (no teardown ran)")

            recovered = Journal.open(journal_path)
            lines.append(f"  next startup finds      : {list(recovered.pending())}")
            lines.append(f"  detail                  : "
                         f"{recovered.pending().get('killswitch', {}).get('detail')}")
            recovered.complete("killswitch")
            lines.append(f"  after cleanup           : "
                         f"{list(Journal.open(journal_path).pending())}")
            lines += [
                "",
                "  Nothing runs on SIGKILL or power loss, so the only defence is",
                "  to record the intent before acting and clean up at the next",
                "  launch. The journal is written atomically, so the crash cannot",
                "  corrupt the thing meant to survive it.",
            ]
            return "\n".join(lines)

        self._start(job)
