"""
gui/panels/concurrency_panel.py — Module G: races, deadlock, and the GIL.

Four demonstrations, each a button that runs real threads:

    Race          the same counter with and without a mutex, ten runs each
    Deadlock      two threads, two locks, opposite order — plus the fix
    GIL           CPU-bound vs I/O-bound scaling, measured
    Ring          bounded buffer with producer and consumer blocking

Everything runs on a worker thread and reports back by signal. Nothing here
touches a widget from a non-GUI thread, which would be a race of its own — and
a particularly embarrassing one in this panel.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from oslab.concurrency.deadlock import (
    run_deadlock_demo,
    run_ordered_demo,
    run_timeout_recovery_demo,
)
from oslab.concurrency.pool import compare_workload_scaling
from oslab.concurrency.ring import BoundedRing, SharedCounter


class DemoWorker(QThread):
    """Runs one demonstration off the GUI thread."""

    output = Signal(str)
    failed = Signal(str)

    def __init__(self, job) -> None:
        super().__init__()
        self.job = job

    def run(self) -> None:
        try:
            self.output.emit(self.job())
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class ConcurrencyPanel(QWidget):
    """Race conditions, deadlock and the GIL, demonstrated on real threads."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._worker: DemoWorker | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        root = QHBoxLayout(self)

        controls = QWidget()
        controls.setMaximumWidth(340)
        layout = QVBoxLayout(controls)

        race_box = QGroupBox("Race condition")
        race_layout = QVBoxLayout(race_box)
        race_layout.addWidget(QLabel(
            "Eight threads each increment a shared counter. Without a mutex "
            "the read-compute-write sequence interleaves and updates are lost."
        ))
        row = QHBoxLayout()
        row.addWidget(QLabel("Increments per thread:"))
        self.increments = QSpinBox()
        self.increments.setRange(1000, 500_000)
        self.increments.setValue(50_000)
        self.increments.setSingleStep(10_000)
        row.addWidget(self.increments)
        race_layout.addLayout(row)
        button = QPushButton("Run 10 unsafe + 10 safe")
        button.clicked.connect(self._run_race)
        race_layout.addWidget(button)
        layout.addWidget(race_box)

        deadlock_box = QGroupBox("Deadlock")
        deadlock_layout = QVBoxLayout(deadlock_box)
        deadlock_layout.addWidget(QLabel(
            "Two threads take two locks in opposite order, detect the cycle in "
            "the wait-for graph, then run the two standard fixes."
        ))
        button = QPushButton("Deadlock, detect, then fix")
        button.clicked.connect(self._run_deadlock)
        deadlock_layout.addWidget(button)
        layout.addWidget(deadlock_box)

        gil_box = QGroupBox("The GIL")
        gil_layout = QVBoxLayout(gil_box)
        gil_layout.addWidget(QLabel(
            "Scale the same pool over CPU-bound and I/O-bound work. Only one "
            "of them speeds up, and that is why thread_count helps the latency "
            "scan but would not help encryption."
        ))
        button = QPushButton("Measure scaling")
        button.clicked.connect(self._run_gil)
        gil_layout.addWidget(button)
        layout.addWidget(gil_box)

        ring_box = QGroupBox("Bounded buffer")
        ring_layout = QVBoxLayout(ring_box)
        ring_layout.addWidget(QLabel(
            "Producers and consumers sharing a fixed-capacity ring, blocking "
            "on a condition variable when full or empty."
        ))
        button = QPushButton("Run producer/consumer")
        button.clicked.connect(self._run_ring)
        ring_layout.addWidget(button)
        layout.addWidget(ring_box)

        self.status = QLabel("Ready.")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        layout.addStretch(1)
        root.addWidget(controls)

        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        from PySide6.QtGui import QFont
        mono = QFont("Consolas")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self.output.setFont(mono)
        root.addWidget(self.output, stretch=1)

    # ── dispatch ─────────────────────────────────────────────────────────────

    def _start(self, job, label: str) -> None:
        if self._worker is not None and self._worker.isRunning():
            return
        self.status.setText(f"Running {label}…")
        self.output.setPlainText(f"Running {label}…")
        self._worker = DemoWorker(job)
        self._worker.output.connect(self._show)
        self._worker.failed.connect(self._show)
        self._worker.finished.connect(lambda: self.status.setText("Ready."))
        self._worker.start()

    def _show(self, text: str) -> None:
        self.output.setPlainText(text)

    # ── demonstrations ───────────────────────────────────────────────────────

    def _run_race(self) -> None:
        per_thread = self.increments.value()

        def job() -> str:
            lines = [
                f"Eight threads, {per_thread:,} increments each "
                f"→ {8 * per_thread:,} expected.",
                "",
                "WITHOUT a mutex:",
            ]
            broken = 0
            for index in range(10):
                result = SharedCounter(safe=False).run_contended(8, per_thread)
                if not result["correct"]:
                    broken += 1
                lines.append(
                    f"  run {index}: actual {result['actual']:>10,}  "
                    f"lost {result['lost']:>10,}"
                    + ("" if result["correct"] else "   ← updates lost")
                )
            lines += ["", f"  {broken}/10 runs lost updates.", "", "WITH a mutex:"]
            exact = 0
            for index in range(10):
                result = SharedCounter(safe=True).run_contended(8, per_thread)
                exact += result["correct"]
                lines.append(
                    f"  run {index}: actual {result['actual']:>10,}  "
                    f"lost {result['lost']:>10,}"
                )
            lines += [
                "", f"  {exact}/10 runs exact.",
                "",
                "At CPython's default 5 ms switch interval the same broken code",
                "usually produces the right answer — the bug is constant, the",
                "exposure is not. That is why races survive testing and appear",
                "under production load.",
            ]
            default = SharedCounter(safe=False).run_contended(
                8, per_thread, switch_interval=None
            )
            lines.append(
                f"  at the default interval: lost {default['lost']:,}"
            )
            return "\n".join(lines)

        self._start(job, "race demo")

    def _run_deadlock(self) -> None:
        def job() -> str:
            lines = ["Two threads, two locks, opposite acquisition order.", ""]
            result = run_deadlock_demo()
            lines += [
                f"  deadlocked      : {result.deadlocked}",
                f"  wait-for cycle  : {' → '.join(result.cycle)} → "
                f"{result.cycle[0] if result.cycle else ''}",
                f"  holds           : {result.graph['holds']}",
                f"  waits for       : {result.graph['waits']}",
                f"  threads finished: {result.completed or 'none'}",
                "",
                "All four Coffman conditions hold at once: mutual exclusion,",
                "hold-and-wait, no preemption, and circular wait. Break any one",
                "and the deadlock cannot occur.",
                "",
                "FIX 1 — consistent lock ordering (breaks circular wait):",
            ]
            ordered = run_ordered_demo()
            lines += [
                f"  deadlocked      : {ordered.deadlocked}",
                f"  threads finished: {sorted(ordered.completed)}",
                f"  order           : {ordered.order}",
                "",
                "FIX 2 — timeout and back off (breaks hold-and-wait):",
            ]
            recovery = run_timeout_recovery_demo()
            lines += [
                f"  deadlocked      : {recovery.deadlocked}",
                f"  backed off      : {recovery.recovered}",
                f"  threads finished: {sorted(recovery.completed)}",
                f"  elapsed         : {recovery.elapsed:.2f}s",
                "",
                "Ordering is preferred: it costs nothing and cannot livelock.",
                "Timeout recovery wastes the work already done and can livelock",
                "if both threads keep backing off together, which is why the",
                "retry delay is randomised.",
            ]
            return "\n".join(lines)

        self._start(job, "deadlock demo")

    def _run_gil(self) -> None:
        def job() -> str:
            result = compare_workload_scaling(count=16, worker_counts=(1, 2, 4, 8))
            lines = ["Same pool, same task count, two kinds of work.", ""]
            for kind, title in (("cpu_bound", "CPU-bound (pure Python arithmetic)"),
                                ("io_bound", "I/O-bound (blocking sleep)")):
                data = result[kind]
                lines.append(title)
                lines.append(f"  {'workers':>8} {'time':>9} {'speedup':>9} "
                             f"{'amdahl':>9}")
                for workers in (1, 2, 4, 8):
                    lines.append(
                        f"  {workers:>8} {data['times'][workers]:>8.3f}s "
                        f"{data['speedups'][workers]:>8.2f}x "
                        f"{data['predicted'][workers]:>8.2f}x"
                    )
                lines.append("")
            lines += [
                f"At 8 workers: CPU-bound "
                f"{result['verdict']['cpu_speedup_at_max_workers']}x, "
                f"I/O-bound {result['verdict']['io_speedup_at_max_workers']}x.",
                "",
                "Python bytecode needs the GIL, so CPU-bound threads take turns",
                "and adding more only adds context switches. A thread blocked in",
                "a socket or a sleep has released the GIL, so I/O-bound work",
                "scales nearly linearly. Threads help exactly when work waits.",
                "",
                "This is measured, not predicted — the Amdahl column is the",
                "theory, the speedup column is the stopwatch.",
            ]
            return "\n".join(lines)

        self._start(job, "GIL measurement")

    def _run_ring(self) -> None:
        def job() -> str:
            import threading

            ring = BoundedRing(capacity=16)
            total = 4000
            consumed: list[int] = []
            lock = threading.Lock()
            counter = iter(range(total))
            counter_lock = threading.Lock()

            def produce() -> None:
                while True:
                    with counter_lock:
                        item = next(counter, None)
                    if item is None:
                        return
                    ring.put(item)

            def consume() -> None:
                while True:
                    item = ring.get(timeout=0.5)
                    if item is None:
                        return
                    with lock:
                        consumed.append(item)

            producers = [threading.Thread(target=produce) for _ in range(3)]
            consumers = [threading.Thread(target=consume) for _ in range(3)]
            for thread in producers + consumers:
                thread.start()
            for thread in producers:
                thread.join(timeout=30)
            for thread in consumers:
                thread.join(timeout=30)

            stats = ring.stats.as_dict()
            return "\n".join([
                f"3 producers, 3 consumers, capacity {ring.capacity}, "
                f"{total:,} items.",
                "",
                f"  items produced        : {stats['puts']:,}",
                f"  items consumed        : {len(consumed):,}",
                f"  unique items          : {len(set(consumed)):,}",
                f"  lost or duplicated    : {total - len(set(consumed)):,}",
                "",
                f"  producer blocked (full) : {stats['producer_blocks']} times, "
                f"{stats['producer_blocked_ms']} ms",
                f"  consumer blocked (empty): {stats['consumer_blocks']} times, "
                f"{stats['consumer_blocked_ms']} ms",
                "",
                "Blocking is the point. A full buffer stops the producer rather",
                "than dropping data, and an empty one parks the consumer instead",
                "of spinning. The condition variable lets the OS scheduler skip",
                "a waiting thread entirely rather than waking it to find nothing.",
            ])

        self._start(job, "bounded buffer")
