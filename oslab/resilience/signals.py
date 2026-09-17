"""
oslab.resilience.signals — make sure teardown actually runs.

The problem this solves
───────────────────────
OnamVPN's kill switch installs firewall rules that block all traffic outside
the tunnel. If the process dies without removing them, the machine has no
internet and no obvious explanation — the VPN app is gone, but its rules are
not. Teardown running reliably is therefore not housekeeping; it is the
difference between a demo and a bricked laptop.

Two things make this harder than it looks.

1. Ctrl+C under a Qt event loop
   Python signal handlers only run between bytecodes of the *interpreter*.
   While Qt is blocked inside its C++ event loop, no Python executes, so a
   SIGINT is recorded and then sits there — sometimes until the next UI event,
   sometimes forever. The fix is a QTimer that fires a few times a second and
   does nothing: each firing returns control to Python briefly, which is
   enough for a pending handler to run. `install_qt_nudge` sets that up.

2. Windows console control events
   Closing the console window or logging off sends CTRL_CLOSE_EVENT, which is
   not a signal and does not reach Python's signal module at all. It has to be
   caught with SetConsoleCtrlHandler. Windows also gives roughly five seconds
   after CTRL_CLOSE_EVENT before killing the process, so teardown must be
   quick — which is why handlers are ordered and individually guarded.

What cannot be caught
─────────────────────
SIGKILL, TerminateProcess, and power loss. Nothing runs. Anything that must
survive those needs to be recoverable at *startup* instead, which is what the
journal below is for: record the intent before acting, clear it after, and on
the next launch clean up whatever is still recorded.
"""

from __future__ import annotations

import atexit
import json
import logging
import platform
import signal
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

logger = logging.getLogger(__name__)

IS_WINDOWS = platform.system().lower() == "windows"


@dataclass
class TeardownHandler:
    name: str
    action: Callable[[], None]
    critical: bool = False


class TeardownRegistry:
    """
    Ordered teardown actions, each individually guarded.

    One handler raising must not prevent the rest from running — the firewall
    rules have to come off even if, say, closing a socket failed first. Each
    is wrapped, and failures are recorded rather than propagated.
    """

    def __init__(self) -> None:
        self._handlers: list[TeardownHandler] = []
        self._lock = threading.Lock()
        self._ran = False
        self.results: list[dict] = []

    def register(self, name: str, action: Callable[[], None],
                 critical: bool = False) -> None:
        """
        Add a teardown action.

        Handlers run in reverse registration order, like a stack: the last
        thing set up is the first thing torn down.
        """
        with self._lock:
            self._handlers.append(TeardownHandler(name, action, critical))

    def run(self, reason: str = "") -> list[dict]:
        """Run every handler once, in reverse order.  Never raises."""
        with self._lock:
            if self._ran:
                return self.results
            self._ran = True
            handlers = list(reversed(self._handlers))

        logger.info("running teardown (%s): %d handler(s)", reason, len(handlers))
        for handler in handlers:
            try:
                handler.action()
                self.results.append({"name": handler.name, "ok": True})
            except Exception as exc:
                logger.exception("teardown handler %r failed", handler.name)
                self.results.append({
                    "name": handler.name, "ok": False,
                    "error": f"{type(exc).__name__}: {exc}",
                    "critical": handler.critical,
                })
        return self.results

    def reset(self) -> None:
        """Forget every handler — used by tests."""
        with self._lock:
            self._handlers.clear()
            self.results.clear()
            self._ran = False

    def __len__(self) -> int:
        return len(self._handlers)


registry = TeardownRegistry()


def install_handlers(on_signal: Callable[[str], None] | None = None,
                     use_registry: bool = True) -> list[str]:
    """
    Install signal, console and atexit handlers.

    Returns the names of everything successfully installed, so a caller can
    report honestly which paths are covered rather than assuming all of them.
    """
    installed: list[str] = []

    def handle(source: str) -> None:
        if on_signal is not None:
            try:
                on_signal(source)
            except Exception:
                logger.exception("signal callback failed")
        if use_registry:
            registry.run(reason=source)

    for signal_name in ("SIGINT", "SIGTERM", "SIGBREAK", "SIGHUP"):
        sig = getattr(signal, signal_name, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, lambda s, f, n=signal_name: (handle(n),
                                                            sys.exit(0)))
            installed.append(signal_name)
        except (ValueError, OSError):
            # ValueError: not on the main thread. This is worth knowing about
            # rather than silently skipping — a handler installed nowhere is
            # indistinguishable from one that never fires.
            logger.debug("could not install %s handler", signal_name)

    if IS_WINDOWS:
        if _install_console_handler(handle):
            installed.append("CONSOLE_CTRL")

    atexit.register(lambda: registry.run(reason="atexit") if use_registry else None)
    installed.append("atexit")
    return installed


def _install_console_handler(handle: Callable[[str], None]) -> bool:
    """
    Catch Windows console control events, which are not signals.

    CTRL_CLOSE_EVENT (closing the window), CTRL_LOGOFF_EVENT and
    CTRL_SHUTDOWN_EVENT never reach Python's signal module. Windows allows
    about five seconds of cleanup after CTRL_CLOSE_EVENT before killing the
    process outright.
    """
    try:
        import ctypes
        from ctypes import wintypes

        names = {
            0: "CTRL_C_EVENT",
            1: "CTRL_BREAK_EVENT",
            2: "CTRL_CLOSE_EVENT",
            5: "CTRL_LOGOFF_EVENT",
            6: "CTRL_SHUTDOWN_EVENT",
        }

        handler_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)

        def console_handler(event: int) -> bool:
            handle(names.get(event, f"CONSOLE_{event}"))
            return True

        callback = handler_type(console_handler)
        # Keep a reference: if this is collected, Windows calls freed memory.
        _console_handler_refs.append(callback)
        return bool(ctypes.windll.kernel32.SetConsoleCtrlHandler(callback, True))
    except Exception:
        logger.debug("could not install console control handler", exc_info=True)
        return False


_console_handler_refs: list = []


def install_qt_nudge(interval_ms: int = 200):
    """
    Give the interpreter a chance to run pending signal handlers under Qt.

    Returns the QTimer, which the caller must keep a reference to — a timer
    that is garbage collected stops firing, and the symptom is Ctrl+C silently
    not working again.
    """
    try:
        from PySide6.QtCore import QTimer
    except ImportError:
        return None

    timer = QTimer()
    timer.timeout.connect(lambda: None)   # the point is returning to Python
    timer.start(interval_ms)
    return timer


# ─────────────────────────────────────────────────────────────────────────────
# Crash-recovery journal
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Journal:
    """
    Records intent before acting, so a crash is recoverable at next startup.

        journal.begin("killswitch", {"rule": "OnamVPN-Block-All"})
        ...apply the firewall rule...
        journal.complete("killswitch")

    A crash between begin and complete leaves the entry on disk. The next
    launch calls `pending()` and removes whatever is still recorded. This is
    the only defence against SIGKILL and power loss, because no handler runs
    in those cases.

    Written through atomic_write_json, so the journal itself cannot be the
    thing that gets corrupted by the crash it exists to survive.
    """

    path: Path
    entries: dict = field(default_factory=dict)

    @classmethod
    def open(cls, path: str | Path = "config/recovery.json") -> "Journal":
        path = Path(path)
        entries: dict = {}
        if path.exists():
            try:
                entries = json.loads(path.read_text(encoding="utf-8")) or {}
            except (OSError, json.JSONDecodeError):
                entries = {}
        return cls(path=path, entries=entries)

    def _flush(self) -> None:
        from .atomicio import atomic_write_json
        self.path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(self.path, self.entries)

    def begin(self, key: str, detail: dict | None = None) -> None:
        self.entries[key] = {"state": "pending", "detail": detail or {}}
        self._flush()

    def complete(self, key: str) -> None:
        self.entries.pop(key, None)
        self._flush()

    def pending(self) -> dict:
        """Entries left behind by a previous run that never completed."""
        return {k: v for k, v in self.entries.items()
                if v.get("state") == "pending"}

    def clear(self) -> None:
        self.entries.clear()
        self._flush()
