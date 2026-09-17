"""
oslab.resilience.singleton — one instance at a time, enforced across processes.

Why the VPN needs this
──────────────────────
Two copies of OnamVPN both managing the same WireGuard tunnel and the same
firewall rules is a real failure: one instance tears down rules the other just
installed, and the kill switch ends up either permanently on (no internet) or
permanently off (no protection). The tunnel is a single shared resource and
needs a single owner.

Why a threading.Lock cannot do this
────────────────────────────────────
A mutex lives inside one process's address space. A second process gets its own
copy and sees nothing. Mutual exclusion *between* processes has to go through
something both can see, which means the kernel — and the portable way to ask
the kernel is a lock on a file.

    Windows   msvcrt.locking(fd, LK_NBLCK, ...)
    POSIX     fcntl.flock(fd, LOCK_EX | LOCK_NB)

Both are advisory locks held by the file *descriptor*, which is the property
that matters here: when a process dies — even killed with SIGKILL or
TerminateProcess, with no chance to clean up — the OS closes its descriptors,
and the lock is released automatically.

Why not a PID file
──────────────────
The obvious approach is to write the PID to a file and check whether that
process is alive. It has two holes that a descriptor lock does not:

  - A crash leaves the file behind, so the next start refuses to run and the
    user has to delete a stale file by hand.
  - PIDs are recycled. The PID in the file may belong to something else
    entirely, and now the check says "already running" about an unrelated
    process.

The file here still records the PID, but only as human-readable diagnostics.
The lock is what enforces exclusion.
"""

from __future__ import annotations

import os
import platform
import sys
from pathlib import Path

IS_WINDOWS = platform.system().lower() == "windows"

#: Byte offset the Windows lock is taken at. Well past any diagnostics text,
#: so the readable part of the file stays readable — see acquire().
_LOCK_OFFSET = 4096

if IS_WINDOWS:
    import msvcrt
else:
    import fcntl


class AlreadyRunning(RuntimeError):
    """Raised when another process already holds the instance lock."""


class SingleInstance:
    """
    Cross-process mutual exclusion via an advisory file lock.

        with SingleInstance("onamvpn"):
            ...      # only one process reaches here at a time

    Non-blocking: acquiring either succeeds immediately or raises, because a
    VPN client that silently waits for another copy to exit is worse than one
    that says what is wrong.
    """

    def __init__(self, name: str = "onamvpn",
                 directory: str | Path | None = None) -> None:
        self.name = name
        base = Path(directory) if directory else Path(
            os.environ.get("TEMP") or os.environ.get("TMPDIR") or "/tmp"
        )
        base.mkdir(parents=True, exist_ok=True)
        self.lock_path = base / f"{name}.lock"
        self._handle = None
        self.acquired = False

    # ── acquire / release ────────────────────────────────────────────────────

    def acquire(self) -> None:
        """Take the lock, or raise AlreadyRunning."""
        if self.acquired:
            return

        # Opened r+ if it exists so an existing lock file is reused rather
        # than truncated — truncating would destroy the other instance's
        # diagnostics while it is still running.
        mode = "r+" if self.lock_path.exists() else "w+"
        self._handle = open(self.lock_path, mode, encoding="utf-8")

        try:
            if IS_WINDOWS:
                # Lock a byte far past the diagnostics, not byte 0.
                #
                # msvcrt.locking locks from the current file position, and a
                # Windows lock is mandatory rather than advisory: locking
                # byte 0 makes the PID text unreadable to every other handle,
                # including holder_info() in this same process. Parking the
                # lock at a high offset keeps the readable region readable
                # while still giving one byte for the kernel to arbitrate.
                self._handle.seek(_LOCK_OFFSET)
                msvcrt.locking(self._handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(self._handle.fileno(),
                            fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self._handle.close()
            self._handle = None
            raise AlreadyRunning(
                f"another OnamVPN instance already holds {self.lock_path}. "
                "Two instances would fight over the tunnel and the firewall "
                "rules."
            ) from exc

        # Diagnostics only — the lock, not this content, provides exclusion.
        self._handle.seek(0)
        self._handle.truncate()
        self._handle.write(f"pid={os.getpid()}\nexe={sys.executable}\n")
        self._handle.flush()
        self.acquired = True

    def release(self) -> None:
        """Release the lock.  Safe to call more than once."""
        if not self.acquired or self._handle is None:
            return
        try:
            if IS_WINDOWS:
                self._handle.seek(_LOCK_OFFSET)
                msvcrt.locking(self._handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass          # the OS releases it on close regardless
        finally:
            try:
                self._handle.close()
            except OSError:
                pass
            self._handle = None
            self.acquired = False

    # ── query ────────────────────────────────────────────────────────────────

    def holder_info(self) -> dict:
        """Read the diagnostics the current holder wrote, if any."""
        if not self.lock_path.exists():
            return {}
        try:
            text = self.lock_path.read_text(encoding="utf-8")
        except OSError:
            return {}
        info: dict = {}
        for line in text.splitlines():
            key, _, value = line.partition("=")
            if key:
                info[key.strip()] = value.strip()
        return info

    @staticmethod
    def is_available(name: str = "onamvpn",
                     directory: str | Path | None = None) -> bool:
        """Test whether the lock could be taken, without keeping it."""
        probe = SingleInstance(name, directory)
        try:
            probe.acquire()
        except AlreadyRunning:
            return False
        probe.release()
        return True

    # ── context manager ──────────────────────────────────────────────────────

    def __enter__(self) -> "SingleInstance":
        self.acquire()
        return self

    def __exit__(self, *exc) -> None:
        self.release()

    def __repr__(self) -> str:
        state = "held" if self.acquired else "free"
        return f"SingleInstance({self.name!r}, {state}, {self.lock_path})"
