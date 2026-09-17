"""
oslab.resilience.atomicio — atomic file I/O utilities.

Provides
--------
atomic_write_json(path, obj)
    Serialise *obj* to JSON and write it atomically to *path*.

    Algorithm:
      1. Serialise obj → UTF-8 JSON bytes (with indent=2 for readability).
      2. Write to a unique temporary sibling file: <path>.<pid>.<rand>.tmp
      3. flush() + os.fsync() that file, so its bytes are on the storage
         device before anything points at them.
      4. Call os.replace(<tmp>, path) — atomic on POSIX and on Windows
         (MoveFileEx with MOVEFILE_REPLACE_EXISTING): a reader sees either
         the old content or the new, never a partial write.

    If an exception is raised at any step, the temp file is cleaned up and
    the original path is left untouched.

    Why the temp name is unique (not a fixed "<path>.tmp"): two processes
    saving the same config concurrently would otherwise share one temp file
    and clobber each other's partial writes.  Phase 8 / Module J adds a
    cross-process lock; until then, a unique name keeps the two writers from
    corrupting one another.

    Durability vs atomicity — these are different guarantees:
      - *Atomicity* (no torn file) comes from os.replace alone.
      - *Durability* (survives power loss) needs the fsync in step 3.
        Without it the rename can reach disk while the data is still in the
        page cache, yielding an atomically-renamed empty or stale file.

    This replaces the direct open(settings.json, 'w') calls in the GUI so that
    a crash or KeyboardInterrupt during a settings save can never leave a
    truncated or empty settings.json.

Concepts demonstrated (Module J — Resilience)
----------------------------------------------
  - Crash consistency via write-temp-then-rename
  - Atomic file replacement (POSIX rename(2) / Windows MoveFileEx)
  - Safe teardown in the presence of concurrent shutdown signals
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def atomic_write_json(path: str | Path, obj: Any, indent: int = 2) -> None:
    """
    Serialise *obj* to JSON and atomically replace *path*.

    Parameters
    ----------
    path : str | Path
        Destination file.  Its parent directory must already exist.
    obj : Any
        JSON-serialisable object (dict, list, …).
    indent : int, optional
        JSON indentation (default 2 spaces).

    Raises
    ------
    TypeError
        If *obj* is not JSON-serialisable.
    OSError
        If the temporary write or the rename fails.

    Notes
    -----
    On Windows, os.replace() maps to MoveFileEx(MOVEFILE_REPLACE_EXISTING),
    which is atomic: a reader opening *path* always sees either the old or the
    new content, never a half-written file.

    That covers atomicity but NOT durability.  The fsync() below is what makes
    the new bytes survive a power loss — without it the rename can be recorded
    while the data is still only in the page cache.  On POSIX, full durability
    would additionally require fsync'ing the *parent directory*; that is done
    here on a best-effort basis and is a no-op on Windows, which has no
    directory file descriptor to sync.
    """
    path = Path(path)
    # Unique per-writer temp name — see module docstring.
    tmp_path = path.with_name(f"{path.name}.{os.getpid()}.{os.urandom(4).hex()}.tmp")

    try:
        payload = json.dumps(obj, indent=indent, ensure_ascii=False)

        # Write + flush + fsync before the rename, so the replace can never
        # publish a file whose contents have not reached the device.
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())

        os.replace(tmp_path, path)

        # Best-effort parent-directory sync (POSIX only; Windows cannot open a
        # directory as a file descriptor and raises, which we ignore).
        try:
            dir_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except (OSError, AttributeError):
            pass

    except Exception:
        # Clean up the temporary file if anything went wrong so we do not
        # leave stale .tmp files lying around.
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
