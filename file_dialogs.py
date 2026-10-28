"""Native file dialogs for choosing where messages are saved and loaded.

Plyer 2.1.0's Linux (zenity) backend is incompatible with zenity 4.x:

* it maps ``title`` to ``--name``, which zenity 4.x removed (``--title`` is
  the correct flag), so the dialog fails to open; and
* it always appends ``--confirm-overwrite``, which is deprecated and does
  nothing, but prints a warning on every open.

On Linux this module therefore drives ``zenity`` (or ``kdialog``) directly
with the correct flags.  On Windows and macOS it defers to plyer's native
implementations.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Any, List, Optional, Sequence

#: A filter is either a bare glob string or ``[name, *glob_patterns]``.
Filter = Sequence[Any]


class DialogError(Exception):
    """Raised when no usable native file dialog backend is available."""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def save_file(*, path: str, filters: Sequence[Filter], title: str) -> Optional[str]:
    """Show the native "save as" dialog; return the path or ``None`` if cancelled."""

    if sys.platform.startswith("linux"):
        return _linux("save", path, filters, title)
    return _plyer("save", path, filters, title)


def open_file(*, path: str, filters: Sequence[Filter], title: str) -> Optional[str]:
    """Show the native "open" dialog; return the path or ``None`` if cancelled."""

    if sys.platform.startswith("linux"):
        return _linux("open", path, filters, title)
    return _plyer("open", path, filters, title)


# ---------------------------------------------------------------------------
# Linux backends (zenity / kdialog)
# ---------------------------------------------------------------------------


def _linux(kind: str, path: str, filters: Sequence[Filter], title: str) -> Optional[str]:
    if shutil.which("zenity"):
        return _zenity(kind, path, filters, title)
    if shutil.which("kdialog"):
        return _kdialog(kind, path, filters, title)
    raise DialogError(
        "No file dialog backend found. Please install 'zenity' or 'kdialog'."
    )


def _zenity(kind: str, path: str, filters: Sequence[Filter], title: str) -> Optional[str]:
    cmd = _zenity_cmd(kind, path, filters, title)
    cmd[0] = shutil.which("zenity")  # type: ignore[list-item]
    return _run_subprocess(cmd)


def _zenity_cmd(kind: str, path: str, filters: Sequence[Filter], title: str) -> List[str]:
    cmd = ["zenity", "--file-selection", "--title", title]
    if kind == "save":
        cmd.append("--save")
    if path:
        cmd += ["--filename", path]
    for item in filters:
        if isinstance(item, str):
            cmd += ["--file-filter", item]
        else:
            name, *patterns = item
            cmd += ["--file-filter", f"{name} | {' '.join(patterns)}"]
    return cmd


def _kdialog(kind: str, path: str, filters: Sequence[Filter], title: str) -> Optional[str]:
    exe = shutil.which("kdialog")
    patterns = _patterns_string(filters)
    default = path or os.path.expanduser("~")
    if kind == "save":
        cmd = [exe, "--getsavefilename", default, patterns]
    else:
        cmd = [exe, "--getopenfilename", default, patterns]
    cmd += ["--title", title]
    return _run_subprocess(cmd)


def _patterns_string(filters: Sequence[Filter]) -> str:
    parts: List[str] = []
    for item in filters:
        if isinstance(item, str):
            parts.append(item)
        else:
            parts.extend(item[1:])
    return " ".join(parts)


def _run_subprocess(cmd: List[str]) -> Optional[str]:
    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
    except OSError as exc:
        raise DialogError(f"Could not run the file dialog ({cmd[0]}): {exc}") from exc

    if proc.returncode == 0:
        return proc.stdout.decode("utf-8", "replace").strip() or None
    # Return code 1 means the user cancelled the dialog.
    if proc.returncode == 1:
        return None
    raise DialogError(f"The file dialog ({cmd[0]}) failed with code {proc.returncode}.")


# ---------------------------------------------------------------------------
# Non-Linux backend (plyer)
# ---------------------------------------------------------------------------


def _plyer(kind: str, path: str, filters: Sequence[Filter], title: str) -> Optional[str]:
    from plyer import filechooser

    function = filechooser.save_file if kind == "save" else filechooser.open_file
    selection = function(title=title, path=path, filters=filters)
    if not selection:
        return None
    if isinstance(selection, str):
        return selection or None
    return selection[0] or None
