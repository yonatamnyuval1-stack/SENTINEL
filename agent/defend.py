import ctypes
import os
from event import log_event
from control import load_control
PROCESS_TERMINATE = 0x0001
# don't touch these plz
_SKIP_NAMES = (
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "smss.exe",
    "system",
)
def armed():
    cfg = load_control()
    return bool(cfg.get("defend", False))

def _safe_image(image):
    name = (image or "").replace("/","\\").lower().split("\\")[-1]
    if not name:
        return True
    return name not in _SKIP_NAMES

def maybe_kill(pid, image="", why=""):
    """
    only run if defend is on in control.json
    alert already happened before this is called
    """
    if not armed():
        return False
    try:
        pid_i = int(pid)
    except (TypeError, ValueError):
        return False
    if pid_i <= 4:
        return False
    if pid_i == os.getpid():
        return False
    if not _safe_image(image):
        log_event(
            "system",
            "skip kill (protected image)",
            pid=str(pid_i),
            image=str(image or ""),
            why=str(why or ""),
            source="defend",
        )
        return False
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid_i)
    if not handle:
        log_event(
            "system",
            "kill failed (open)",
            pid=str(pid_i),
            image=str(image or ""),
            why=str(why or ""),
            source="defend",
        )
        return False
    ok = False
    try:
        ok = bool(kernel32.TerminateProcess(handle, 1))
    finally:
        kernel32.CloseHandle(handle)
    if ok:
        log_event(
            "alert",
            "killed process",
            pid = str(pid_i),
            image = str(image or ""),
            why = str(why or ""),
            source = "defend",
        )
    else:
        log_event(
            "system",
            "kill failed(terminate)",
            pid = str(pid_i),
            image = str(image or ""),
            why = str(why or ""),
            source = "defend",
        )
    return ok

import winreg
from pathlib import Path

def maybe_revert_persistence(entry, value="", why="new"):
    """
    yank a new run/startup thing if defend is on.
    skips scheduled tasks for now, those are messy.
    """
    if not armed():
        return False
    entry = str(entry or "")
    if not entry:
        return False
    if entry.startswith("task:"):
        log_event(
            "system",
            "skip revert(task)",
            entry=entry,
            why = str(why or ""),
            source="defend",
        )
        return False
    ok = False
    detail = ""
    if entry.startswith("startup:"):
        path = Path(entry[len("startup:"):])
        try:
            if path.exists() and path.is_file():
                path.unlink()
                ok = True
                detail = "deleted file"
            else:
                detail = "file gone already"
        except OSError as exc:
            detail = str(exc)
    elif entry.startswith("run:") or entry.startswith("runonce:"):
        if entry.startswith("runonce:"):
            body = entry[len("runonce:") :]
            kind = "runonce"
        else:
            body = entry[len("run:") :]
            kind = "run"
        cut = body.rfind(":")
        if cut <= 0:
            log_event(
                "system",
                "revert failed(bad entry)",
                entry=entry,
                source="defend",
            )
            return False
        reg_path = body[:cut]
        name = body[cut + 1 :]
        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            try:
                key = winreg.OpenKey(
                    hive,
                    reg_path,
                    0,
                    winreg.KEY_SET_VALUE | winreg.KEY_READ,
                )
            except OSError:
                continue
            try:
                winreg.DeleteValue(key, name)
                ok = True
                detail = "deleted " + kind + " value"
                break
            except OSError as exc:
                detail = str(exc)
            finally:
                winreg.CloseKey(key)
    else:
        log_event(
            "system",
            "skip revert (unknown kind)",
            entry=entry,
            source="defend",
        )
        return False
    if ok:
        log_event(
            "alert",
            "reverted persistence",
            entry=entry,
            value=str(value or ""),
            detail=detail,
            why=str(why or ""),
            source="defend",
        )
    else:
        log_event(
            "system",
            "revert failed",
            entry=entry,
            value=str(value or ""),
            detail=detail,
            why=str(why or ""),
            source="defend",
        )
    return ok