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