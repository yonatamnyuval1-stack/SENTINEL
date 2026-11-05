import ctypes
import os
from event import log_event
from control import load_control
import subprocess
import shutil
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
        maybe_quarantine(image, why=why)
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
def _boring_ip(ip):
    ip = str(ip or "").strip()
    if not ip:
        return True
    if ip in ("127.0.0.1", "::1", "0.0.0.0"):
        return True
    if ip.startswith("10."):
        return True
    if ip.startswith("192.168."):
        return True
    if ip.startswith("169.254."):
        return True
    if ip.startswith("172."):
        bits = ip.split(".")
        if len(bits) > 1:
            try:
                n = int(bits[1])
            except ValueError:
                n = -1
            if 16 <= n <= 31:
                return True
    return False
def maybe_block_ip(remote_ip, remote_port="", why=""):
    """
    drop outbound to this ip if defend is on.
    needs admin sometimes or netsh just shrugs.
    """
    if not armed():
        return False
    ip = str(remote_ip or "").strip()
    if _boring_ip(ip):
        log_event(
            "system",
            "skip block (local/private ip)",
            remote_ip=ip,
            why = str(why or ""),
            source= "defend",
        )
        return False
    rule = "SENTINEL_block_" + ip.replace(":", "_")
    cmd = [
        "netsh",
        "advfirewall",
        "firewall",
        "add",
        "rule",
        "name=" + rule,
        "dir=out",
        "action=block",
        "remoteip=" + ip,
        "enable=yes",
    ]
    try:
        done = subprocess.run (
            cmd,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        log_event(
            "system",
            "block failed",
            remote_ip=ip,
            remote_port=str(remote_port or ""),
            detail=str(exc),
            why=str(why or ""),
            source="defend",
        )
        return False
    if done.returncode != 0:
        err = (done.stderr or done.stdout or "").strip()[:200]
        log_event(
            "system",
            "block failed",
            remote_ip=ip,
            remote_port=str(remote_port or ""),
            detail=err or ("exit " + str(done.returncode)),
            why=str(why or ""),
            source="defend",
        )
        return False
    log_event(
        "alert",
        "blocked outbound ip",
        remote_ip=ip,
        remote_port=str(remote_port or ""),
        rule=rule,
        why=str(why or ""),
        source="defend",
    )
    return True

def _leave_it(path):
    p = str(path or "").lower().replace("/","\\")
    for bit in ("\\windows\\", "\\program files\\", "\\program files (x86)\\"):
        if bit in p:
            return True
    return False

def maybe_quarantine(image, why=""):
    if not armed():
        return False
    src = Path(str(image or "").strip().strip('"'))
    try:
        src = src.resolve()
    except OSError:
        return False
    if not src.is_file():
        return False
    here = Path(__file__).resolve().parent
    if here == src or here in src.parents:
        return False
    if _leave_it(src):
        log_event(
            "system",
            "skip quarantine (system path)",
            image=str(src),
            why=(why or ""),
            source="defend",
        )
        return False
    folder = here / "data" / "quarantine"
    try:
        folder.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        log_event(
            "system",
            "quarantine failed",
            image=str(src),
            detail=str(exc),
            source="defend",
        )
        return False
    from datetime import datetime
    stamp = datetime.now().strftime("%H%M%S")
    dest = folder / (src.stem + "_" + stamp + src.suffix)
    try:
        shutil.move(str(src), str(dest))
    except OSError as exc:
        log_event(
            "system",
            "quarantine failed",
            image = str(src),
            detail = str(exc),
            why = str(why or ""),
            source="defend",
        )
        return False
    log_event(
        "alert",
        "quarantined file",
        image=str(src),
        detail=str(dest),
        why=(why or ""),
        source="defend",
    )
    return True