import ctypes
import threading
from ctypes import wintypes
from pathlib import Path
from event import log_event
PROCESS_QUERY_LIMITED_INFORMATION =  0x1000
SUSPICIOUS_PATH_PARTS = (
    "\\temp\\",
    "\\tmp\\",
    "\\downloads\\",
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\temp\\",
)
try:
    from etw import ETW, ProviderInfo
    from etw.GUID import GUID
except ImportError:
    ETW = None
    ProviderInfo = None
    GUID = None
KERNEL_PROCESS_GUID = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"
PROCESS_START_ID = 1
def _field(event_id, name, default=""):
    try:
        return event_id[name]
    except Exception:
        return default
def _query_image(pid):
    try:
        pid_i = int(pid)
    except( TypeError, ValueError):
        return ""
    if pid_i <=0:
        return ""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION, False, pid_i
    )
    if not handle:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(32768)
        ok = kernel32.QueryFullProcessImageNameW(
            handle, 0, buf, ctypes.byref(size)
        )
        if ok:
            return buf.value
    finally:
        kernel32.CloseHandle(handle)
    return ""
def _normalize_image(raw):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors = "replace")
    text = str(raw or "").strip()
    if not text:
        return ""
    text = text.replace("\\Device\\HarddiskVolume", "vol")
    return text
def _suspicious_reasons(image_path, parent_path):
    reasons = []
    low = image_path.lower().replace("/","\\")
    if not low:
        return reasons
    for part in SUSPICIOUS_PATH_PARTS:
        if part in low:
            reasons.append("suspicious_path")
            break
    name = Path(low).name
    parent_low = parent_path.lower().replace("/","\\")
    parent_name = Path(parent_low).name if parent_low else ""
    if parent_name in ("wscript.exe","cscript.exe","mshta.exe","cmd.exe","powershell.exe","pwsh.exe"):
        if "\\users\\" in low and (
            "\\temp\\" in low
            or "\\downloads\\" in low
            or "\\appdata\\" in low
        ):
            reasons.append("script_parent_user_path")
    if name.endswith(".exe") and "\\downloads\\" in low:
        reasons.append("exe_from_downloads")
    out = []
    for r in reasons:
        if r not in out:
            out.append(r)
    return out
class ProcessWatch:
    def __init__(self):
        self._etw = None
        self._thread = None
        self._stop = threading.Event()
        self._seen = set()

    def setup(self):
        if ETW is None:
            log_event(
                "system",
                "Process watch unavailable: pywintrace not installed",
            )
            return
        self._stop.clear()
        provider = ProviderInfo(
            "Microsoft-Windows-Kernel-Process",
            GUID(KERNEL_PROCESS_GUID),
        )
        self._etw = ETW(
            providers=[provider],
            event_callback=self._on_event,
        )
        self._thread = threading.Thread(
            target=self._run, name="process-watch", daemon=True
        )
        self._thread.start()
        log_event("system", "Process watch started (ETW)")

    def stop(self):
        self._stop.set()
        if self._etw is not None:
            try:
                self._etw.stop()
            except Exception:
                pass
            self._etw = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def _run(self):
        try:
            self._etw.start()
        except Exception as exc:
            log_event(
                "system",
                "Process watch failed (need Administrator for ETW)",
                error=str(exc),
            )

    def _on_event(self, event_data):
        if self._stop.is_set():
            return
        try:
            eid = int(event_data[1])
        except Exception:
            return
        if eid != PROCESS_START_ID:
            return
        fields = event_data[0] if event_data else {}
        pid = _field(fields, "ProcessID", _field(fields, "ProcessId", ""))
        ppid = _field(
            fields,
            "ParentProcessID",
            _field(fields, "ParentProcessId", ""),
        )
        image = _field(
            fields,
            "ImageName",
            _field(fields, "ImageFileName", ""),
        )
        image = _normalize_image(image)
        full = _query_image(pid) or image
        parent = _query_image(ppid) or ""

        key = f"{pid}|{ppid}|{full}"
        if key in self._seen:
            return
        self._seen.add(key)
        if len(self._seen) > 5000:
            self._seen = set(list(self._seen)[-2000:])
        reasons = _suspicious_reasons(full, parent)
        log_event(
            "system",
            "Process started",
            pid=str(pid),
            ppid=str(ppid),
            image=full,
            parent=parent,
            source="process_etw",
        )
        if reasons:
            log_event(
                "alert",
                "Suspicious process start",
                pid=str(pid),
                ppid=str(ppid),
                image=full,
                parent=parent,
                reasons=",".join(reasons),
                source="process_etw",
            )