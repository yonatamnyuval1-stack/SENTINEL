import ctypes
import json
import threading
import time
from ctypes import wintypes
from datetime import datetime,timezone
from pathlib import Path
from event import EVENTS_FILE, log_event
DATA_DIR = Path(__file__).resolve().parent / "data"
BASELINE_FILE = DATA_DIR / "process_baseline.json"
CONFIG_PATH = Path(__file__).resolve().parent / "process.json"
PROCESS_QUERY_LIMITED_INFORMATION =  0x1000
SUSPICIOUS_PATH_PARTS = (
    "\\temp\\",
    "\\tmp\\",
    "\\downloads\\",
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\temp\\",
)

def load_process_config():
    cfg = {
        "warm_up_hours": 48,
        "min_count": 2,
        "alert_on_unknown": True,
        "save_every": 20,
        "correlate_window_seconds": 120
    }
    if not CONFIG_PATH.exists():
        return cfg
    try:
        raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except(OSError, json.JSONDecodeError):
        return cfg
    for key in("warm_up_hours","min_count","save_every", "correlate_window_seconds"):
        if isinstance(raw.get(key), int) and raw[key] >0:
            cfg[key] = raw[key]
    if "alert_on_unknown" in raw:
        cfg["alert_on_unknown"] = bool(raw["alert_on_unknown"])
    return cfg

def _norm_key(path):
    return str(path or "").strip().lower().replace("/","\\")

def load_baseline():
    if not BASELINE_FILE.exists():
        return {
            "started_at": datetime.now(timezone.utc).isoformat(),
            "images": {},
            "pairs": {}, 
        }
    try:
        raw = json.loads(BASELINE_FILE.read_text(encoding="utf-8"))
    except(OSError, json.JSONDecodeError):
        return{
            "started_at": datetime.now(timezone.utc).isformat(),
            "images": {},
            "pairs": {},
        }
    if not isinstance(raw,dict):
        raw = {}
    return {
        "started_at": raw.get("started_at")
        or datetime.now(timezone.utc).isoformat(),
        "images": raw.get("images") if isinstance(raw.get("images"), dict) else{},
        "pairs": raw.get("pairs") if isinstance(raw.get("pairs"), dict) else {},
    }
def save_baseline(data):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    BASELINE_FILE.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
def _in_warm_up(baseline, warm_up_hours):
    try:
        started = datetime.fromisoformat(baseline["started_at"])
    except Exception:
        return True
    age_h = (datetime.now(timezone.utc) - started).total_seconds() / 3600.0
    return age_h < float(warm_up_hours)
def _touch_entry(bucket,key):
    now = datetime.now(timezone.utc).isoformat()
    item = bucket.get(key)
    if not isinstance(item, dict):
        bucket[key] = {"count": 1, "last": now}
        return 1
    item["count"] = int(item.get("count", 0)) + 1
    item["last"] = now
    return int(item["count"])
def _count_of(bucket, key):
    item = bucket.get(key)
    if not isinstance(item, dict):
        return 0
    try:
        return int(item.get("count", 0))
    except Exception:
        return 0
def _event_ts(event):
    raw = event.get("time") or ""
    try:
        return datetime.fromisoformat(raw).timestamp()
    except Exception:
        return 0.0

def recent_related_alerts(window_seconds):
    if not EVENTS_FILE.exists():
        return []
    try:
        lines = EVENTS_FILE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    cutoff = time.time() - float(window_seconds)
    hits = []
    for line in lines[-400:]:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("kind") != "alert":
            continue
        if _event_ts(event) < cutoff:
            continue
        src = str(event.get("source") or "")
        msg = str(event.get("message") or event.get("massage") or "")
        related = False
        tag = ""
        if src == "persistence":
            related = True
            tag = "persistence"
        elif src == "windows_audit" or "Trap" in msg:
            related = True
            tag = "honeyfiles"
        if related:
            hits.append({"tag": tag, "massage": msg, "source": src})
    return hits

def maybe_correlate(pid,ppid, image, parent, process_reasons, window_seconds):
    if not process_reasons:
        return
    hits = recent_related_alerts(window_seconds)
    if not hits:
        return
    tags = []
    for hit in hits:
        if hit["tag"] not in tags:
            tags.append(hit["tag"])
    log_event(
        "alert",
        "Correlated host activity",
        pid=str(pid),
        ppid=str(ppid),
        image=image,
        parent=parent,
        process_reasons=",".join(process_reasons),
        related =",".join(tags),
        window_seconds= int(window_seconds),
        source="correlation",
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
        self.cfg = load_process_config()
        self.baseline = load_baseline()
        self._lock = threading.Lock()
        self._since_save = 0
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
        mode = (
            "warm_up"
            if _in_warm_up(self.baseline, self.cfg["warm_up_hours"])
            else "monitor"
        )
        log_event(
            "system",
            "Process watch started (ETW)",
            mode=mode,
            baseline_images = len(self.baseline.get("images", {})),
            baseline_pairs = len(self.baseline.get("pairs", {})), 
            path = str(BASELINE_FILE),
            )
    def stop(self):
        self._stop.set()
        with self._lock:
            save_baseline(self.baseline)
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
        img_key = _norm_key(full)
        par_key = _norm_key(parent)
        pair_key = par_key + "|" + img_key
        with self._lock:
            warm = _in_warm_up(self.baseline, self.cfg["warm_up_hours"])
            images = self.baseline.setdefault("images", {})
            pairs = self.baseline.setdefault("pairs",{})
            img_before = _count_of(images, img_key) 
            pair_before = _count_of(pairs, pair_key) 
            if warm:
                img_count = _touch_entry(images, img_key) if img_key else 0
                pair_count = _touch_entry(pairs, pair_key) if img_key else 0
            else:
                if img_key and img_before > 0:
                    img_count = _touch_entry(images, img_key)
                else:
                    img_count = img_before
                if img_key and pair_before > 0:
                    pair_count = _touch_entry(pairs, pair_key)
                else:
                    pair_count = pair_before
            self._since_save += 1
            if self._since_save >= self.cfg["save_every"]:
                save_baseline(self.baseline)
                self._since_save = 0
        log_event(
            "system",
            "Process started",
            pid=str(pid),
            ppid=str(ppid),
            image=full,
            parent=parent,
            mode = "warm_up" if warm else "monitor",
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
        if ( not warm and self.cfg["alert_on_unknown"] and img_key):
            min_count = self.cfg["min_count"]
            unknown_bits = []
            if img_before < min_count:
                unknown_bits.append("unknown_image")
            if pair_before < min_count:
                unknown_bits.append("unknown_pair")
            if unknown_bits:
                log_event(
                    "alert",
                    "Process outside baseline",
                    pid = str(pid),
                    ppid = str(ppid),
                    image = full,
                    parent = parent,
                    reasons = ",".join(unknown_bits),
                    image_count = img_before,
                    pair_count = pair_before,
                    source = "process_etw"
                )
        corr_reasons = list(reasons)
        if (not warm) and self.cfg["alert_on_unknown"] and img_key:
            if img_before < self.cfg["min_count"]:
                corr_reasons.append("unknown_image")
            if pair_before < self.cfg["min_count"]:
                corr_reasons.append("unknown_pair")
        maybe_correlate(
            pid,
            ppid,
            full,
            parent,
            corr_reasons,
            self.cfg.get("correlate_window_seconds", 120)
        )