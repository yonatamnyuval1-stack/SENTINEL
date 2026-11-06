import json
import threading
from pathlib import Path
from event import log_event
DATA_DIR = Path(__file__).resolve().parent / "data"
BASELINE_FILE = DATA_DIR / "files_baseline.json"
CONFIG_PATH = Path(__file__).resolve().parent / "files.json"

def load_config():
    cfg = {
        "poll_seconds": 15,
        "paths": [
            r"C:\Windows\System32\drivers\etc\hosts",
        ]
    }
    if not CONFIG_PATH.exists():
        return cfg
    try:
        raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except(OSError, json.JSONDecodeError):
        return cfg
    if isinstance(raw.get("poll_seconds"), int) and raw["poll_seconds"] > 0:
        cfg["poll_seconds"] = raw["poll_seconds"]
    paths = raw.get("paths")
    if isinstance(paths, list) and paths:
        cfg["paths"] = [str(p) for p in paths if str(p).strip()]
    return cfg

def _stamp(path):
    p = Path(path)
    try:
        if not p.exists():
            return "missing"
        st = p.stat()
        return str(st.st_size) + "|" + str(st.st_mtime_ns)
    except OSError:
        return "unreadable"
def load_baseline():
    if not BASELINE_FILE.exists():
        return None
    try:
        raw = json.loads(BASELINE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(raw, dict):
        return None
    return raw
def save_baseline(data):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    BASELINE_FILE.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

def snapshot(paths):
    out = {}
    for path in paths:
        out[str(path)] = _stamp(path)
    return out

class FilesWatch:
    def __init__(self):
        self.cfg = load_config()
        self.poll_seconds = self.cfg["poll_seconds"]
        self._stop = threading.Event()
        self._thread = None
        self._base = {}
    def setup(self):
        saved = load_baseline()
        if not saved:
            self._base = snapshot(self.cfg["paths"])
            save_baseline(self._base)
            log_event(
                "system",
                "files watch baseline ready",
                count=len(self._base),
                path = str(BASELINE_FILE),
            )
        else:
            self._base = dict(saved)
            log_event("system","files baseline loaded",count=len(self._base))
        self._stop.clear()
        self._thread = threading.Thread(
            target = self._loop, name= "files-watch", daemon=True
        )
        self._thread.start()
        log_event("system","files watch started")
    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
    def _loop(self):
        while not self._stop.is_set():
            try:
                self._check()
            except Exception as exc:
                log_event("system", "files watch error", error = str(exc))
            self._stop.wait(self.poll_seconds)
    def _check(self):
        now = snapshot(self.cfg["paths"])
        for path, cur in now.items():
            old = self._base.get(path)
            if old is None:
                log_event(
                    "alert",
                    "new watched file",
                    path=path,
                    value=cur,
                    source="files",
                )
            elif cur != old:
                log_event(
                    "alert",
                    "watched file changed",
                    path=path,
                    old=old,
                    new=cur,
                    source="files",
                )
        self._base = now
        save_baseline(self._base)