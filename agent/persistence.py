import json
import threading
import winreg
from pathlib import Path
from event import log_event

DATA_DIR = Path(__file__).resolve().parent/ "data"
BASELINE_FILE = DATA_DIR/ "persistence_baseline.json"
CONFIG_PATH = Path(__file__).resolve().parent / "persistence.json"

RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "runonce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "runonce"),
]

def load_config():
    cfg = {
        "poll_seconds": 10,
        "watch": {
            "run": True,
            "runonce": True,
            "startup": True,
            "tasks": True,
        },
        "ignore_prefixes": [
            "task:Microsoft/",
            "task:Microsoft\\",
        ],
    }
    if not CONFIG_PATH.exists():
        return cfg
    try:
        raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return cfg
    if isinstance(raw.get("poll_seconds"), int) and raw["poll_seconds"] >0:
        cfg["poll_seconds"] = raw["poll_seconds"]
    watch = raw.get("watch")
    if isinstance(watch,dict):
        for key in cfg["watch"]:
            if key in watch:
                cfg["watch"][key] = bool(watch[key])
    ignores = raw.get("ignore_prefixes")
    if isinstance(ignores, list):
        cfg["ignore_prefixes"] = [str(x) for x in ignores]
    return cfg
def _ignored(entry, prefixes):
    for prefix in prefixes:
        if entry.startswith(prefix):
            return True
    return False

def _startup_dirs():
    home = Path.home()
    dirs = [
        home / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
    ]
    progdata = Path(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
    if progdata.exists():
        dirs.append(progdata)
    return dirs

def _read_run_key(hive, path, kind):
    items = {}
    try:
        key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
    except OSError:
        return items
    try:
        i = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, i)
            except OSError:
                break
            items[f"{kind}:{path}:{name}"] = str(value)
            i += 1
    finally:
        winreg.CloseKey(key)
    return items

def _read_startup_files():
    items = {}
    for folder in _startup_dirs():
        if not folder.exists():
            continue
        for entry in folder.iterdir():
            if entry.name.lower() == "desktop.ini":
                continue
            key = f"startup:{entry}"
            try:
                stamp = entry.stat().st_mtime_ns
            except OSError:
                stamp = 0
            items[key] = f"{entry.name}|{stamp}"
    return items

def _read_scheduled_tasks():
    items = {}
    root = Path(r"C:\Windows\System32\Tasks")
    if not root.exists():
        return items
    try:
        paths = root.rglob("*")
    except OSError:
        return items
    for path in paths:
        try:
            if not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            st = path.stat()
            items[f"task:{rel}"] = f"{st.st_size}|{st.st_mtime_ns}"
        except OSError:
            continue
    return items

def snapshot(cfg = None):
    if cfg is None:
        cfg = load_config()
    watch = cfg["watch"]
    data = {}
    for hive, path, kind in RUN_KEYS:
        if not watch.get(kind, True):
            continue
        data.update(_read_run_key(hive, path, kind))
    if watch.get("startup", True):
        data.update(_read_startup_files())
    if watch.get("tasks", True):
        data.update(_read_scheduled_tasks())
    ignores = cfg.get("ignore_prefixes", [])
    if ignores:
        data = {
            key: value
            for key, value in data.items()
            if not _ignored(key, ignores)
        }
    return data

def load_baseline():
    if not BASELINE_FILE.exists():
        return None
    try:
        raw = json.loads(BASELINE_FILE.read_text(encoding="utf-8"))
    except(OSError, json.JSONDecodeError):
        return None
    return{str(k): str(v) for k,v in raw.items()}

def save_baseline(data):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    BASELINE_FILE.write_text(
        json.dumps(data, ensure_ascii = False, indent=2) + "\n",
        encoding = "utf-8",
    )

class PersistenceWatch:
    def __init__(self, poll_seconds=None):
        self.cfg = load_config()
        self.poll_seconds = (
            poll_seconds
            if poll_seconds is not None
            else self.cfg["poll_seconds"]
        )
        self._stop = threading.Event()
        self._thread = None
        self._base = {}
    def setup(self):
        saved = load_baseline()
        if saved is None:
            self._base = snapshot(self.cfg)
            save_baseline(self._base)
            log_event(
                "system",
                "Persistence watch baseline ready",
                entries=len(self._base),
                path = str(BASELINE_FILE)
            )
        else:
            ignores = self.cfg.get("ignore_prefixes", [])
            self._base = {
                key: value
                for key, value in saved.items()
                if not _ignored(key, ignores)
            }
            log_event(
                "system", 
                "Persistence baseline loaded",
                entries = len(self._base),
                path = str(BASELINE_FILE)),
            self._check()
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="persistence-watch", daemon=True
        )
        self._thread.start()
        log_event("system", "Persistence watch started")
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
                log_event("system", "Persistence watch error", error=str(exc))
            self._stop.wait(self.poll_seconds)
    def _check(self):
        now = snapshot(self.cfg)
        old_keys = set(self._base)
        new_keys = set(now)
        for key in sorted(new_keys - old_keys):
            log_event(
                "alert",
                "New persistence entry",
                entry=key,
                value=now[key],
                source="persistence",
            )
        for key in sorted(old_keys - new_keys):
            log_event(
                "alert",
                "Persistence entry removed",
                entry=key,
                value=self._base[key],
                source="persistence",
            )
        for key in sorted(old_keys & new_keys):
            if now[key] != self._base[key]:
                log_event(
                    "alert",
                    "Persistence entry changed",
                    entry=key,
                    old=self._base[key],
                    new=now[key],
                    source="persistence",
                )
        self._base = now
        save_baseline(self._base)