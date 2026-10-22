import threading
import winreg
from pathlib import Path
from event import log_event
RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
]

def _startup_dirs():
    home = Path.home()
    dirs = [
        home / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
    ]
    progdata = Path(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
    if progdata.exists():
        dirs.append(progdata)
    return dirs

def _read_run_key(hive, path):
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
            items[f"run:{path}:{name}"] = str(value)
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

def snapshot():
    data = {}
    for hive, path in RUN_KEYS:
        data.update(_read_run_key(hive, path))
    data.update(_read_startup_files())
    data.update(_read_scheduled_tasks())
    return data

class PersistenceWatch:
    def __init__(self, poll_seconds=10):
        self.poll_seconds = poll_seconds
        self._stop = threading.Event()
        self._thread = None
        self._base = {}

    def setup(self):
        self._base = snapshot()
        log_event(
            "system",
            "Persistence watch baseline ready",
            entries=len(self._base),
        )
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
        now = snapshot()
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