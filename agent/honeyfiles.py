from pathlib import Path
import json
from event import log_event
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from audit_watch import AuditWatch
CONFIG_PATH = Path(__file__).resolve().parent / "honey.json"

def load_config():
    raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    root = raw["decoy_root"].replace("{home}", str(Path.home()))
    return {
        "decoy_root": Path(root),
        "fillers": raw.get("fillers", {}),
        "traps": raw.get("traps", {}),
    }

class TrapEventHandler(FileSystemEventHandler):
    def __init__(self, trap_paths, traps_by_name):
        super().__init__()
        self.trap_paths = {str(Path(p).resolve()) for p in trap_paths}
        self.traps_by_name = traps_by_name
    def _is_trap(self, path):
        if not path:
            return False
        return str(Path(path).resolve()) in self.trap_paths

    def _restore(self,path):
        path = Path(path)
        content = self.traps_by_name.get(path.name)
        if content is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text(content, encoding="utf-8")
            log_event("system", "Trap file restored", path=str(path))

    def on_modified(self, event):
        if event.is_directory:
            return
        if self._is_trap(event.src_path):
            log_event(
                "alert",
                "Trap file was modified",
                path=event.src_path,
            )

    def on_deleted(self, event):
        if event.is_directory:
            return
        if self._is_trap(event.src_path):
            log_event(
                "alert",
                "Trap file was deleted or moved",
                path=event.src_path,
            )
            self._restore(event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return
        if self._is_trap(event.src_path) or self._is_trap(event.dest_path):
            log_event(
                "alert",
                "Trap file was moved/renamed",
                path=event.src_path,
                dest=getattr(event, "dest_path", None),
            )
            if self._is_trap(event.src_path):
                self._restore(event.src_path)

class HoneyfileGuard:
    def __init__(self):
        self.observer = None
        self.config = None
        self.audit = None

    def setup(self):
        self.config = load_config()
        decoy_root = self.config["decoy_root"]
        fillers = self.config["fillers"]
        traps = self.config["traps"]
        decoy_root.mkdir(parents=True, exist_ok=True)
        for name, content in fillers.items():
            path = decoy_root / name
            if not path.exists():
                path.write_text(content, encoding="utf-8")
        for name, content in traps.items():
            path = decoy_root / name
            if not path.exists():
                path.write_text(content, encoding="utf-8")
                log_event("system", "Trap file created", path=str(path))
        log_event(
            "system",
            "Honeyfile decoy archive ready",
            path=str(decoy_root),
            traps=len(traps),
        )
        trap_paths = [str(decoy_root / name) for name in traps]
        handler = TrapEventHandler(trap_paths,traps)
        self.observer = Observer()
        self.observer.schedule(handler, str(decoy_root), recursive=False)
        self.observer.start()
        log_event("system", "Honeyfile watcher started", path=str(decoy_root))
        self.audit = AuditWatch(trap_paths)
        self.audit.start()

    def stop(self):
        if self.observer is not None:
            self.observer.stop()
            self.observer.join(timeout=5)
            self.observer = None
        if self.audit is not None:
            self.audit.stop()
            self.audit = None