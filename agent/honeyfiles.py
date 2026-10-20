from pathlib import Path
from event import log_event
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
DECOY_ROOT = Path.home() / "Documents" / "WorkArchive_2023"
FILLER_FILES = {
    "meeting_notes_q3.txt": (
        "Q3 sync\n"
        "- budget review moved to Friday\n"
        "- wait for finance export before payroll\n"
    ),
    "readme_archive.txt": (
        "Old work files. Keep until 2025 audit closes.\n"
    ),
    "vendor_contacts.txt": (
        "Acme Supplies - office@acme.example - +1-555-0100\n"
        "Northwind - billing@northwind.example\n"
    ),
}
TRAP_FILES = {
    "credentials_export.csv": (
        "service,username,password,note\n"
        "email,admin@company.example,ChangeMe2023!,legacy\n"
        "vpn,j.smith,Summer2023!,personal-backup\n"
        "payroll,finance_bot,P@ssw0rd!,do-not-share\n"
    ),
    "salary_backup.csv": (
        "name,role,monthly\n"
        "Alex,Engineer,12000\n"
        "Sam,Manager,15000\n"
        "Jordan,Intern,4000\n"
    ),
}

class TrapEventHandler(FileSystemEventHandler):
    def __init__(self, trap_paths):
        super().__init__()
        self.trap_paths = {str(Path(p).resolve()) for p in trap_paths}

    def _is_trap(self,path):
        if not path:
            return False
        return str(Path(path).resolve()) in self.trap_paths
        
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

class HoneyfileGuard:
    def __init__(self):
        self.observer = None
        self.trap_states = {}

    def setup(self):
        DECOY_ROOT.mkdir(parents=True, exist_ok=True)
        for name, content in FILLER_FILES.items():
            path = DECOY_ROOT / name
            if not path.exists():
                path.write_text(content, encoding="utf-8")
        for name, content in TRAP_FILES.items():
            path = DECOY_ROOT / name
            if not path.exists():
                path.write_text(content, encoding="utf-8")
                log_event("system", "Trap file created", path=str(path))
            stat = path.stat()
            self.trap_states[str(path)] = {
                "mtime": stat.st_mtime,
                "size": stat.st_size,
            }
        log_event(
            "system",
            "Honeyfile decoy archive ready",
            path=str(DECOY_ROOT),
            traps=len(TRAP_FILES),
        )
        trap_paths = [str(DECOY_ROOT / name) for name in TRAP_FILES]
        handler = TrapEventHandler(trap_paths)
        self.observer = Observer()
        self.observer.schedule(handler, str(DECOY_ROOT), recursive=False)
        self.observer.start()
        log_event("system", "Honeyfile watcher started", path=str(DECOY_ROOT))

    def check(self):
        return False

    def stop(self):
        if self.observer is not None:
            self.observer.stop()
            self.observer.join(timeout=5)
            self.observer = None