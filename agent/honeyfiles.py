from pathlib import Path
from event import log_event
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

class HoneyfileGuard:
    def __init__(self):
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

    def check(self):
        alerted = False
        for path_str, state in list(self.trap_states.items()):
            path = Path(path_str)
            if not path.exists():
                log_event(
                    "alert",
                    "Trap file was deleted or moved",
                    path=path_str,
                )
                name = path.name
                content = TRAP_FILES.get(name)
                if content is not None:
                    path.write_text(content, encoding="utf-8")
                    stat = path.stat()
                    self.trap_states[path_str] = {
                        "mtime": stat.st_mtime,
                        "size": stat.st_size,
                    }
                alerted = True
                continue
            stat = path.stat()
            if stat.st_mtime != state["mtime"] or stat.st_size != state["size"]:
                log_event(
                    "alert",
                    "Trap file was touched or modified",
                    path=path_str,
                    old_size=state["size"],
                    new_size=stat.st_size,
                )
                self.trap_states[path_str] = {
                    "mtime": stat.st_mtime,
                    "size": stat.st_size,
                }
                alerted = True
        return alerted