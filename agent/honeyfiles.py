from pathlib import Path
from event import log_event
HONEYPOT_DIR = Path(__file__).resolve().parent / "honeypots"
HONEYFILE_NAME = "passwords_BACKUP.txt"
HONEYFILE_CONTENT = """DO NOT EDIT
This is a SENTINEL decoy file.
If this file is opened or changed, SENTINEL will raise an alert.
"""
class HoneyfileGuard:
    def __init__(self):
        self.path = HONEYPOT_DIR / HONEYFILE_NAME
        self.last_mtime = None
        self.last_size = None
    def setup(self):
        HONEYPOT_DIR.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text(HONEYFILE_CONTENT, encoding="utf-8")
            log_event("system", "Honeyfile created", path=str(self.path))
        stat = self.path.stat()
        self.last_mtime = stat.st_mtime
        self.last_size = stat.st_size
        log_event("system", "Honeyfile watch started", path=str(self.path))
    def check(self):
        """Call this every loop. Returns True if an alert was raised."""
        if not self.path.exists():
            log_event(
                "alert",
                "Honeyfile was deleted or moved",
                path=str(self.path),
            )
            self.setup()
            return True
        stat = self.path.stat()
        mtime = stat.st_mtime
        size = stat.st_size
        if mtime != self.last_mtime or size != self.last_size:
            log_event(
                "alert",
                "Honeyfile was touched or modified",
                path=str(self.path),
                old_size=self.last_size,
                new_size=size,
            )
            self.last_mtime = mtime
            self.last_size = size
            return True
        return False