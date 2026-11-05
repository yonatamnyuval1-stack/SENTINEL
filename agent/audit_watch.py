import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from event import log_event
from defend import maybe_kill

EVENT_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

def _norm(path):
    try:
        return str(Path(path).resolve()).lower()
    except Exception:
        return str(path).lower()

class AuditWatch:
    """Reads Windows Security log (4663) for honey trap paths."""
    def __init__(self, trap_paths, poll_seconds=3):
        self.trap_paths = {_norm(p) for p in trap_paths}
        self.poll_seconds = poll_seconds
        self._stop = threading.Event()
        self._thread = None
        self._seen = set()
        self._recent = {}
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="audit-watch", daemon=True
        )
        self._thread.start()
        log_event("system", "Audit watch started")

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
    
    def _loop(self):
        while not self._stop.is_set():
            try:
                self._poll()
            except Exception as exc:
                log_event("system", "Audit watch error", error=str(exc))
            self._stop.wait(self.poll_seconds)

    def _poll(self):
        cmd = [
            "wevtutil",
            "qe",
            "Security",
            "/q:*[System[(EventID=4663)]]",
            "/c:40",
            "/f:xml",
            "/rd:true",
        ]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if proc.returncode != 0:
            err = (proc.stderr or "").strip()
            if err:
                raise RuntimeError(err)
            return
        xml_text = proc.stdout.strip()
        if not xml_text:
            return
        wrapped = "<Events>" + xml_text + "</Events>"
        root = ET.fromstring(wrapped)
        for event in root.findall("e:Event", EVENT_NS):
            self._handle_event(event)
    def _handle_event(self, event):
        system = event.find("e:System", EVENT_NS)
        if system is None:
            return
        record = system.find("e:EventRecordID", EVENT_NS)
        record_id = record.text if record is not None else None
        if record_id and record_id in self._seen:
            return
        if record_id:
            self._seen.add(record_id)
            if len(self._seen) > 5000:
                self._seen = set(list(self._seen)[-2000:])
        data = {}
        for item in event.findall("e:EventData/e:Data", EVENT_NS):
            name = item.attrib.get("Name")
            if name:
                data[name] = item.text or ""
        obj_name = data.get("ObjectName", "")
        if not obj_name:
            return
        if _norm(obj_name) not in self.trap_paths:
            return
        process_name = data.get("ProcessName", "") or "unknown"
        user = data.get("SubjectUserName", "") or "unknown"
        access = data.get("AccessMask", "") or ""
        dedupe_key = f"{_norm(obj_name)}|{process_name}|{user}|{access}"
        now = time.time()
        last = self._recent.get(dedupe_key, 0)
        if now - last < 2:
            return
        self._recent[dedupe_key] = now
        log_event(
            "alert",
            "Trap file access audited",
            pid=data.get("ProcessId") or "",
            path=obj_name,
            process=process_name,
            user=user,
            access_mask=access,
            source="windows_audit",
        )
        pid = data.get("ProcessId") or ""
        name = process_name.replace("/", "\\").split("\\")[-1].lower()
        if name in ("explorer.exe", "searchindexer.exe", "msmpeng.exe"):
            return
        maybe_kill(pid, process_name, why="honey")