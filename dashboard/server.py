import json
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs
ROOT = Path(__file__).resolve().parent
STATIC_DIR = ROOT/ "static"
EVENTS_FILE = ROOT.parent / "agent" / "data" / "events.jsonl"
HONEY_JSON = ROOT.parent / "agent" / "honey.json"
HOST = "127.0.0.1"
PORT = 8787
def read_events(limit=200):
    if not EVENTS_FILE.exists():
        return []
    lines = EVENTS_FILE.read_text(encoding="utf-8").splitlines()
    events = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    events.reverse()
    return events

def build_status(events):
    counts = {"alert": 0, "system": 0, "other": 0}
    for event in events:
        kind = event.get("kind", "other")
        if kind in counts:
            counts[kind] += 1
        else:
            counts["other"] += 1
    return {
        "ok": True,
        "events_file": str(EVENTS_FILE),
        "total": len(events),
        "counts": counts,
    }
def build_honey():
    if not HONEY_JSON.exists():
        return {
            "ok": False,
            "error": "honey.json missing",
            "decoy_root": "",
            "fillers": [],
            "traps": [],
            "alerts": [],
        }
    raw = json.loads(HONEY_JSON.read_text(encoding="utf-8"))
    home = str(Path.home())
    decoy_root = raw.get("decoy_root", "").replace("{home}", home)
    fillers = sorted(raw.get("fillers", {}).keys())
    traps = sorted(raw.get("traps", {}).keys())
    decoy_path = Path(decoy_root)
    trap_rows = []
    for name in traps:
        path = decoy_path / name
        trap_rows.append({
            "name": name,
            "path": str(path),
            "exists": path.exists(),
        })
    filler_rows = []
    for name in fillers:
        path = decoy_path / name
        filler_rows.append({
            "name": name,
            "path": str(path),
            "exists": path.exists(),
        })
    honey_alerts = []
    for event in read_events(limit=800):
        if event.get("kind") != "alert":
            continue
        msg = event.get("message") or event.get("massage") or ""
        path = str(event.get("path") or "")
        looks_honey = (
            "Trap" in msg
            or event.get("source") == "windows_audit"
            or (decoy_root and decoy_root.lower() in path.lower())
        )
        if not looks_honey:
            continue
        honey_alerts.append(event)
        if len(honey_alerts) >= 40:
            break
    return {
        "ok": True,
        "decoy_root": decoy_root,
        "decoy_exists": decoy_path.exists(),
        "fillers": filler_rows,
        "traps": trap_rows,
        "alerts": honey_alerts,
    }
def build_persistence():
    events = read_events(limit = 1200)
    alerts = []
    baseline_entries = None
    watch_seen = False
    for event in events:
        text = event.get("message") or event.get("massage") or ""
        if event.get("kind") == "system":
            if "Persistence watch baseline ready" in text and baseline_entries is None:
                baseline_entries = event.get("entries")
            if "Persistence watch started" in text:
                watch_seen = True
        if event.get("kind") == "alert" and event.get("source") == "persistence" and len(alerts) < 50:
            alerts.append(event)
    counts = {"run": 0, "startup": 0, "task": 0, "other": 0}
    for event in alerts:
        entry = str(event.get("entry") or "")
        if entry.startswith("run:"):
            counts["run"] += 1
        elif entry.startswith("startup:"):
            counts["startup"] += 1
        elif entry.startswith("task:"):
            counts["task"] += 1
        else:
            counts["other"] += 1
    return{
        "ok":True,
        "watch_seen": watch_seen or baseline_entries is not None,
        "baseline_entries": baseline_entries,
        "alert_counts": counts,
        "alerts": alerts,
    }

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/events":
            qs = parse_qs(parsed.query)
            limit = int(qs.get("limit", ["200"])[0])
            payload = {"events": read_events(limit=limit)}
            return self._json(payload)
        if parsed.path == "/api/status":
            events = read_events(limit=500)
            return self._json(build_status(events))
        if parsed.path == "/api/honey":
            return self._json(build_honey())
        if parsed.path == "/api/persistence":
            return self._json(build_persistence())
        if parsed.path == "/":
            self.path = "/index.html"
        return super().do_GET()
    def _json(self, payload):
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)
    def log_message(self, fmt, *args):
        return
def main():
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"SENTINEL dashboard: http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
        server.server_close()
if __name__ == "__main__":
    main()