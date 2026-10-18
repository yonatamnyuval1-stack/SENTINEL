import json
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs
ROOT = Path(__file__).resolve().parent
STATIC_DIR = ROOT/ "static"
EVENTS_FILE = ROOT.parent / "agent" / "data" / "events.jsonl"
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