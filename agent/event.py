import json
from notify import maybe_toast
from datetime import datetime,timezone
from pathlib import Path
DATA_DIR = Path(__file__).resolve().parent / "data"
EVENTS_FILE = DATA_DIR / "events.jsonl"

def ensure_data_dir():
    DATA_DIR.mkdir(parents = True, exist_ok = True)

def log_event(kind,massage, **extra):
    ensure_data_dir()

    event = {
        "time": datetime.now(timezone.utc).isoformat(),
        "kind": kind,
        "massage": massage,
    }
    event.update(extra)
    with EVENTS_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
    print(f"[{event['kind']}] {event['massage']}")
    maybe_toast(event["kind"], event["massage"], event.get("source") or "")
    return event