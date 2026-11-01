import json
from datetime import datetime,timezone
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "data"
CONTROL_FILE = DATA_DIR / "control.json"
HEARTBEAT_FILE = DATA_DIR / "agent_heartbeat.json"
DEFAULTS = {
    "honey": True,
    "persistence": True,
    "process": True,
    "network": True
}

def load_control():
    cfg = dict(DEFAULTS)
    if not CONTROL_FILE.exists():
        save_control(cfg)
        return cfg
    try:
        raw = json.loads(CONTROL_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return cfg
    if not isinstance(raw, dict):
        return cfg
    for key in DEFAULTS:
        if key in raw:
            cfg[key] = bool(raw[key])
    return cfg

def save_control(cfg):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    out = dict(DEFAULTS)
    if isinstance(cfg, dict):
        for key in DEFAULTS:
            if key in cfg:
                out[key] = bool(cfg[key])
    CONTROL_FILE.write_text(
        json.dumps(out, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8"
    )
    return out

def bump_heartbeat():
    DATA_DIR.mkdir(parents=True, exist_ok=True),
    payload = {
        "time": datetime.now(timezone.utc).isoformat()
    }
    HEARTBEAT_FILE.write_text(
        json.dumps(payload, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )