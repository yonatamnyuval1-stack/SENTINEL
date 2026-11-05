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
    cfg["muted_until"] = {}
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
    cfg["defend"] = False
    if "defend" in raw:
        cfg["defend"] = bool(raw.get("defend"))
    muted = {}
    raw_muted = raw.get("muted_until") if isinstance(raw, dict) else None
    if isinstance(raw_muted, dict):
        for key in DEFAULTS:
            if key in raw_muted and raw_muted[key]:
                muted[key] = str(raw_muted[key])
    cfg["muted_until"] = muted
    return cfg

def save_control(cfg):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    out = dict(DEFAULTS)
    muted_out = {}
    raw_muted = cfg.get("muted_until") if isinstance(cfg, dict) else None
    if isinstance(raw_muted, dict):
        for key in DEFAULTS:
            if key in raw_muted and raw_muted[key]:
                muted_out[key] = str(raw_muted[key])
    out["muted_until"] = muted_out
    if isinstance(cfg, dict):
        for key in DEFAULTS:
            if key in cfg:
                out[key] = bool(cfg[key])
    out["defend"] = bool(cfg.get("defend", False)) if isinstance(cfg, dict) else False
    CONTROL_FILE.write_text(
        json.dumps(out, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8"
    )
    return out

def bump_heartbeat(running=None):
    DATA_DIR.mkdir(parents=True, exist_ok=True),
    payload = {
        "time": datetime.now(timezone.utc).isoformat(),
    }
    if isinstance(running, dict):
        payload["running"] = {
            "honey": bool(running.get("honey")),
            "persistence": bool(running.get("persistence")),
            "process": bool(running.get("process")),
            "network": bool(running.get("network")),
        }
    HEARTBEAT_FILE.write_text(
        json.dumps(payload, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

def want_running(cfg, name):
    if not bool(cfg.get(name, True)):
        return False
    until = (cfg.get("muted_until") or {}).get(name)
    if not until:
        return True
    try:
        end = datetime.fromisoformat(until)
    except ValueError:
        return True
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) >= end

def clear_finished_mutes(cfg):
    muted = dict(cfg.get("muted_until") or {})
    if not muted:
        return cfg, []
    now = datetime.now(timezone.utc)
    done = []
    for key, until in list(muted.items()):
        try:
            end = datetime.fromisoformat(str(until))
        except ValueError:
            done.append(key)
            muted.pop(key, None)
            continue
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)
        if now >= end:
            done.append(key)
            muted.pop(key, None)
    if done:
        cfg = dict(cfg)
        cfg["muted_until"] = muted
        save_control(cfg)
    return cfg, done

def mute_for(cfg, name, minutes):
    try:
        mins = int(minutes)
    except (TypeError, ValueError):
        return cfg
    if name not in DEFAULTS or mins <= 0:
        return cfg
    from datetime import timedelta
    end = datetime.now(timezone.utc) + timedelta(minutes=mins)
    cfg=dict(cfg)
    muted = dict(cfg.get("muted_until") or {})
    muted[name] = end.isoformat()
    cfg["muted_until"] = muted
    return save_control(cfg)