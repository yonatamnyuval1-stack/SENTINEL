import json
import time
from pathlib import Path
from event import log_event
EVENT_FILE = Path(__file__).resolve().parent / "data" / "events.jsonl"
_last_by_key = {}
def _ts(event):
    raw = event.get("time") or ""
    try:
        from datetime import datetime
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0.0

def _tag(event):
    src = str(event.get("source") or "")
    msg = str(event.get("massage") or "")
    if src == "persistence":
        return "persistence"
    if src in ("windows_audit", "honeyfiles") or "trap" in msg or "honey" in msg.lower():
        return "honey"
    if src == "process_etw":
        return "process"
    if src == "network_tcp":
        return "network"
    if src in ("correlation", "network_corr"):
        return "link"
    return ""

def _line(event):
    tag = _tag(event) or "?"
    msg = str(event.get("massage") or event.get("message") or "")
    bits = [tag + ": " + msg]
    if event.get("image"):
        bits.append("image: "+ str(event.get("image")))
    if event.get("pid"):
        bits.append("pid: "+ str(event.get("pid")))
    if event.get("remote_ip"):
        bits.append(
            "remote="
            + str(event.get("remote_ip"))
            + ":"
            + str(event.get("remote_port") or "")
        )
    if event.get("path"):
        bits.append("path=" + str(event.get("path")))
    if event.get("entry"):
        bits.append("entry=" + str(event.get("entry")))
    return " | ".join(bits)

def _grab_window(window_seconds, pid=None, image=None):
    if not EVENT_FILE.exists():
        return []
    try:
        lines = EVENT_FILE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    cutoff = time.time() - float(window_seconds)
    pid_s = str(pid) if pid not in (None, "") else ""
    img = (image or "").lower()
    img_name = Path(image).name.lower() if image else ""
    out = []
    for line in lines[-500:]:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("kind") != "alert":
            continue
        if _ts(event) < cutoff:
            continue
        if (event.get("source") or "") == "incident":
            continue
        tag= _tag(event)
        if not tag:
            continue
        same = False
        ev_img = str(event.get("image") or "").lower()
        if pid_s and str(event.get("pid") or "") == pid_s:
            same = True
        if img and ev_img and (img == ev_img or (img_name and img_name in ev_img)):
            same = True
        if tag in ("honey", "persistence", "link"):
            same = True
        if not same:
            continue
        out.append(event)
    return out

def maybe_write_incident(pid, image, score, related,window_seconds=120,why=""):
    """
    turn a bunch of nearby alert into one row
    called after correlation already fired
    """
    key = str(pid) + " | " +str(image or "")
    now = time.time()
    prev = _last_by_key.get(key, 0)
    if now - prev < 45:
        return None
    events = _grab_window(window_seconds, pid=pid, image=image)
    if len(events) < 2:
        return None
    tags = []
    for ev in events:
        t = _tag(ev)
        if t and t not in tags:
            tags.append(t)
    if len(tags) < 2:
        return None
    steps = []
    for ev in events[-12:]:
        when = ev.get("time") or ""
        steps.append(when + " " + _line(ev))
    timeline = "\n".join(steps)
    title_bits = []
    for t in tags:
        if t != "link" and t not in title_bits:
            title_bits.append(t)
    title = "story: " + " + ".join(title_bits[:4])
    if why:
        title = title + " ( " + str(why) + " ) "
    _last_by_key[key] = now
    return log_event(
        "alert",
        title,
        pid=str(pid or ""),
        image=str(image or ""),
        score=int(score or 0),
        related=",".join(tags),
        timeline=timeline,
        window_seconds=int(window_seconds),
        source="incident",
    )