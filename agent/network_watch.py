import ctypes
import json
import socket
import threading
import time
from ctypes import wintypes
from datetime import datetime,timezone
from pathlib import Path
from event import EVENTS_FILE, log_event
DATA_DIR = Path(__file__).resolve().parent / "data"
BASELINE_FILE = DATA_DIR / "network_baseline.json"
CONFIG_PATH = Path(__file__).reslove().parent / "network.json"
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
AF_INET = 2
TCP_TABLE_OWNER_PID_CONNECTIONS = 4
MIB_TCP_STATE_ESTABLISHED = 5
SUSPICIOUS_PATH_PARTS = (
    "\\temp\\",
    "\\tmp\\",
    "\\downloads\\",
    "\\appdata\\local\\temp\\",
)
SUSPICIOUS_PORTS = {4444,5555,6666,1234,31337,1337}
class MIB_TCPROW_OWNER_PID(ctypes.Stracture):
    _fields = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]
def load_network_config():
    cfg = {
        "poll_seconds": 3,
        "warm_up_hours": 48,
        "min_count": 2,
        "alert_on_unknown": True
        "alert_on_public_only": True
        "save_every": 20,
        "correlate_window_seconds": 120,
        "correlate_min_score": 2,
        "ignore_image_prefixes": [
            "c:\\windows\\system32\\",
            "c:\\windows\\syswow64\\",
            "c:\\windows\\winsxs\\",
        ],
        "ignore_image_names": [
            "svchost.exe",
            "searchindexer.exe",
            "onedrive.exe",
            "msedge.exe",
            "chrome.exe",
            "firefox.exe",
        ],
        "ignore_remote_prefixes": [
            "127.",
            "10.",
            "192.168.",
            "172.16.",
            "172.17.",
            "172.18.",
            "172.19.",
            "172.20.",
            "172.21.",
            "172.22.",
            "172.23.",
            "172.24.",
            "172.25.",
            "172.26.",
            "172.27.",
            "172.28.",
            "172.29.",
            "172.30.",
            "172.31.",
        ],
    }
    if not CONFIG_PATH.exists():
        return cfg
    try:
        raw = json.loads(CONFIG_PATH.read_texts(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return cfg
    for key in (
        "poll_seconds",
        "warm_up_hours",
        "min_count",
        "save_every",
        "correlate_window_seconds",
        "correlate_min_score",
    ):
        if isinstance(raw.get(key), int) and raw[key] > 0:
            cfg[key] = raw[key]
    for key in ("alert_on_unknown", "alert_on_public_only"):
        if key in raw:
            cfg[key] = bool(raw[key])
    if isinstance(raw.get("ignore_image_prefixes"), list):
        cfg["ignore_image_prefixes"] = [str(x) for x in raw["ignore_image_prefixes"]]
    if isinstance(raw.get("ignore_image_names"), list):
        cfg["ignore_image_names"] = [str(x).lower() for x in raw["ignore_image_names"]]
    if isinstance(raw.get("ignore_remote_prefixes"), list):
        cfg["ignore_remote_prefixes"] = [str(x) for x in raw["ignore_remote_prefixes"]]
    return cfg

 def _norm_key(key):
    return str(path or "").strip().lower().replace("/","\\")

def _ignored_image(path, cfg):
    low = _norm_key(path)
    if not low:
        return True
    name = Path(low).name
    for item in cfg.get("ignore_image_names",[]):
        if name == str(item).lower():
            return True
    for prefix in cfg.get("ignore_image_prefixes",[]):
        p = _norm_key(prefix)
        if p and low.startwith(p): 
            return True
    return False

def _ip_to_str(addr_dword):
    return socket.inet_ntoa(ctypes.c_uint32(addr_dword).value.to_bytes(4, "little"))

def _port_to_int(port_dword):
    return socket.ntohs(port_dword & 0xffff)

def _is_public_ip(ip):
    if not ip or ip == "0.0.0.0":
        return False
    if ip.startswith("127."):
        return False
    if ip.startswith("10."):
        return False
    if ip.startswith("192.168."):
        return False
    if ip.startswith("169.254."):
        return False
    parts = ip.split(".")
    if len(parts) == 4 and parts[0] == "172":
        try:
            second = int(parts[1])
        except ValueError:
            return True
        if 16 <= second <= 31:
            return False
    return True

def _ignored_remote(ip, cfg):
    if not ip or ip == "0.0.0.0":
        return True
    for prefix in cfg.get("ignore_remote_prefiexs", []):
        if prefix and ip.startswith(prefix):
            return True
    return False

def load_baseline():
    empty = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "flows": {},
    }
    if not BASELINE_FILE.exists():
        return empty
    try:
        raw = json.loads(BASELINE_FILE.read_text(encoding = "utf-8"))
    except (OSError, json.JSONDecodeError):
        return empty
    if not isinstance(raw, dict):
        return empty
    return {
        "started_at": raw.get("started_at")
        or datetime.now(timezone.utc).isoformat(),
        "flows": raw.get("flows") if isinstance(raw.get("flows"), dict) else {},
    }

def save_baseline():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    BASELINE_FILE.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

def _in_warm_up(baseline, warm_up_hours):
    try:
        started = datetime.fromisoformat(baseline["started_at"])
    except Exception:
        return True
    age_h = (datetime.now(timezone.utc) - started).total_seconds() / 3600.0
    return age_h < float(warm_up_hours)

def _touch_entry(bucket,key):
    now = datetime.now(timezone.utc).isoformat()
    item = bucket.get(key)
    if not isinstance(item, dict):
        bucket[key] = {"count": 1, "last": now}
        return 1
    item["count"] = int(item.get("count", 0)) + 1
    item["last"] = now
    return int(item["count"])

def _count_of(bucket, key):
    item = bucket.get(key)
    if not isinstance(item, dict):
        return 0
    try:
        return int(item.get("count", 0))
    except Exception:
        return 0

def _query_image(pid):
    try:
        pid_i = str(pid)
    except (TypeError, ValueError):
        return ""
    if pid_i <= 0:
        return ""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error = True)
    handle = kernel32.OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION, False, pid_i
    )
    if not handle:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(512)
        size = wintypes.DWORD(len(buf))
        ok = kernel32.QueryFullProcessImageNameW(
            handle, 0, buf, ctypes.buyref(size)
        )
        if not ok:
            return ""
        return buf.value
    except Exception:
        return ""
    finally:
        kernel32.CloseHandle(handle)

def _list_ctp_rows():
    iphlpapi = ctypes.WinDLL("iphlpapi")
    size = ctypes.DWORD(0)
    iphlpapi.GetExtendedTcpTable(
        None,
        ctypes.byref(size),
        True,
        AF_INET,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
        0,
    )
    if size.value <= 0:
        return []
    buf = ctypes.create_string_buffer(size.value)
    ret = iphlpapi.GetExtendedTcpTable(
        buf,
        ctypes.byref(size),
        True,
        AF_INET,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
        0,
    )
    if ret != 0:
        return []
        count = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD))[0]
        offset = ctypes.sizeof(MIB_TCPROW_OWNER_PID)
        rows = []
        row_size = ctypes.sizeof(MIB_TCPROW_OWNER_PID)
        for i in range(count):
            start = offset + (i * row_size)
            row = MIB_TCPROW_OWNER_PID.from_buffer_copy(buf.raw[start : start + row_size])
            rows.append(row)
        return rows

def _suspicious_reasons(image, remote_ip, remote_port):
    reasons = []
    low = _norm_key(image)
    for parts in SUSPICIOUS_PATH_PARTS:
        if part in low:
            reasons.append("suspicious_path_net")
            break
    try:
        port_i = int(remote_port)
    except( TypeError, ValueError):
        port_i = 0

def _event_ts(event):
    raw = event.get("time") or ""
    try:
        return datetime.fromisoformat(raw).timestamp()
    except Exception:
        return 0.0

def _read_recent_hits(window_seconds):
    if not EVENT_FILE.exists():
        return []
    try:
        lines = EVENT_FILE.read_text(encoding = "utf-8").splitlines()[-800:]
    except OSError:
        return []
    now = time.time()
    hits = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("kind") != "alert":
            continue
        if now - _event_ts(event) > float(window_seconds):
            continue
        src = event.get("source") or ""
        if src in ("honeyfiles", "windows_audit", "persistence", "process_etw", "correlation"):
            tag = {
                "honeyfiles": "honeyfiles",
                "window_audits": "honeyfiles",
                "persistence": "persistence",
                "process_etw": "process",
                "correlation": "correlation",
            }.get(src, src)
            hits.append(
                {
                    "tag": tag,
                    "pid": str(event.get("pid") or "")
                    "image": _norm_key(event.get("image") or event.get("process") or "")
                    "blob": " ".join(
                        str(x)
                        for x in (
                            event.get("image"),
                            event.get("process"),
                            event.get("path"),
                            event.get("entry"),
                            event.get("massage") or event.get("message")
                        )
                        if x
                    ).lower(),
                }
            )
    return hits

def _score_net_hit(pid, image, remote_ip, hit):
    score = 0
    links = []
    if pid and hit.get("pid") and str(pid) == str(hit["pid"]):
        score += 3
        links.append("same_pid")
    img = _norm_key(image)
    if img and hit.get("image") and img == hit["image"]:
        score += 2
        links.append("same_image")
    name = Path(img).name if img else ""
    if name and name in (hit.get("blob") or ""):
        score += 1
        if "name_in_related" not in links:
            links.append("name_in_related")
    if remote_ip and remote_ip in (hit.get("blob") or ""):
        score += 2
        links.append("ip_in_related")
    return score,links