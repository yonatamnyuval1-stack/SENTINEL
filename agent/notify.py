import subprocess
import time
_last = 0.0
_OK = {
    "honeyfiles",
    "windows_audit",
    "persistence",
    "process_etw",
    "correlation",
    "network_corr",
    "incident",
    "files",
}
def _clean(text):
    return str(text or "").replace("'", " ").replace("'", " ").replace("\n", "")[:120]

def maybe_toast(kind,massage,source=""):
    global _last
    src = source
    if kind != "alert":
        return 
    if src and src not in _OK:
        return
    now = time.time()
    if now - _last < 8:
        return
    _last = now
    title = _clean("SENTINEL")
    body = _clean(massage)
    if src:
        body = _clean(src + ":"+ massage)
    ps = (
        "Add-Type -AssemblyName System.Windows.Forms; "
        "Add-Type -AssemblyName System.Drawing; "
        "$n = New-Object System.Windows.Forms.NotifyIcon; "
        "$n.Icon = [System.Drawing.SystemIcons]::Shield; "
        "$n.Visible = $true; "
        "$n.ShowBalloonTip(5000, '" + title + "', '" + body + "', "
        "[System.Windows.Forms.ToolTipIcon]::Warning); "
        "Start-Sleep -Seconds 6; "
        "$n.Dispose()"
    )
    try:
        subprocess.Popen(
            [
                "powershell",
                "-NoProfile",
                "-WindowStyle",
                "Hidden",
                "-command",
                ps,
            ],
            close_fds = True,
        )
    except OSError:
        pass