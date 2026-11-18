#!python3.12
"""Start dashboard then the SENTINEL agent (pynsist launcher)."""
import os
import site
import subprocess
import sys

scriptdir, _ = os.path.split(os.path.abspath(__file__))
pkgdir = os.path.join(scriptdir, "pkgs")
sys.path.insert(0, pkgdir)
site.addsitedir(pkgdir)

agent_dir = os.path.join(scriptdir, "agent")
dash_dir = os.path.join(scriptdir, "dashboard")
sys.path.insert(0, agent_dir)

# Prefer console python next to this launcher for the dashboard child.
py = sys.executable
if py.lower().endswith("pythonw.exe"):
    py = py[:-len("pythonw.exe")] + "python.exe"

dash_py = os.path.join(dash_dir, "server.py")
if os.path.isfile(dash_py):
    creation = 0
    if hasattr(subprocess, "CREATE_NEW_CONSOLE"):
        creation = subprocess.CREATE_NEW_CONSOLE
    try:
        subprocess.Popen(
            [py, dash_py],
            cwd=dash_dir,
            creationflags=creation,
        )
    except OSError:
        subprocess.Popen([py, dash_py], cwd=dash_dir)

os.chdir(agent_dir)
from main import main

if __name__ == "__main__":
    main()
