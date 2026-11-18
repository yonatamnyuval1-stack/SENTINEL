import os
import sys
import site
import subprocess
here = os.path.dirname(os.path.abspath(__file__))
pkgs = os.path.join(here, "pkgs")
sys.path.insert(0, pkgs)
site.addsitedir(pkgs)
agent = os.path.join(here, "agent")
dash = os.path.join(here, "dashboard")
sys.path.insert(0,agent)
py = sys.executable
if py.lower().endswith("pythonw.exe"):
    py = py.replace("pythonw.exe", "python.exe").replace("PYTHONW.EXE", "python.exe")
dash_file = os.path.join(dash,"server.py")
subprocess.Popen([py, dash_file], cwd=dash)
os.chdir(agent)
from main import main
main()