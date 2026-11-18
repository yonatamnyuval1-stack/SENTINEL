#!python3.12
"""Optional shortcut: dashboard only."""
import os
import site
import sys

scriptdir, _ = os.path.split(os.path.abspath(__file__))
pkgdir = os.path.join(scriptdir, "pkgs")
sys.path.insert(0, pkgdir)
site.addsitedir(pkgdir)

dash_dir = os.path.join(scriptdir, "dashboard")
sys.path.insert(0, dash_dir)
os.chdir(dash_dir)

from server import main

if __name__ == "__main__":
    main()
