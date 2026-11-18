import os
import sys
import site
here = os.path.dirname(os.path.abspath(__file__))
pkgs = os.path.join(here, "pkgs")
sys.path.insert(0,pkgs)
site.addsitedir(pkgs)
dash = os.path.join(here,"dashboard")
sys.path.insert(0,dash)
os.chdir(dash)
from server import main
main()