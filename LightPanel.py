import sys
import os

if sys.platform == "win32":
    os.system("python LightPanelWin.py")
else:
    os.system("sudo venv/bin/python LightPanelLin.py")