import os
import sys
import getpass

if sys.platform == "win32":
    BASE_APP_DIR = os.getenv("LOCALAPPDATA")
elif sys.platform == "darwin":
    BASE_APP_DIR = os.path.expanduser("~/Library/Application Support")
elif sys.platform.startswith("linux"):
    BASE_APP_DIR = os.path.expanduser("~/.local/share")  
else:
    BASE_APP_DIR = os.getcwd() 

APP_FOLDER = os.path.join(BASE_APP_DIR, "CipherAuth")
os.makedirs(APP_FOLDER, exist_ok=True)
ENCODED_FILE = os.path.join(APP_FOLDER, "creds.txt")

SERVICE_NAME = "CipherAuth"
USERNAME = getpass.getuser()

decrypt_key = None
toast_label = None
inner_frame = None
popup_window = None
frames = []
