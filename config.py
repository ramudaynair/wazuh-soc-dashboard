from dotenv import load_dotenv
import os

load_dotenv()

HOST = os.getenv("WAZUH_HOST", "https://127.0.0.1:55000")
USERNAME = os.getenv("WAZUH_USERNAME", "wazuh-wui")
PASSWORD = os.getenv("WAZUH_PASSWORD", "")
VERIFY_SSL = os.getenv("VERIFY_SSL", "false").lower() == "true"

# Dashboard Settings
REFRESH_INTERVAL = int(os.getenv("REFRESH_INTERVAL", "30"))
THEME = os.getenv("THEME", "dark")
PAGE_SIZE = int(os.getenv("PAGE_SIZE", "20"))
