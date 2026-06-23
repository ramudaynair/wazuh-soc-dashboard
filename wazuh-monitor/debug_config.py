import os
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

print(f"Current working directory: {os.getcwd()}")
print(f"Expected config path: {CONFIG_PATH}")
print(f"Config file exists: {os.path.exists(CONFIG_PATH)}")

if os.path.exists(CONFIG_PATH):
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
        
        wz = cfg.get("wazuh", {})
        print("\n--- Loaded 'wazuh' block ---")
        print(f"api_url: {repr(wz.get('api_url'))}")
        print(f"username: {repr(wz.get('username'))}")
        password = wz.get('password')
        print(f"password present: {bool(password)}")
        if password:
            print(f"password length: {len(password)}")
            print(f"password starts with: {repr(password[:2])}...")
        
        print("\n--- Checking condition ---")
        api_url = wz.get("api_url", "")
        username = wz.get("username", "")
        print(f"api_url present: {bool(api_url)}")
        print(f"username present: {bool(username)}")
        print(f"All three present: {bool(api_url and username and password)}")
        
    except Exception as e:
        print(f"Error reading/parsing config: {e}")
else:
    print("Could not find config.json!")
