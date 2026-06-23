import os
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

print(f"--- Environment Debug ---")
print(f"Current working directory: {os.getcwd()}")
print(f"Expected config path: {CONFIG_PATH}")
print(f"Config file exists: {os.path.exists(CONFIG_PATH)}")

def print_structure(d, indent=""):
    for k, v in d.items():
        if isinstance(v, dict):
            print(f"{indent}{k} (dict):")
            print_structure(v, indent + "  ")
        elif isinstance(v, list):
            print(f"{indent}{k} (list of length {len(v)}):")
            for i, item in enumerate(v):
                if isinstance(item, dict):
                    print(f"{indent}  [{i}] (dict):")
                    print_structure(item, indent + "    ")
                else:
                    print(f"{indent}  [{i}]: {type(item).__name__}")
        else:
            # Mask password values to prevent leaking secrets in chat
            if "pass" in k.lower():
                val_repr = f"string (length={len(str(v))})" if isinstance(v, str) else f"{type(v).__name__}"
                is_empty = not bool(v)
                print(f"{indent}{k}: {val_repr} [empty={is_empty}]")
            else:
                print(f"{indent}{k}: {repr(v)}")

if os.path.exists(CONFIG_PATH):
    print("\n--- JSON Structure ---")
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
        print_structure(cfg)
    except Exception as e:
        print(f"Error parsing config file: {e}")
else:
    print("\nCould not find config.json!")
