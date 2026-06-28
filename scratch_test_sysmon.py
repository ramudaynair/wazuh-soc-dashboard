import json, sys, os
sys.path.insert(0, '.')
from services.wazuh_service import wazuh_service, _normalize_security_event

# Read and parse a candidate
if os.path.exists(wazuh_service.alerts_json_path):
    with open(wazuh_service.alerts_json_path, 'r', encoding='utf-8') as f:
        for line in f:
            if "eventChannel" in line or "eventdata" in line:
                if '"event_id":"3"' in line or '"eventID":"3"' in line or '"EventID":3' in line or 'EventID": 3' in line or 'EventID\":\"3\"' in line or '"event_id": 3' in line:
                    ev = json.loads(line)
                    print("RAW RULE:", json.dumps(ev.get("rule"), indent=2))
                    print("RAW DATA:", json.dumps(ev.get("data", {}).get("win", {}).get("system"), indent=2))
                    normalized = _normalize_security_event(ev)
                    print("NORMALIZED:", json.dumps(normalized, indent=2))
                    break
