import json, sys, os
sys.path.insert(0, '.')
from services.wazuh_service import wazuh_service

# Load alerts
alerts = wazuh_service._get_cached_security_alerts()
print(f"Total alerts in cache: {len(alerts)}")

sysmon_counts = {}
for a in alerts:
    sys = a.get("sysmon")
    if sys:
        eid = sys.get("event_id")
        sysmon_counts[eid] = sysmon_counts.get(eid, 0) + 1

print("\n=== SYSMON EVENT ID BREAKDOWN ===")
for eid, cnt in sorted(sysmon_counts.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 999):
    print(f"Event ID {eid}: {cnt} events")

# Check why network connection (ID 3) might not be parsed
# Let's inspect a raw line from archives.json that has event_id 3 or network connection
print("\n=== SCANNING ARCHIVES.JSON FOR EVENT ID 3 OR NETWORK ===")
raw_count = 0
found_raw = []
if os.path.exists(wazuh_service.alerts_json_path):
    with open(wazuh_service.alerts_json_path, 'r', encoding='utf-8') as f:
        for line in f:
            if "eventChannel" in line or "eventdata" in line:
                if '"event_id":"3"' in line or '"eventID":"3"' in line or '"EventID":3' in line or 'EventID": 3' in line or 'EventID\":\"3\"' in line or '"event_id": 3' in line or 'destinationIp' in line.lower() or 'destinationport' in line.lower():
                    raw_count += 1
                    if len(found_raw) < 2:
                        found_raw.append(line)
print(f"Found {raw_count} raw candidates for Event ID 3 / network connection in archives.json")
for line in found_raw:
    try:
        ev = json.loads(line)
        print("\nCandidate Event:")
        print(json.dumps(ev.get("data", {}).get("win", {}).get("system", {}), indent=2))
        print("eventdata:", json.dumps(ev.get("data", {}).get("win", {}).get("eventdata", {}), indent=2))
        normalized = wazuh_service._normalize_security_event(ev)
        print("Normalized Sysmon block:", json.dumps(normalized.get("sysmon") if normalized else None, indent=2))
    except Exception as exc:
        print("Error parsing candidate:", exc)
