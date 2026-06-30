"""
incident_service.py — SIEM Incident Correlation tier with persistent state management.
"""

import logging
import json
import os
from datetime import datetime
from services.wazuh_service import wazuh_service

log = logging.getLogger("wazuh-monitor.incident")

STATE_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "incidents_state.json")

class IncidentService:
    """Service to handle incident correlation rules and state mapping."""
    
    def __init__(self):
        self._ensure_state_dir()

    def _ensure_state_dir(self):
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        if not os.path.exists(STATE_FILE):
            with open(STATE_FILE, "w") as f:
                json.dump({}, f)

    def _load_states(self):
        try:
            if os.path.exists(STATE_FILE):
                with open(STATE_FILE, "r") as f:
                    return json.load(f)
        except Exception as exc:
            log.error("Failed to load incident states: %s", exc)
        return {}

    def _save_states(self, states):
        try:
            with open(STATE_FILE, "w") as f:
                json.dump(states, f, indent=2)
        except Exception as exc:
            log.error("Failed to save incident states: %s", exc)

    def get_incident_status(self, incident_id):
        states = self._load_states()
        return states.get(incident_id, "Open")

    def update_incident_status(self, incident_id, status):
        valid_statuses = ["Open", "Investigating", "Resolved", "False Positive"]
        if status not in valid_statuses:
            raise ValueError(f"Invalid status: {status}")
        states = self._load_states()
        states[incident_id] = status
        self._save_states(states)
        return status

    def get_incidents(self, status_filter=None, limit=20, offset=0):
        """
        Fetches raw security alerts and applies correlation logic to group them into incidents,
        enriching every timeline event with the full original alert metadata.
        """
        res = wazuh_service.get_alerts(limit=1000, show_infra=False)
        items = res.get("items", [])

        incidents = []
        by_host = {}
        
        for item in items:
            host = item.get("agent", {}).get("name", "manager")
            by_host.setdefault(host, []).append(item)

        states = self._load_states()

        for host, events in by_host.items():
            events_sorted = sorted(events, key=lambda x: x.get("timestamp", ""))
            
            # Rule 1: Privilege Escalation (Win Special Privilege / Service creation or root elevations)
            priv_logons = [e for e in events_sorted if e.get("raw", {}).get("data", {}).get("win", {}).get("system", {}).get("eventID") == "4672" or "privilege escalation" in e.get("rule", {}).get("groups", [])]
            service_createds = [e for e in events_sorted if e.get("raw", {}).get("data", {}).get("win", {}).get("system", {}).get("eventID") == "7045" or "service startup" in e.get("rule", {}).get("description", "").lower()]
            
            if priv_logons and service_createds:
                timeline = []
                for p in priv_logons:
                    username = p.get("raw", {}).get("data", {}).get("win", {}).get("eventdata", {}).get("subjectUserName", "Unknown")
                    timeline.append({
                        "timestamp": p.get("timestamp"),
                        "description": f"Special privilege assigned to {username}",
                        "alert": p
                    })
                for s in service_createds:
                    timeline.append({
                        "timestamp": s.get("timestamp"),
                        "description": s.get("rule", {}).get("description"),
                        "alert": s
                    })
                
                timeline.sort(key=lambda x: x["timestamp"])
                inc_id = f"INC-PRIV-{host}-{timeline[0]['timestamp'][:19].replace(':', '')}"
                incidents.append({
                    "id": inc_id,
                    "title": "Potential Privilege Escalation",
                    "severity": "High",
                    "host": host,
                    "timeline": timeline,
                    "recommendation": "Verify administrator activity and check if the created service was authorized.",
                    "timestamp": timeline[-1]["timestamp"],
                    "status": states.get(inc_id, "Open")
                })
                continue

            # Rule 2: Brute Force Attempt (5+ failed logons)
            failed_logins = [e for e in events_sorted if e.get("auth_status") == "failed"]
            success_logins = [e for e in events_sorted if e.get("auth_status") == "success"]
            
            if len(failed_logins) >= 5:
                by_user = {}
                for fl in failed_logins:
                    usr = fl.get("username", "—")
                    by_user.setdefault(usr, []).append(fl)
                
                for usr, fls in by_user.items():
                    if len(fls) >= 5:
                        timeline = [{
                            "timestamp": f.get("timestamp"),
                            "description": f"Failed login attempt for user '{usr}' from {f.get('src_ip')}",
                            "alert": f
                        } for f in fls]
                        
                        success_after = [s for s in success_logins if s.get("username") == usr and s.get("timestamp") > fls[-1].get("timestamp")]
                        
                        title = "Brute Force Attack (Multiple Failures)"
                        severity = "Medium"
                        rec = "Investigate source IP and lock down account if necessary."
                        if success_after:
                            title = "Successful Brute Force Attack"
                            severity = "Critical"
                            rec = "IMMEDIATE ATTENTION: User account compromise detected. Revoke sessions and reset password."
                            for sa in success_after[:1]:
                                timeline.append({
                                    "timestamp": sa.get("timestamp"),
                                    "description": f"Successful login for user '{usr}' from {sa.get('src_ip')}",
                                    "alert": sa
                                })

                        inc_id = f"INC-BF-{host}-{usr}-{timeline[0]['timestamp'][:19].replace(':', '')}"
                        incidents.append({
                            "id": inc_id,
                            "title": title,
                            "severity": severity,
                            "host": host,
                            "timeline": timeline,
                            "recommendation": rec,
                            "timestamp": timeline[-1]["timestamp"],
                            "status": states.get(inc_id, "Open")
                        })

            # Rule 3: Malware activity
            malware_events = [e for e in events_sorted if e.get("category") == "malware" or "virus" in e.get("rule", {}).get("description", "").lower()]
            if malware_events:
                timeline = [{
                    "timestamp": m.get("timestamp"),
                    "description": m.get("rule", {}).get("description"),
                    "alert": m
                } for m in malware_events]
                inc_id = f"INC-MAL-{host}-{timeline[0]['timestamp'][:19].replace(':', '')}"
                incidents.append({
                    "id": inc_id,
                    "title": "Malware Detection Alert",
                    "severity": "Critical",
                    "host": host,
                    "timeline": timeline,
                    "recommendation": "Quarantine the host from the network, initiate full system scan, and review suspicious processes.",
                    "timestamp": timeline[-1]["timestamp"],
                    "status": states.get(inc_id, "Open")
                })

        # Apply status filtering if specified
        if status_filter:
            incidents = [inc for inc in incidents if inc["status"].lower() == status_filter.lower()]

        incidents.sort(key=lambda x: x["timestamp"], reverse=True)
        total = len(incidents)
        paginated = incidents[offset : offset + limit]
        return {"items": paginated, "total": total}

incident_service = IncidentService()
