"""
wazuh_service.py — All Wazuh API interactions.

Every function calls the Wazuh REST API through the auth_service JWT
and optionally caches results via cache_service.
"""

import logging
import requests
import urllib3
import os
import json
import threading
from datetime import datetime

from services.auth_service import auth
from services.cache_service import cache

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("wazuh-monitor.wazuh")

REQUEST_TIMEOUT = 15  # seconds


# ── Low-level helper ────────────────────────────────────────────

def _get(path, params=None, cache_key=None, cache_ttl=30):
    """
    Authenticated GET to the Wazuh API.
    Returns parsed JSON dict or raises.
    """
    # Check cache first
    if cache_key:
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

    if not auth.is_connected:
        raise ConnectionError("Not authenticated with Wazuh API")

    url = f"{auth.api_url}{path}"
    headers = auth.get_headers()

    try:
        resp = requests.get(
            url,
            headers=headers,
            params=params,
            verify=False,
            timeout=REQUEST_TIMEOUT,
        )
    except requests.exceptions.RequestException as exc:
        log.error("Request failed: %s %s → %s", "GET", path, exc)
        raise ConnectionError(f"Wazuh API request failed: {exc}") from exc

    if resp.status_code == 401:
        # Token expired — try refresh
        log.info("Got 401 — attempting re-auth")
        if auth.authenticate():
            headers = auth.get_headers()
            resp = requests.get(
                url, headers=headers, params=params,
                verify=False, timeout=REQUEST_TIMEOUT,
            )
        else:
            raise PermissionError("Wazuh re-authentication failed")

    if resp.status_code != 200:
        log.error("Wazuh API %s returned %d: %s", path, resp.status_code, resp.text[:300])
        raise RuntimeError(f"Wazuh API error {resp.status_code} on {path}")

    data = resp.json()

    if cache_key:
        cache.set(cache_key, data, cache_ttl)

    return data


# ── Agent endpoints ─────────────────────────────────────────────

def get_agent_summary():
    """GET /agents/summary/status — returns status counts."""
    data = _get(
        "/agents/summary/status",
        cache_key="agent_summary",
        cache_ttl=15,
    )
    # Wazuh 4.x: data.data.connection → {active, disconnected, …}
    # or data.data → {active, disconnected, …}
    connection = data.get("data", {})
    if "connection" in connection:
        connection = connection["connection"]
    return connection


def get_agents(offset=0, limit=20, search=None, status=None, group=None, sort=None):
    """GET /agents — paginated agent list."""
    params = {
        "offset": offset,
        "limit": limit,
        "select": "id,name,ip,status,os.name,os.version,os.platform,version,"
                  "lastKeepAlive,dateAdd,group,node_name,manager",
        "q": "id!=000",
    }
    if search:
        params["search"] = search
    if status:
        params["status"] = status
    if group:
        params["group"] = group
    if sort:
        params["sort"] = sort
    else:
        params["sort"] = "-lastKeepAlive"

    # Don't cache when filters are active (too many combos)
    ck = None
    if not any([search, status, group]) and offset == 0:
        ck = f"agents_{offset}_{limit}"

    data = _get("/agents", params=params, cache_key=ck, cache_ttl=30)
    items = data.get("data", {}).get("affected_items", [])
    total = data.get("data", {}).get("total_affected_items", 0)
    return {"items": items, "total": total}


def get_agent(agent_id):
    """GET /agents?agents_list=<id> — single agent detail."""
    data = _get(
        "/agents",
        params={"agents_list": agent_id, "select": "id,name,ip,status,os.name,"
                "os.version,os.platform,os.arch,version,lastKeepAlive,dateAdd,"
                "group,node_name,manager,registerIP,configSum,mergedSum"},
        cache_key=f"agent_{agent_id}",
        cache_ttl=15,
    )
    items = data.get("data", {}).get("affected_items", [])
    if items:
        return items[0]
    return None


# ── Alert / log endpoints ──────────────────────────────────────

def get_alerts(offset=0, limit=20, level=None, agent=None,
               group=None, search=None, sort=None, tag=None):
    """
    GET /manager/logs — fetch manager logs (used as alerts source).
    Wazuh 4.x manager/logs returns syslog-style entries.

    When level="error" is requested, also fetch "critical" entries
    since the Wazuh API only supports exact level matching.
    """
    params = {
        "offset": offset,
        "limit": limit,
    }
    if sort:
        params["sort"] = sort
    else:
        params["sort"] = "-timestamp"
    if search:
        params["search"] = search
    if tag:
        params["tag"] = tag

    # If filtering for "error" level, also include "critical"
    if level and level.lower() == "error":
        all_items = []
        total = 0
        for lv in ("error", "critical"):
            p = {**params, "level": lv}
            try:
                data = _get("/manager/logs", params=p, cache_ttl=15)
                items = data.get("data", {}).get("affected_items", [])
                total += data.get("data", {}).get("total_affected_items", 0)
                all_items.extend(items)
            except Exception:
                pass
        # Sort combined results by timestamp descending
        all_items.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        # Apply limit
        all_items = all_items[:limit]
        normalised = [_normalise_log(item) for item in all_items]
        return {"items": normalised, "total": total}
    else:
        if level:
            params["level"] = level
        data = _get("/manager/logs", params=params, cache_ttl=15)
        items = data.get("data", {}).get("affected_items", [])
        total = data.get("data", {}).get("total_affected_items", 0)
        normalised = [_normalise_log(item) for item in items]
        return {"items": normalised, "total": total}


def get_security_alerts(offset=0, limit=20, level_min=None, agent_name=None,
                        group=None, search=None, sort=None):
    """
    Try the /alerts endpoint (requires Wazuh indexer).
    Falls back to /manager/logs if not available.
    """
    try:
        params = {
            "offset": offset,
            "limit": limit,
            "sort": sort or "-timestamp",
        }
        if level_min:
            params["q"] = f"rule.level>={level_min}"

        data = _get("/alerts", params=params, cache_ttl=15)
        items = data.get("data", {}).get("affected_items", [])
        total = data.get("data", {}).get("total_affected_items", 0)
        return {"items": items, "total": total}
    except Exception:
        # Fallback to manager logs
        return get_alerts(offset=offset, limit=limit, level=level_min,
                          search=search, sort=sort)


def _normalise_log(item):
    """Convert a Wazuh manager/logs entry into a uniform alert dict."""
    # Manager logs have: timestamp, tag, level, description
    level_num = _log_level_to_num(item.get("level", "info"))
    return {
        "timestamp": item.get("timestamp", ""),
        "rule": {
            "id": item.get("tag", "—"),
            "level": level_num,
            "description": item.get("description", ""),
            "groups": [item.get("tag", "system")],
        },
        "agent": {
            "id": "000",
            "name": "manager",
            "ip": "127.0.0.1",
        },
        "decoder": {"name": item.get("tag", "")},
        "raw": item,
    }


def _log_level_to_num(level_str):
    """Map Wazuh log-level string to a numeric severity."""
    mapping = {
        "critical": 15,
        "error": 12,
        "warning": 7,
        "info": 3,
        "debug": 1,
    }
    return mapping.get(level_str.lower(), 3)


# ── Statistics ──────────────────────────────────────────────────

def get_stats():
    """Build a dashboard stats payload with real severity breakdown."""
    try:
        summary = get_agent_summary()
    except Exception:
        summary = {}

    active = summary.get("active", 0)
    disconnected = summary.get("disconnected", 0)
    pending = summary.get("pending", 0)
    never = summary.get("never_connected", 0)
    total = active + disconnected + pending + never

    # Try to get alert counts broken down by severity
    alert_total = 0
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    info_count = 0
    top_tags = []  # for "Top Alerted Agents" chart (tags = sources)
    try:
        logs = _get("/manager/logs/summary", cache_key="log_summary", cache_ttl=30)
        # Sum up all tag counts
        log_data = logs.get("data", {}).get("affected_items", [])
        if isinstance(log_data, list):
            # Each entry is a dict like {"wazuh-authd": {"all": 7, "info": 6, ...}}
            for entry in log_data:
                for tag_name, counts in entry.items():
                    if isinstance(counts, dict):
                        tag_all = counts.get("all", 0)
                        alert_total += tag_all
                        critical_count += counts.get("critical", 0)
                        high_count += counts.get("error", 0)
                        medium_count += counts.get("warning", 0)
                        low_count += counts.get("info", 0)
                        info_count += counts.get("debug", 0)
                        top_tags.append({"name": tag_name, "count": tag_all})
            # Sort by count descending, take top 5
            top_tags.sort(key=lambda x: x["count"], reverse=True)
            top_tags = top_tags[:5]
        elif isinstance(log_data, dict):
            for tag, counts in log_data.items():
                if isinstance(counts, dict):
                    tag_all = counts.get("all", 0)
                    alert_total += tag_all
                    critical_count += counts.get("critical", 0)
                    high_count += counts.get("error", 0)
                    medium_count += counts.get("warning", 0)
                    low_count += counts.get("info", 0)
                    info_count += counts.get("debug", 0)
                    top_tags.append({"name": tag, "count": tag_all})
            top_tags.sort(key=lambda x: x["count"], reverse=True)
            top_tags = top_tags[:5]
    except Exception as exc:
        log.warning("Could not fetch log summary: %s", exc)

    return {
        "agents": {
            "total": total,
            "active": active,
            "disconnected": disconnected,
            "pending": pending,
            "never_connected": never,
        },
        "alerts": {
            "total": alert_total,
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "info": info_count,
        },
        "top_sources": top_tags,
    }


# ── Manager info ────────────────────────────────────────────────

def get_manager_info():
    """GET /manager/info"""
    data = _get("/manager/info", cache_key="manager_info", cache_ttl=60)
    return data.get("data", {}).get("affected_items", [data.get("data", {})])[0] \
        if isinstance(data.get("data", {}).get("affected_items"), list) \
        else data.get("data", {})


# ── Groups ──────────────────────────────────────────────────────

def get_groups():
    """GET /groups — list all agent groups."""
    try:
        data = _get("/groups", cache_key="groups", cache_ttl=60)
        items = data.get("data", {}).get("affected_items", [])
        return [g.get("name", "") for g in items if g.get("name")]
    except Exception:
        return []


# ── SOC Security Events & Inventory Parsing ─────────────────────

ALERTS_JSON_PATH = "/var/ossec/logs/archives/archives.json"

_alerts_cache = {
    "mtime": 0.0,
    "size": 0,
    "parsed_events": [],
    "last_pos": 0
}
_alerts_cache_lock = threading.Lock()

def _read_last_rule_lines(filepath, num_lines=15000):
    """
    Reads the file backwards, returning up to `num_lines` lines that contain a rule block.
    """
    try:
        stat = os.stat(filepath)
        size = stat.st_size
    except OSError:
        return []

    lines = []
    chunk_size = 65536
    buffer = b""
    
    try:
        with open(filepath, "rb") as f:
            f.seek(0, os.SEEK_END)
            pos = f.tell()
            while pos > 0 and len(lines) < num_lines:
                read_size = min(chunk_size, pos)
                pos -= read_size
                f.seek(pos)
                chunk = f.read(read_size)
                buffer = chunk + buffer
                
                parts = buffer.split(b"\n")
                buffer = parts[0]
                for line in reversed(parts[1:]):
                    if b'"rule":' in line:
                        lines.append(line.decode("utf-8", errors="ignore").strip())
                        if len(lines) >= num_lines:
                            break
            
            if len(lines) < num_lines and b'"rule":' in buffer:
                lines.append(buffer.decode("utf-8", errors="ignore").strip())
                
        lines.reverse()
        return lines
    except Exception:
        return []

def _get_cached_security_alerts():
    """
    Thread-safe helper that returns a cached list of parsed security alerts.
    Re-parses only if the file's modification time or size has changed.
    Uses delta-reading to read only newly appended data for O(delta) performance.
    """
    global _alerts_cache
    if not os.path.exists(ALERTS_JSON_PATH):
        return []

    try:
        stat = os.stat(ALERTS_JSON_PATH)
        current_mtime = stat.st_mtime
        current_size = stat.st_size
    except Exception as exc:
        log.error("Failed to stat archives.json: %s", exc)
        return []

    with _alerts_cache_lock:
        # 1. No change in size
        if current_size == _alerts_cache["size"]:
            return _alerts_cache["parsed_events"]

        # 2. File was rotated, shrunk, or first load
        if current_size < _alerts_cache["size"] or _alerts_cache["size"] == 0:
            alerts = []
            try:
                lines = _read_last_rule_lines(ALERTS_JSON_PATH, 15000)
                for line in lines:
                    try:
                        raw_event = json.loads(line)
                        parsed = _normalize_security_event(raw_event)
                        if parsed:
                            alerts.append(parsed)
                    except Exception:
                        continue

                # Sort newest first
                alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
                
                # Update cache
                _alerts_cache["mtime"] = current_mtime
                _alerts_cache["size"] = current_size
                _alerts_cache["parsed_events"] = alerts[:15000]
                _alerts_cache["last_pos"] = current_size
                log.info("Initial loaded archives.json cache: %d events", len(_alerts_cache["parsed_events"]))
            except Exception as exc:
                log.error("Failed initial load of archives.json: %s", exc)
                return _alerts_cache["parsed_events"]

            return _alerts_cache["parsed_events"]

        # 3. File grew (Delta load)
        else:
            last_pos = _alerts_cache["last_pos"]
            new_events = []
            try:
                with open(ALERTS_JSON_PATH, "rb") as f:
                    f.seek(last_pos)
                    new_data = f.read(current_size - last_pos)
                
                lines = new_data.split(b"\n")
                for line in lines:
                    line_str = line.decode("utf-8", errors="ignore").strip()
                    if not line_str:
                        continue
                    try:
                        raw_event = json.loads(line_str)
                        parsed = _normalize_security_event(raw_event)
                        if parsed:
                            new_events.append(parsed)
                    except Exception:
                        continue
            except Exception as exc:
                log.error("Failed delta reading archives.json: %s", exc)
                # Fallback: reset cache size to trigger a full reload next time
                _alerts_cache["size"] = 0
                return _alerts_cache["parsed_events"]

            if new_events:
                # Sort new events newest first
                new_events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
                # Prepend new events to existing cache
                combined = new_events + _alerts_cache["parsed_events"]

                # Keep only last 15,000 events
                _alerts_cache["parsed_events"] = combined[:15000]

            _alerts_cache["mtime"] = current_mtime
            _alerts_cache["size"] = current_size
            _alerts_cache["last_pos"] = current_size
            log.info("Delta loaded archives.json cache: added %d events, total cache size: %d", len(new_events), len(_alerts_cache["parsed_events"]))
            return _alerts_cache["parsed_events"]


def read_security_alerts(offset=0, limit=20, search=None, level=None, agent=None, category=None, show_infra=False):
    """
    Reads SIEM alerts from cached /var/ossec/logs/alerts/alerts.json.
    Filters by:
      - search keyword
      - minimum severity level
      - agent name/ID
      - category tag (authentication, usb, applications, malware, system, security)
      - show_infra toggle (if false, excludes internal maintenance logs)
    """
    alerts = _get_cached_security_alerts()

    # Filter
    filtered = []
    for item in alerts:
        # 1. Noise reduction: skip infrastructure unless requested
        if not show_infra:
            desc = item.get("rule", {}).get("description", "").lower()
            groups = item.get("rule", {}).get("groups", [])
            decoder = item.get("decoder", {}).get("name", "").lower()
            infra_keywords = ["syscollector", "rootcheck", "indexer-connector", "wazuh-modulesd", "inventory synchronization", "evaluation started", "evaluation finished"]
            if any(k in desc or k in groups or k in decoder for k in infra_keywords):
                continue

        # 2. Agent filter (matches agent ID or agent Name)
        if agent:
            agent_id = item.get("agent", {}).get("id")
            agent_name = item.get("agent", {}).get("name", "").lower()
            if agent != agent_id and agent.lower() != agent_name:
                continue

        # 3. Level filter (matches minimum numeric level)
        if level:
            try:
                min_lvl = int(level)
                if item.get("rule", {}).get("level", 0) < min_lvl:
                    continue
            except ValueError:
                # Match by string level: critical, error, warning, info
                mapping = {"critical": 12, "error": 9, "warning": 5, "info": 3}
                target_lvl = mapping.get(level.lower(), 3)
                if item.get("rule", {}).get("level", 0) < target_lvl:
                    continue

        # 4. Category filter
        if category:
            if item.get("category") != category.lower():
                continue

        # 5. Text Search filter (scans description, username, source IP, rule ID, decoder, groups)
        if search:
            search_lower = search.lower()
            desc = item.get("rule", {}).get("description", "").lower()
            rule_id = str(item.get("rule", {}).get("id", ""))
            groups = " ".join(item.get("rule", {}).get("groups", [])).lower()
            decoder = item.get("decoder", {}).get("name", "").lower()
            username = item.get("username", "").lower()
            src_ip = item.get("src_ip", "").lower()
            agent_name = item.get("agent", {}).get("name", "").lower()
            
            match_found = (
                search_lower in desc or
                search_lower in rule_id or
                search_lower in groups or
                search_lower in decoder or
                search_lower in username or
                search_lower in src_ip or
                search_lower in agent_name
            )
            if not match_found:
                continue

        filtered.append(item)

    total = len(filtered)
    paginated = filtered[offset : offset + limit]
    return {"items": paginated, "total": total}


def _normalize_security_event(raw):
    """
    Parses a raw Wazuh alert JSON from archives.json or alerts.json into a unified SIEM event.
    Annotates with category, username, source IP, etc.
    """
    rule = raw.get("rule")
    if not rule or not isinstance(rule, dict) or not rule.get("id"):
        return None

    desc = rule.get("description", "")
    desc_lower = desc.lower()
    groups = rule.get("groups", [])
    if not isinstance(groups, list):
        groups = []

    agent = raw.get("agent")
    if not isinstance(agent, dict):
        agent = {}

    decoder = raw.get("decoder")
    if not isinstance(decoder, dict):
        decoder = {}
    decoder_name = decoder.get("name", "")
    decoder_lower = decoder_name.lower()

    category = "security"
    username = "—"
    src_ip = "—"
    auth_status = None

    # Identify Sysmon Events
    is_sysmon = False
    sysmon_id = None
    event_id = None
    win_data = raw.get("data", {})
    if isinstance(win_data, dict):
        win_data = win_data.get("win", {})
    else:
        win_data = {}

    if isinstance(win_data, dict) and win_data:
        system = win_data.get("system", {})
        if isinstance(system, dict):
            event_id = str(system.get("eventID", ""))
            provider_name = system.get("providerName", "").lower()
            if "sysmon" in provider_name or "sysmon" in groups:
                is_sysmon = True
                sysmon_id = event_id

    # Safely convert rule ID to integer for ranges
    rule_id_str = rule.get("id", "0")
    try:
        rule_id = int(rule_id_str)
    except (ValueError, TypeError):
        rule_id = 0

    # 1. Authentication Check
    auth_success = (
        "authentication_success" in groups
        or "win_authentication" in groups
        or (5501 <= rule_id <= 5504)
        or event_id in ["4624", "4672"]
    )
    auth_failed = (
        "authentication_failed" in groups
        or rule_id == 5503
        or event_id in ["4625"]
    )

    if auth_success or auth_failed or event_id in ["4624", "4625", "4672", "4740"] or any(k in desc_lower for k in ["logon", "login", "authentication", "auth", "lockout", "password"]):
        category = "authentication"
        
        # Determine status
        if event_id:
            if event_id in ["4624", "4672"]:
                auth_status = "success"
            elif event_id in ["4625"]:
                auth_status = "failed"
            elif event_id in ["4740"]:
                auth_status = "lockout"
            else:
                system_obj = win_data.get("system", {})
                severity = system_obj.get("severityValue", "") if isinstance(system_obj, dict) else ""
                if "success" in severity.lower() or "audit_success" in severity.lower():
                    auth_status = "success"
                elif "failure" in severity.lower() or "audit_failure" in severity.lower():
                    auth_status = "failed"
                else:
                    if "lockout" in desc_lower or "locked" in desc_lower:
                        auth_status = "lockout"
                    elif "failed" in desc_lower or "failure" in desc_lower or "invalid" in desc_lower:
                        auth_status = "failed"
                    else:
                        auth_status = "success"
        else:
            if "authentication_success" in groups:
                auth_status = "success"
            elif "authentication_failed" in groups or "invalid_login" in groups:
                auth_status = "failed"
            else:
                if "lockout" in desc_lower or "locked" in desc_lower:
                    auth_status = "lockout"
                elif "failed" in desc_lower or "failure" in desc_lower or "invalid" in desc_lower or "denied" in desc_lower:
                    auth_status = "failed"
                elif "success" in desc_lower or "accepted" in desc_lower or "opened" in desc_lower:
                    auth_status = "success"
                else:
                    auth_status = "success"

        # Extract username
        data = raw.get("data", {})
        if not isinstance(data, dict):
            data = {}
        username = data.get("dstuser") or data.get("srcuser") or data.get("username")
        if not username and win_data:
            eventdata = win_data.get("eventdata", {})
            if isinstance(eventdata, dict):
                username = eventdata.get("targetUserName") or eventdata.get("subjectUserName")
        if not username:
            username = "—"

        # Extract source IP
        src_ip = data.get("srcip") or data.get("src_ip")
        if not src_ip and win_data:
            eventdata = win_data.get("eventdata", {})
            if isinstance(eventdata, dict):
                src_ip = eventdata.get("ipAddress") or eventdata.get("clientIP")
        if not src_ip:
            src_ip = "—"

    # 2. USB Activity Check (exclude syscollector interface updates)
    elif (any(k in desc_lower or k in groups for k in ["usb", "mass storage", "removable media", "mount", "unmount", "inserted", "removed"]) or event_id in ["6416"]) and decoder_lower != "syscollector":
        category = "usb"
        data = raw.get("data", {})
        if not isinstance(data, dict):
            data = {}
        username = data.get("srcuser") or data.get("dstuser") or "—"
        src_ip = "—"

    # 3. Applications / Software Change Check
    elif any(k in desc_lower or k in groups for k in ["dpkg", "yum", "rpm", "software_added", "software_removed", "software_updated", "installed", "uninstall"]) or decoder_lower == "dpkg-decoder":
        category = "applications"
        data = raw.get("data", {})
        if not isinstance(data, dict):
            data = {}
        package_name = data.get("package") or data.get("name")
        version = data.get("version")
        if package_name:
            desc = f"Package {package_name} ({version or 'unknown'}) change detected"
        elif decoder_lower == "dpkg-decoder":
            full_log = raw.get("full_log", "")
            desc = f"Dpkg Log: {full_log}"

    # 4. Malware Check
    elif any(k in desc_lower or k in groups for k in ["virus", "malware", "trojan", "clamav", "defender", "antivirus"]):
        category = "malware"

    # 5. Sysmon mappings
    elif is_sysmon:
        category = "system"
        if sysmon_id == "1":
            category = "security"
            eventdata = win_data.get("eventdata", {})
            image_name = eventdata.get("image", "unknown") if isinstance(eventdata, dict) else "unknown"
            desc = f"Process Created: {image_name}"
        elif sysmon_id == "3":
            eventdata = win_data.get("eventdata", {})
            dest_ip = eventdata.get("destinationIp", "unknown") if isinstance(eventdata, dict) else "unknown"
            dest_port = eventdata.get("destinationPort", "") if isinstance(eventdata, dict) else ""
            desc = f"Network Connection: {dest_ip}:{dest_port}"
        elif sysmon_id in ["12", "13", "14"]:
            eventdata = win_data.get("eventdata", {})
            target_obj = eventdata.get("targetObject", "unknown") if isinstance(eventdata, dict) else "unknown"
            desc = f"Registry Change: {target_obj}"

    # 6. Service creation/installation
    elif "service_installation" in groups or "service_creation" in groups or any(k in desc_lower for k in ["service startup", "service created", "service installed"]) or event_id == "7045":
        category = "system"

    # Default category determination if none matches
    if category == "security" and any(k in desc_lower for k in ["apparmor", "selinux", "policy violation", "privilege escalation", "sudo"]):
        category = "security"

    # Determine description and level for logs without a rule
    if not desc:
        if win_data:
            system = win_data.get("system", {})
            if isinstance(system, dict):
                msg = system.get("message", "")
                if msg:
                    first_line = msg.split("\n")[0].split("\r")[0].strip('" \t\r\n')
                    desc = first_line
                else:
                    desc = f"Windows Event Channel Log (ID {event_id})"
            else:
                desc = f"Windows Event Channel Log (ID {event_id})"
        elif raw.get("full_log"):
            full_log = raw.get("full_log", "").strip()
            desc = (full_log[:97] + "...") if len(full_log) > 100 else full_log
        else:
            desc = f"Wazuh Event (Decoder: {decoder_name or 'unknown'})"

    # Map dynamic levels for archives.json logs without a rule
    rule_level = rule.get("level")
    if rule_level is None:
        if category == "malware":
            rule_level = 12
        elif category == "authentication":
            if auth_status == "lockout":
                rule_level = 9
            elif auth_status == "failed":
                rule_level = 5
            else:
                rule_level = 3
        elif event_id == "7045":
            rule_level = 4
        else:
            rule_level = 3

    return {
        "timestamp": raw.get("timestamp", ""),
        "rule": {
            "id": rule.get("id", "—"),
            "level": rule_level,
            "description": desc,
            "groups": groups,
        },
        "agent": {
            "id": agent.get("id", "000"),
            "name": agent.get("name", "manager"),
            "ip": agent.get("ip", "127.0.0.1"),
        },
        "decoder": {"name": decoder_name},
        "category": category,
        "username": username,
        "src_ip": src_ip,
        "auth_status": auth_status,
        "raw": raw,
    }





def get_security_summary_stats():
    """
    Aggregates stats for 'Today' (based on event timestamp) from /var/ossec/logs/alerts/alerts.json.
    """
    stats = {
        "failed_logins": 0,
        "successful_logins": 0,
        "locked_accounts": 0,
        "usb_events": 0,
        "software_changes": 0,
        "malware_alerts": 0,
        "offline_endpoints": 0,
    }
    
    # Get offline endpoints from Wazuh API
    try:
        summary = get_agent_summary()
        stats["offline_endpoints"] = summary.get("disconnected", 0)
    except Exception:
        pass

    today_str = datetime.now().strftime("%Y-%m-%d")
    alerts = _get_cached_security_alerts()

    for parsed in alerts:
        try:
            ts = parsed.get("timestamp", "")
            if not ts:
                continue
            
            # Early break: since alerts are sorted newest-first,
            # we can stop processing as soon as we reach events older than today.
            if ts[:10] < today_str:
                break
                
            if today_str not in ts:
                continue
            
            cat = parsed.get("category")
            if cat == "authentication":
                status = parsed.get("auth_status")
                if status == "success":
                    stats["successful_logins"] += 1
                elif status == "failed":
                    stats["failed_logins"] += 1
                elif status == "lockout":
                    stats["locked_accounts"] += 1
            elif cat == "usb":
                stats["usb_events"] += 1
            elif cat == "applications":
                stats["software_changes"] += 1
            elif cat == "malware":
                stats["malware_alerts"] += 1
        except Exception:
            continue

    return stats


def get_consolidated_applications():
    """
    Queries /syscollector/{agent_id}/packages for all active agents
    and compiles a list of applications.
    """
    consolidated = []
    
    try:
        agents_data = get_agents(limit=100)
        agents = agents_data.get("items", [])
        
        # Include manager
        agents.append({
            "id": "000",
            "name": "manager",
            "ip": "127.0.0.1",
            "status": "active"
        })
        
        for agent in agents:
            if agent.get("status") != "active":
                continue
            agent_id = agent.get("id")
            agent_name = agent.get("name")
            
            try:
                path = f"/syscollector/{agent_id}/packages"
                res = _get(path, params={"limit": 500}, cache_key=f"sys_packages_{agent_id}", cache_ttl=120)
                packages = res.get("data", {}).get("affected_items", [])
                
                for pkg in packages:
                    consolidated.append({
                        "agent_id": agent_id,
                        "agent_name": agent_name,
                        "name": pkg.get("name", "—"),
                        "version": pkg.get("version", "—"),
                        "vendor": pkg.get("vendor", "—"),
                        "install_date": pkg.get("install_time", "—")
                    })
            except Exception as e:
                log.warning("Could not fetch packages for agent %s: %s", agent_id, e)
                
    except Exception as exc:
        log.error("Failed to consolidate applications: %s", exc)
        
    return consolidated
