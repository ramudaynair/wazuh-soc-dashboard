"""
wazuh_service.py — All Wazuh API interactions.

Every function calls the Wazuh REST API through the auth_service JWT
and optionally caches results via cache_service.
"""

import logging
import requests
import urllib3

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
    """
    params = {
        "offset": offset,
        "limit": limit,
    }
    if sort:
        params["sort"] = sort
    else:
        params["sort"] = "-timestamp"
    if level:
        params["level"] = level
    if search:
        params["search"] = search
    if tag:
        params["tag"] = tag

    data = _get("/manager/logs", params=params, cache_ttl=15)
    items = data.get("data", {}).get("affected_items", [])
    total = data.get("data", {}).get("total_affected_items", 0)

    # Normalise each log entry into our alert format
    normalised = []
    for item in items:
        normalised.append(_normalise_log(item))

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
    """Build a dashboard stats payload."""
    try:
        summary = get_agent_summary()
    except Exception:
        summary = {}

    active = summary.get("active", 0)
    disconnected = summary.get("disconnected", 0)
    pending = summary.get("pending", 0)
    never = summary.get("never_connected", 0)
    total = active + disconnected + pending + never

    # Try to get alert counts
    alert_total = 0
    critical_count = 0
    high_count = 0
    try:
        logs = _get("/manager/logs/summary", cache_key="log_summary", cache_ttl=30)
        # Sum up all tag counts
        log_data = logs.get("data", {}).get("affected_items", [])
        if isinstance(log_data, list):
            for entry in log_data:
                alert_total += entry.get("all", 0)
                critical_count += entry.get("critical", 0) + entry.get("error", 0)
                high_count += entry.get("warning", 0)
        elif isinstance(log_data, dict):
            for tag, counts in log_data.items():
                if isinstance(counts, dict):
                    alert_total += counts.get("all", 0)
                    critical_count += counts.get("critical", 0) + counts.get("error", 0)
                    high_count += counts.get("warning", 0)
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
        },
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
