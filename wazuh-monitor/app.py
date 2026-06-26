"""
app.py — Wazuh Monitor SOC Dashboard

Flask application that proxies all Wazuh API calls, serves the frontend,
and exposes clean internal REST endpoints.
"""

import json
import os
import logging

from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify

# Load .env
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

import config
from services.wazuh_service import wazuh_service
from services.incident_service import incident_service
from services.dashboard_service import get_dashboard_data
from services.cache_service import cache

# ── Logging ─────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(name)-28s  %(levelname)-7s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("wazuh-monitor")

# ── Flask App ───────────────────────────────────────────────────

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)
app.config["JSON_SORT_KEYS"] = False


def init_auth_from_config():
    """Initialize the Wazuh service and attempt silent login on startup."""
    try:
        if wazuh_service.login():
            log.info("Auto-connected to Wazuh on startup")
        else:
            log.warning("Auto-connect failed: %s", wazuh_service.last_error)
    except Exception as exc:
        log.warning("Auto-connect failed with exception: %s", exc)


# ── Page routes ─────────────────────────────────────────────────

@app.route("/")
def page_dashboard():
    return render_template("dashboard.html",
                           page="dashboard",
                           refresh_interval=config.REFRESH_INTERVAL)


@app.route("/incidents")
def page_incidents():
    return render_template("incidents.html",
                           page="incidents",
                           page_size=config.PAGE_SIZE)


@app.route("/logs")
def page_logs():
    return render_template("logs.html",
                           page="logs",
                           page_size=config.PAGE_SIZE)


@app.route("/agents")
def page_agents():
    return render_template("agents.html",
                           page="agents",
                           page_size=config.PAGE_SIZE)


@app.route("/agents/<agent_id>")
def page_agent_detail(agent_id):
    return render_template("agent_detail.html", page="agents", agent_id=agent_id)


@app.route("/settings")
def page_settings():
    return render_template("settings.html", page="settings")


@app.route("/authentication")
def page_authentication():
    return render_template("authentication.html",
                           page="authentication",
                           page_size=config.PAGE_SIZE)


@app.route("/applications")
def page_applications():
    return render_template("applications.html",
                           page="applications",
                           page_size=config.PAGE_SIZE)


# ── API: Connection ─────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    """Return current connection status (no secrets)."""
    return jsonify(wazuh_service.status())


@app.route("/api/connect", methods=["POST"])
def api_connect():
    """Authenticate with Wazuh using credentials from config or request body."""
    body = request.get_json(silent=True) or {}

    api_url = body.get("api_url")
    username = body.get("username")
    password = body.get("password")
    verify = body.get("verify_ssl", False)

    if api_url and username and password:
        wazuh_service.host = api_url.rstrip("/")
        wazuh_service.username = username
        wazuh_service.password = password
        wazuh_service.verify_ssl = verify

    if wazuh_service.login():
        return jsonify({"success": True, "status": wazuh_service.status()})
    else:
        return jsonify({"error": wazuh_service.last_error}), 401


@app.route("/api/disconnect", methods=["POST"])
def api_disconnect():
    wazuh_service._token = None
    wazuh_service.is_connected = False
    cache.clear()
    return jsonify({"success": True})


@app.route("/api/test-connection", methods=["POST"])
def api_test_connection():
    """Test connection with provided credentials without saving."""
    body = request.get_json(silent=True) or {}
    api_url = body.get("api_url", "").rstrip("/")
    username = body.get("username", "")
    password = body.get("password", "")

    if not all([api_url, username, password]):
        return jsonify({"error": "Missing credentials"}), 400

    import requests as req_lib
    try:
        resp = req_lib.get(
            f"{api_url}/security/user/authenticate?raw=true",
            auth=(username, password),
            verify=False,
            timeout=10,
        )
        if resp.status_code == 200 and len(resp.text.strip()) > 20:
            return jsonify({"success": True, "message": "Connection successful"})
        else:
            return jsonify({"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}), 400
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── API: Dashboard ──────────────────────────────────────────────

@app.route("/api/dashboard")
def api_dashboard():
    if not wazuh_service.is_connected:
        return jsonify({"error": "Not connected"}), 401
    try:
        offset = request.args.get("offset", 0, type=int)
        limit = request.args.get("limit", 10, type=int)
        show_infra = request.args.get("show_infra", "false").lower() == "true"
        
        # 1. Manager Status
        mgr_status = wazuh_service.get_manager_status()
        
        # 2. Agents Summary
        summary = wazuh_service.get_agent_summary()
        online = summary.get("active", 0)
        offline = summary.get("disconnected", 0)
        
        # 3. Alerts Summary
        stats = wazuh_service.get_stats()
        alerts = stats.get("alerts", {})
        
        # 4. Vulnerabilities Summary
        vuln_crit = 0
        vuln_high = 0
        try:
            agents_res = wazuh_service.get_agents(limit=50)
            for agent in agents_res.get("items", []):
                if agent.get("status") == "active":
                    vulns = wazuh_service.get_vulnerabilities(agent.get("id"), limit=100)
                    for item in vulns.get("items", []):
                        sev = item.get("severity", "").lower()
                        if sev == "critical":
                            vuln_crit += 1
                        elif sev == "high":
                            vuln_high += 1
        except Exception:
            pass

        # If summary format is requested specifically
        if request.args.get("format", "").lower() == "summary":
            return jsonify({
                "manager": mgr_status.get("status", "Healthy"),
                "agents": {
                    "online": online,
                    "offline": offline
                },
                "alerts": {
                    "critical": alerts.get("critical", 0),
                    "high": alerts.get("high", 0)
                },
                "vulnerabilities": {
                    "critical": vuln_crit,
                    "high": vuln_high
                }
            })
            
        # Default full UI aggregated response
        result = get_dashboard_data(limit=limit, offset=offset, show_infra=show_infra)
        result["manager"] = mgr_status.get("status", "Healthy")
        result["agents_summary"] = {
            "online": online,
            "offline": offline
        }
        result["alerts_summary"] = {
            "critical": alerts.get("critical", 0),
            "high": alerts.get("high", 0)
        }
        result["vulnerabilities_summary"] = {
            "critical": vuln_crit,
            "high": vuln_high
        }
        return jsonify(result)
    except Exception as exc:
        log.exception("Dashboard aggregation error")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/stats")
def api_stats():
    if not wazuh_service.is_connected:
        return jsonify({"error": "Not connected"}), 401
    try:
        return jsonify(wazuh_service.get_stats())
    except Exception as exc:
        log.exception("Stats error")
        return jsonify({"error": str(exc)}), 500


# ── API: Agents ─────────────────────────────────────────────────

@app.route("/api/agents")
def api_agents():
    if not wazuh_service.is_connected:
        return jsonify({"error": "Not connected"}), 401
    try:
        offset = request.args.get("offset", 0, type=int)
        limit = request.args.get("limit", 20, type=int)
        search = request.args.get("search", None)
        status = request.args.get("status", None)
        group = request.args.get("group", None)
        sort = request.args.get("sort", None)
        result = wazuh_service.get_agents(offset=offset, limit=limit, search=search,
                                          status=status, group=group, sort=sort)
        return jsonify(result)
    except Exception as exc:
        log.exception("Agents error")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/agents/<agent_id>")
def api_agent_detail(agent_id):
    if not wazuh_service.is_connected:
        return jsonify({"error": "Not connected"}), 401
    try:
        agent = wazuh_service.get_agent(agent_id)
        if agent:
            return jsonify(agent)
        return jsonify({"error": "Agent not found"}), 404
    except Exception as exc:
        log.exception("Agent detail error")
        return jsonify({"error": str(exc)}), 500


# ── API: Incidents ──────────────────────────────────────────────

@app.route("/api/incidents")
def api_incidents():
    if not wazuh_service.is_connected:
        return jsonify({"error": "Not connected"}), 401
    try:
        offset = request.args.get("offset", 0, type=int)
        limit = request.args.get("limit", 20, type=int)
        result = incident_service.get_incidents(limit=limit, offset=offset)
        return jsonify(result)
    except Exception as exc:
        log.exception("Incidents error")
        return jsonify({"error": str(exc)}), 500


# ── API: Vulnerabilities ────────────────────────────────────────

@app.route("/api/vulnerabilities")
def api_vulnerabilities():
    if not wazuh_service.is_connected:
        return jsonify({"error": "Not connected"}), 401
    try:
        agent_id = request.args.get("agent_id")
        offset = request.args.get("offset", 0, type=int)
        limit = request.args.get("limit", 20, type=int)
        if not agent_id:
            consolidated = []
            agents_res = wazuh_service.get_agents(limit=50)
            for agent in agents_res.get("items", []):
                if agent.get("status") == "active":
                    res = wazuh_service.get_vulnerabilities(agent.get("id"), offset=offset, limit=limit)
                    consolidated.extend(res.get("items", []))
            return jsonify({"items": consolidated, "total": len(consolidated)})
        
        result = wazuh_service.get_vulnerabilities(agent_id, offset=offset, limit=limit)
        return jsonify(result)
    except Exception as exc:
        log.exception("Vulnerabilities error")
        return jsonify({"error": str(exc)}), 500


# ── API: Alerts / Logs ──────────────────────────────────────────

@app.route("/api/alerts")
@app.route("/api/security/alerts")
@app.route("/api/logs")
def api_security_alerts():
    if not wazuh_service.is_connected:
        return jsonify({"error": "Not connected"}), 401
    try:
        offset = request.args.get("offset", 0, type=int)
        limit = request.args.get("limit", 20, type=int)
        search = request.args.get("search", None)
        level = request.args.get("level", None)
        agent = request.args.get("agent", None)
        category = request.args.get("category", None)
        show_infra = request.args.get("show_infra", "false").lower() == "true"
        
        result = wazuh_service.get_alerts(
            offset=offset, limit=limit, search=search, level=level,
            agent=agent, category=category, show_infra=show_infra
        )
        return jsonify(result)
    except Exception as exc:
        log.exception("Security alerts error")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/security/stats")
def api_security_stats():
    if not wazuh_service.is_connected:
        return jsonify({"error": "Not connected"}), 401
    try:
        return jsonify(wazuh_service.get_security_summary_stats())
    except Exception as exc:
        log.exception("Security stats error")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/syscollector/applications")
def api_syscollector_applications():
    if not wazuh_service.is_connected:
        return jsonify({"error": "Not connected"}), 401
    try:
        return jsonify({"items": wazuh_service.get_consolidated_applications()})
    except Exception as exc:
        log.exception("Syscollector applications error")
        return jsonify({"error": str(exc)}), 500


# ── API: Manager ───────────────────────────────────────────────

@app.route("/api/manager/info")
def api_manager_info():
    if not wazuh_service.is_connected:
        return jsonify({"error": "Not connected"}), 401
    try:
        return jsonify(wazuh_service.get_manager_status())
    except Exception as exc:
        log.exception("Manager info error")
        return jsonify({"error": str(exc)}), 500


# ── API: Groups ─────────────────────────────────────────────────

@app.route("/api/groups")
def api_groups():
    if not wazuh_service.is_connected:
        return jsonify({"error": "Not connected"}), 401
    try:
        res = wazuh_service._get("/groups", cache_key="groups_list", cache_ttl=120)
        return jsonify({"groups": res.get("data", {}).get("affected_items", [])})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── API: Search ─────────────────────────────────────────────────

@app.route("/api/search")
def api_search():
    if not wazuh_service.is_connected:
        return jsonify({"error": "Not connected"}), 401
    try:
        query = request.args.get("q", "")
        limit = request.args.get("limit", 50, type=int)
        result = wazuh_service.search(query, limit=limit)
        return jsonify(result)
    except Exception as exc:
        log.exception("Search error")
        return jsonify({"error": str(exc)}), 500


# ── API: Settings ───────────────────────────────────────────────

@app.route("/api/settings")
def api_get_settings():
    """Return settings with password redacted."""
    return jsonify({
        "wazuh": {
            "api_url": wazuh_service.host,
            "username": wazuh_service.username,
            "password": "••••••••",
            "verify_ssl": wazuh_service.verify_ssl
        },
        "dashboard": {
            "refresh_interval": config.REFRESH_INTERVAL,
            "theme": config.THEME,
            "page_size": config.PAGE_SIZE
        }
    })


@app.route("/api/settings", methods=["POST"])
def api_save_settings():
    body = request.get_json(silent=True) or {}

    wz = body.get("wazuh", {})
    dash = body.get("dashboard", {})

    host = wz.get("api_url", wazuh_service.host)
    username = wz.get("username", wazuh_service.username)
    password = wz.get("password", "")
    if password in ("••••••••", ""):
        password = wazuh_service.password
    verify = wz.get("verify_ssl", wazuh_service.verify_ssl)

    env_content = f"""WAZUH_HOST={host}
WAZUH_USERNAME={username}
WAZUH_PASSWORD={password}
VERIFY_SSL={str(verify).lower()}
"""
    try:
        env_path = os.path.join(BASE_DIR, ".env")
        with open(env_path, "w", encoding="utf-8") as f:
            f.write(env_content)
    except Exception as exc:
        return jsonify({"error": f"Failed to save settings: {exc}"}), 500

    config.HOST = host
    config.USERNAME = username
    config.PASSWORD = password
    config.VERIFY_SSL = verify
    
    if dash:
        config.REFRESH_INTERVAL = int(dash.get("refresh_interval", config.REFRESH_INTERVAL))
        config.THEME = dash.get("theme", config.THEME)
        config.PAGE_SIZE = int(dash.get("page_size", config.PAGE_SIZE))

    wazuh_service.host = host.rstrip("/")
    wazuh_service.username = username
    wazuh_service.password = password
    wazuh_service.verify_ssl = verify
    wazuh_service.login()

    return jsonify({"success": True})


# ── API: Cache ──────────────────────────────────────────────────

@app.route("/api/cache/clear", methods=["POST"])
def api_cache_clear():
    cache.clear()
    from services.wazuh_service import wazuh_service
    with wazuh_service._alerts_cache_lock:
        wazuh_service._alerts_cache["size"] = 0
        wazuh_service._alerts_cache["last_pos"] = 0
        wazuh_service._alerts_cache["parsed_events"] = []
    return jsonify({"success": True})


# ── Error handlers ──────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Not found"}), 404
    return render_template("dashboard.html", page="dashboard", refresh_interval=config.REFRESH_INTERVAL), 404


@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error"}), 500


# ── Bootstrap ───────────────────────────────────────────────────
init_auth_from_config()

if __name__ == "__main__":
    log.info("Starting Wazuh Monitor on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
