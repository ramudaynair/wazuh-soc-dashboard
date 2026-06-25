"""
app.py — Wazuh Monitor SOC Dashboard

Flask application that proxies all Wazuh API calls, serves the frontend,
and exposes clean internal REST endpoints.  The browser NEVER communicates
directly with the Wazuh API.

Usage (development):
    python app.py

Usage (production):
    gunicorn -w 4 -b 0.0.0.0:5000 app:app
"""

import json
import os
import logging

from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify

# ── Load .env ───────────────────────────────────────────────────

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

from services.auth_service import auth
from services.wazuh_service import (
    get_stats, get_agents, get_agent, get_agent_summary,
    get_alerts, get_manager_info, get_groups,
    read_security_alerts, get_security_summary_stats, get_consolidated_applications,
)
from services.cache_service import cache

# ── Logging ─────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(name)-28s  %(levelname)-7s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("wazuh-monitor")

# ── Flask App ───────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)
app.config["JSON_SORT_KEYS"] = False


# ── Config helpers ──────────────────────────────────────────────

def load_config():
    """Read config.json and return as dict."""
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        log.warning("config.json not found — using defaults")
        return {
            "wazuh": {"api_url": "", "username": "", "password": "", "verify_ssl": False},
            "dashboard": {"refresh_interval": 30, "theme": "dark", "page_size": 20},
            "managers": [],
        }


def save_config(cfg):
    """Persist config dict to config.json."""
    with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=4)


def init_auth_from_config():
    """Configure the auth service from environment variables (.env)."""
    api_url = os.environ.get("WAZUH_API_URL", "").rstrip("/")
    username = os.environ.get("WAZUH_USERNAME", "")
    password = os.environ.get("WAZUH_PASSWORD", "")
    verify_env = os.environ.get("WAZUH_VERIFY_SSL", "false")
    verify = verify_env.lower() in ("true", "1", "yes")

    if api_url and username and password:
        auth.configure(api_url, username, password, verify)
        log.info("Auth configured for %s (credentials from .env)", api_url)
        # Attempt silent connect
        try:
            if auth.authenticate():
                log.info("Auto-connected to Wazuh on startup")
            else:
                log.warning("Auto-connect failed: %s", auth.last_error)
        except Exception as exc:
            log.warning("Auto-connect failed with exception: %s", exc)
    else:
        log.warning("Auth NOT configured — set WAZUH_API_URL, WAZUH_USERNAME, WAZUH_PASSWORD in .env  "
                    "(api_url: %s, username: %s, password set: %s)",
                    bool(api_url), bool(username), bool(password))


# ── Page routes ─────────────────────────────────────────────────

@app.route("/")
def page_dashboard():
    cfg = load_config()
    return render_template("dashboard.html",
                           page="dashboard",
                           refresh_interval=cfg.get("dashboard", {}).get("refresh_interval", 30))


@app.route("/logs")
def page_logs():
    cfg = load_config()
    return render_template("logs.html",
                           page="logs",
                           page_size=cfg.get("dashboard", {}).get("page_size", 20))


@app.route("/agents")
def page_agents():
    cfg = load_config()
    return render_template("agents.html",
                           page="agents",
                           page_size=cfg.get("dashboard", {}).get("page_size", 20))


@app.route("/agents/<agent_id>")
def page_agent_detail(agent_id):
    return render_template("agent_detail.html", page="agents", agent_id=agent_id)


@app.route("/settings")
def page_settings():
    return render_template("settings.html", page="settings")


@app.route("/authentication")
def page_authentication():
    cfg = load_config()
    return render_template("authentication.html",
                           page="authentication",
                           page_size=cfg.get("dashboard", {}).get("page_size", 20))


@app.route("/applications")
def page_applications():
    cfg = load_config()
    return render_template("applications.html",
                           page="applications",
                           page_size=cfg.get("dashboard", {}).get("page_size", 20))





# ── API: Connection ─────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    """Return current connection status (no secrets)."""
    return jsonify(auth.status())


@app.route("/api/connect", methods=["POST"])
def api_connect():
    """Authenticate with Wazuh using credentials from config or request body."""
    body = request.get_json(silent=True) or {}

    api_url = body.get("api_url")
    username = body.get("username")
    password = body.get("password")
    verify = body.get("verify_ssl", False)

    if api_url and username and password:
        auth.configure(api_url, username, password, verify)
    elif not auth.is_configured:
        return jsonify({"error": "No credentials provided or configured"}), 400

    if auth.authenticate():
        return jsonify({"success": True, "status": auth.status()})
    else:
        return jsonify({"error": auth.last_error}), 401


@app.route("/api/disconnect", methods=["POST"])
def api_disconnect():
    auth.disconnect()
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


# ── API: Dashboard stats ───────────────────────────────────────

@app.route("/api/stats")
def api_stats():
    if not auth.is_connected:
        return jsonify({"error": "Not connected"}), 401
    try:
        return jsonify(get_stats())
    except Exception as exc:
        log.exception("Stats error")
        return jsonify({"error": str(exc)}), 500


# ── API: Agents ─────────────────────────────────────────────────

@app.route("/api/agents")
def api_agents():
    if not auth.is_connected:
        return jsonify({"error": "Not connected"}), 401
    try:
        offset = request.args.get("offset", 0, type=int)
        limit = request.args.get("limit", 20, type=int)
        search = request.args.get("search", None)
        status = request.args.get("status", None)
        group = request.args.get("group", None)
        sort = request.args.get("sort", None)
        result = get_agents(offset=offset, limit=limit, search=search,
                            status=status, group=group, sort=sort)
        return jsonify(result)
    except Exception as exc:
        log.exception("Agents error")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/agents/<agent_id>")
def api_agent_detail(agent_id):
    if not auth.is_connected:
        return jsonify({"error": "Not connected"}), 401
    try:
        agent = get_agent(agent_id)
        if agent:
            return jsonify(agent)
        return jsonify({"error": "Agent not found"}), 404
    except Exception as exc:
        log.exception("Agent detail error")
        return jsonify({"error": str(exc)}), 500


# ── API: Alerts / logs ─────────────────────────────────────────

@app.route("/api/alerts")
def api_alerts():
    if not auth.is_connected:
        return jsonify({"error": "Not connected"}), 401
    try:
        offset = request.args.get("offset", 0, type=int)
        limit = request.args.get("limit", 20, type=int)
        level = request.args.get("level", None)
        search = request.args.get("search", None)
        agent = request.args.get("agent", None)
        result = read_security_alerts(offset=offset, limit=limit, level=level, agent=agent,
                                      search=search, show_infra=False)
        return jsonify(result)
    except Exception as exc:
        log.exception("Alerts error")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/security/stats")
def api_security_stats():
    if not auth.is_connected:
        return jsonify({"error": "Not connected"}), 401
    try:
        return jsonify(get_security_summary_stats())
    except Exception as exc:
        log.exception("Security stats error")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/security/alerts")
def api_security_alerts():
    if not auth.is_connected:
        return jsonify({"error": "Not connected"}), 401
    try:
        offset = request.args.get("offset", 0, type=int)
        limit = request.args.get("limit", 20, type=int)
        search = request.args.get("search", None)
        level = request.args.get("level", None)
        agent = request.args.get("agent", None)
        category = request.args.get("category", None)
        show_infra = request.args.get("show_infra", "false").lower() == "true"
        
        result = read_security_alerts(
            offset=offset, limit=limit, search=search, level=level,
            agent=agent, category=category, show_infra=show_infra
        )
        return jsonify(result)
    except Exception as exc:
        log.exception("Security alerts error")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/syscollector/applications")
def api_syscollector_applications():
    if not auth.is_connected:
        return jsonify({"error": "Not connected"}), 401
    try:
        return jsonify({"items": get_consolidated_applications()})
    except Exception as exc:
        log.exception("Syscollector applications error")
        return jsonify({"error": str(exc)}), 500


# ── API: Manager ───────────────────────────────────────────────

@app.route("/api/manager/info")
def api_manager_info():
    if not auth.is_connected:
        return jsonify({"error": "Not connected"}), 401
    try:
        return jsonify(get_manager_info())
    except Exception as exc:
        log.exception("Manager info error")
        return jsonify({"error": str(exc)}), 500


# ── API: Groups ─────────────────────────────────────────────────

@app.route("/api/groups")
def api_groups():
    if not auth.is_connected:
        return jsonify({"error": "Not connected"}), 401
    try:
        return jsonify({"groups": get_groups()})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── API: Settings ───────────────────────────────────────────────

@app.route("/api/settings")
def api_get_settings():
    """Return settings with password redacted."""
    cfg = load_config()
    # Redact passwords
    if cfg.get("wazuh", {}).get("password"):
        cfg["wazuh"]["password"] = "••••••••"
    for mgr in cfg.get("managers", []):
        if mgr.get("password"):
            mgr["password"] = "••••••••"
    return jsonify(cfg)


@app.route("/api/settings", methods=["POST"])
def api_save_settings():
    """Save settings.  If password is the redaction mask, keep existing."""
    body = request.get_json(silent=True) or {}
    current = load_config()

    # Merge wazuh section
    wz = body.get("wazuh", {})
    if wz:
        if wz.get("password") in ("••••••••", ""):
            wz["password"] = current.get("wazuh", {}).get("password", "")
        current["wazuh"] = {**current.get("wazuh", {}), **wz}

    # Merge dashboard section
    dash = body.get("dashboard", {})
    if dash:
        current["dashboard"] = {**current.get("dashboard", {}), **dash}

    # Merge managers
    mgrs = body.get("managers")
    if mgrs is not None:
        for mgr in mgrs:
            if mgr.get("password") in ("••••••••", ""):
                # Find matching existing manager and keep password
                for existing in current.get("managers", []):
                    if existing.get("name") == mgr.get("name"):
                        mgr["password"] = existing.get("password", "")
                        break
        current["managers"] = mgrs

    save_config(current)

    # Re-init auth if wazuh section changed
    init_auth_from_config()

    return jsonify({"success": True})


# ── API: Cache ──────────────────────────────────────────────────

@app.route("/api/cache/clear", methods=["POST"])
def api_cache_clear():
    cache.clear()
    # Also reset the in-memory alerts cache so the next request
    # triggers a full re-parse (picks up any updated dedup logic)
    from services.wazuh_service import _alerts_cache, _alerts_cache_lock
    with _alerts_cache_lock:
        _alerts_cache["size"] = 0
        _alerts_cache["last_pos"] = 0
        _alerts_cache["parsed_events"] = []
    return jsonify({"success": True})


# ── Error handlers ──────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Not found"}), 404
    return render_template("dashboard.html", page="dashboard", refresh_interval=30), 404


@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error"}), 500


# ── Bootstrap ───────────────────────────────────────────────────
init_auth_from_config()

if __name__ == "__main__":
    log.info("Starting Wazuh Monitor on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)


