"""
dashboard_service.py — Aggregates SOC dashboard data.
"""

import logging
from services.wazuh_service import wazuh_service

log = logging.getLogger("wazuh-monitor.dashboard")

def get_dashboard_data(limit=10, offset=0, show_infra=False):
    """
    Aggregates stats, status, security summary, agents, and latest security alerts
    into a single payload for the SOC dashboard.
    """
    status_data = wazuh_service.status()
    
    stats_data = {}
    security_data = {}
    agents_list = []
    latest_alerts_data = {"items": [], "total": 0}
    incidents_list = []
    
    if wazuh_service.is_connected:
        try:
            stats_data = wazuh_service.get_stats()
        except Exception as exc:
            log.warning("Failed to fetch general stats for dashboard: %s", exc)
            
        try:
            security_data = wazuh_service.get_security_summary_stats()
        except Exception as exc:
            log.warning("Failed to fetch security summary stats: %s", exc)
            
        try:
            agents_res = wazuh_service.get_agents(limit=50)
            agents_list = agents_res.get("items", [])
        except Exception as exc:
            log.warning("Failed to fetch agents list: %s", exc)
            
        try:
            latest_alerts_data = wazuh_service.get_alerts(
                offset=offset, limit=limit, show_infra=show_infra
            )
        except Exception as exc:
            log.warning("Failed to fetch latest alerts: %s", exc)

        try:
            from services.incident_service import incident_service
            inc_res = incident_service.get_incidents(limit=8)
            incidents_list = inc_res.get("items", [])
        except Exception as exc:
            log.warning("Failed to fetch incidents list: %s", exc)
            
    return {
        "status": status_data,
        "stats": stats_data,
        "security": security_data,
        "agents": agents_list,
        "latest_alerts": latest_alerts_data.get("items", []),
        "latest_alerts_total": latest_alerts_data.get("total", 0),
        "incidents": incidents_list
    }
