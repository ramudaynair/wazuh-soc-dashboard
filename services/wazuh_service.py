"""
wazuh_service.py — Wazuh REST API Service tier.
"""

import time
import logging
import requests
import urllib3
import os
import json
import threading
from datetime import datetime

import config
from services.cache_service import cache

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger("wazuh-monitor.wazuh")

class WazuhService:
    """Service to handle connection and queries to the Wazuh API."""
    TOKEN_REFRESH_MARGIN = 120
    REQUEST_TIMEOUT = 15

    def __init__(self):
        self.host = config.HOST.rstrip("/")
        self.username = config.USERNAME
        self.password = config.PASSWORD
        self.verify_ssl = config.VERIFY_SSL
        
        # Wazuh Indexer (OpenSearch) connection for vulnerability queries
        self.indexer_host = config.INDEXER_HOST.rstrip("/")
        self.indexer_username = config.INDEXER_USERNAME
        self.indexer_password = config.INDEXER_PASSWORD
        
        self._token = None
        self._token_expires = 0
        self.is_connected = False
        self.last_error = None
        self._lock = threading.Lock()
        
        self.alerts_json_path = "/var/ossec/logs/archives/archives.json"
        self._alerts_cache = {
            "mtime": 0.0,
            "size": 0,
            "parsed_events": [],
            "last_pos": 0
        }
        self._alerts_cache_lock = threading.Lock()

    def login(self):
        """
        Authenticate with the Wazuh API using config credentials.
        Returns True if successful, False otherwise.
        """
        if not self.host or not self.username:
            self.last_error = "Credentials not configured"
            return False

        with self._lock:
            url = f"{self.host}/security/user/authenticate?raw=true"
            log.info("Logging in to %s as %s", self.host, self.username)
            try:
                resp = requests.get(
                    url,
                    auth=(self.username, self.password),
                    verify=self.verify_ssl,
                    timeout=self.REQUEST_TIMEOUT
                )
                if resp.status_code == 200:
                    token = resp.text.strip().strip('"').strip("'")
                    if token and len(token) > 20:
                        self._token = token
                        self._token_expires = time.time() + 900
                        self.is_connected = True
                        self.last_error = None
                        log.info("Wazuh Login successful")
                        return True
                    else:
                        self.last_error = "Empty token returned"
                else:
                    self.last_error = f"HTTP {resp.status_code}: {resp.text[:200]}"
                log.error("Login failed: %s", self.last_error)
                self.is_connected = False
                return False
            except Exception as exc:
                self.last_error = str(exc)
                log.exception("Login failed with exception")
                self.is_connected = False
                return False

    def get_token(self):
        """
        Retrieves a valid token, auto-refreshing if near expiration.
        """
        if not self._token:
            self.login()
        elif time.time() > (self._token_expires - self.TOKEN_REFRESH_MARGIN):
            log.info("Token nearing expiry — refreshing")
            self.login()
        return self._token

    def get_headers(self):
        token = self.get_token()
        if not token:
            return {}
        return {"Authorization": f"Bearer {token}"}

    def status(self):
        """Return a status dict containing connectivity info."""
        return {
            "connected": self.is_connected,
            "api_url": self.host,
            "username": self.username,
            "has_token": self._token is not None,
            "token_expires_in": max(0, int(self._token_expires - time.time())),
            "last_error": self.last_error,
        }

    def _get(self, path, params=None, cache_key=None, cache_ttl=30, ignore_404=False):
        """
        Authenticated GET request helper with caching and auto-retry on 401.
        """
        if cache_key:
            cached = cache.get(cache_key)
            if cached is not None:
                return cached

        token = self.get_token()
        if not token:
            raise ConnectionError("Not authenticated with Wazuh API")

        url = f"{self.host}{path}"
        headers = self.get_headers()

        try:
            resp = requests.get(
                url,
                headers=headers,
                params=params,
                verify=self.verify_ssl,
                timeout=self.REQUEST_TIMEOUT
            )
        except Exception as exc:
            log.error("Wazuh API request failed: %s", exc)
            raise ConnectionError(f"Wazuh API request failed: {exc}") from exc

        if resp.status_code == 401:
            log.info("Got 401, re-authenticating and retrying")
            self.login()
            headers = self.get_headers()
            try:
                resp = requests.get(
                    url,
                    headers=headers,
                    params=params,
                    verify=self.verify_ssl,
                    timeout=self.REQUEST_TIMEOUT
                )
            except Exception as exc:
                raise ConnectionError(f"Wazuh API retry failed: {exc}") from exc

        if resp.status_code != 200:
            if resp.status_code == 404 and ignore_404:
                return {}
            raise RuntimeError(f"Wazuh API returned HTTP {resp.status_code} on {path}: {resp.text[:200]}")

        data = resp.json()
        if cache_key:
            cache.set(cache_key, data, cache_ttl)
        return data

    # ── Wazuh Indexer (OpenSearch) Query Helper ─────────────────────

    def _indexer_query(self, index, query_body, cache_key=None, cache_ttl=60):
        """
        Query the Wazuh Indexer (OpenSearch) using HTTP Basic Auth.
        Used for vulnerability state data which is no longer served by
        the Manager API in Wazuh 4.x.
        """
        if cache_key:
            cached = cache.get(cache_key)
            if cached is not None:
                return cached

        if not self.indexer_password:
            log.warning("Wazuh Indexer password not configured — set WAZUH_INDEXER_PASSWORD in .env")
            return {"hits": {"total": {"value": 0}, "hits": []}}

        url = f"{self.indexer_host}/{index}/_search"
        try:
            resp = requests.post(
                url,
                json=query_body,
                auth=(self.indexer_username, self.indexer_password),
                verify=self.verify_ssl,
                timeout=self.REQUEST_TIMEOUT,
                headers={"Content-Type": "application/json"}
            )
        except Exception as exc:
            log.error("Wazuh Indexer request failed: %s", exc)
            return {"hits": {"total": {"value": 0}, "hits": []}}

        if resp.status_code == 401:
            log.error("Wazuh Indexer auth failed (HTTP 401) — check WAZUH_INDEXER_USERNAME/PASSWORD in .env")
            return {"hits": {"total": {"value": 0}, "hits": []}}

        if resp.status_code != 200:
            log.error("Wazuh Indexer returned HTTP %s: %s", resp.status_code, resp.text[:300])
            return {"hits": {"total": {"value": 0}, "hits": []}}

        data = resp.json()
        if cache_key:
            cache.set(cache_key, data, cache_ttl)
        return data

    # ── Wazuh API Mappings ──────────────────────────────────────────

    def get_agents(self, offset=0, limit=20, search=None, status=None, group=None, sort=None):
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

        ck = None
        if not any([search, status, group]) and offset == 0:
            ck = f"agents_{offset}_{limit}"

        data = self._get("/agents", params=params, cache_key=ck, cache_ttl=30)
        items = data.get("data", {}).get("affected_items", [])
        total = data.get("data", {}).get("total_affected_items", 0)
        return {"items": items, "total": total}

    def get_agent(self, agent_id):
        """GET /agents?agents_list=<id> — single agent detail."""
        data = self._get(
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

    def get_agent_summary(self):
        """GET /agents/summary/status — returns status counts."""
        try:
            data = self._get(
                "/agents/summary/status",
                cache_key="agent_summary",
                cache_ttl=15,
            )
            connection = data.get("data", {})
            if "connection" in connection:
                connection = connection["connection"]
            return connection
        except Exception:
            return {}

    def get_vulnerabilities(self, agent_id=None, offset=0, limit=50, severity=None):
        """
        Query vulnerability state from the Wazuh Indexer (OpenSearch).
        In Wazuh 4.x, vulnerability data is stored in the Indexer under
        the 'wazuh-states-vulnerabilities-*' index, NOT the Manager API.
        """
        try:
            # Build OpenSearch query
            must_clauses = []
            if agent_id:
                must_clauses.append({"match": {"agent.id": str(agent_id)}})
            
            if severity:
                if isinstance(severity, list):
                    must_clauses.append({"terms": {"vulnerability.severity": severity}})
                else:
                    must_clauses.append({"match": {"vulnerability.severity": severity}})
            
            query = {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}}

            body = {
                "query": query,
                "from": offset,
                "size": limit,
                "sort": [{"vulnerability.detected_at": {"order": "desc", "unmapped_type": "date"}}]
            }

            res = self._indexer_query(
                "wazuh-states-vulnerabilities-*",
                body,
                cache_key=f"vulns_{agent_id}_{offset}_{limit}_{severity}",
                cache_ttl=60
            )

            hits = res.get("hits", {})
            total_obj = hits.get("total", {})
            total = total_obj.get("value", 0) if isinstance(total_obj, dict) else int(total_obj)

            items = []
            for hit in hits.get("hits", []):
                src = hit.get("_source", {})
                vuln = src.get("vulnerability", {})
                agent = src.get("agent", {})
                pkg = src.get("package", {})
                items.append({
                    "cve": vuln.get("id", ""),
                    "title": vuln.get("title", "") or vuln.get("description", ""),
                    "severity": vuln.get("severity", "Unknown"),
                    "name": pkg.get("name", ""),
                    "version": pkg.get("version", ""),
                    "architecture": pkg.get("architecture", ""),
                    "status": vuln.get("status", ""),
                    "detected_at": vuln.get("detected_at", ""),
                    "published_at": vuln.get("published_at", ""),
                    "reference": vuln.get("reference", ""),
                    "agent_id": agent.get("id", ""),
                    "agent_name": agent.get("name", ""),
                })

            return {"items": items, "total": total}
        except Exception as exc:
            log.warning("Failed to fetch vulnerabilities for agent %s: %s", agent_id, exc)
            return {"items": [], "total": 0}

    def get_vulnerabilities_summary(self):
        """
        Get global vulnerability summary by severity directly from indexer aggregation.
        """
        try:
            body = {
                "size": 0,
                "aggs": {
                    "by_severity": {
                        "terms": {
                            "field": "vulnerability.severity"
                        }
                    }
                }
            }
            res = self._indexer_query(
                "wazuh-states-vulnerabilities-*",
                body,
                cache_key="vulns_global_summary",
                cache_ttl=30
            )
            buckets = res.get("aggregations", {}).get("by_severity", {}).get("buckets", [])
            summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for b in buckets:
                key = str(b.get("key", "")).lower()
                doc_count = b.get("doc_count", 0)
                if key in summary:
                    summary[key] = doc_count
            return summary
        except Exception as exc:
            log.warning("Failed to get vulnerabilities summary via indexer: %s", exc)
            return {"critical": 0, "high": 0, "medium": 0, "low": 0}

    def get_sca(self, agent_id, offset=0, limit=50):
        """GET /sca/{agent_id}"""
        try:
            res = self._get(
                f"/sca/{agent_id}",
                params={"limit": limit, "offset": offset},
                cache_key=f"sca_{agent_id}_{offset}_{limit}",
                cache_ttl=60
            )
            return {
                "items": res.get("data", {}).get("affected_items", []),
                "total": res.get("data", {}).get("total_affected_items", 0)
            }
        except Exception as exc:
            log.warning("Failed to fetch SCA for agent %s: %s", agent_id, exc)
            return {"items": [], "total": 0}

    def get_syscheck(self, agent_id, offset=0, limit=50):
        """GET /syscheck/{agent_id}"""
        try:
            res = self._get(
                f"/syscheck/{agent_id}",
                params={"limit": limit, "offset": offset},
                cache_key=f"syscheck_{agent_id}_{offset}_{limit}",
                cache_ttl=60
            )
            return {
                "items": res.get("data", {}).get("affected_items", []),
                "total": res.get("data", {}).get("total_affected_items", 0)
            }
        except Exception as exc:
            log.warning("Failed to fetch syscheck for agent %s: %s", agent_id, exc)
            return {"items": [], "total": 0}

    def get_syscollector(self, agent_id, resource="packages", offset=0, limit=50):
        """GET /syscollector/{agent_id}/{resource}"""
        try:
            params = {}
            if resource not in ("hardware", "os"):
                params = {"limit": limit, "offset": offset}
            res = self._get(
                f"/syscollector/{agent_id}/{resource}",
                params=params,
                cache_key=f"syscol_{agent_id}_{resource}_{offset}_{limit}",
                cache_ttl=60
            )
            return {
                "items": res.get("data", {}).get("affected_items", []),
                "total": res.get("data", {}).get("total_affected_items", 0)
            }
        except Exception as exc:
            log.warning("Failed to fetch syscollector %s for agent %s: %s", resource, agent_id, exc)
            return {"items": [], "total": 0}

    def get_manager_status(self):
        """Aggregates Wazuh manager info and status."""
        try:
            info = self._get("/manager/info", cache_key="mgr_info", cache_ttl=60)
            items = info.get("data", {}).get("affected_items", [])
            info_data = items[0] if items else info.get("data", {})
            
            status_str = "Healthy"
            try:
                status_res = self._get("/manager/status", cache_key="mgr_status", cache_ttl=30)
                status_items = status_res.get("data", {}).get("affected_items", [])
                if status_items:
                    status_data = status_items[0]
                    for k, v in status_data.items():
                        if v != "running" and k != "name":
                            status_str = "Degraded"
                            break
            except Exception:
                pass
                
            return {
                "status": status_str,
                "version": info_data.get("version", "unknown"),
                "name": info_data.get("name", "manager"),
                "os": info_data.get("os", {}).get("name", "unknown")
            }
        except Exception as exc:
            log.error("Failed to fetch manager status: %s", exc)
            return {"status": "Unhealthy", "version": "unknown", "name": "manager"}

    def get_stats(self):
        """Build a stats payload with real severity breakdown from security alerts."""
        try:
            summary = self.get_agent_summary()
        except Exception:
            summary = {}

        active = summary.get("active", 0)
        disconnected = summary.get("disconnected", 0)
        pending = summary.get("pending", 0)
        never = summary.get("never_connected", 0)
        total = active + disconnected + pending + never

        alert_total = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        info_count = 0
        top_agents = {}
        
        try:
            alerts = self._get_cached_security_alerts()
            alert_total = len(alerts)
            for item in alerts:
                lvl = item.get("rule", {}).get("level", 0)
                if lvl >= 12:
                    critical_count += 1
                elif lvl >= 9:
                    high_count += 1
                elif lvl >= 5:
                    medium_count += 1
                elif lvl >= 3:
                    low_count += 1
                else:
                    info_count += 1
                
                agent_name = item.get("agent", {}).get("name", "manager")
                top_agents[agent_name] = top_agents.get(agent_name, 0) + 1
            
            top_tags = [{"name": name, "count": count} for name, count in top_agents.items()]
            top_tags.sort(key=lambda x: x["count"], reverse=True)
            top_tags = top_tags[:5]
        except Exception as exc:
            log.warning("Could not calculate stats from cached alerts: %s", exc)
            top_tags = []

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

    def search(self, query, limit=50):
        """Searches across events using a query string."""
        return self.get_alerts(limit=limit, search=query)

    # ── Local archives.json SIEM Event Parsing ──────────────────────

    def get_alerts(self, offset=0, limit=20, search=None, level=None, agent=None, category=None, show_infra=False, sysmon_event_id=None):
        """
        Reads SIEM alerts from cached archives.json.
        """
        alerts = self._get_cached_security_alerts()

        filtered = []
        for item in alerts:
            if not show_infra:
                desc = item.get("rule", {}).get("description", "").lower()
                groups = item.get("rule", {}).get("groups", [])
                decoder = item.get("decoder", {}).get("name", "").lower()
                infra_keywords = ["syscollector", "rootcheck", "indexer-connector", "wazuh-modulesd", "inventory synchronization", "evaluation started", "evaluation finished"]
                if any(k in desc or k in groups or k in decoder for k in infra_keywords):
                    continue

            if sysmon_event_id:
                if not item.get("sysmon") or item.get("sysmon", {}).get("event_id") != str(sysmon_event_id):
                    continue

            if agent:
                agent_id = item.get("agent", {}).get("id")
                agent_name = item.get("agent", {}).get("name", "").lower()
                if agent != agent_id and agent.lower() != agent_name:
                    continue

            if level:
                try:
                    min_lvl = int(level)
                    if item.get("rule", {}).get("level", 0) < min_lvl:
                        continue
                except ValueError:
                    mapping = {"critical": 12, "error": 9, "warning": 5, "info": 3}
                    target_lvl = mapping.get(level.lower(), 3)
                    if item.get("rule", {}).get("level", 0) < target_lvl:
                        continue

            if category:
                if item.get("category") != category.lower():
                    continue

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

    def _get_cached_security_alerts(self):
        """Thread-safe helper that returns cached parsed SIEM alerts from archives.json."""
        if not os.path.exists(self.alerts_json_path):
            return []

        try:
            stat = os.stat(self.alerts_json_path)
            current_mtime = stat.st_mtime
            current_size = stat.st_size
        except Exception as exc:
            log.error("Failed to stat archives.json: %s", exc)
            return []

        with self._alerts_cache_lock:
            if current_size == self._alerts_cache["size"]:
                return self._alerts_cache["parsed_events"]

            if current_size < self._alerts_cache["size"] or self._alerts_cache["size"] == 0:
                alerts = []
                try:
                    lines = _read_last_rule_lines(self.alerts_json_path, 15000)
                    for line in lines:
                        try:
                            raw_event = json.loads(line)
                            parsed = _normalize_security_event(raw_event)
                            if parsed:
                                alerts.append(parsed)
                        except Exception:
                            continue
                    alerts = _deduplicate_low_severity(alerts)
                    alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
                    
                    self._alerts_cache["mtime"] = current_mtime
                    self._alerts_cache["size"] = current_size
                    self._alerts_cache["parsed_events"] = alerts[:15000]
                    self._alerts_cache["last_pos"] = current_size
                    log.info("Loaded archives.json: %d events", len(self._alerts_cache["parsed_events"]))
                except Exception as exc:
                    log.error("Failed initial load: %s", exc)
                    return self._alerts_cache["parsed_events"]
                return self._alerts_cache["parsed_events"]
            else:
                last_pos = self._alerts_cache["last_pos"]
                new_events = []
                try:
                    with open(self.alerts_json_path, "rb") as f:
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
                    log.error("Failed delta read: %s", exc)
                    self._alerts_cache["size"] = 0
                    return self._alerts_cache["parsed_events"]

                if new_events:
                    new_events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
                    combined = new_events + self._alerts_cache["parsed_events"]
                    combined = _deduplicate_low_severity(combined)
                    self._alerts_cache["parsed_events"] = combined[:15000]

                self._alerts_cache["mtime"] = current_mtime
                self._alerts_cache["size"] = current_size
                self._alerts_cache["last_pos"] = current_size
                log.info("Delta loaded archives.json: added %d events, total: %d", len(new_events), len(self._alerts_cache["parsed_events"]))
                return self._alerts_cache["parsed_events"]

    def get_security_summary_stats(self):
        """Aggregates stats for 'Today' based on event timestamp."""
        stats = {
            "failed_logins": 0,
            "successful_logins": 0,
            "locked_accounts": 0,
            "new_users": 0,
            "privileged_logins": 0,
            "remote_logins": 0,
            "failures_by_user": {},
            "failures_by_ip": {},
            "usb_events": 0,
            "software_changes": 0,
            "malware_alerts": 0,
            "offline_endpoints": 0,
        }
        
        try:
            summary = self.get_agent_summary()
            stats["offline_endpoints"] = summary.get("disconnected", 0)
        except Exception:
            pass
 
        today_str = datetime.now().strftime("%Y-%m-%d")
        alerts = self._get_cached_security_alerts()
 
        for parsed in alerts:
            try:
                ts = parsed.get("timestamp", "")
                if not ts:
                    continue
                if ts[:10] < today_str:
                    break
                if today_str not in ts:
                    continue
                
                cat = parsed.get("category")
                rule = parsed.get("rule", {})
                groups = rule.get("groups", [])
                description = rule.get("description", "").lower()
                raw_data = parsed.get("raw", {}).get("data", {})
                win_system = raw_data.get("win", {}).get("system", {})
                event_id = str(win_system.get("eventID", ""))
                
                # Check for user creation
                if event_id == "4720" or "user_added" in groups or "group_added" in groups or "user creation" in description:
                    stats["new_users"] += 1
                
                # Check for privileged login (root/admin or event 4672 assign privilege)
                if event_id == "4672" or (cat == "authentication" and parsed.get("auth_status") == "success" and parsed.get("username", "").lower() in ["root", "admin", "administrator", "system"]):
                    stats["privileged_logins"] += 1

                if cat == "authentication":
                    status = parsed.get("auth_status")
                    usr = parsed.get("username", "—")
                    src = parsed.get("src_ip", "—")
                    
                    if status == "success":
                        stats["successful_logins"] += 1
                        # Remote logins (RDP Logon Type 10 or sshd or has source IP that is not local loopback)
                        logon_type = str(raw_data.get("win", {}).get("eventdata", {}).get("logonType", ""))
                        if logon_type == "10" or "sshd" in description or (src and src not in ["—", "127.0.0.1", "::1"]):
                            stats["remote_logins"] += 1
                    elif status == "failed":
                        stats["failed_logins"] += 1
                        if usr and usr != "—":
                            stats["failures_by_user"][usr] = stats["failures_by_user"].get(usr, 0) + 1
                        if src and src != "—":
                            stats["failures_by_ip"][src] = stats["failures_by_ip"].get(src, 0) + 1
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
 
        # Sort and limit top failures
        stats["failures_by_user"] = dict(sorted(stats["failures_by_user"].items(), key=lambda x: x[1], reverse=True)[:5])
        stats["failures_by_ip"] = dict(sorted(stats["failures_by_ip"].items(), key=lambda x: x[1], reverse=True)[:5])
        return stats

    def get_consolidated_applications(self):
        """Query applications packages for all active agents."""
        consolidated = []
        try:
            agents_data = self.get_agents(limit=100)
            agents = agents_data.get("items", [])
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
                    res = self._get(f"/syscollector/{agent_id}/packages", params={"limit": 500}, cache_key=f"sys_packages_{agent_id}", cache_ttl=120)
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


# ── Module Helpers ────────────────────────────────────────────────

def _read_last_rule_lines(filepath, num_lines=15000):
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
                    if b'"rule":' in line or b'"win":' in line:
                        lines.append(line.decode("utf-8", errors="ignore").strip())
                        if len(lines) >= num_lines:
                            break
            
            if len(lines) < num_lines and (b'"rule":' in buffer or b'"win":' in buffer):
                lines.append(buffer.decode("utf-8", errors="ignore").strip())
                
        lines.reverse()
        return lines
    except Exception:
        return []

def _should_suppress_sysmon(sysmon_id, sysmon_details):
    if not sysmon_details:
        return False

    src_img = (sysmon_details.get("source_image") or sysmon_details.get("image") or "").lower()
    tgt_img = (sysmon_details.get("target_image") or "").lower()
    tgt_obj = (sysmon_details.get("target_object") or "").lower()
    query_name = (sysmon_details.get("query_name") or "").lower()

    # Event ID 10: Process Access
    if sysmon_id == "10":
        suppressed_sources = [
            "kaspersky", "avp.exe", "nview", "wondershare", 
            "msedgewebview2.exe", "svchost.exe", "chrome.exe", 
            "msedge.exe", "teams.exe", "explorer.exe", "searchindexer.exe",
            "onedrive.exe"
        ]
        if any(s in src_img for s in suppressed_sources):
            return True
        if any(s in tgt_img for s in ["conhost.exe", "explorer.exe"]):
            if any(s in src_img for s in ["grammarly", "whatsapp", "onedrive"]):
                return True

    # Event ID 12/13/14: Registry modification noise
    elif sysmon_id in ["12", "13", "14"]:
        if "capabilityaccessmanager" in tgt_obj or "services\\bam" in tgt_obj:
            return True
        if "svchost.exe" in src_img:
            return True

    # Event ID 22: DNS query noise
    elif sysmon_id == "22":
        if "svchost.exe" in src_img:
            return True
        benign_domains = [
            "autodesk.com", "grammarly.io", "grammarly.com", 
            "epicgames.com", "kaspersky.com", "vivoglobal.com", 
            "google.com", "googleapis.com", "whatsapp.net", 
            "facebook.com", "msftconnecttest.com", "wpad"
        ]
        if any(d in query_name for d in benign_domains):
            return True

    return False

def _normalize_security_event(raw):
    win_data = raw.get("data", {})
    if isinstance(win_data, dict):
        win_data = win_data.get("win", {})
    else:
        win_data = {}

    is_windows = isinstance(win_data, dict) and win_data

    rule = raw.get("rule")
    if not rule or not isinstance(rule, dict) or not rule.get("id"):
        if not is_windows:
            return None
        system = win_data.get("system", {}) if isinstance(win_data, dict) else {}
        event_id_str = str(system.get("eventID", "")) if isinstance(system, dict) else ""
        rule = {
            "id": f"win_{event_id_str}" if event_id_str else "win_unknown",
            "level": 3,
            "description": f"Windows Event Channel Log (ID {event_id_str})" if event_id_str else "Windows Event Channel Log",
            "groups": ["windows", "windows_eventchannel"]
        }

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

    is_sysmon = False
    sysmon_id = None
    event_id = None
    sysmon_details = None

    if is_windows:
        system = win_data.get("system", {})
        if isinstance(system, dict):
            event_id = str(system.get("eventID", ""))
            provider_name = system.get("providerName", "").lower()
            if "sysmon" in provider_name or "sysmon" in groups:
                is_sysmon = True
                sysmon_id = event_id

    rule_id_str = rule.get("id", "0")
    try:
        rule_id = int(rule_id_str)
    except (ValueError, TypeError):
        rule_id = 0

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

    if is_sysmon:
        category = "system"
        eventdata = win_data.get("eventdata", {})
        if not isinstance(eventdata, dict):
            eventdata = {}
        
        sysmon_details = {
            "event_id": sysmon_id,
            "image": eventdata.get("image", eventdata.get("sourceImage", "")),
            "parent_image": eventdata.get("parentImage", ""),
            "command_line": eventdata.get("commandLine", ""),
            "parent_command_line": eventdata.get("parentCommandLine", ""),
            "user": eventdata.get("user", eventdata.get("subjectUserName", "")),
            "process_guid": eventdata.get("processGuid", ""),
            "parent_process_guid": eventdata.get("parentProcessGuid", ""),
            "process_id": eventdata.get("processId", ""),
            "parent_process_id": eventdata.get("parentProcessId", ""),
            "target_filename": eventdata.get("targetFilename", ""),
            "target_object": eventdata.get("targetObject", ""),
            "details": eventdata.get("details", ""),
            "dest_ip": eventdata.get("destinationIp", ""),
            "dest_port": eventdata.get("destinationPort", ""),
            "src_ip": eventdata.get("sourceIp", ""),
            "src_port": eventdata.get("sourcePort", ""),
            "protocol": eventdata.get("protocol", ""),
            "query_name": eventdata.get("queryName", ""),
            "query_status": eventdata.get("queryStatus", ""),
            "call_trace": eventdata.get("callTrace", ""),
            "target_image": eventdata.get("targetImage", ""),
            "source_image": eventdata.get("sourceImage", ""),
            "mitre_technique": "",
            "mitre_tactic": "",
            "mitre_name": ""
        }

        if _should_suppress_sysmon(sysmon_id, sysmon_details):
            return None

        if sysmon_id == "1":
            category = "security"
            image_name = sysmon_details["image"] or "unknown"
            desc = f"Process Created: {image_name}"
            cmd = sysmon_details["command_line"].lower()
            img = image_name.lower()
            if "powershell" in img or "powershell" in cmd:
                sysmon_details["mitre_technique"] = "T1059.001"
                sysmon_details["mitre_tactic"] = "Execution"
                sysmon_details["mitre_name"] = "PowerShell"
            elif "certutil" in img or "certutil" in cmd:
                sysmon_details["mitre_technique"] = "T1105"
                sysmon_details["mitre_tactic"] = "Command and Control"
                sysmon_details["mitre_name"] = "Ingress Tool Transfer"
            elif "cmd.exe" in img or "cmd.exe" in cmd:
                sysmon_details["mitre_technique"] = "T1059.003"
                sysmon_details["mitre_tactic"] = "Execution"
                sysmon_details["mitre_name"] = "Windows Command Shell"
            else:
                sysmon_details["mitre_technique"] = "T1204.002"
                sysmon_details["mitre_tactic"] = "Execution"
                sysmon_details["mitre_name"] = "Malicious File Execution"

        elif sysmon_id == "3":
            category = "security"
            dest_ip = sysmon_details["dest_ip"] or "unknown"
            dest_port = sysmon_details["dest_port"] or ""
            desc = f"Network Connection: {dest_ip}:{dest_port}"
            sysmon_details["mitre_technique"] = "T1071"
            sysmon_details["mitre_tactic"] = "Command and Control"
            sysmon_details["mitre_name"] = "Application Layer Protocol"

        elif sysmon_id == "10":
            category = "security"
            src = sysmon_details["source_image"] or "unknown"
            tgt = sysmon_details["target_image"] or "unknown"
            desc = f"Process Access: {src} accessed {tgt}"
            if "lsass" in tgt.lower() or "lsass" in src.lower():
                sysmon_details["mitre_technique"] = "T1003.001"
                sysmon_details["mitre_tactic"] = "Credential Access"
                sysmon_details["mitre_name"] = "LSASS Memory"
            else:
                sysmon_details["mitre_technique"] = "T1055"
                sysmon_details["mitre_tactic"] = "Defense Evasion"
                sysmon_details["mitre_name"] = "Process Injection"

        elif sysmon_id == "11":
            category = "security"
            filename = sysmon_details["target_filename"] or "unknown"
            desc = f"File Created: {filename}"
            sysmon_details["mitre_technique"] = "T1106"
            sysmon_details["mitre_tactic"] = "Execution"
            sysmon_details["mitre_name"] = "Native API"

        elif sysmon_id in ["12", "13", "14"]:
            category = "security"
            target_obj = sysmon_details["target_object"] or "unknown"
            desc = f"Registry Change: {target_obj}"
            if "run" in target_obj.lower() or "runonce" in target_obj.lower():
                sysmon_details["mitre_technique"] = "T1547.001"
                sysmon_details["mitre_tactic"] = "Persistence"
                sysmon_details["mitre_name"] = "Registry Run Keys"
            else:
                sysmon_details["mitre_technique"] = "T1112"
                sysmon_details["mitre_tactic"] = "Defense Evasion"
                sysmon_details["mitre_name"] = "Modify Registry"

        elif sysmon_id == "22":
            category = "security"
            query = sysmon_details["query_name"] or "unknown"
            desc = f"DNS Query: {query}"
            sysmon_details["mitre_technique"] = "T1071.004"
            sysmon_details["mitre_tactic"] = "Command and Control"
            sysmon_details["mitre_name"] = "DNS"
        else:
            desc = f"Sysmon Event ID {sysmon_id}"

        if sysmon_details.get("user"):
            username = sysmon_details["user"]
        if sysmon_details.get("src_ip"):
            src_ip = sysmon_details["src_ip"]

    elif auth_success or auth_failed or event_id in ["4624", "4625", "4672", "4740"] or any(k in desc_lower for k in ["logon", "login", "authentication", "auth", "lockout", "password"]):
        category = "authentication"
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

        src_ip = data.get("srcip") or data.get("src_ip")
        if not src_ip and win_data:
            eventdata = win_data.get("eventdata", {})
            if isinstance(eventdata, dict):
                src_ip = eventdata.get("ipAddress") or eventdata.get("clientIP")
        if not src_ip:
            src_ip = "—"

    elif (any(k in desc_lower or k in groups for k in ["usb", "mass storage", "removable media", "mount", "unmount", "inserted", "removed"]) or event_id in ["6416"]) and decoder_lower != "syscollector":
        category = "usb"
        data = raw.get("data", {})
        if not isinstance(data, dict):
            data = {}
        username = data.get("srcuser") or data.get("dstuser") or "—"
        src_ip = "—"

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

    elif any(k in desc_lower or k in groups for k in ["virus", "malware", "trojan", "clamav", "defender", "antivirus"]):
        category = "malware"

    elif "service_installation" in groups or "service_creation" in groups or any(k in desc_lower for k in ["service startup", "service created", "service installed"]) or event_id == "7045":
        category = "system"

    if category == "security" and any(k in desc_lower for k in ["apparmor", "selinux", "policy violation", "privilege escalation", "sudo"]):
        category = "security"

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
        "sysmon": sysmon_details,
        "raw": raw,
    }

def _deduplicate_low_severity(alerts):
    BURST_WINDOW_SECONDS = 60
    seen_burst = {}
    seen_exact = set()
    result = []

    for event in alerts:
        agent_id = str(event.get("agent", {}).get("id", ""))
        ts_raw = event.get("timestamp", "")[:19]
        cat = event.get("category", "")
        usr = event.get("username", "")
        src = event.get("src_ip", "")
        desc = event.get("rule", {}).get("description", "").strip().lower()
        rule_id = str(event.get("rule", {}).get("id", ""))
        level = event.get("rule", {}).get("level", 0)

        # 1. Exact Duplicate Filter (same second, agent, user, src, status/description)
        if cat == "authentication":
            exact_key = (agent_id, ts_raw, cat, usr, src, event.get("auth_status"))
        else:
            exact_key = (agent_id, ts_raw, cat, usr, src, desc)
            
        if exact_key in seen_exact:
            continue
        seen_exact.add(exact_key)

        # 2. Burst window suppression for low severity (< 7)
        if level >= 7:
            result.append(event)
            continue

        burst_key = (rule_id, agent_id, desc)
        try:
            event_dt = datetime.strptime(ts_raw, "%Y-%m-%dT%H:%M:%S")
        except (ValueError, TypeError):
            result.append(event)
            continue

        if burst_key not in seen_burst:
            seen_burst[burst_key] = event_dt
            result.append(event)
        else:
            diff = abs((seen_burst[burst_key] - event_dt).total_seconds())
            if diff > BURST_WINDOW_SECONDS:
                seen_burst[burst_key] = event_dt
                result.append(event)

    return result


# Singleton instance
wazuh_service = WazuhService()
