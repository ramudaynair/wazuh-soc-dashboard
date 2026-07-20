# Troubleshooting

Common issues and fixes for the Wazuh SOC Dashboard.

---

## Dashboard shows "Not Connected" (red dot)

**Cause:** Incorrect `.env` credentials, unreachable Wazuh Manager API, or the application hasn't attempted to connect yet.

**Fix:**

1. Check your `.env` values are correct (no trailing spaces, correct IP/port).
2. Confirm the Wazuh Manager API is reachable from the dashboard server:
   ```bash
   curl -k -u wazuh-wui:YOUR_PASSWORD "https://YOUR_IP:55000/"
   ```
3. Go to **Settings** (`/settings`) → enter credentials manually → click **Save & Reconnect**.

---

## No Sysmon Events in Live Activity

**Cause:** Sysmon not installed on the endpoint, agent not enrolled, archive logging not enabled, or the Sysmon event channel is not configured in `agent.conf`.

**Fix:**

1. Confirm Sysmon is installed and running on the Windows endpoint:
   ```powershell
   Get-Service Sysmon64
   ```
2. Verify the agent is enrolled and shows **Active** in Wazuh:
   ```bash
   sudo /var/ossec/bin/agent_control -l
   ```
3. Confirm the `agent.conf` on the Manager includes the Sysmon event channel:
   ```bash
   cat /var/ossec/etc/shared/default/agent.conf
   ```
   It should contain:
   ```xml
   <localfile>
     <location>Microsoft-Windows-Sysmon/Operational</location>
     <log_format>eventchannel</log_format>
   </localfile>
   ```
4. Check archives are being written:
   ```bash
   sudo tail -f /var/ossec/logs/archives/archives.json
   ```
5. Confirm `logall_json=yes` is set in `ossec.conf` and the Manager was restarted.

---

## Vulnerabilities Tab is Empty

**Cause:** The Wazuh Indexer credentials are not configured, or the vulnerability scanner is not enabled on the Manager.

**Fix:**

1. Ensure `WAZUH_INDEXER_HOST`, `WAZUH_INDEXER_USERNAME`, and `WAZUH_INDEXER_PASSWORD` are set in `.env`.
2. Enable the vulnerability scanner on the Wazuh Manager:
   ```bash
   sudo /var/ossec/bin/wazuh-control enable vulnerabilities
   sudo systemctl restart wazuh-manager
   ```
3. Verify the Indexer is reachable:
   ```bash
   curl -k -u admin:YOUR_PASSWORD "https://YOUR_IP:9200/_cat/indices?v" | grep vuln
   ```

---

## Archives File Not Found

**Cause:** Archive logging is not enabled in `ossec.conf`.

The Live Activity page reads from `/var/ossec/logs/archives/archives.json`. If this file doesn't exist:

**Fix:**

1. Edit `ossec.conf` and ensure `logall_json=yes` is set inside the `<global>` block.
2. Restart the Manager:
   ```bash
   sudo systemctl restart wazuh-manager
   ```
3. Verify the file appears:
   ```bash
   ls -lh /var/ossec/logs/archives/
   ```

---

## Port 5000 Already in Use

**Cause:** Another process is bound to port 5000.

**Fix:**

```bash
# Find and kill the process using port 5000
sudo lsof -ti:5000 | xargs sudo kill -9

# Then re-run
python app.py
```

Alternatively, bind to a different port:

```bash
gunicorn --bind 0.0.0.0:8080 --workers 2 --timeout 120 app:app
```

---

## Python Dependency Errors

**Cause:** Corrupted virtual environment or version conflict.

**Fix:**

```bash
# Deactivate and recreate the venv
deactivate
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## SSL Certificate Warnings

**Cause:** Wazuh uses self-signed certificates by default. With `VERIFY_SSL=false`, Python's `urllib3` will print `InsecureRequestWarning` messages.

**Fix:**

- In **lab/dev environments**, this is expected behavior. The dashboard suppresses these warnings in the logs.
- In **production**, configure a proper CA certificate and set `VERIFY_SSL=true` in `.env`.
