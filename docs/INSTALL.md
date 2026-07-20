# Installation Guide

Complete setup guide for the Wazuh SOC Dashboard — from a fresh Wazuh deployment to a running dashboard.

---

## Prerequisites

**Requires a working Wazuh 4.x deployment.** For the best experience, run the dashboard on the Wazuh Manager host, as Live Activity reads `archives.json` from the local filesystem.

### Server (Linux — Ubuntu/Debian recommended)

| Requirement | Version |
|---|---|
| Python | 3.10 or newer |
| pip | Latest |
| git | Any |
| Wazuh Manager | 4.x (self-hosted or OVA) |

### Windows Endpoints

| Requirement | Notes |
|---|---|
| Windows 10/11 or Server 2016+ | Required for Sysmon |
| Wazuh Agent | Installed and enrolled |
| Sysmon (Sysinternals) | v15.x recommended |
| Administrator privileges | Required for agent & Sysmon install |

---

## 1. Install Wazuh Manager

> Skip this section if you already have a running Wazuh Manager.

### Option A — OVA (Easiest)

Download the pre-built virtual machine from the [Wazuh Downloads Page](https://documentation.wazuh.com/current/deployment-options/virtual-machine/virtual-machine.html) and import it into VirtualBox or VMware. Default credentials are `admin / admin`.

### Option B — Quick Install Script (Ubuntu/Debian)

```bash
# Download the Wazuh installer
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh

# Run the all-in-one installation
sudo bash wazuh-install.sh -a
```

After the install completes, save the printed credentials — especially for `admin` (Wazuh Indexer) and `wazuh-wui` (Wazuh API).

### Retrieve Credentials

If you missed the output, extract passwords from the installer archive:

```bash
sudo tar -O -xf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

Look for `wazuh-wui` (API password) and `admin` (Indexer password).

### Verify Wazuh Manager is Running

```bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
```

All three should show `active (running)`.

### Test the API

```bash
# Replace YOUR_IP with your Wazuh Manager IP
curl -k -u wazuh-wui:YOUR_PASSWORD \
  "https://YOUR_IP:55000/security/user/authenticate?raw=true"
```

A long JWT token string means the API is accessible.

---

## 2. Deploy Wazuh Agent on Windows

### Step 1 — Download the Agent Installer

Go to the Wazuh Manager Dashboard (`https://YOUR_IP`) → **Agents** → **Deploy new agent**, and download the Windows MSI installer, or download directly:

```
https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.x-1.msi
```

### Step 2 — Install via PowerShell (Administrator)

```powershell
# Replace values with your Manager IP and a name for this endpoint
$WAZUH_MANAGER = "192.168.1.100"
$AGENT_NAME    = "DESKTOP-MYPC"

msiexec.exe /i wazuh-agent-4.7.x-1.msi /q `
  WAZUH_MANAGER="$WAZUH_MANAGER" `
  WAZUH_AGENT_NAME="$AGENT_NAME"
```

### Step 3 — Start the Agent

```powershell
NET START WazuhSvc
```

### Step 4 — Verify Enrollment

On the Wazuh Manager (Linux):

```bash
sudo /var/ossec/bin/agent_control -l
```

Your new agent should appear with status `Active`.

---

## 3. Install & Configure Sysmon

Sysmon is a Windows system service that logs detailed process, network, registry, and file activity into the Windows Event Log. Wazuh reads these events and forwards them to the Manager.

### Step 1 — Download Sysmon

```powershell
# Download Sysmon from Microsoft Sysinternals
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" `
  -OutFile "$env:TEMP\Sysmon.zip"

Expand-Archive -Path "$env:TEMP\Sysmon.zip" -DestinationPath "C:\Sysmon"
```

### Step 2 — Download a Quality Config

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
  -OutFile "C:\Sysmon\sysmonconfig.xml"
```

### Step 3 — Install Sysmon with the Config

```powershell
# Open PowerShell as Administrator
cd C:\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

### Step 4 — Verify Sysmon is Running

```powershell
Get-Service Sysmon64
# Status should be: Running
```

Check that events are being generated:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 |
  Select-Object Id, TimeCreated, Message
```

### Step 5 — Update or Uninstall (Future Reference)

```powershell
# Update config
.\Sysmon64.exe -c sysmonconfig.xml

# Uninstall
.\Sysmon64.exe -u
```

---

## 4. Configure Wazuh for Sysmon

### a) Tell the Agent to Collect Sysmon Events

On the **Wazuh Manager** (Linux), open the shared agent config:

```bash
sudo nano /var/ossec/etc/shared/default/agent.conf
```

Add the following block inside `<agent_config>`:

```xml
<agent_config os="Windows">
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</agent_config>
```

> **Why this is needed:** Wazuh agents don't collect Sysmon events by default. Adding this `localfile` block tells the agent to read from the `Microsoft-Windows-Sysmon/Operational` event channel and forward those events to the Manager.

### b) Enable Archive Logging

Edit `ossec.conf`:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Find the `<global>` block and add/ensure:

```xml
<global>
  <logall>yes</logall>
  <logall_json>yes</logall_json>
</global>
```

> **Why this is needed:** Wazuh normally stores only alerts (events that matched Wazuh rules) in `alerts.json`. The dashboard's Live Activity feature needs complete telemetry — including Sysmon events that may not trigger any Wazuh rule. Enabling `logall_json=yes` causes Wazuh to write every collected event to `/var/ossec/logs/archives/archives.json`. Without this setting, Live Activity and some incident correlation features will not function because only alerts would be available.

### c) Restart Wazuh Manager

```bash
sudo systemctl restart wazuh-manager
```

### d) Verify Archives are Being Written

```bash
sudo tail -f /var/ossec/logs/archives/archives.json | grep -i sysmon
```

You should see JSON lines with `"sysmon"` channel data flowing in.

---

## 5. Install the Dashboard

### Step 1 — Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/wazuh-soc-dashboard.git
cd wazuh-soc-dashboard
```

### Step 2 — Create a Python Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3 — Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4 — Configure Environment Variables

```bash
cp .env.example .env
nano .env
```

```dotenv
# ── Wazuh Manager API (port 55000) ──────────────────────────────
WAZUH_HOST=https://192.168.1.100:55000
WAZUH_USERNAME=YOUR_WUI_USERNAME_HERE
WAZUH_PASSWORD=YOUR_WUI_PASSWORD_HERE
VERIFY_SSL=false

# ── Wazuh Indexer / OpenSearch (port 9200) ───────────────────────
# Required for vulnerability data
WAZUH_INDEXER_HOST=https://192.168.1.100:9200
WAZUH_INDEXER_USERNAME=YOUR_INDEXER_USERNAME_HERE
WAZUH_INDEXER_PASSWORD=YOUR_INDEXER_PASSWORD_HERE

# ── Optional Dashboard Settings ──────────────────────────────────
REFRESH_INTERVAL=30
THEME=dark
PAGE_SIZE=20
```

> **⚠️ Security Note:** The `.env` file is excluded by `.gitignore` and should never be committed to version control.

> **⚠️ SSL Note:** The default `VERIFY_SSL=false` is acceptable for lab and development environments. In production, configure a custom CA bundle and set `VERIFY_SSL=true`.

> **Important:** The dashboard reads `archives.json` directly from the local filesystem. The Flask application must run on the same machine as the Wazuh Manager, or the archive file must be accessible via a shared mount.

---

## 6. Run the Dashboard

### Development Mode (Recommended for Testing)

```bash
# Make sure venv is active
source venv/bin/activate

python app.py
```

The server starts at: **http://0.0.0.0:5000**

Open your browser and go to: **http://localhost:5000**

### Production Mode (Gunicorn)

For running on a server with multiple workers:

```bash
source venv/bin/activate

gunicorn \
  --bind 0.0.0.0:5000 \
  --workers 2 \
  --timeout 120 \
  app:app
```

### Run as a Background Service (systemd)

Create a service file:

```bash
sudo nano /etc/systemd/system/wazuh-dashboard.service
```

```ini
[Unit]
Description=Wazuh SOC Dashboard
After=network.target

[Service]
User=wazuh
WorkingDirectory=/home/wazuh/wazuh-soc-dashboard
ExecStart=/home/wazuh/wazuh-soc-dashboard/venv/bin/gunicorn \
          --bind 0.0.0.0:5000 --workers 2 --timeout 120 app:app
Restart=always
RestartSec=5
EnvironmentFile=/home/wazuh/wazuh-soc-dashboard/.env

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-dashboard
sudo systemctl start wazuh-dashboard
sudo systemctl status wazuh-dashboard
```

---

## 7. Verify Setup

| Check | Command / Action |
|---|---|
| Wazuh Manager API responds | `curl -k -u wazuh-wui:PASS https://YOUR_IP:55000/` |
| Archives file exists | `ls -lh /var/ossec/logs/archives/archives.json` |
| Sysmon service running (Windows) | `Get-Service Sysmon64` |
| Agent enrolled and active | `sudo /var/ossec/bin/agent_control -l` |
| Dashboard loads in browser | Visit `http://localhost:5000` |
| Status dot is green | Top-right header shows connected |
| Agents appear on dashboard | `/agents` page shows enrolled endpoints |
| Live Activity shows Sysmon events | `/live_activity` page shows process/network events |

On first load, the dashboard auto-connects using your `.env` credentials. If the top-right dot is **red**, go to **Settings** (`/settings`) and verify your API URL, username, and password.

---

## 8. Common Installation Issues

| Issue | Fix |
|---|---|
| Port 5000 already in use | `sudo lsof -ti:5000 \| xargs sudo kill -9`, then re-run |
| Archives file doesn't exist | Ensure `logall_json=yes` is set in `ossec.conf`, then `sudo systemctl restart wazuh-manager` |
| Python dependency errors | `deactivate && rm -rf venv && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt` |

For runtime issues, see [Troubleshooting](TROUBLESHOOTING.md).
