# 🛡️ Wazuh Monitor — SOC Dashboard

A high-fidelity Security Operations Center (SOC) dashboard built on the Wazuh SIEM platform. It provides real-time visibility into endpoint health, live Sysmon telemetry, correlated incidents, and vulnerability data through a clean web interface.

---

## 📋 Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Infrastructure: Install Wazuh Manager](#2-infrastructure-install-wazuh-manager)
3. [Wazuh Agent Setup (on Windows Endpoints)](#3-wazuh-agent-setup-on-windows-endpoints)
4. [Sysmon Installation & Configuration](#4-sysmon-installation--configuration)
5. [Wazuh + Sysmon Integration (on the Manager)](#5-wazuh--sysmon-integration-on-the-manager)
6. [Clone & Install Wazuh Monitor](#6-clone--install-wazuh-monitor)
7. [Configure Environment Variables](#7-configure-environment-variables)
8. [Run the Dashboard](#8-run-the-dashboard)
9. [Verify Everything is Working](#9-verify-everything-is-working)
10. [Application Pages Reference](#10-application-pages-reference)
11. [Project Structure](#11-project-structure)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Prerequisites

### On the Server (Linux — Ubuntu/Debian recommended)
| Requirement | Version |
|---|---|
| Python | 3.10 or newer |
| pip | Latest |
| git | Any |
| Wazuh Manager | 4.x (self-hosted or OVA) |

### On Windows Endpoints
| Requirement | Notes |
|---|---|
| Windows 10/11 or Server 2016+ | Required for Sysmon |
| Wazuh Agent | Installed and enrolled |
| Sysmon (Sysinternals) | v15.x recommended |
| Administrator privileges | Required for agent & Sysmon install |

---

## 2. Infrastructure: Install Wazuh Manager

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

### Retrieve Credentials Later

If you missed the output, extract passwords from the installer archive:

```bash
sudo tar -O -xf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

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

## 3. Wazuh Agent Setup (on Windows Endpoints)

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

## 4. Sysmon Installation & Configuration

Sysmon is a Windows system service that logs detailed process, network, registry, and file activity into the Windows Event Log. Wazuh reads these events and forwards them to the Manager.

### Step 1 — Download Sysmon

```powershell
# Download Sysmon from Microsoft Sysinternals
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" `
  -OutFile "$env:TEMP\Sysmon.zip"

Expand-Archive -Path "$env:TEMP\Sysmon.zip" -DestinationPath "C:\Sysmon"
```

### Step 2 — Download a Quality Config (SwiftOnSecurity) or (Olaf Heartong)

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

## 5. Wazuh + Sysmon Integration (on the Manager)

Tell the Wazuh Manager to collect Sysmon events from enrolled Windows agents.

### Step 1 — Edit the Agent Configuration

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

### Step 2 — Enable Archive Logging

Archives are required for the **Live Activity** tab. Edit `ossec.conf`:

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

### Step 3 — Restart Wazuh Manager

```bash
sudo systemctl restart wazuh-manager
```

### Step 4 — Verify Archives are Being Written

```bash
sudo tail -f /var/ossec/logs/archives/archives.json | grep -i sysmon
```

You should see JSON lines with `"sysmon"` channel data flowing in.

---

## 6. Clone & Install Wazuh Monitor

### Step 1 — Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/wazuh-monitor.git
cd wazuh-monitor
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

The dependencies installed are:

| Package | Purpose |
|---|---|
| `flask` | Web framework and API routing |
| `requests` | HTTP client for Wazuh API calls |
| `gunicorn` | Production WSGI server |
| `python-dotenv` | `.env` file loading |

---

## 7. Configure Environment Variables

### Step 1 — Copy the Example File

```bash
cp .env.example .env
```

### Step 2 — Edit `.env` with Your Values

```bash
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

### Finding Your Passwords

```bash
# On the Wazuh Manager server:
sudo tar -O -xf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

Look for `wazuh-wui` (API password) and `admin` (Indexer password).

---

## 8. Run the Dashboard

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
sudo nano /etc/systemd/system/wazuh-monitor.service
```

```ini
[Unit]
Description=Wazuh Monitor SOC Dashboard
After=network.target

[Service]
User=wazuh
WorkingDirectory=/home/wazuh/Downloads/wazuh-monitor
ExecStart=/home/wazuh/Downloads/wazuh-monitor/venv/bin/gunicorn \
          --bind 0.0.0.0:5000 --workers 2 --timeout 120 app:app
Restart=always
RestartSec=5
EnvironmentFile=/home/wazuh/Downloads/wazuh-monitor/.env

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-monitor
sudo systemctl start wazuh-monitor
sudo systemctl status wazuh-monitor
```

---

## 9. Verify Everything is Working

### ✅ Checklist

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

### Dashboard Connection Status

On first load, the dashboard auto-connects using your `.env` credentials. If the top-right dot is **red**, go to **Settings** (`/settings`) and verify your API URL, username, and password.

---

## 10. Application Pages Reference

| URL | Page | Description |
|---|---|---|
| `/` | **Dashboard** | High-level security summary, alert trends, severity distribution |
| `/agents` | **Agents** | All enrolled endpoints with online/offline status |
| `/agents/<id>` | **Agent Detail** | Per-endpoint inventory, Sysmon timeline, Endpoint Explorer tabs |
| `/live_activity` | **Live Activity** | Real-time Sysmon telemetry (Process, Network, Registry, DNS, File) |
| `/incidents` | **Incidents** | Correlated security incidents (Brute Force, Privilege Escalation, Malware) |
| `/logs` | **Security Logs** | Raw alert viewer with search, severity filter, and JSON detail drawer |
| `/vulnerabilities` | **Vulnerabilities** | CVE data from Wazuh Indexer per agent |
| `/applications` | **Applications** | Consolidated installed software inventory across all agents |
| `/authentication` | **Authentication** | Windows authentication event audit log |
| `/settings` | **Settings** | API credentials, refresh interval, and theme configuration |

---

## 11. Project Structure

```
wazuh-monitor/
├── app.py                      # Flask routes and API endpoints
├── config.py                   # Environment variable loader
├── requirements.txt            # Python dependencies
├── .env                        # Your secrets (never commit this)
├── .env.example                # Template for .env
├── .gitignore
│
├── services/
│   ├── wazuh_service.py        # Wazuh API client + archives parser + Sysmon ingest
│   ├── incident_service.py     # Correlation engine (Brute Force, Privilege Esc., etc.)
│   ├── dashboard_service.py    # Dashboard data aggregation helper
│   ├── cache_service.py        # In-memory TTL cache to reduce API load
│   └── auth_service.py         # Authentication helpers
│
├── templates/
│   ├── base.html               # Shared layout, navigation, header
│   ├── dashboard.html          # Main dashboard page
│   ├── agent_detail.html       # Agent profile + Endpoint Explorer tabs
│   ├── live_activity.html      # Sysmon live telemetry viewer
│   ├── incidents.html          # Correlated incident list
│   ├── logs.html               # Raw security log viewer
│   ├── agents.html             # Agent list page
│   ├── vulnerabilities.html    # Vulnerability table
│   ├── applications.html       # Software inventory
│   ├── authentication.html     # Auth event log
│   └── settings.html           # Settings panel
│
└── static/
    ├── css/
    │   └── style.css           # Unified dark-mode design system
    └── js/
        ├── app.js              # Global state, auto-refresh, notifications
        ├── dashboard.js        # Dashboard charts and widgets
        ├── live_activity.js    # Sysmon real-time feed logic
        ├── agent_detail.js     # Endpoint Explorer tabs
        ├── incidents.js        # Incident list and status updates
        ├── logs.js             # Log viewer and search
        ├── agents.js           # Agent list and filters
        ├── vulnerabilities.js  # Vuln table and drawer
        ├── applications.js     # Applications inventory
        ├── authentication.js   # Auth log viewer
        └── settings.js         # Settings form and connection test
```

---

## 12. Troubleshooting

### Dashboard shows "Not Connected"

1. Check your `.env` values are correct (no trailing spaces, correct IP/port).
2. Confirm Wazuh Manager API is reachable: `curl -k https://YOUR_IP:55000/`
3. Go to **Settings** → enter credentials manually → click **Save & Reconnect**.

### No Sysmon Events in Live Activity

1. Confirm Sysmon is installed and running on the Windows endpoint.
2. Verify the agent is enrolled and shows **Active** in Wazuh.
3. Confirm the `agent.conf` on the Manager includes the Sysmon event channel.
4. Check archives are being written: `sudo tail -f /var/ossec/logs/archives/archives.json`
5. Confirm `logall_json=yes` is set in `ossec.conf` and Manager was restarted.

### Vulnerabilities Tab is Empty

The vulnerability scanner must be enabled on the Wazuh Manager. Run:

```bash
sudo /var/ossec/bin/wazuh-control enable vulnerabilities
sudo systemctl restart wazuh-manager
```

Also ensure your `WAZUH_INDEXER_HOST` and password are set in `.env`.

### Archives File Not Found

The Live Activity page reads from `/var/ossec/logs/archives/archives.json`. If this file doesn't exist:

```bash
# Confirm logall_json is enabled in ossec.conf, then restart
sudo systemctl restart wazuh-manager

# Check the file appears after restart
ls -lh /var/ossec/logs/archives/
```

### Python Dependency Errors

```bash
# Deactivate and recreate the venv
deactivate
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Port 5000 Already in Use

```bash
# Find and kill the process using port 5000
sudo lsof -ti:5000 | xargs sudo kill -9

# Then re-run
python app.py
```

---

## 📝 Quick Start Summary

```bash
# 1. Clone and enter the project
git clone https://github.com/YOUR_USERNAME/wazuh-monitor.git
cd wazuh-monitor

# 2. Create and activate virtual environment
python3 -m venv venv && source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set up your environment
cp .env.example .env && nano .env

# 5. Run the dashboard
python app.py

# 6. Open in browser
xdg-open http://localhost:5000
```

---

*Built for security teams who need fast, actionable insight into their Wazuh-monitored infrastructure.*
