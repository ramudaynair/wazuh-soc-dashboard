/* ═══════════════════════════════════════════════════════════════
   agent_detail.js — Agent details page logic
   Loads metadata, system profile inventory, timeline, applications, and related alerts
   ═══════════════════════════════════════════════════════════════ */

let agentId = null;
let agentName = '';
let currentCategory = ''; // All by default

document.addEventListener('DOMContentLoaded', () => {
    const configEl = document.getElementById('agentDetailConfig');
    if (configEl) {
        agentId = configEl.dataset.agentId;
    }

    if (!agentId) {
        toast('Error', 'No Agent ID specified.', 'error');
        return;
    }

    // Initialize Tabs Event Listeners
    const tabs = document.querySelectorAll('.detail-tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.detail-tab-content').forEach(c => c.classList.remove('active'));

            tab.classList.add('active');
            const targetContent = document.getElementById(`tabContent_${tab.dataset.tab}`);
            if (targetContent) targetContent.classList.add('active');

            // Load specific tab data on click
            if (tab.dataset.tab === 'apps') {
                loadAgentApps();
            } else if (tab.dataset.tab === 'explorer') {
                loadEndpointExplorer();
            }
        });
    });

    // Security Category Sub-tabs
    const secTabs = document.querySelectorAll('.sec-cat-btn');
    secTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            secTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            currentCategory = tab.dataset.secCat;
            loadAgentAlerts();
        });
    });

    // Initial load
    loadAgent();

    // Auto-refresh every 30 seconds
    if (typeof startAutoRefresh === 'function') {
        startAutoRefresh(30, () => {
            refreshPage();
        });
    }
});

function refreshPage() {
    loadAgent();
    loadAgentAlerts();
    loadTimeline();
    const activeTab = document.querySelector('.detail-tab.active')?.dataset.tab;
    if (activeTab === 'apps') loadAgentApps();
}

async function loadAgent() {
    try {
        const agent = await api(`/api/agents/${agentId}`);
        agentName = agent.name || '';

        // Update Headers
        document.getElementById('agentNameHeader').textContent = agentName;
        document.getElementById('agentStatusBadge').innerHTML = statusBadge(agent.status);

        // Populate Overview Tab
        document.getElementById('infoId').textContent = agent.id || '—';
        document.getElementById('infoIp').textContent = agent.ip || '—';
        const os = agent.os || {};
        document.getElementById('infoOs').textContent = os.name ? `${os.name} ${os.version || ''}` : '—';
        document.getElementById('infoVersion').textContent = agent.version || '—';
        document.getElementById('infoDateReg').textContent = formatTime(agent.dateAdd);
        document.getElementById('infoLastSeen').textContent = formatTime(agent.lastKeepAlive);

        // Populate Inventory Tab
        document.getElementById('infoNode').textContent = agent.node_name || '—';
        document.getElementById('infoOsPlatform').textContent = os.platform || '—';
        document.getElementById('infoOsArch').textContent = os.arch || '—';
        document.getElementById('infoManager').textContent = agent.manager || '—';
        document.getElementById('infoRegIp').textContent = agent.registerIP || '—';
        document.getElementById('infoConfigSum').textContent = agent.configSum || '—';

        // Load Alerts and Timeline
        loadAgentAlerts();
        loadTimeline();
    } catch (err) {
        document.getElementById('agentNameHeader').textContent = 'Error Loading Profile';
        toast('Load Profile Failed', err.message, 'error');
    }
}

async function loadAgentAlerts() {
    const tbody = document.getElementById('agentAlertsTbody');
    const badge = document.getElementById('agentAlertCount');
    if (!tbody) return;

    tbody.innerHTML = skeletonRows(4, 4);

    let url = `/api/security/alerts?agent=${agentId}&limit=50`;
    if (currentCategory) url += `&category=${currentCategory}`;

    try {
        const data = await api(url);
        const alerts = data.items || [];
        
        badge.textContent = `${data.total || alerts.length} events`;

        if (!alerts.length) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="4">
                        <div class="empty-state">
                            <div class="empty-icon">🔍</div>
                            <div class="empty-text">No security events found in this category</div>
                        </div>
                    </td>
                </tr>`;
            return;
        }

        tbody.innerHTML = alerts.map(a => {
            const rule = a.rule || {};
            const alertJson = JSON.stringify(a).replace(/'/g, "&#39;");
            
            return `
                <tr onclick='openDrawer(${alertJson})'>
                    <td>${levelBadge(rule.level)}</td>
                    <td><span class="rule-id">${escapeHtml(String(rule.id || '—'))}</span></td>
                    <td class="primary" style="max-width:400px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis" title="${escapeHtml(rule.description || '')}">
                        ${escapeHtml(rule.description || '—')}
                    </td>
                    <td class="mono">${formatTime(a.timestamp)}</td>
                </tr>`;
        }).join('');
    } catch (err) {
        tbody.innerHTML = `
            <tr>
                <td colspan="4">
                    <div class="empty-state">
                        <div class="empty-icon">⚠️</div>
                        <div class="empty-text">Failed to load events: ${escapeHtml(err.message)}</div>
                    </div>
                </td>
            </tr>`;
        toast('Fetch Events Failed', err.message, 'error');
    }
}

async function loadTimeline() {
    const container = document.getElementById('timelineContainer');
    if (!container) return;

    try {
        const data = await api(`/api/security/alerts?agent=${agentId}&limit=20`);
        const alerts = data.items || [];

        if (!alerts.length) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">📈</div>
                    <div class="empty-text">No timeline activity recorded yet</div>
                </div>`;
            return;
        }

        container.style.position = 'relative';
        container.style.paddingLeft = '30px';

        // Add vertical line
        let html = `<div style="position: absolute; left: 14px; top: 10px; bottom: 10px; width: 2px; background: var(--border); z-index: 1;"></div>`;

        html += alerts.map(a => {
            let color = 'var(--blue)';
            let icon = 'ℹ️';
            
            if (a.rule.level >= 12) {
                color = 'var(--critical)';
                icon = '🔴';
            } else if (a.rule.level >= 9) {
                color = 'var(--high)';
                icon = '🟠';
            } else if (a.rule.level >= 5) {
                color = 'var(--yellow)';
                icon = '🟡';
            }
            if (a.category === 'authentication') {
                icon = a.auth_status === 'success' ? '🔑' : '🔒';
            } else if (a.category === 'applications') {
                icon = '📦';
            } else if (a.category === 'malware') {
                icon = '💀';
                color = 'var(--critical)';
            }

            return `
                <div class="timeline-item" style="display: flex; gap: 15px; margin-bottom: 20px; position: relative; z-index: 2;" onclick='openDrawer(${JSON.stringify(a).replace(/'/g, "&#39;")})'>
                    <div class="timeline-dot" style="width: 30px; height: 30px; border-radius: 50%; background: #1c2333; border: 2px solid ${color}; display: flex; align-items: center; justify-content: center; font-size: 14px; flex-shrink: 0; box-shadow: 0 0 8px rgba(0,0,0,0.3);">
                        ${icon}
                    </div>
                    <div class="timeline-content" style="background: rgba(255,255,255,0.02); border: 1px solid var(--border); border-radius: 6px; padding: 12px 16px; flex: 1; cursor: pointer; transition: all 0.2s ease;">
                        <style>
                            .timeline-content:hover {
                                background: rgba(255,255,255,0.04) !important;
                                border-color: #58a6ff !important;
                            }
                        </style>
                        <div style="display: flex; justify-content: space-between; margin-bottom: 6px; flex-wrap: wrap; gap: 8px;">
                            <strong style="color: #e6edf3; font-size: 14px;">${escapeHtml(a.rule.description)}</strong>
                            <span style="font-size: 11px; color: #8b949e; font-family: monospace;">${formatTime(a.timestamp)}</span>
                        </div>
                        <div style="font-size: 12px; color: #8b949e; display: flex; gap: 15px; flex-wrap: wrap;">
                            <span>User: <strong>${escapeHtml(a.username || 'system')}</strong></span>
                            <span>Category: <strong>${escapeHtml(a.category)}</strong></span>
                            <span>Rule ID: <strong>${escapeHtml(a.rule.id)}</strong></span>
                        </div>
                    </div>
                </div>`;
        }).join('');

        container.innerHTML = html;
    } catch (err) {
        container.innerHTML = `<div class="empty-state"><div class="empty-text" style="color:var(--red)">Failed to load timeline: ${err.message}</div></div>`;
    }
}

async function loadAgentApps() {
    const tbody = document.getElementById('agentAppsTbody');
    const badge = document.getElementById('agentAppCount');
    if (!tbody) return;

    tbody.innerHTML = skeletonRows(4, 4);

    try {
        const data = await api(`/api/syscollector/applications`);
        const items = (data.items || []).filter(pkg => pkg.agent_id === agentId);
        
        badge.textContent = `${items.length} applications`;

        if (!items.length) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="4">
                        <div class="empty-state">
                            <div class="empty-icon">📦</div>
                            <div class="empty-text">No installed applications found for this agent</div>
                        </div>
                    </td>
                </tr>`;
            return;
        }

        tbody.innerHTML = items.map(item => `
            <tr>
                <td class="primary font-bold">${escapeHtml(item.name || '—')}</td>
                <td class="mono">${escapeHtml(item.version || '—')}</td>
                <td>${escapeHtml(item.vendor || '—')}</td>
                <td class="mono">${escapeHtml(item.install_date || '—')}</td>
            </tr>
        `).join('');
    } catch (err) {
        tbody.innerHTML = `
            <tr>
                <td colspan="4">
                    <div class="empty-state">
                        <div class="empty-icon">✕</div>
                        <div class="empty-text" style="color:var(--red)">Failed to load applications</div>
                    </div>
                </td>
            </tr>`;
    }
}

// ── Endpoint Explorer Engine ────────────────────────────────────

let activeSubtab = "processes";

async function loadEndpointExplorer() {
    setupSubtabs();
    loadExplorerHardware();
    loadActiveSubtabData();
}

function setupSubtabs() {
    const subtabs = document.querySelectorAll('.explorer-subtab-btn');
    subtabs.forEach(btn => {
        // Prevent duplicate listener additions
        if (!btn.dataset.listenerBound) {
            btn.dataset.listenerBound = "true";
            btn.addEventListener('click', () => {
                subtabs.forEach(t => t.classList.remove('active'));
                btn.classList.add('active');
                
                activeSubtab = btn.dataset.subtab;
                
                document.querySelectorAll('.explorer-subview').forEach(view => {
                    view.style.display = "none";
                });
                
                const targetView = document.getElementById(`subview_${activeSubtab}`);
                if (targetView) targetView.style.display = "block";
                
                loadActiveSubtabData();
            });
        }
    });
}

function loadActiveSubtabData() {
    if (activeSubtab === "processes") loadExplorerProcesses();
    else if (activeSubtab === "ports") loadExplorerPorts();
    else if (activeSubtab === "netaddr") loadExplorerNet();
    else if (activeSubtab === "users") loadExplorerUsers();
}

// Load CPU and RAM hardware info
async function loadExplorerHardware() {
    const cpuEl = document.getElementById('cpuModelName');
    const cpuCoresEl = document.getElementById('cpuCoresValue');
    const cpuMhzEl = document.getElementById('cpuMhzValue');
    
    const ramUsagePercent = document.getElementById('ramUsagePercent');
    const ramUsageBar = document.getElementById('ramUsageBar');
    const ramTotalValue = document.getElementById('ramTotalValue');
    const ramFreeValue = document.getElementById('ramFreeValue');
    
    try {
        const data = await api(`/api/agents/${agentId}/explorer/hardware`);
        const item = data.items && data.items[0] ? data.items[0] : null;
        
        if (item) {
            cpuEl.textContent = item.cpu ? item.cpu.name : "Unknown CPU";
            cpuCoresEl.textContent = item.cpu ? `${item.cpu.cores} Cores` : "— Cores";
            cpuMhzEl.textContent = item.cpu ? `${Math.round(item.cpu.mhz || 0)} MHz` : "— MHz";
            
            const ramTotalGb = ((item.ram ? item.ram.total : 0) / 1024 / 1024).toFixed(2);
            const ramFreeGb = ((item.ram ? item.ram.free : 0) / 1024 / 1024).toFixed(2);
            const usedPercent = item.ram ? Math.round(item.ram.usage || 0) : 0;
            
            ramUsagePercent.textContent = `${usedPercent}%`;
            ramUsageBar.style.width = `${usedPercent}%`;
            ramTotalValue.textContent = `${ramTotalGb} GB`;
            ramFreeValue.textContent = `${ramFreeGb} GB`;
            
            // Adjust bar color based on usage
            if (usedPercent > 85) {
                ramUsageBar.style.background = "var(--red)";
                ramUsagePercent.style.color = "var(--red)";
            } else if (usedPercent > 65) {
                ramUsageBar.style.background = "var(--yellow)";
                ramUsagePercent.style.color = "var(--yellow)";
            } else {
                ramUsageBar.style.background = "var(--green)";
                ramUsagePercent.style.color = "var(--green)";
            }
        }
    } catch (err) {
        console.error("Failed to load hardware", err);
        cpuEl.textContent = "Failed to load hardware telemetry";
    }
}

// 1. Running Processes
async function loadExplorerProcesses() {
    const tbody = document.getElementById('explorerProcessesTbody');
    const badge = document.getElementById('explorerProcessCount');
    tbody.innerHTML = `<tr><td colspan="4"><div class="empty-state"><div class="empty-icon">⏳</div><div class="empty-text">Loading processes...</div></div></td></tr>`;
    
    try {
        const data = await api(`/api/agents/${agentId}/explorer/processes`);
        const items = data.items || [];
        badge.textContent = `${items.length} processes`;
        
        if (!items.length) {
            tbody.innerHTML = `<tr><td colspan="4"><div class="empty-state"><div class="empty-text">No processes found</div></div></td></tr>`;
            return;
        }
        
        // Sort processes by PID numerically
        items.sort((a, b) => (parseInt(a.pid) || 0) - (parseInt(b.pid) || 0));
        
        tbody.innerHTML = items.map(p => {
            const rawState = p.state || 'active';
            const stateLabel = rawState.charAt(0).toUpperCase() + rawState.slice(1);
            let stateBg = 'var(--border)';
            let stateColor = 'var(--text-muted)';
            const stateLower = rawState.toLowerCase();
            if (stateLower === 'running' || stateLower === 'active') {
                stateBg = 'rgba(63,185,80,0.15)';
                stateColor = 'var(--green)';
            } else if (stateLower === 'sleeping') {
                stateBg = 'rgba(88,166,255,0.15)';
                stateColor = 'var(--blue)';
            } else if (stateLower === 'zombie' || stateLower === 'stopped') {
                stateBg = 'rgba(248,81,73,0.15)';
                stateColor = 'var(--red)';
            }

            const nameHtml = `<strong>${escapeHtml(p.name || '—')}</strong>${p.uname ? `<br><span style="font-size:10px; color:var(--muted)">User: ${escapeHtml(p.uname)}</span>` : ''}`;

            return `
            <tr>
                <td class="mono font-bold">${escapeHtml(String(p.pid || '—'))}</td>
                <td>${nameHtml}</td>
                <td class="mono" style="font-size:11px; max-width:400px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(p.cmd || '')}">
                    ${escapeHtml(p.cmd || '—')}
                </td>
                <td><span class="badge" style="background:${stateBg}; color:${stateColor}; border:1px solid ${stateColor}22;">${escapeHtml(stateLabel)}</span></td>
            </tr>`;
        }).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="4"><div class="empty-state" style="color:var(--red)"><div class="empty-text">Error loading processes: ${escapeHtml(err.message)}</div></div></td></tr>`;
    }
}

// 2. Open Ports
async function loadExplorerPorts() {
    const tbody = document.getElementById('explorerPortsTbody');
    const badge = document.getElementById('explorerPortsCount');
    tbody.innerHTML = `<tr><td colspan="5"><div class="empty-state"><div class="empty-icon">⏳</div><div class="empty-text">Loading ports...</div></div></td></tr>`;
    
    try {
        const data = await api(`/api/agents/${agentId}/explorer/ports`);
        const items = data.items || [];
        badge.textContent = `${items.length} ports`;
        
        if (!items.length) {
            tbody.innerHTML = `<tr><td colspan="5"><div class="empty-state"><div class="empty-text">No open ports found</div></div></td></tr>`;
            return;
        }
        
        tbody.innerHTML = items.map(p => {
            // Wazuh returns { local: { ip, port }, remote: { ip, port }, process, state, protocol, pid }
            const localIp  = (p.local  && p.local.ip)   || '0.0.0.0';
            const localPort = (p.local  && p.local.port) || '—';
            const proto    = (p.protocol || 'TCP').toUpperCase();
            const state    = p.state || 'UNKNOWN';
            const pid      = p.pid || '—';
            const process  = p.process || '—';
            const isListen = state.toLowerCase() === 'listening' || state.toLowerCase() === 'listen';
            return `
            <tr>
                <td class="mono">${escapeHtml(String(localIp))}</td>
                <td class="mono font-bold">${escapeHtml(String(localPort))}</td>
                <td><span class="badge" style="background:var(--panel);">${escapeHtml(proto)}</span></td>
                <td><span class="badge" style="background:${isListen ? 'rgba(63,185,80,0.15); color:var(--green);' : 'var(--border);'}">${escapeHtml(state)}</span></td>
                <td class="mono">${escapeHtml(String(pid))} <span style="color:var(--muted); font-size:11px;">${escapeHtml(process)}</span></td>
            </tr>`;
        }).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5"><div class="empty-state" style="color:var(--red)"><div class="empty-text">Error loading ports: ${escapeHtml(err.message)}</div></div></td></tr>`;
    }
}

// 3. Network Interfaces
async function loadExplorerNet() {
    const tbody = document.getElementById('explorerNetTbody');
    tbody.innerHTML = `<tr><td colspan="4"><div class="empty-state"><div class="empty-icon">⏳</div><div class="empty-text">Loading network interfaces...</div></div></td></tr>`;
    
    try {
        const data = await api(`/api/agents/${agentId}/explorer/netaddr`);
        const items = data.items || [];
        
        if (!items.length) {
            tbody.innerHTML = `<tr><td colspan="4"><div class="empty-state"><div class="empty-text">No interfaces found</div></div></td></tr>`;
            return;
        }
        
        tbody.innerHTML = items.map(n => {
            // Wazuh netaddr: { iface, address, proto, netmask, broadcast }
            const ip      = n.address || n.ip || '—';
            const iface   = n.iface   || '—';
            const proto   = (n.proto  || 'ipv4').toUpperCase();
            const netmask = n.netmask || '—';
            return `
            <tr>
                <td><strong>${escapeHtml(iface)}</strong></td>
                <td class="mono font-bold">${escapeHtml(ip)}</td>
                <td class="mono" style="color:var(--muted);">${escapeHtml(netmask)}</td>
                <td><span class="badge" style="background:var(--panel);">${escapeHtml(proto)}</span></td>
            </tr>`;
        }).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="4"><div class="empty-state" style="color:var(--red)"><div class="empty-text">Error loading interfaces: ${escapeHtml(err.message)}</div></div></td></tr>`;
    }
}

// 4. Users (Windows syscollector returns nested user object)
async function loadExplorerUsers() {
    const tbody = document.getElementById('explorerUsersTbody');
    const badge = document.getElementById('explorerUsersCount');
    tbody.innerHTML = `<tr><td colspan="4"><div class="empty-state"><div class="empty-icon">⏳</div><div class="empty-text">Loading users...</div></div></td></tr>`;
    
    try {
        const data = await api(`/api/agents/${agentId}/explorer/users`);
        const items = data.items || [];
        badge.textContent = `${items.length} users`;
        
        if (!items.length) {
            tbody.innerHTML = `<tr><td colspan="4"><div class="empty-state"><div class="empty-text">No users found</div></div></td></tr>`;
            return;
        }
        
        tbody.innerHTML = items.map(u => {
            // Windows Wazuh returns { user: { name, id, groups, type, full_name, ... }, login: {...} }
            const userObj  = u.user  || u; // fallback to flat for Linux agents
            const loginObj = u.login || {};
            const name     = userObj.name     || u.username || '—';
            const uid      = userObj.id       || u.uid      || '—';
            const groups   = userObj.groups   || u.gid      || '—';
            const userType = userObj.type     || 'local';
            const fullName = userObj.full_name || '';
            const lastLogin = loginObj.status !== undefined
                ? (loginObj.status === 0 ? 'Not logged in' : 'Active')
                : '—';
            return `
            <tr>
                <td class="font-bold">${escapeHtml(name)}<br><span style="font-size:11px;color:var(--muted)">${escapeHtml(fullName)}</span></td>
                <td class="mono">${escapeHtml(String(uid))}</td>
                <td><span class="badge" style="background:var(--panel);">${escapeHtml(groups)}</span></td>
                <td><span class="badge" style="background:${userType === 'local' ? 'var(--border)' : 'rgba(88,166,255,0.15); color:var(--blue);'}">${escapeHtml(userType)}</span></td>
            </tr>`;
        }).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="4"><div class="empty-state" style="color:var(--red)"><div class="empty-text">Error loading users: ${escapeHtml(err.message)}</div></div></td></tr>`;
    }
}
