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

