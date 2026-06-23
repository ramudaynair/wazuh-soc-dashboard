/* ═══════════════════════════════════════════════════════════════
   agent_detail.js — Agent details page logic
   Loads metadata, system profile inventory, and related alerts
   ═══════════════════════════════════════════════════════════════ */

let agentId = null;
let agentName = '';

document.addEventListener('DOMContentLoaded', () => {
    // Read agent ID from HTML payload
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
            // Remove active from all tabs
            tabs.forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.detail-tab-content').forEach(c => c.classList.remove('active'));

            // Add active to clicked tab
            tab.classList.add('active');
            const targetContent = document.getElementById(`tabContent_${tab.dataset.tab}`);
            if (targetContent) targetContent.classList.add('active');
        });
    });

    // Initial load
    loadAgent();
});

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

        // Load Alerts associated with this agent
        loadAgentAlerts();
    } catch (err) {
        document.getElementById('agentNameHeader').textContent = 'Error Loading Profile';
        toast('Load Profile Failed', err.message, 'error');
    }
}

async function loadAgentAlerts() {
    const tbody = document.getElementById('agentAlertsTbody');
    const badge = document.getElementById('agentAlertCount');
    if (!tbody) return;

    tbody.innerHTML = skeletonRows(4, 5);

    // Search for the agent name in alerts logs
    let url = `/api/alerts?limit=25`;
    if (agentName) {
        url += `&search=${encodeURIComponent(agentName)}`;
    }

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
                            <div class="empty-text">No security events found for this agent</div>
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
                        <div class="empty-text">Failed to load alerts: ${escapeHtml(err.message)}</div>
                    </div>
                </td>
            </tr>`;
        toast('Fetch Alerts Failed', err.message, 'error');
    }
}
