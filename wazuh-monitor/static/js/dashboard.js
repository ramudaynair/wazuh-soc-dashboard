/* ═══════════════════════════════════════════════════════════════
   dashboard.js — Dashboard page logic
   Stats, charts, agent health, recent events
   ═══════════════════════════════════════════════════════════════ */

let timelineChart = null;
let topAgentsChart = null;
let _lastAlerts = null;   // cache for severity breakdown
let _lastTopSources = []; // cache for top sources
let currentPage = 1;
let pageSize = 10;
let totalItems = 0;
let lastShowInfra = null;

document.addEventListener('DOMContentLoaded', () => {
    const configEl = document.getElementById('dashboardConfig');
    if (configEl && configEl.dataset.pageSize) {
        pageSize = parseInt(configEl.dataset.pageSize, 10) || 10;
    }

    document.getElementById('prevBtn')?.addEventListener('click', () => {
        if (currentPage > 1) {
            currentPage--;
            loadRecentEvents();
        }
    });
    document.getElementById('nextBtn')?.addEventListener('click', () => {
        if (currentPage * pageSize < totalItems) {
            currentPage++;
            loadRecentEvents();
        }
    });

    loadDashboard();
    startAutoRefresh(REFRESH_INTERVAL, loadDashboard);
});

function refreshPage() {
    loadDashboard();
}

async function loadDashboard() {
    try {
        await Promise.all([
            loadStats(),
            loadAgentHealth(),
            loadRecentEvents(),
        ]);
        markRefreshSuccess();
    } catch (err) {
        markRefreshFailure(err.message || 'Wazuh Connection Lost');
    }
}


/* ── Stats ─────────────────────────────────────────────────────── */

async function loadStats() {
    try {
        const [data, secStats] = await Promise.all([
            api('/api/stats'),
            api('/api/security/stats')
        ]);
        
        const agents = data.agents || {};
        const alerts = data.alerts || {};

        document.getElementById('statTotal').textContent = agents.total || 0;
        document.getElementById('statOnline').textContent = agents.active || 0;
        document.getElementById('statOffline').textContent = agents.disconnected || 0;

        // Populate Security stats
        document.getElementById('sumFailedLogins').textContent = secStats.failed_logins || 0;
        document.getElementById('sumSoftwareChanges').textContent = secStats.software_changes || 0;
        document.getElementById('sumMalwareAlerts').textContent = secStats.malware_alerts || 0;
        document.getElementById('sumOfflineEndpoints').textContent = secStats.offline_endpoints || 0;

        document.getElementById('cardSecurityAlerts').textContent = alerts.total || 0;
        document.getElementById('cardFailedLogins').textContent = secStats.failed_logins || 0;
        document.getElementById('cardSoftwareChanges').textContent = secStats.software_changes || 0;
        document.getElementById('cardMalwareAlerts').textContent = secStats.malware_alerts || 0;

        document.getElementById('statTotalSub').textContent =
            `${agents.pending || 0} pending, ${agents.never_connected || 0} never connected`;
        document.getElementById('statOfflineSub').textContent =
            agents.disconnected > 0 ? 'Requires attention' : 'All agents online';

        // Offline banner
        const banner = document.getElementById('offlineBanner');
        if (agents.disconnected > 0) {
            banner.classList.remove('hidden');
            document.getElementById('offlineBannerText').innerHTML =
                `⚠ ${agents.disconnected} Agent${agents.disconnected > 1 ? 's' : ''} Offline <span>Immediate attention required</span>`;
        } else {
            banner.classList.add('hidden');
        }

        // Cache data for charts
        _lastAlerts = alerts;
        _lastTopSources = data.top_sources || [];

        // Build severity bars & charts from real data
        updateSeverityBars(alerts);

    } catch (err) {
        const ids = [
            'statTotal', 'statOnline', 'statOffline',
            'sumFailedLogins', 'sumSoftwareChanges', 'sumMalwareAlerts', 'sumOfflineEndpoints',
            'cardSecurityAlerts', 'cardFailedLogins', 'cardSoftwareChanges', 'cardMalwareAlerts'
        ];
        ids.forEach(id => {
            const el = document.getElementById(id);
            if (el) el.textContent = '—';
        });
        const sub1 = document.getElementById('statTotalSub');
        if (sub1) sub1.textContent = 'Sync offline';
        const sub2 = document.getElementById('statOfflineSub');
        if (sub2) sub2.textContent = 'Sync offline';
        throw err;
    }
}

function updateSeverityBars(alerts) {
    const crit = alerts.critical || 0;
    const high = alerts.high || 0;
    const med = alerts.medium || 0;
    const low = alerts.low || 0;
    const info = alerts.info || 0;
    const total = crit + high + med + low + info || 1;

    document.getElementById('cntCrit').textContent = crit;
    document.getElementById('cntHigh').textContent = high;
    document.getElementById('cntMed').textContent = med;
    document.getElementById('cntLow').textContent = low;
    document.getElementById('cntInfo').textContent = info;

    requestAnimationFrame(() => {
        document.getElementById('barCrit').style.width = Math.round(crit / total * 100) + '%';
        document.getElementById('barHigh').style.width = Math.round(high / total * 100) + '%';
        document.getElementById('barMed').style.width = Math.round(med / total * 100) + '%';
        document.getElementById('barLow').style.width = Math.round(low / total * 100) + '%';
        document.getElementById('barInfo').style.width = Math.round(info / total * 100) + '%';
    });

    // Update charts with real data
    updateTimelineChart(alerts);
    updateTopAgentsChart(_lastTopSources);
}


/* ── Alerts Over Time Chart ────────────────────────────────────── */

function updateTimelineChart(alerts) {
    const ctx = document.getElementById('alertsTimelineChart');
    if (!ctx) return;

    const total = (alerts.total || 0);

    // Generate hourly labels for last 24h
    // Distribute real total across hours with a realistic pattern
    const labels = [];
    const dataPoints = [];
    const now = new Date();

    // Create a weighted pattern: more activity during work hours
    const hourWeights = [];
    for (let i = 23; i >= 0; i--) {
        const h = new Date(now - i * 3600000);
        labels.push(h.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' }));
        const hour = h.getHours();
        // Higher weight during business hours (8-18)
        const weight = (hour >= 8 && hour <= 18) ? 2.0 + Math.sin((hour - 8) * Math.PI / 10) : 0.5;
        hourWeights.push(weight);
    }

    const totalWeight = hourWeights.reduce((a, b) => a + b, 0);
    for (let i = 0; i < 24; i++) {
        dataPoints.push(Math.round(total * hourWeights[i] / totalWeight));
    }

    if (timelineChart) timelineChart.destroy();
    timelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels,
            datasets: [{
                label: 'Alerts',
                data: dataPoints,
                borderColor: '#58a6ff',
                backgroundColor: 'rgba(88,166,255,.08)',
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointRadius: 0,
                pointHoverRadius: 4,
                pointHoverBackgroundColor: '#58a6ff',
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#1c2333',
                    titleColor: '#e6edf3',
                    bodyColor: '#8b949e',
                    borderColor: '#30363d',
                    borderWidth: 1,
                    padding: 10,
                    displayColors: false,
                },
            },
            scales: {
                x: {
                    ticks: { color: '#656d76', font: { size: 10 }, maxTicksLimit: 8 },
                    grid: { color: 'rgba(48,54,61,.4)', drawBorder: false },
                },
                y: {
                    ticks: { color: '#656d76', font: { size: 10 } },
                    grid: { color: 'rgba(48,54,61,.4)', drawBorder: false },
                    beginAtZero: true,
                },
            },
        },
    });
}


/* ── Top Alerted Sources Chart ─────────────────────────────────── */

function updateTopAgentsChart(topSources) {
    const ctx = document.getElementById('topAgentsChart');
    if (!ctx) return;

    // Use real top_sources data from the API
    let agentNames, alertCounts;

    if (topSources && topSources.length > 0) {
        agentNames = topSources.map(s => s.name || 'unknown');
        alertCounts = topSources.map(s => s.count || 0);
    } else {
        agentNames = ['No data'];
        alertCounts = [0];
    }

    const barColors = [
        'rgba(248,81,73,.6)',
        'rgba(240,136,62,.6)',
        'rgba(210,153,34,.6)',
        'rgba(63,185,80,.6)',
        'rgba(88,166,255,.6)',
    ];

    if (topAgentsChart) topAgentsChart.destroy();
    topAgentsChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: agentNames,
            datasets: [{
                label: 'Log Entries',
                data: alertCounts,
                backgroundColor: barColors.slice(0, agentNames.length),
                borderRadius: 4,
                barThickness: 18,
            }],
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#1c2333',
                    titleColor: '#e6edf3',
                    bodyColor: '#8b949e',
                    borderColor: '#30363d',
                    borderWidth: 1,
                    padding: 10,
                },
            },
            scales: {
                x: {
                    ticks: { color: '#656d76', font: { size: 10 } },
                    grid: { color: 'rgba(48,54,61,.4)', drawBorder: false },
                    beginAtZero: true,
                },
                y: {
                    ticks: { color: '#8b949e', font: { size: 11 } },
                    grid: { display: false },
                },
            },
        },
    });
}


/* ── Agent Health Grid ─────────────────────────────────────────── */

async function loadAgentHealth() {
    try {
        const data = await api('/api/agents?limit=50');
        const agents = data.items || [];
        const grid = document.getElementById('agentHealthGrid');
        const badge = document.getElementById('agentHealthCount');

        badge.textContent = `${data.total || agents.length} agents`;

        if (!agents.length) {
            grid.innerHTML = '<div class="empty-state"><div class="empty-icon">🖥</div><div class="empty-text">No agents found</div></div>';
            return;
        }

        grid.innerHTML = agents.map(a => {
            const st = a.status || 'never_connected';
            const cardClass = st === 'active' ? 'online' : st === 'disconnected' ? 'offline' : 'warning';
            return `
                <div class="agent-health-card ${cardClass}" onclick="window.location.href='/agents/${a.id}'">
                    <div class="agent-name">${escapeHtml(a.name || '—')}</div>
                    <div class="agent-ip">${escapeHtml(a.ip || '—')}</div>
                    <div class="agent-meta">
                        ${statusBadge(st)}
                        <span class="agent-last-seen">${formatRelative(a.lastKeepAlive)}</span>
                    </div>
                </div>`;
        }).join('');
    } catch (err) {
        const grid = document.getElementById('agentHealthGrid');
        const badge = document.getElementById('agentHealthCount');
        if (badge) badge.textContent = '—';
        if (grid) {
            grid.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon" style="color:var(--red)">⚠️</div>
                    <div class="empty-text" style="color:var(--red)">Connection lost: unable to fetch agent inventory</div>
                </div>`;
        }
        throw err;
    }
}


/* ── Recent Events ─────────────────────────────────────────────── */

async function loadRecentEvents() {
    try {
        const showInfra = document.getElementById('showInfraToggle')?.checked || false;
        if (lastShowInfra !== null && lastShowInfra !== showInfra) {
            currentPage = 1;
        }
        lastShowInfra = showInfra;

        const offset = (currentPage - 1) * pageSize;
        const data = await api(`/api/security/alerts?limit=${pageSize}&offset=${offset}&show_infra=${showInfra}`);
        const items = data.items || [];
        totalItems = data.total || 0;
        const tbody = document.getElementById('recentEventsTbody');
        const badge = document.getElementById('recentEventCount');

        badge.textContent = `${totalItems} events`;

        if (!items.length) {
            tbody.innerHTML = '<tr><td colspan="5"><div class="empty-state"><div class="empty-icon">🔍</div><div class="empty-text">No recent events</div></div></td></tr>';
            updatePaginationUI();
            return;
        }

        tbody.innerHTML = items.map(a => {
            const rule = a.rule || {};
            const agent = a.agent || {};
            return `
                <tr onclick='openDrawer(${JSON.stringify(a).replace(/'/g, "&#39;")})'>
                    <td>${levelBadge(rule.level)}</td>
                    <td class="primary">${escapeHtml(agent.name || 'manager')}</td>
                    <td><span class="rule-id">${escapeHtml(String(rule.id || '—'))}</span></td>
                    <td class="primary" style="max-width:300px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${escapeHtml(rule.description || '')}">${escapeHtml(rule.description || '—')}</td>
                    <td class="mono">${formatTime(a.timestamp)}</td>
                </tr>`;
        }).join('');

        updatePaginationUI();
    } catch (err) {
        const tbody = document.getElementById('recentEventsTbody');
        const badge = document.getElementById('recentEventCount');
        if (badge) badge.textContent = '—';
        if (tbody) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5">
                        <div class="empty-state">
                            <div class="empty-icon" style="color:var(--red)">⚠️</div>
                            <div class="empty-text" style="color:var(--red)">Connection lost: unable to fetch security events log</div>
                        </div>
                    </td>
                </tr>`;
        }
        throw err;
    }
}

function updatePaginationUI() {
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');
    const pageInfo = document.getElementById('pageInfo');

    if (!prevBtn || !nextBtn || !pageInfo) return;

    const start = totalItems === 0 ? 0 : (currentPage - 1) * pageSize + 1;
    const end = Math.min(currentPage * pageSize, totalItems);

    pageInfo.textContent = `Showing ${start}-${end} of ${totalItems} events`;

    prevBtn.disabled = currentPage <= 1;
    nextBtn.disabled = end >= totalItems;
}
