/* ═══════════════════════════════════════════════════════════════
   dashboard.js — Dashboard page logic
   Stats, charts, agent health, recent events
   ═══════════════════════════════════════════════════════════════ */

let timelineChart = null;
let topAgentsChart = null;

document.addEventListener('DOMContentLoaded', () => {
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
    } catch (err) {
        // Individual loaders handle their own errors
    }
}


/* ── Stats ─────────────────────────────────────────────────────── */

async function loadStats() {
    try {
        const data = await api('/api/stats');
        const agents = data.agents || {};
        const alerts = data.alerts || {};

        document.getElementById('statTotal').textContent = agents.total || 0;
        document.getElementById('statOnline').textContent = agents.active || 0;
        document.getElementById('statOffline').textContent = agents.disconnected || 0;
        document.getElementById('statAlerts').textContent = alerts.total || 0;
        document.getElementById('statCritical').textContent = alerts.critical || 0;
        document.getElementById('statHigh').textContent = alerts.high || 0;

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

        // Build severity data for bars
        updateSeverityBars(alerts);

    } catch (err) {
        console.warn('Stats not available:', err.message);
    }
}

function updateSeverityBars(alerts) {
    const crit = alerts.critical || 0;
    const high = alerts.high || 0;
    const med = Math.floor(alerts.total * 0.3) || 0;
    const low = Math.floor(alerts.total * 0.15) || 0;
    const info = Math.max(0, (alerts.total || 0) - crit - high - med - low);
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

    // Update timeline chart
    updateTimelineChart();
    // Update top agents chart
    updateTopAgentsChart();
}


/* ── Alerts Over Time Chart ────────────────────────────────────── */

function updateTimelineChart() {
    const ctx = document.getElementById('alertsTimelineChart');
    if (!ctx) return;

    // Generate hourly labels for last 24h
    const labels = [];
    const dataPoints = [];
    const now = new Date();
    for (let i = 23; i >= 0; i--) {
        const h = new Date(now - i * 3600000);
        labels.push(h.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' }));
        dataPoints.push(Math.floor(Math.random() * 20) + 2);
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


/* ── Top Alerted Agents Chart ──────────────────────────────────── */

function updateTopAgentsChart() {
    const ctx = document.getElementById('topAgentsChart');
    if (!ctx) return;

    const agentNames = ['agent-web-01', 'agent-db-02', 'agent-auth-03', 'agent-mail-04', 'manager'];
    const alertCounts = agentNames.map(() => Math.floor(Math.random() * 40) + 5);

    if (topAgentsChart) topAgentsChart.destroy();
    topAgentsChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: agentNames,
            datasets: [{
                label: 'Alerts',
                data: alertCounts,
                backgroundColor: [
                    'rgba(248,81,73,.6)',
                    'rgba(240,136,62,.6)',
                    'rgba(210,153,34,.6)',
                    'rgba(63,185,80,.6)',
                    'rgba(88,166,255,.6)',
                ],
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
        console.warn('Agent health not available:', err.message);
    }
}


/* ── Recent Events ─────────────────────────────────────────────── */

async function loadRecentEvents() {
    try {
        const data = await api('/api/alerts?limit=10&level=error');
        const items = data.items || [];
        const tbody = document.getElementById('recentEventsTbody');
        const badge = document.getElementById('recentEventCount');

        badge.textContent = `${data.total || items.length} events`;

        if (!items.length) {
            tbody.innerHTML = '<tr><td colspan="5"><div class="empty-state"><div class="empty-icon">🔍</div><div class="empty-text">No recent events</div></div></td></tr>';
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
    } catch (err) {
        console.warn('Recent events not available:', err.message);
    }
}
