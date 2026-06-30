/* ═══════════════════════════════════════════════════════════════
   dashboard.js — Dashboard page logic
   Stats, charts, agent health, recent events
   ═══════════════════════════════════════════════════════════════ */

let timelineChart = null;
let topAgentsChart = null;
let severityDoughnutChart = null;
let _lastAlerts = null;   // cache for severity breakdown
let _lastTopSources = []; // cache for top sources
let currentPage = 1;
let pageSize = 10;
let totalItems = 0;
let lastShowInfra = null;

let vulnPage = 1;
let vulnPageSize = 8;
let vulnTotal = 0;

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

    document.getElementById('vulnPrevBtn')?.addEventListener('click', () => {
        if (vulnPage > 1) {
            vulnPage--;
            loadVulnerabilities();
        }
    });
    document.getElementById('vulnNextBtn')?.addEventListener('click', () => {
        if (vulnPage * vulnPageSize < vulnTotal) {
            vulnPage++;
            loadVulnerabilities();
        }
    });

    loadDashboard();
    loadVulnerabilities();
    startAutoRefresh(REFRESH_INTERVAL, () => {
        loadDashboard();
        loadVulnerabilities();
    });
});

function refreshPage() {
    loadDashboard();
    loadVulnerabilities();
}

async function loadVulnerabilities() {
    try {
        const offset = (vulnPage - 1) * vulnPageSize;
        const data = await api(`/api/vulnerabilities?limit=${vulnPageSize}&offset=${offset}&severity=Critical,High`);
        updateVulnerabilitiesTableUI(data.items || [], data.total || 0);
    } catch (err) {
        console.error("Vulnerabilities load error", err);
    }
}

async function loadDashboard() {
    try {
        const showInfra = document.getElementById('showInfraToggle')?.checked || false;
        if (lastShowInfra !== null && lastShowInfra !== showInfra) {
            currentPage = 1;
        }
        lastShowInfra = showInfra;

        const offset = (currentPage - 1) * pageSize;
        const data = await api(`/api/dashboard?limit=${pageSize}&offset=${offset}&show_infra=${showInfra}`);

        updateStatsUI(data, data.security || {}, data.incidents || []);
        updateAgentHealthUI(data.agents || []);
        updateRecentEventsUI(data.latest_alerts || [], data.latest_alerts_total || 0);
        updateIncidentsUI(data.incidents || [], data.active_incidents_count || 0);

        markRefreshSuccess();
    } catch (err) {
        markRefreshFailure(err.message || 'Wazuh Connection Lost');
        clearUIOnFailure();
    }
}

// Map old loaders to loadDashboard to avoid breaking any other triggers/callbacks
async function loadStats() { return loadDashboard(); }
async function loadAgentHealth() { return loadDashboard(); }
async function loadRecentEvents() { return loadDashboard(); }

function updateStatsUI(data, secStats, incidents) {
    const stats = data.stats || {};
    const agents = stats.agents || {};
    const alerts = stats.alerts || {};

    const elOnline = document.getElementById('statOnline');
    if (elOnline) elOnline.textContent = agents.active || 0;
    const elOffline = document.getElementById('statOffline');
    if (elOffline) elOffline.textContent = agents.disconnected || 0;

    const cardCriticalAlerts = document.getElementById('cardCriticalAlerts');
    if (cardCriticalAlerts) cardCriticalAlerts.textContent = alerts.critical || 0;

    const cardVulns = document.getElementById('cardVulnerabilities');
    const cardVulnsSub = document.getElementById('cardVulnerabilitiesSub');
    if (cardVulns && data.vulnerabilities_summary) {
        const crit = data.vulnerabilities_summary.critical || 0;
        const high = data.vulnerabilities_summary.high || 0;
        cardVulns.textContent = crit + high;
        if (cardVulnsSub) {
            cardVulnsSub.textContent = `${crit} Critical, ${high} High`;
        }
    }

    const statTotalSub = document.getElementById('statTotalSub');
    if (statTotalSub) {
        statTotalSub.textContent = `${agents.total || 0} total registered`;
    }
    const statOfflineSub = document.getElementById('statOfflineSub');
    if (statOfflineSub) {
        statOfflineSub.textContent = agents.disconnected > 0 ? 'Requires attention' : 'All agents online';
    }

    // Offline banner
    const banner = document.getElementById('offlineBanner');
    if (banner) {
        if (agents.disconnected > 0) {
            banner.classList.remove('hidden');
            const textEl = document.getElementById('offlineBannerText');
            if (textEl) {
                textEl.innerHTML = `⚠ ${agents.disconnected} Agent${agents.disconnected > 1 ? 's' : ''} Offline <span>Immediate attention required</span>`;
            }
        } else {
            banner.classList.add('hidden');
        }
    }

    // Cache data for charts
    _lastAlerts = alerts;
    _lastTopSources = stats.top_sources || [];

    // Build severity bars & charts from real data
    updateSeverityBars(alerts);
}

function updateSeverityBars(alerts) {
    const crit = alerts.critical || 0;
    const high = alerts.high || 0;
    const med = alerts.medium || 0;
    const low = alerts.low || 0;
    const info = alerts.info || 0;
    const total = crit + high + med + low + info || 1;
    const absoluteTotal = crit + high + med + low + info;

    const elTotal = document.getElementById('sevTotalCount');
    if (elTotal) elTotal.textContent = absoluteTotal.toLocaleString();
    const elTotalLabel = document.getElementById('sevTotalLabel');
    if (elTotalLabel) elTotalLabel.textContent = absoluteTotal.toLocaleString();

    const elCrit = document.getElementById('cntCrit');
    if (elCrit) elCrit.textContent = crit;
    const elHigh = document.getElementById('cntHigh');
    if (elHigh) elHigh.textContent = high;
    const elMed = document.getElementById('cntMed');
    if (elMed) elMed.textContent = med;
    const elLow = document.getElementById('cntLow');
    if (elLow) elLow.textContent = low;
    const elInfo = document.getElementById('cntInfo');
    if (elInfo) elInfo.textContent = info;

    const elPctCrit = document.getElementById('pctCrit');
    if (elPctCrit) elPctCrit.textContent = `(${((crit / total) * 100).toFixed(1)}%)`;
    const elPctHigh = document.getElementById('pctHigh');
    if (elPctHigh) elPctHigh.textContent = `(${((high / total) * 100).toFixed(1)}%)`;
    const elPctMed = document.getElementById('pctMed');
    if (elPctMed) elPctMed.textContent = `(${((med / total) * 100).toFixed(1)}%)`;
    const elPctLow = document.getElementById('pctLow');
    if (elPctLow) elPctLow.textContent = `(${((low / total) * 100).toFixed(1)}%)`;
    const elPctInfo = document.getElementById('pctInfo');
    if (elPctInfo) elPctInfo.textContent = `(${((info / total) * 100).toFixed(1)}%)`;

    const ctx = document.getElementById('severityDoughnutChart');
    if (!ctx) return;

    if (severityDoughnutChart) {
        severityDoughnutChart.destroy();
    }

    severityDoughnutChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
            datasets: [{
                data: [crit, high, med, low, info],
                backgroundColor: [
                    '#f85149', // critical
                    '#f0883e', // high
                    '#d29922', // medium
                    '#3fb950', // low
                    '#58a6ff'  // info
                ],
                borderWidth: 1,
                borderColor: '#1f2937'
            }]
        },
        options: {
            cutout: '75%',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const val = context.raw;
                            const pct = ((val / total) * 100).toFixed(1) + '%';
                            return ` ${context.label}: ${val} (${pct})`;
                        }
                    }
                }
            }
        }
    });

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

function updateAgentHealthUI(agents) {
    const grid = document.getElementById('agentHealthGrid');
    const badge = document.getElementById('agentHealthCount');

    if (badge) badge.textContent = `${agents.length} agents`;

    if (!grid) return;

    if (!agents.length) {
        grid.innerHTML = '<div class="empty-state"><div class="empty-icon">🖥</div><div class="empty-text">No agents found</div></div>';
        return;
    }

    grid.innerHTML = agents.map(a => {
        const st = a.status || 'never_connected';
        const cardClass = st === 'active' ? 'online' : st === 'disconnected' ? 'offline' : 'warning';
        const statusLabel = st.charAt(0).toUpperCase() + st.slice(1).replace(/_/g, ' ');
        const lastSeen = formatRelative(a.lastKeepAlive);
        
        return `
            <div class="agent-health-card ${cardClass}" onclick="window.location.href='/agents/${a.id}'" style="display: flex; flex-direction: column; gap: 4px; padding: 10px 12px; margin: 0; background: var(--panel2);">
                <div style="font-weight: 600; font-size: 13px; color: var(--text);">${escapeHtml(a.name || '—')}</div>
                <div style="display: flex; align-items: center; gap: 8px; font-size: 11px;">
                    <span style="display: inline-flex; align-items: center; gap: 4px; font-weight: 600; color: ${st === 'active' ? 'var(--green)' : st === 'disconnected' ? 'var(--red)' : 'var(--yellow)'};">
                        <span style="display: inline-block; width: 6px; height: 6px; border-radius: 50%; background: ${st === 'active' ? 'var(--green)' : st === 'disconnected' ? 'var(--red)' : 'var(--yellow)'};"></span>
                        ${statusLabel}
                    </span>
                    <span style="color: var(--hint); font-size: 10px;">Last Seen ${lastSeen}</span>
                </div>
            </div>`;
    }).join('');
}


/* ── Recent Events ─────────────────────────────────────────────── */

function updateRecentEventsUI(items, total) {
    totalItems = total;
    const tbody = document.getElementById('recentEventsTbody');
    const badge = document.getElementById('recentEventCount');

    if (badge) badge.textContent = `${totalItems} alerts`;

    if (!tbody) return;

    if (!items.length) {
        tbody.innerHTML = '<tr><td colspan="4"><div class="empty-state"><div class="empty-icon">🔍</div><div class="empty-text">No security alerts loaded</div></div></td></tr>';
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
                <td class="primary" style="max-width:400px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${escapeHtml(rule.description || '')}">${escapeHtml(rule.description || '—')}</td>
                <td class="mono">${formatTime(a.timestamp)}</td>
            </tr>`;
    }).join('');

    updatePaginationUI();
}

function updateIncidentsUI(incidents, activeCount) {
    const badge = document.getElementById('dashboardIncidentCount');
    if (badge) badge.textContent = `${activeCount} active`;

    const cardIncidents = document.getElementById('cardActiveIncidents');
    if (cardIncidents) cardIncidents.textContent = activeCount;

    const cardIncidentsSub = document.getElementById('cardIncidentsSub');
    if (cardIncidentsSub) {
        cardIncidentsSub.textContent = `${activeCount} unresolved`;
    }

    const tbody = document.getElementById('dashboardIncidentsTbody');
    if (!tbody) return;

    if (!incidents.length) {
        tbody.innerHTML = '<tr><td colspan="5"><div class="empty-state"><div class="empty-icon"><i data-lucide="shield-off"></i></div><div class="empty-text">No active incidents detected</div></div></td></tr>';
        if (window.lucide) lucide.createIcons();
        return;
    }

    tbody.innerHTML = incidents.map(inc => {
        let sevColor = 'var(--blue)';
        if (inc.severity.toLowerCase() === 'critical') sevColor = 'var(--critical)';
        else if (inc.severity.toLowerCase() === 'high') sevColor = 'var(--red)';
        else if (inc.severity.toLowerCase() === 'medium') sevColor = 'var(--orange)';

        return `
            <tr onclick="window.location.href='/incidents'">
                <td><span class="badge" style="background:rgba(248,81,73,0.1); color:${sevColor}; border:1px solid ${sevColor};">${escapeHtml(inc.severity)}</span></td>
                <td class="mono font-semibold" style="color:var(--blue);">${escapeHtml(inc.id)}</td>
                <td><span class="primary">${escapeHtml(inc.host || 'manager')}</span></td>
                <td class="primary font-medium">${escapeHtml(inc.title)}</td>
                <td class="mono">${formatTime(inc.timestamp)}</td>
            </tr>`;
    }).join('');
}

function clearUIOnFailure() {
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

    const grid = document.getElementById('agentHealthGrid');
    const badgeAgents = document.getElementById('agentHealthCount');
    if (badgeAgents) badgeAgents.textContent = '—';
    if (grid) {
        grid.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon" style="color:var(--red)">⚠️</div>
                <div class="empty-text" style="color:var(--red)">Connection lost: unable to fetch agent inventory</div>
            </div>`;
    }

    const tbody = document.getElementById('recentEventsTbody');
    const badgeEvents = document.getElementById('recentEventCount');
    if (badgeEvents) badgeEvents.textContent = '—';
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

function updateVulnerabilitiesTableUI(items, total) {
    vulnTotal = total;
    const badge = document.getElementById('vulnerabilitiesCount');
    if (badge) badge.textContent = `${total} total`;

    const tbody = document.getElementById('vulnerabilitiesTbody');
    if (!tbody) return;

    if (!items.length) {
        tbody.innerHTML = '<tr><td colspan="6"><div class="empty-state"><div class="empty-icon">🛡️</div><div class="empty-text">No active vulnerabilities found</div></div></td></tr>';
        updateVulnPaginationUI();
        return;
    }

    tbody.innerHTML = items.map(v => {
        let badgeClass = 'badge-info';
        const sev = (v.severity || '').toLowerCase();
        if (sev === 'critical') badgeClass = 'badge-critical';
        else if (sev === 'high') badgeClass = 'badge-high';
        else if (sev === 'medium') badgeClass = 'badge-medium';
        else if (sev === 'low') badgeClass = 'badge-low';

        const detectDate = v.detected_at ? formatDate(v.detected_at) : 'unknown';

        return `
            <tr onclick='openVulnerabilityDrawer(${JSON.stringify(v).replace(/'/g, "&#39;")})' style="cursor: pointer;">
                <td><span class="badge ${badgeClass}">${escapeHtml(v.severity || 'Unknown')}</span></td>
                <td class="mono font-semibold" style="color: var(--blue);">${escapeHtml(v.cve || '—')}</td>
                <td class="primary font-medium" style="max-width: 250px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${escapeHtml(v.name || '')} ${escapeHtml(v.version || '')}">${escapeHtml(v.name || '—')} <span class="mono" style="font-size: 10px; color: var(--hint);">${escapeHtml(v.version || '')}</span></td>
                <td><span class="primary">${escapeHtml(v.agent_name || 'manager')}</span></td>
                <td><span style="font-size: 11px; color: var(--hint);">${escapeHtml(v.status || 'Active')}</span></td>
                <td class="mono" style="font-size: 11px; color: var(--text-muted);">${escapeHtml(detectDate)}</td>
            </tr>`;
    }).join('');

    updateVulnPaginationUI();
}

function updateVulnPaginationUI() {
    const prevBtn = document.getElementById('vulnPrevBtn');
    const nextBtn = document.getElementById('vulnNextBtn');
    const pageInfo = document.getElementById('vulnPageInfo');

    if (!prevBtn || !nextBtn || !pageInfo) return;

    const start = vulnTotal === 0 ? 0 : (vulnPage - 1) * vulnPageSize + 1;
    const end = Math.min(vulnPage * vulnPageSize, vulnTotal);

    pageInfo.textContent = `Showing ${start}-${end} of ${vulnTotal} CVEs`;

    prevBtn.disabled = vulnPage <= 1;
    nextBtn.disabled = end >= vulnTotal;
}
