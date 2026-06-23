/* ═══════════════════════════════════════════════════════════════
   logs.js — Logs page logic
   Paginated alerts loading, severity filtering, and text search
   ═══════════════════════════════════════════════════════════════ */

let currentPage = 1;
let pageSize = 20;
let totalEvents = 0;
let searchDebounceTimer = null;

document.addEventListener('DOMContentLoaded', () => {
    // Read page size config
    const configEl = document.getElementById('logsConfig');
    if (configEl && configEl.dataset.pageSize) {
        pageSize = parseInt(configEl.dataset.pageSize, 10) || 20;
    }

    // Initialize Event Listeners
    document.getElementById('levelFilter').addEventListener('change', () => {
        currentPage = 1;
        loadLogs();
    });

    document.getElementById('searchInput').addEventListener('input', () => {
        currentPage = 1;
        clearTimeout(searchDebounceTimer);
        searchDebounceTimer = setTimeout(loadLogs, 300);
    });

    document.getElementById('resetFiltersBtn').addEventListener('click', resetFilters);
    document.getElementById('prevBtn').addEventListener('click', prevPage);
    document.getElementById('nextBtn').addEventListener('click', nextPage);

    // Initial load
    loadLogs();
});

async function loadLogs() {
    const tbody = document.getElementById('logsTbody');
    if (!tbody) return;

    // Show skeletons during load
    tbody.innerHTML = skeletonRows(5, 8);

    const level = document.getElementById('levelFilter').value;
    const search = document.getElementById('searchInput').value.trim();
    const offset = (currentPage - 1) * pageSize;

    // Build URL query params
    let url = `/api/alerts?offset=${offset}&limit=${pageSize}`;
    if (level) url += `&level=${level}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;

    try {
        const data = await api(url);
        const alerts = data.items || [];
        totalEvents = data.total || 0;

        if (!alerts.length) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5">
                        <div class="empty-state">
                            <div class="empty-icon">🔍</div>
                            <div class="empty-text">No security events found matching current criteria</div>
                        </div>
                    </td>
                </tr>`;
            updatePaginationUI();
            return;
        }

        tbody.innerHTML = alerts.map(a => {
            const rule = a.rule || {};
            const agent = a.agent || {};
            
            // Clean/serialise alert data for drawer onClick safely
            const alertJson = JSON.stringify(a).replace(/'/g, "&#39;");
            
            return `
                <tr onclick='openDrawer(${alertJson})'>
                    <td>${levelBadge(rule.level)}</td>
                    <td class="primary">${escapeHtml(agent.name || 'manager')}</td>
                    <td><span class="rule-id">${escapeHtml(String(rule.id || '—'))}</span></td>
                    <td class="primary" style="max-width:400px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis" title="${escapeHtml(rule.description || '')}">
                        ${escapeHtml(rule.description || '—')}
                    </td>
                    <td class="mono">${formatTime(a.timestamp)}</td>
                </tr>`;
        }).join('');

        updatePaginationUI();
    } catch (err) {
        tbody.innerHTML = `
            <tr>
                <td colspan="5">
                    <div class="empty-state">
                        <div class="empty-icon">⚠️</div>
                        <div class="empty-text">Failed to load logs: ${escapeHtml(err.message)}</div>
                    </div>
                </td>
            </tr>`;
        toast('Fetch Error', err.message, 'error');
    }
}

function updatePaginationUI() {
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');
    const pageInfo = document.getElementById('pageInfo');

    if (!prevBtn || !nextBtn || !pageInfo) return;

    const start = totalEvents === 0 ? 0 : (currentPage - 1) * pageSize + 1;
    const end = Math.min(currentPage * pageSize, totalEvents);

    pageInfo.textContent = `Showing ${start}-${end} of ${totalEvents} events`;

    prevBtn.disabled = currentPage <= 1;
    nextBtn.disabled = end >= totalEvents;
}

function prevPage() {
    if (currentPage > 1) {
        currentPage--;
        loadLogs();
    }
}

function nextPage() {
    const end = currentPage * pageSize;
    if (end < totalEvents) {
        currentPage++;
        loadLogs();
    }
}

function resetFilters() {
    document.getElementById('levelFilter').value = '';
    document.getElementById('searchInput').value = '';
    currentPage = 1;
    loadLogs();
}
