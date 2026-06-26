/* ═══════════════════════════════════════════════════════════════
   agents.js — Agents list page logic
   Paginated agents loading, status filtering, and endpoint search
   ═══════════════════════════════════════════════════════════════ */

let currentPage = 1;
let pageSize = 20;
let totalAgents = 0;
let searchDebounceTimer = null;

document.addEventListener('DOMContentLoaded', () => {
    // Read page size config
    const configEl = document.getElementById('agentsConfig');
    if (configEl && configEl.dataset.pageSize) {
        pageSize = parseInt(configEl.dataset.pageSize, 10) || 20;
    }

    // Initialize Event Listeners
    document.getElementById('statusFilter').addEventListener('change', () => {
        currentPage = 1;
        loadAgents();
    });

    document.getElementById('searchInput').addEventListener('input', () => {
        currentPage = 1;
        clearTimeout(searchDebounceTimer);
        searchDebounceTimer = setTimeout(loadAgents, 300);
    });

    document.getElementById('resetFiltersBtn').addEventListener('click', resetFilters);
    document.getElementById('prevBtn').addEventListener('click', prevPage);
    document.getElementById('nextBtn').addEventListener('click', nextPage);

    // Initial load
    loadAgents();

    // Auto-refresh every 30 seconds
    if (typeof startAutoRefresh === 'function') {
        startAutoRefresh(30, () => {
            loadAgents();
        });
    }
});

async function loadAgents() {
    const tbody = document.getElementById('agentsTbody');
    if (!tbody) return;

    // Show skeletons during load
    tbody.innerHTML = skeletonRows(5, 8);

    const status = document.getElementById('statusFilter').value;
    const search = document.getElementById('searchInput').value.trim();
    const offset = (currentPage - 1) * pageSize;

    // Build URL query params
    let url = `/api/agents?offset=${offset}&limit=${pageSize}`;
    if (status) url += `&status=${status}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;

    try {
        const data = await api(url);
        const agents = data.items || [];
        totalAgents = data.total || 0;

        if (!agents.length) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5">
                        <div class="empty-state">
                            <div class="empty-icon">🖥</div>
                            <div class="empty-text">No monitored agents found matching current criteria</div>
                        </div>
                    </td>
                </tr>`;
            updatePaginationUI();
            return;
        }

        tbody.innerHTML = agents.map(a => {
            const os = a.os || {};
            const osText = os.name ? `${os.name} ${os.version || ''} (${os.platform || '—'})` : '—';
            
            return `
                <tr onclick="window.location.href='/agents/${a.id}'">
                    <td class="primary">
                        <div style="display: flex; flex-direction: column;">
                            <span style="font-weight: 600;">${escapeHtml(a.name || '—')}</span>
                            <span class="mono" style="font-size: 10px; color: var(--hint)">ID: ${escapeHtml(a.id)}</span>
                        </div>
                    </td>
                    <td class="mono">${escapeHtml(a.ip || '—')}</td>
                    <td>${statusBadge(a.status)}</td>
                    <td class="primary">${escapeHtml(osText)}</td>
                    <td class="mono">${formatTime(a.lastKeepAlive)}</td>
                </tr>`;
        }).join('');

        updatePaginationUI();
    } catch (err) {
        tbody.innerHTML = `
            <tr>
                <td colspan="5">
                    <div class="empty-state">
                        <div class="empty-icon">⚠️</div>
                        <div class="empty-text">Failed to load agents: ${escapeHtml(err.message)}</div>
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

    const start = totalAgents === 0 ? 0 : (currentPage - 1) * pageSize + 1;
    const end = Math.min(currentPage * pageSize, totalAgents);

    pageInfo.textContent = `Showing ${start}-${end} of ${totalAgents} agents`;

    prevBtn.disabled = currentPage <= 1;
    nextBtn.disabled = end >= totalAgents;
}

function prevPage() {
    if (currentPage > 1) {
        currentPage--;
        loadAgents();
    }
}

function nextPage() {
    const end = currentPage * pageSize;
    if (end < totalAgents) {
        currentPage++;
        loadAgents();
    }
}

function resetFilters() {
    document.getElementById('statusFilter').value = '';
    document.getElementById('searchInput').value = '';
    currentPage = 1;
    loadAgents();
}

function refreshPage() {
    loadAgents();
}
