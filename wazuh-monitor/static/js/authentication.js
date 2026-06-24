/* ═══════════════════════════════════════════════════════════════
   authentication.js — Authentication Monitoring page logic
   ═══════════════════════════════════════════════════════════════ */

let currentPage = 1;
let pageSize = 20;
let totalItems = 0;

document.addEventListener('DOMContentLoaded', () => {
    const configEl = document.getElementById('authConfig');
    if (configEl) {
        pageSize = Number(configEl.getAttribute('data-page-size')) || 20;
    }

    // Event listeners
    document.getElementById('statusFilter').addEventListener('change', () => { currentPage = 1; loadAll(); });
    document.getElementById('searchInput').addEventListener('input', debounce(() => { currentPage = 1; loadAll(); }, 300));
    document.getElementById('resetFiltersBtn').addEventListener('click', resetFilters);
    document.getElementById('prevBtn').addEventListener('click', prevPage);
    document.getElementById('nextBtn').addEventListener('click', nextPage);

    loadAll();

    // Auto-refresh
    if (typeof startAutoRefresh === 'function') {
        startAutoRefresh(30, () => {
            loadAll();
        });
    }
});

function refreshPage() {
    loadAll();
}

async function loadAll() {
    try {
        await Promise.all([
            loadAuthStats(),
            loadAuthEvents()
        ]);
        markRefreshSuccess();
    } catch (err) {
        markRefreshFailure(err.message || 'Failed to sync authentication data');
    }
}

async function loadAuthStats() {
    try {
        const stats = await api('/api/security/stats');
        document.getElementById('authFailedCount').textContent = stats.failed_logins || 0;
        document.getElementById('authSuccessCount').textContent = stats.successful_logins || 0;
        document.getElementById('authLockedCount').textContent = stats.locked_accounts || 0;
    } catch (err) {
        const ids = ['authFailedCount', 'authSuccessCount', 'authLockedCount'];
        ids.forEach(id => {
            const el = document.getElementById(id);
            if (el) el.textContent = '—';
        });
        throw err;
    }
}

async function loadAuthEvents() {
    const tbody = document.getElementById('authTbody');
    const search = document.getElementById('searchInput').value.trim();
    const status = document.getElementById('statusFilter').value;
    const offset = (currentPage - 1) * pageSize;

    let query = `/api/security/alerts?category=authentication&limit=${pageSize}&offset=${offset}`;
    if (search) query += `&search=${encodeURIComponent(search)}`;
    
    // Status filtering in frontend helper or backend query. Let's filter on search/status
    if (status) query += `&search=${encodeURIComponent(status)}`;

    try {
        const data = await api(query);
        const items = data.items || [];
        totalItems = data.total || 0;

        tbody.innerHTML = '';

        if (!items.length) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5">
                        <div class="empty-state">
                            <div class="empty-icon">🔍</div>
                            <div class="empty-text">No authentication logs found</div>
                        </div>
                    </td>
                </tr>`;
            updatePagination();
            return;
        }

        tbody.innerHTML = items.map(a => {
            let statusBadge = '';
            if (a.auth_status === 'lockout') {
                statusBadge = '<span class="status-badge state-offline">🔒 LOCKOUT</span>';
            } else if (a.auth_status === 'success') {
                statusBadge = '<span class="status-badge state-online">✓ SUCCESS</span>';
            } else {
                statusBadge = '<span class="status-badge state-warning">✕ FAILED</span>';
            }

            return `
                <tr onclick='openDrawer(${JSON.stringify(a).replace(/'/g, "&#39;")})'>
                    <td>${statusBadge}</td>
                    <td class="primary font-bold">${escapeHtml(a.username || '—')}</td>
                    <td class="mono">${escapeHtml(a.src_ip || '—')}</td>
                    <td>${escapeHtml(a.agent.name || 'manager')} <span class="rule-id" style="font-size:11px">${escapeHtml(a.agent.id)}</span></td>
                    <td class="mono">${formatTime(a.timestamp)}</td>
                </tr>`;
        }).join('');

        updatePagination();
    } catch (err) {
        tbody.innerHTML = `
            <tr>
                <td colspan="5">
                    <div class="empty-state">
                        <div class="empty-icon">✕</div>
                        <div class="empty-text" style="color:var(--red)">Failed to load authentication events</div>
                    </div>
                </td>
            </tr>`;
        throw err;
    }
}

function updatePagination() {
    const start = totalItems === 0 ? 0 : (currentPage - 1) * pageSize + 1;
    const end = Math.min(currentPage * pageSize, totalItems);
    document.getElementById('pageInfo').textContent = `Showing ${start}-${end} of ${totalItems} events`;
    
    document.getElementById('prevBtn').disabled = currentPage <= 1;
    document.getElementById('nextBtn').disabled = currentPage * pageSize >= totalItems;
}

function prevPage() {
    if (currentPage > 1) {
        currentPage--;
        loadAuthEvents();
    }
}

function nextPage() {
    if (currentPage * pageSize < totalItems) {
        currentPage++;
        loadAuthEvents();
    }
}

function resetFilters() {
    document.getElementById('statusFilter').value = '';
    document.getElementById('searchInput').value = '';
    currentPage = 1;
    loadAuthEvents();
}

function debounce(func, wait) {
    let timeout;
    return function(...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), wait);
    };
}
