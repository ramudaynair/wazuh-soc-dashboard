/* ═══════════════════════════════════════════════════════════════
   applications.js — Applications & Software page logic
   ═══════════════════════════════════════════════════════════════ */

let activeTab = 'inventory'; // 'inventory' or 'changes'
let currentPage = 1;
let pageSize = 20;
let allInventoryItems = [];  // cached list of packages for local filtering
let filteredInventoryItems = [];
let totalItems = 0;

document.addEventListener('DOMContentLoaded', () => {
    const configEl = document.getElementById('appsConfig');
    if (configEl) {
        pageSize = Number(configEl.getAttribute('data-page-size')) || 20;
    }

    // Tab Listeners
    document.getElementById('tabInventory').addEventListener('click', () => switchTab('inventory'));
    document.getElementById('tabChanges').addEventListener('click', () => switchTab('changes'));

    // Filter/Pagination Listeners
    document.getElementById('searchInput').addEventListener('input', debounce(() => { currentPage = 1; loadAll(); }, 300));
    document.getElementById('resetFiltersBtn').addEventListener('click', resetFilters);
    document.getElementById('prevBtn').addEventListener('click', prevPage);
    document.getElementById('nextBtn').addEventListener('click', nextPage);

    loadAll();
    
    // Auto refresh
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
        const promises = [loadAppStats()];
        if (activeTab === 'changes') {
            promises.push(loadChanges());
        } else {
            promises.push(loadInventory());
        }
        await Promise.all(promises);
        markRefreshSuccess();
    } catch (err) {
        markRefreshFailure(err.message || 'Failed to sync applications data');
    }
}

async function loadAppStats() {
    try {
        const stats = await api('/api/security/stats');
        document.getElementById('appInstallCount').textContent = stats.software_changes || 0;
    } catch (err) {
        const el = document.getElementById('appInstallCount');
        if (el) el.textContent = '—';
        throw err;
    }
}

function switchTab(tab) {
    if (activeTab === tab) return;
    activeTab = tab;
    currentPage = 1;

    const btnInv = document.getElementById('tabInventory');
    const btnChg = document.getElementById('tabChanges');
    const tblInv = document.getElementById('inventoryTableContainer');
    const tblChg = document.getElementById('changesTableContainer');

    if (tab === 'inventory') {
        btnInv.classList.add('active');
        btnChg.classList.remove('active');
        tblInv.classList.remove('hidden');
        tblChg.classList.add('hidden');
        loadAll();
    } else {
        btnInv.classList.remove('active');
        btnChg.classList.add('active');
        tblInv.classList.add('hidden');
        tblChg.classList.remove('hidden');
        loadAll();
    }
}

async function loadInventory() {
    const tbody = document.getElementById('inventoryTbody');
    try {
        const data = await api('/api/syscollector/applications');
        allInventoryItems = data.items || [];
        renderInventory();
    } catch (err) {
        tbody.innerHTML = `
            <tr>
                <td colspan="5">
                    <div class="empty-state">
                        <div class="empty-icon">✕</div>
                        <div class="empty-text" style="color:var(--red)">Failed to load applications inventory</div>
                    </div>
                </td>
            </tr>`;
        throw err;
    }
}

function renderInventory() {
    const tbody = document.getElementById('inventoryTbody');
    const search = document.getElementById('searchInput').value.trim().toLowerCase();

    // Filter local cache
    if (search) {
        filteredInventoryItems = allInventoryItems.filter(item => 
            (item.name && item.name.toLowerCase().includes(search)) ||
            (item.vendor && item.vendor.toLowerCase().includes(search)) ||
            (item.agent_name && item.agent_name.toLowerCase().includes(search))
        );
    } else {
        filteredInventoryItems = [...allInventoryItems];
    }

    totalItems = filteredInventoryItems.length;

    if (totalItems === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="5">
                    <div class="empty-state">
                        <div class="empty-icon">🔍</div>
                        <div class="empty-text">No matching applications found</div>
                    </div>
                </td>
            </tr>`;
        updatePagination();
        return;
    }

    // Paginate in memory
    const start = (currentPage - 1) * pageSize;
    const end = start + pageSize;
    const pageItems = filteredInventoryItems.slice(start, end);

    tbody.innerHTML = pageItems.map(item => `
        <tr>
            <td class="primary">${escapeHtml(item.agent_name || 'manager')} <span class="rule-id" style="font-size:11px">${escapeHtml(item.agent_id)}</span></td>
            <td class="primary font-bold">${escapeHtml(item.name || '—')}</td>
            <td class="mono">${escapeHtml(item.version || '—')}</td>
            <td>${escapeHtml(item.vendor || '—')}</td>
            <td class="mono">${escapeHtml(item.install_date || '—')}</td>
        </tr>
    `).join('');

    updatePagination();
}

async function loadChanges() {
    const tbody = document.getElementById('changesTbody');
    const search = document.getElementById('searchInput').value.trim();
    const offset = (currentPage - 1) * pageSize;

    let query = `/api/security/alerts?category=applications&limit=${pageSize}&offset=${offset}`;
    if (search) query += `&search=${encodeURIComponent(search)}`;

    try {
        const data = await api(query);
        const items = data.items || [];
        totalItems = data.total || 0;

        if (!items.length) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="4">
                        <div class="empty-state">
                            <div class="empty-icon">🔍</div>
                            <div class="empty-text">No package modification logs found</div>
                        </div>
                    </td>
                </tr>`;
            updatePagination();
            return;
        }

        tbody.innerHTML = items.map(a => {
            const rule = a.rule || {};
            return `
                <tr onclick='openDrawer(${JSON.stringify(a).replace(/'/g, "&#39;")})'>
                    <td>${levelBadge(rule.level)}</td>
                    <td class="primary">${escapeHtml(a.agent.name || 'manager')} <span class="rule-id" style="font-size:11px">${escapeHtml(a.agent.id)}</span></td>
                    <td class="primary font-bold">${escapeHtml(rule.description || '—')}</td>
                    <td class="mono">${formatTime(a.timestamp)}</td>
                </tr>`;
        }).join('');

        updatePagination();
    } catch (err) {
        tbody.innerHTML = `
            <tr>
                <td colspan="4">
                    <div class="empty-state">
                        <div class="empty-icon">✕</div>
                        <div class="empty-text" style="color:var(--red)">Failed to load software changes</div>
                    </div>
                </td>
            </tr>`;
        throw err;
    }
}

function updatePagination() {
    const start = totalItems === 0 ? 0 : (currentPage - 1) * pageSize + 1;
    const end = Math.min(currentPage * pageSize, totalItems);
    document.getElementById('pageInfo').textContent = `Showing ${start}-${end} of ${totalItems} items`;
    
    document.getElementById('prevBtn').disabled = currentPage <= 1;
    document.getElementById('nextBtn').disabled = currentPage * pageSize >= totalItems;
}

function prevPage() {
    if (currentPage > 1) {
        currentPage--;
        loadAll();
    }
}

function nextPage() {
    if (currentPage * pageSize < totalItems) {
        currentPage++;
        loadAll();
    }
}

function resetFilters() {
    document.getElementById('searchInput').value = '';
    currentPage = 1;
    loadAll();
}

function debounce(func, wait) {
    let timeout;
    return function(...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), wait);
    };
}
