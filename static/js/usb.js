/* ═══════════════════════════════════════════════════════════════
   usb.js — USB & Peripheral Activity page logic
   ═══════════════════════════════════════════════════════════════ */

let currentPage = 1;
let pageSize = 20;
let totalItems = 0;

document.addEventListener('DOMContentLoaded', () => {
    const configEl = document.getElementById('usbConfig');
    if (configEl) {
        pageSize = Number(configEl.getAttribute('data-page-size')) || 20;
    }

    // Event listeners
    document.getElementById('typeFilter').addEventListener('change', () => { currentPage = 1; loadAll(); });
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
            loadUsbStats(),
            loadUsbEvents()
        ]);
        markRefreshSuccess();
    } catch (err) {
        markRefreshFailure(err.message || 'Failed to sync USB activity data');
    }
}

async function loadUsbStats() {
    try {
        const stats = await api('/api/security/stats');
        document.getElementById('usbCount').textContent = stats.usb_events || 0;
    } catch (err) {
        const el = document.getElementById('usbCount');
        if (el) el.textContent = '—';
        throw err;
    }
}

async function loadUsbEvents() {
    const tbody = document.getElementById('usbTbody');
    const search = document.getElementById('searchInput').value.trim();
    const type = document.getElementById('typeFilter').value;
    const offset = (currentPage - 1) * pageSize;

    let query = `/api/security/alerts?category=usb&limit=${pageSize}&offset=${offset}`;
    if (search) query += `&search=${encodeURIComponent(search)}`;
    if (type) query += `&search=${encodeURIComponent(type)}`;

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
                            <div class="empty-icon">🔌</div>
                            <div class="empty-text">No USB storage events found</div>
                        </div>
                    </td>
                </tr>`;
            updatePagination();
            return;
        }

        tbody.innerHTML = items.map(a => {
            const desc = a.rule.description.toLowerCase();
            const isRemoved = desc.includes('removed') || desc.includes('unmount') || desc.includes('detach');
            
            let typeBadge = '';
            if (isRemoved) {
                typeBadge = '<span class="status-badge state-offline">✕ DETACHED</span>';
            } else {
                typeBadge = '<span class="status-badge state-online">✓ ATTACHED</span>';
            }

            // Extract cleaner description if full log is huge
            const cleanDesc = a.rule.description;

            return `
                <tr onclick='openDrawer(${JSON.stringify(a).replace(/'/g, "&#39;")})'>
                    <td>${typeBadge}</td>
                    <td class="primary font-bold" style="max-width:320px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${escapeHtml(cleanDesc)}">${escapeHtml(cleanDesc)}</td>
                    <td class="primary">${escapeHtml(a.username || 'system')}</td>
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
                        <div class="empty-text" style="color:var(--red)">Failed to load USB events</div>
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
    document.getElementById('typeFilter').value = '';
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
