/* ═══════════════════════════════════════════════════════════════
   vulnerabilities.js — Vulnerabilities and CVE list page logic
   ═══════════════════════════════════════════════════════════════ */

let currentPage = 1;
let pageSize = 20;
let totalItems = 0;
let items = [];

// DOM Elements
const tbody = document.getElementById('vulnsTbody');
const searchInput = document.getElementById('searchInput');
const severityFilter = document.getElementById('severityFilter');
const resetBtn = document.getElementById('resetFiltersBtn');
const prevBtn = document.getElementById('prevBtn');
const nextBtn = document.getElementById('nextBtn');
const pageInfo = document.getElementById('pageInfo');

function formatDate(ts) {
    if (!ts) return '—';
    try {
        const d = new Date(ts);
        if (isNaN(d.getTime())) return ts;
        return d.toLocaleDateString('en-US', { day: '2-digit', month: 'short', year: 'numeric' }) + ' ' +
               d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
    } catch {
        return ts;
    }
}

async function loadSummaryStats() {
    try {
        const summary = await api('/api/dashboard?format=summary');
        const critVal = document.getElementById('criticalVulnCount');
        const highSub = document.getElementById('highVulnSub');
        
        if (critVal && summary.vulnerabilities) {
            const critical = summary.vulnerabilities.critical || 0;
            const high = summary.vulnerabilities.high || 0;
            const total = critical + high;
            critVal.textContent = total;
            if (highSub) {
                highSub.textContent = `${critical} Critical, ${high} High-severity CVEs`;
            }
        }
    } catch (err) {
        console.error("Failed to load vulnerabilities summary stats:", err);
    }
}

async function loadVulnerabilities() {
    if (!tbody) return;
    tbody.innerHTML = `
        <tr>
            <td colspan="6">
                <div class="empty-state">
                    <div class="empty-icon">⏳</div>
                    <div class="empty-text">Loading vulnerability database...</div>
                </div>
            </td>
        </tr>`;

    try {
        // Query consolidate vulnerabilities endpoint (all active agents)
        const data = await api(`/api/vulnerabilities?limit=250`); // Fetch a batch for local search/filtering
        items = data.items || [];
        totalItems = items.length;
        
        applyFiltersAndRender();
    } catch (err) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6">
                    <div class="empty-state">
                        <div class="empty-icon" style="color:var(--red)"><i data-lucide="alert-triangle"></i></div>
                        <div class="empty-text" style="color:var(--red)">Failed to load vulnerabilities database: ${escapeHtml(err.message)}</div>
                    </div>
                </td>
            </tr>`;
    }
}

function applyFiltersAndRender() {
    const q = searchInput.value.toLowerCase().trim();
    const severity = severityFilter.value.toLowerCase();

    // Filter items
    let filtered = items.filter(v => {
        const matchesSearch = !q || 
            (v.cve && v.cve.toLowerCase().includes(q)) || 
            (v.title && v.title.toLowerCase().includes(q)) ||
            (v.name && v.name.toLowerCase().includes(q)) || 
            (v.agent_name && v.agent_name.toLowerCase().includes(q));

        const matchesSeverity = !severity || (v.severity && v.severity.toLowerCase() === severity);

        return matchesSearch && matchesSeverity;
    });

    totalItems = filtered.length;
    
    // Pagination slicing
    const start = (currentPage - 1) * pageSize;
    const end = Math.min(start + pageSize, totalItems);
    const pageItems = filtered.slice(start, end);

    renderTable(pageItems);
    updatePagination(start, end);
}

function renderTable(pageItems) {
    if (!pageItems.length) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6">
                    <div class="empty-state">
                        <div class="empty-icon"><i data-lucide="search"></i></div>
                        <div class="empty-text">No active vulnerabilities match search criteria</div>
                    </div>
                </td>
            </tr>`;
        if (window.lucide) lucide.createIcons();
        return;
    }

    tbody.innerHTML = pageItems.map(v => {
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
                <td><span class="primary">${escapeHtml(v.agent_name || 'manager')}</span></td>
                <td class="primary font-medium" title="${escapeHtml(v.title || '')}">
                    ${escapeHtml(v.name || '—')} <span class="mono" style="font-size: 10px; color: var(--hint);">${escapeHtml(v.version || '')}</span>
                </td>
                <td><span style="font-size: 11px; color: var(--hint);">${escapeHtml(v.status || 'Active')}</span></td>
                <td class="mono" style="font-size: 11px; color: var(--text-muted);">${escapeHtml(detectDate)}</td>
            </tr>`;
    }).join('');

    if (window.lucide) {
        lucide.createIcons();
    }
}

function updatePagination(start, end) {
    if (!prevBtn || !nextBtn || !pageInfo) return;

    pageInfo.textContent = `Showing ${totalItems === 0 ? 0 : start + 1}-${end} of ${totalItems} vulnerabilities`;
    prevBtn.disabled = currentPage <= 1;
    nextBtn.disabled = end >= totalItems;
}

// Event Listeners
if (searchInput) searchInput.addEventListener('input', () => { currentPage = 1; applyFiltersAndRender(); });
if (severityFilter) severityFilter.addEventListener('change', () => { currentPage = 1; applyFiltersAndRender(); });

if (resetBtn) {
    resetBtn.addEventListener('click', () => {
        searchInput.value = '';
        severityFilter.value = '';
        currentPage = 1;
        applyFiltersAndRender();
    });
}

if (prevBtn) {
    prevBtn.addEventListener('click', () => {
        if (currentPage > 1) {
            currentPage--;
            applyFiltersAndRender();
        }
    });
}

if (nextBtn) {
    nextBtn.addEventListener('click', () => {
        if ((currentPage * pageSize) < totalItems) {
            currentPage++;
            applyFiltersAndRender();
        }
    });
}

// Global page refresh callback
function refreshPage() {
    loadSummaryStats();
    loadVulnerabilities();
}

// Initial load
document.addEventListener('DOMContentLoaded', () => {
    const configEl = document.getElementById('vulnsConfig');
    if (configEl) {
        pageSize = parseInt(configEl.getAttribute('data-page-size')) || 20;
    }
    loadSummaryStats();
    loadVulnerabilities();
});
