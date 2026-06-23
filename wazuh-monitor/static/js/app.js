/* ═══════════════════════════════════════════════════════════════
   app.js — Shared utilities for Wazuh Monitor
   Sidebar, drawer, toasts, fetch wrapper, formatters
   ═══════════════════════════════════════════════════════════════ */

/* ── API Fetch Wrapper ─────────────────────────────────────────── */

async function api(path, options = {}) {
    const url = path.startsWith('/') ? path : '/' + path;
    try {
        const resp = await fetch(url, {
            headers: { 'Content-Type': 'application/json', ...options.headers },
            ...options,
        });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({ error: resp.statusText }));
            throw new Error(err.error || `HTTP ${resp.status}`);
        }
        return resp.json();
    } catch (err) {
        console.error(`API error: ${path}`, err);
        throw err;
    }
}


/* ── Toast Notifications ───────────────────────────────────────── */

function toast(title, msg, type = 'info', duration = 4000) {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.innerHTML = `
        <div class="toast-content">
            <div class="toast-title">${escapeHtml(title)}</div>
            <div class="toast-msg">${escapeHtml(msg)}</div>
        </div>`;
    container.appendChild(el);

    setTimeout(() => {
        el.style.opacity = '0';
        el.style.transform = 'translateX(20px)';
        el.style.transition = 'all .3s';
        setTimeout(() => el.remove(), 300);
    }, duration);
}


/* ── HTML Escaping ─────────────────────────────────────────────── */

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}


/* ── Status Dot ────────────────────────────────────────────────── */

function updateConnectionStatus() {
    api('/api/status')
        .then(data => {
            const dot = document.getElementById('statusDot');
            const label = document.getElementById('statusLabel');
            if (!dot || !label) return;

            if (data.connected) {
                dot.className = 'status-dot connected';
                label.textContent = 'Connected';
            } else if (data.last_error) {
                dot.className = 'status-dot error';
                label.textContent = 'Disconnected';
            } else {
                dot.className = 'status-dot';
                label.textContent = 'Not connected';
            }
        })
        .catch(() => {});
}


/* ── Clock ─────────────────────────────────────────────────────── */

function updateClock() {
    const el = document.getElementById('clockDisplay');
    if (!el) return;
    const now = new Date();
    el.textContent = now.toLocaleTimeString('en-GB', {
        hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
}


/* ── Sidebar ───────────────────────────────────────────────────── */

function initSidebar() {
    const sidebar = document.getElementById('sidebar');
    const toggle = document.getElementById('sidebarToggle');
    if (!sidebar || !toggle) return;

    // Restore state
    const collapsed = localStorage.getItem('sidebar_collapsed') === 'true';
    if (collapsed) sidebar.classList.add('collapsed');

    toggle.addEventListener('click', () => {
        sidebar.classList.toggle('collapsed');
        localStorage.setItem('sidebar_collapsed', sidebar.classList.contains('collapsed'));
    });
}


/* ── Alert Detail Drawer ───────────────────────────────────────── */

function openDrawer(alertData) {
    const overlay = document.getElementById('drawerOverlay');
    const drawer = document.getElementById('drawer');
    const body = document.getElementById('drawerBody');
    if (!overlay || !drawer || !body) return;

    const rule = alertData.rule || {};
    const agent = alertData.agent || {};
    const decoder = alertData.decoder || {};
    const mitre = alertData.mitre || {};
    const groups = (rule.groups || []);

    body.innerHTML = `
        <div class="drawer-section">
            <div class="drawer-section-title">Alert Details</div>
            <div class="drawer-field">
                <span class="drawer-field-label">Severity</span>
                <span class="drawer-field-value">${levelBadge(rule.level || 0)}</span>
            </div>
            <div class="drawer-field">
                <span class="drawer-field-label">Rule ID</span>
                <span class="drawer-field-value"><span class="rule-id">${escapeHtml(String(rule.id || '—'))}</span></span>
            </div>
            <div class="drawer-field">
                <span class="drawer-field-label">Description</span>
                <span class="drawer-field-value">${escapeHtml(rule.description || '—')}</span>
            </div>
            <div class="drawer-field">
                <span class="drawer-field-label">Timestamp</span>
                <span class="drawer-field-value mono">${formatTime(alertData.timestamp)}</span>
            </div>
        </div>

        <div class="drawer-section">
            <div class="drawer-section-title">Agent Information</div>
            <div class="drawer-field">
                <span class="drawer-field-label">Agent Name</span>
                <span class="drawer-field-value">${escapeHtml(agent.name || '—')}</span>
            </div>
            <div class="drawer-field">
                <span class="drawer-field-label">Agent ID</span>
                <span class="drawer-field-value mono">${escapeHtml(agent.id || '—')}</span>
            </div>
            <div class="drawer-field">
                <span class="drawer-field-label">Agent IP</span>
                <span class="drawer-field-value mono">${escapeHtml(agent.ip || '—')}</span>
            </div>
        </div>

        <div class="drawer-section">
            <div class="drawer-section-title">Classification</div>
            <div class="drawer-field">
                <span class="drawer-field-label">Groups</span>
                <span class="drawer-field-value">${groups.map(g => `<span class="group-tag">${escapeHtml(g)}</span>`).join(' ') || '—'}</span>
            </div>
            <div class="drawer-field">
                <span class="drawer-field-label">Decoder</span>
                <span class="drawer-field-value mono">${escapeHtml(decoder.name || '—')}</span>
            </div>
            ${mitre.id ? `<div class="drawer-field">
                <span class="drawer-field-label">MITRE ATT&CK</span>
                <span class="drawer-field-value">${escapeHtml(mitre.id || '')} — ${escapeHtml(mitre.tactic || '')}</span>
            </div>` : ''}
        </div>

        <div class="drawer-section">
            <div class="drawer-section-title">Raw Event</div>
            <div class="drawer-raw">${escapeHtml(JSON.stringify(alertData.raw || alertData, null, 2))}</div>
        </div>
    `;

    overlay.classList.add('open');
    drawer.classList.add('open');
    document.body.style.overflow = 'hidden';
}

function closeDrawer() {
    const overlay = document.getElementById('drawerOverlay');
    const drawer = document.getElementById('drawer');
    if (overlay) overlay.classList.remove('open');
    if (drawer) drawer.classList.remove('open');
    document.body.style.overflow = '';
}


/* ── Formatters ────────────────────────────────────────────────── */

function formatTime(iso) {
    if (!iso) return '—';
    try {
        const d = new Date(iso);
        return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) +
            ' ' + d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch { return iso; }
}

function formatRelative(iso) {
    if (!iso) return '—';
    const diff = (Date.now() - new Date(iso).getTime()) / 1000;
    if (diff < 0) return 'just now';
    if (diff < 60) return `${Math.floor(diff)}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
}


/* ── Severity Badge ────────────────────────────────────────────── */

function levelBadge(level) {
    const lv = parseInt(level) || 0;
    if (lv >= 15) return `<span class="badge badge-critical">Critical ${lv}</span>`;
    if (lv >= 12) return `<span class="badge badge-high">High ${lv}</span>`;
    if (lv >= 7)  return `<span class="badge badge-medium">Medium ${lv}</span>`;
    if (lv >= 4)  return `<span class="badge badge-low">Low ${lv}</span>`;
    return `<span class="badge badge-info">Info ${lv}</span>`;
}

function levelClass(level) {
    const lv = parseInt(level) || 0;
    if (lv >= 15) return 'critical';
    if (lv >= 12) return 'high';
    if (lv >= 7)  return 'medium';
    if (lv >= 4)  return 'low';
    return 'info';
}


/* ── Agent Status ──────────────────────────────────────────────── */

function statusBadge(status) {
    const st = (status || 'never_connected').toLowerCase();
    const label = st.replace(/_/g, ' ');
    return `<span class="agent-status ${st}">${label}</span>`;
}


/* ── Auto Refresh ──────────────────────────────────────────────── */

let _autoRefreshTimer = null;

function startAutoRefresh(intervalSeconds, callback) {
    stopAutoRefresh();
    if (!intervalSeconds || intervalSeconds < 5) return;
    _autoRefreshTimer = setInterval(callback, intervalSeconds * 1000);
}

function stopAutoRefresh() {
    if (_autoRefreshTimer) {
        clearInterval(_autoRefreshTimer);
        _autoRefreshTimer = null;
    }
}


/* ── Debounce ──────────────────────────────────────────────────── */

function debounce(fn, delay = 300) {
    let timer;
    return (...args) => {
        clearTimeout(timer);
        timer = setTimeout(() => fn(...args), delay);
    };
}


/* ── Loading Skeletons ─────────────────────────────────────────── */

function skeletonRows(cols, rows = 5) {
    let html = '';
    for (let i = 0; i < rows; i++) {
        html += '<tr>';
        for (let j = 0; j < cols; j++) {
            const w = 40 + Math.random() * 50;
            html += `<td><div class="skeleton" style="width:${w}%"></div></td>`;
        }
        html += '</tr>';
    }
    return html;
}


/* ── Init on DOM Ready ─────────────────────────────────────────── */

document.addEventListener('DOMContentLoaded', () => {
    initSidebar();
    updateClock();
    setInterval(updateClock, 1000);
    updateConnectionStatus();
    setInterval(updateConnectionStatus, 30000);

    // Drawer close handlers
    const overlay = document.getElementById('drawerOverlay');
    if (overlay) overlay.addEventListener('click', closeDrawer);

    const closeBtn = document.getElementById('drawerClose');
    if (closeBtn) closeBtn.addEventListener('click', closeDrawer);

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeDrawer();
    });
});
