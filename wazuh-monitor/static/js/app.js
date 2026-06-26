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
        const data = await resp.json();
        if (!path.startsWith('/api/status')) {
            markRefreshSuccess();
        }
        return data;
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


/* ── Status Dot & Freshness Helpers ────────────────────────────── */

let lastSuccessfulRefresh = null;
let isSourceAvailable = true;

function markRefreshSuccess() {
    lastSuccessfulRefresh = new Date();
    isSourceAvailable = true;

    const banner = document.getElementById('errorBanner');
    if (banner) banner.style.display = 'none';

    const dot = document.getElementById('statusDot');
    const label = document.getElementById('statusLabel');
    if (dot && label) {
        dot.className = 'status-dot connected';
        label.textContent = 'Connected';
    }
    updateFreshnessText();
}

function markRefreshFailure(errorMessage) {
    isSourceAvailable = false;

    const banner = document.getElementById('errorBanner');
    const msgEl = document.getElementById('errorMessage');
    const freshEl = document.getElementById('errorFreshness');
    if (banner && msgEl && freshEl) {
        msgEl.textContent = errorMessage || 'Wazuh Data Source Unavailable';
        if (lastSuccessfulRefresh) {
            freshEl.textContent = `Last successful refresh: ${lastSuccessfulRefresh.toLocaleTimeString('en-GB')} IST`;
        } else {
            freshEl.textContent = 'Last successful refresh: Never';
        }
        banner.style.display = 'flex';
    }

    const dot = document.getElementById('statusDot');
    const label = document.getElementById('statusLabel');
    if (dot && label) {
        dot.className = 'status-dot error';
        label.textContent = 'Disconnected';
    }
}

function updateFreshnessText() {
    const el = document.getElementById('freshnessIndicator');
    if (!el) return;
    if (!lastSuccessfulRefresh) {
        el.textContent = 'Last sync: Never';
        return;
    }
    const diffSeconds = Math.floor((new Date() - lastSuccessfulRefresh) / 1000);
    if (diffSeconds < 5) {
        el.textContent = 'Last sync: just now';
    } else if (diffSeconds < 60) {
        el.textContent = `Last sync: ${diffSeconds}s ago`;
    } else {
        const diffMinutes = Math.floor(diffSeconds / 60);
        el.textContent = `Last sync: ${diffMinutes}m ${diffSeconds % 60}s ago`;
    }
}

function updateConnectionStatus() {
    api('/api/status')
        .then(data => {
            const dot = document.getElementById('statusDot');
            const label = document.getElementById('statusLabel');
            if (!dot || !label) return;

            if (data.connected) {
                if (isSourceAvailable) {
                    dot.className = 'status-dot connected';
                    label.textContent = 'Connected';
                    const banner = document.getElementById('errorBanner');
                    if (banner) banner.style.display = 'none';
                }
            } else {
                const errMsg = data.last_error || 'Disconnected from Wazuh server';
                markRefreshFailure(errMsg);
            }
        })
        .catch(err => {
            markRefreshFailure(err.message || 'Wazuh Monitor Service Offline');
        });
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

function openIncidentDrawer(inc) {
    const overlay = document.getElementById('drawerOverlay');
    const drawer = document.getElementById('drawer');
    const body = document.getElementById('drawerBody');
    if (!overlay || !drawer || !body) return;

    let timelineHtml = inc.timeline.map((t, idx) => {
        const alertData = t.alert || {};
        const rule = alertData.rule || {};
        const agent = alertData.agent || {};
        const decoder = alertData.decoder || {};
        const mitre = alertData.mitre || {};
        const groups = (rule.groups || []);
        const rawJson = JSON.stringify(alertData.raw || alertData, null, 2);

        let badgeClass = "badge-info";
        const level = parseInt(rule.level) || 0;
        if (level >= 15) badgeClass = "badge-critical";
        else if (level >= 12) badgeClass = "badge-high";
        else if (level >= 7) badgeClass = "badge-medium";
        else if (level >= 4) badgeClass = "badge-low";

        return `
        <div class="timeline-item" style="border-left: 2px solid var(--border); padding-left: 20px; margin-bottom: 20px; position: relative;">
            <div style="width: 10px; height: 10px; border-radius: 50%; background: var(--wazuh); position: absolute; left: -6px; top: 4px; border: 2px solid var(--surface);"></div>
            
            <div class="timeline-header" onclick="toggleTimelineEvent(${idx})" style="cursor: pointer; display: flex; align-items: center; justify-content: space-between; user-select: none;">
                <div>
                    <span style="font-size: 11px; color: var(--hint); display: block; margin-bottom: 2px;">${formatTime(t.timestamp)}</span>
                    <span style="color: var(--text); font-weight: 500; font-size: 13px;">${escapeHtml(t.description || 'Alert Match')}</span>
                </div>
                <div style="display: flex; align-items: center; gap: 8px;">
                    <span class="badge ${badgeClass}" style="font-size: 9px; padding: 1px 6px;">Lvl ${level}</span>
                    <span id="chevron-${idx}" style="font-size: 12px; color: var(--hint); transition: transform 0.2s;">▶</span>
                </div>
            </div>

            <div id="details-${idx}" class="timeline-event-details" style="display: none; margin-top: 12px; padding: 12px; background: rgba(255,255,255,0.02); border: 1px solid var(--border); border-radius: 6px; font-size: 12px;">
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 12px;">
                    <div>
                        <span style="font-size: 10px; text-transform: uppercase; color: var(--hint); font-weight: 600; display: block;">Rule ID</span>
                        <span class="rule-id" style="font-size: 11px;">${escapeHtml(String(rule.id || '—'))}</span>
                    </div>
                    <div>
                        <span style="font-size: 10px; text-transform: uppercase; color: var(--hint); font-weight: 600; display: block;">Decoder</span>
                        <span class="mono" style="color: var(--text);">${escapeHtml(decoder.name || '—')}</span>
                    </div>
                    <div>
                        <span style="font-size: 10px; text-transform: uppercase; color: var(--hint); font-weight: 600; display: block;">Agent</span>
                        <span style="color: var(--text);">${escapeHtml(agent.name || 'manager')} (${escapeHtml(agent.ip || '127.0.0.1')})</span>
                    </div>
                    <div>
                        <span style="font-size: 10px; text-transform: uppercase; color: var(--hint); font-weight: 600; display: block;">Groups</span>
                        <span style="color: var(--text);">${groups.map(g => `<span class="group-tag" style="font-size: 9px; padding: 1px 4px;">${escapeHtml(g)}</span>`).join(' ') || '—'}</span>
                    </div>
                </div>

                ${mitre.id ? `
                <div style="margin-bottom: 12px;">
                    <span style="font-size: 10px; text-transform: uppercase; color: var(--hint); font-weight: 600; display: block;">MITRE ATT&CK</span>
                    <span style="color: var(--yellow);">${escapeHtml(mitre.id)} — ${escapeHtml(mitre.tactic)}</span>
                </div>
                ` : ''}

                <div style="margin-bottom: 12px;">
                    <span style="font-size: 10px; text-transform: uppercase; color: var(--hint); font-weight: 600; display: block;">Description</span>
                    <span style="color: var(--muted);">${escapeHtml(rule.description || '—')}</span>
                </div>

                <div style="margin-top: 10px;">
                    <button class="page-btn" onclick="toggleRawEvent(${idx})" style="padding: 3px 8px; font-size: 10px; border-color: var(--border2);">Show Raw Event</button>
                    <pre id="raw-${idx}" class="drawer-raw" style="display: none; margin-top: 10px; max-height: 200px; overflow-y: auto; font-size: 11px; padding: 8px; background: #090d13; border: 1px solid var(--border); border-radius: 4px; color: var(--text); font-family: monospace;">${escapeHtml(rawJson)}</pre>
                </div>
            </div>
        </div>
        `;
    }).join("");

    body.innerHTML = `
        <div style="display:flex; flex-direction:column; gap:20px; padding:20px;">
            <div>
                <h3 style="font-size:16px; font-weight:600; color:var(--text); margin-bottom:6px;">${inc.title}</h3>
                <span class="badge ${inc.severity === 'Critical' ? 'badge-critical' : inc.severity === 'High' ? 'badge-high' : 'badge-medium'}">${inc.severity} Severity</span>
            </div>
            
            <div>
                <span style="font-size:11px; text-transform:uppercase; color:var(--hint); font-weight:600;">Affected Host</span>
                <div style="font-size:14px; font-weight:600; color:var(--text); margin-top:3px;">${inc.host}</div>
            </div>

            <div>
                <span style="font-size:11px; text-transform:uppercase; color:var(--hint); font-weight:600;">Incident ID</span>
                <div class="mono" style="font-size:12px; margin-top:3px; background:var(--panel2); padding:4px 8px; border-radius:4px;">${inc.id}</div>
            </div>

            <div>
                <span style="font-size:11px; text-transform:uppercase; color:var(--hint); font-weight:600; display:block; margin-bottom:10px;">Timeline & Triggering Events</span>
                <div style="margin-top:5px; padding-left:5px;">
                    ${timelineHtml}
                </div>
            </div>

            <div style="background:rgba(88,166,255,0.05); border:1px dashed var(--blue); padding:15px; border-radius:6px; margin-top:10px;">
                <span style="font-size:11px; text-transform:uppercase; color:var(--blue); font-weight:600; display:block; margin-bottom:6px;">Recommended Action</span>
                <div style="font-size:12px; color:var(--text); line-height:1.5;">${inc.recommendation}</div>
            </div>
        </div>
    `;

    overlay.classList.add('open');
    drawer.classList.add('open');
    document.body.style.overflow = 'hidden';
}

window.toggleTimelineEvent = function(idx) {
    const el = document.getElementById(`details-${idx}`);
    const chev = document.getElementById(`chevron-${idx}`);
    if (!el) return;
    if (el.style.display === "none") {
        el.style.display = "block";
        if (chev) {
            chev.innerText = "▼";
            chev.style.transform = "rotate(90deg)";
        }
    } else {
        el.style.display = "none";
        if (chev) {
            chev.innerText = "▶";
            chev.style.transform = "none";
        }
    }
};

window.toggleRawEvent = function(idx) {
    const el = document.getElementById(`raw-${idx}`);
    if (!el) return;
    if (el.style.display === "none") {
        el.style.display = "block";
    } else {
        el.style.display = "none";
    }
};


/* ── Formatters ────────────────────────────────────────────────── */

function formatTime(ts) {
    if (!ts) return '—';
    try {
        // Wazuh /manager/logs returns timestamps in server local time
        // but appends "Z" suffix — strip it to avoid incorrect UTC conversion
        let normalised = ts.replace(/\//g, '-');
        // Remove trailing Z so JS treats it as local time, not UTC
        normalised = normalised.replace(/Z$/i, '');
        const d = new Date(normalised);
        if (isNaN(d.getTime())) return ts;  // Fallback: show raw string
        return d.toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' }) +
            ' ' + d.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }) +
            ' IST';
    } catch { return ts; }
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
    if (lv >= 7) return `<span class="badge badge-medium">Medium ${lv}</span>`;
    if (lv >= 4) return `<span class="badge badge-low">Low ${lv}</span>`;
    return `<span class="badge badge-info">Info ${lv}</span>`;
}

function levelClass(level) {
    const lv = parseInt(level) || 0;
    if (lv >= 15) return 'critical';
    if (lv >= 12) return 'high';
    if (lv >= 7) return 'medium';
    if (lv >= 4) return 'low';
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
    setInterval(updateConnectionStatus, 15000); // Check API health every 15s
    setInterval(updateFreshnessText, 1000); // Update freshness text every second

    // Drawer close handlers
    const overlay = document.getElementById('drawerOverlay');
    if (overlay) overlay.addEventListener('click', closeDrawer);

    const closeBtn = document.getElementById('drawerClose');
    if (closeBtn) closeBtn.addEventListener('click', closeDrawer);

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeDrawer();
    });
});
