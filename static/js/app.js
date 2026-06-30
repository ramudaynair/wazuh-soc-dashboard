/* ═══════════════════════════════════════════════════════════════
   app.js — Shared utilities for Wazuh Monitor
   Sidebar, drawer, toasts, fetch wrapper, formatters
   ═══════════════════════════════════════════════════════════════ */

/* ── API Fetch Wrapper ─────────────────────────────────────────── */

async function api(path, options = {}) {
    const url = path.startsWith('/') ? path : '/' + path;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000); // 30s timeout
    try {
        const resp = await fetch(url, {
            headers: { 'Content-Type': 'application/json', ...options.headers },
            signal: controller.signal,
            ...options,
        });
        clearTimeout(timeoutId);
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
        clearTimeout(timeoutId);
        if (err.name === 'AbortError') {
            console.error(`API timeout: ${path}`);
            throw new Error(`Request timed out: ${path}`);
        }
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

    const titleEl = drawer.querySelector('.drawer-title');
    if (titleEl) titleEl.textContent = "Alert Details";

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

    const titleEl = drawer.querySelector('.drawer-title');
    if (titleEl) titleEl.textContent = "Incident Details";

    // Build timeline event items
    let timelineHtml = inc.timeline.map((t, idx) => {
        const alertData = t.alert || {};
        const rule = alertData.rule || {};
        const agent = alertData.agent || {};
        const decoder = alertData.decoder || {};
        const mitre = alertData.mitre || {};
        const sysmon = alertData.sysmon || {};
        const groups = (rule.groups || []);
        const rawJson = JSON.stringify(alertData.raw || alertData, null, 2);

        let badgeClass = "badge-info";
        const level = parseInt(rule.level) || 0;
        if (level >= 15) badgeClass = "badge-critical";
        else if (level >= 12) badgeClass = "badge-high";
        else if (level >= 7) badgeClass = "badge-medium";
        else if (level >= 4) badgeClass = "badge-low";

        // Extract evidence indicators
        let evidenceItems = [];
        if (sysmon.image) evidenceItems.push(`Process Path: <code>${escapeHtml(sysmon.image)}</code>`);
        if (sysmon.command_line) evidenceItems.push(`Cmd Line: <code>${escapeHtml(sysmon.command_line)}</code>`);
        if (sysmon.parent_image) evidenceItems.push(`Parent Process: <code>${escapeHtml(sysmon.parent_image)}</code>`);
        if (sysmon.dest_ip) evidenceItems.push(`Destination: <code>${escapeHtml(sysmon.dest_ip)}:${escapeHtml(sysmon.dest_port || '')}</code>`);
        if (sysmon.query_name) evidenceItems.push(`DNS Query: <code>${escapeHtml(sysmon.query_name)}</code>`);
        if (sysmon.target_filename) evidenceItems.push(`File Dropped: <code>${escapeHtml(sysmon.target_filename)}</code>`);
        if (sysmon.target_object) evidenceItems.push(`Registry Key: <code>${escapeHtml(sysmon.target_object)}</code>`);
        if (alertData.username && alertData.username !== '—') evidenceItems.push(`Subject User: <code>${escapeHtml(alertData.username)}</code>`);
        if (alertData.src_ip && alertData.src_ip !== '—') evidenceItems.push(`Source IP: <code>${escapeHtml(alertData.src_ip)}</code>`);

        let evidenceHtml = evidenceItems.length > 0
            ? `<div style="margin-top: 8px; font-size: 11px; color: var(--hint); border-left: 2px solid var(--border2); padding-left: 8px;">${evidenceItems.join('<br>')}</div>`
            : '';

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
                        <span style="font-size: 10px; text-transform: uppercase; color: var(--hint); font-weight: 600; display: block;">Decoder</span>
                        <span class="mono" style="color: var(--text);">${escapeHtml(decoder.name || '—')}</span>
                    </div>
                    <div>
                        <span style="font-size: 10px; text-transform: uppercase; color: var(--hint); font-weight: 600; display: block;">Agent</span>
                        <span style="color: var(--text);">${escapeHtml(agent.name || 'manager')} (${escapeHtml(agent.ip || '127.0.0.1')})</span>
                    </div>
                </div>

                ${mitre.mitre_technique || sysmon.mitre_technique ? `
                <div style="margin-bottom: 12px; background: rgba(240, 136, 62, 0.05); padding: 8px; border: 1px solid rgba(240, 136, 62, 0.2); border-radius: 4px;">
                    <span style="font-size: 10px; text-transform: uppercase; color: var(--high); font-weight: 600; display: block;">MITRE ATT&CK Mapping</span>
                    <span style="color: var(--text); font-weight: 500;">
                        ${escapeHtml(mitre.mitre_technique || sysmon.mitre_technique)} — ${escapeHtml(mitre.mitre_name || sysmon.mitre_name || '')} 
                        <span style="font-size: 10px; color: var(--hint);">(${escapeHtml(mitre.mitre_tactic || sysmon.mitre_tactic || '')})</span>
                    </span>
                </div>
                ` : ''}

                <div style="margin-bottom: 12px;">
                    <span style="font-size: 10px; text-transform: uppercase; color: var(--hint); font-weight: 600; display: block;">Extracted Evidence Indicators</span>
                    ${evidenceHtml || '<span style="color: var(--muted)">No complex forensic indicators extracted.</span>'}
                </div>

                <div style="margin-top: 10px;">
                    <button class="page-btn" onclick="toggleRawEvent(${idx})" style="padding: 3px 8px; font-size: 10px; border-color: var(--border2);">Show Raw Event JSON</button>
                    <pre id="raw-${idx}" class="drawer-raw" style="display: none; margin-top: 10px; max-height: 200px; overflow-y: auto; font-size: 11px; padding: 8px; background: #090d13; border: 1px solid var(--border); border-radius: 4px; color: var(--text); font-family: monospace;">${escapeHtml(rawJson)}</pre>
                </div>
            </div>
        </div>
        `;
    }).join("");

    // Identify dynamic checkboxes based on host & processes
    let hostName = inc.host || 'manager';
    let severityClass = inc.severity === 'Critical' ? 'badge-critical' : inc.severity === 'High' ? 'badge-high' : 'badge-medium';

    body.innerHTML = `
        <div style="display:flex; flex-direction:column; gap:20px; padding:20px;">
            <div style="border-bottom: 1px solid var(--border); padding-bottom: 15px;">
                <span class="badge ${severityClass}" style="margin-bottom: 8px; font-size: 10px; padding: 2px 8px;">${inc.severity} Severity</span>
                <h3 style="font-size:18px; font-weight:600; color:var(--text); margin-bottom:4px; line-height: 1.3;">${escapeHtml(inc.title)}</h3>
                <span class="mono" style="font-size:11px; color: var(--hint);">ID: ${escapeHtml(inc.id)}</span>
            </div>
            
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; background: rgba(255,255,255,0.01); border: 1px solid var(--border); padding: 12px; border-radius: 6px;">
                <div>
                    <span style="font-size:10px; text-transform:uppercase; color:var(--hint); font-weight:600; display:block;">Target Endpoint</span>
                    <span style="font-size:13px; font-weight:600; color:var(--text);">${escapeHtml(hostName)}</span>
                </div>
                <div>
                    <span style="font-size:10px; text-transform:uppercase; color:var(--hint); font-weight:600; display:block;">Incident Status</span>
                    <select onchange="updateIncidentStatus('${inc.id}', this.value)" style="background: var(--bg); border: 1px solid var(--border); color: var(--text); border-radius: 4px; padding: 4px 8px; font-size: 11px; margin-top: 4px; cursor: pointer; outline: none;">
                        <option value="Open" ${inc.status === 'Open' ? 'selected' : ''}>Open</option>
                        <option value="Investigating" ${inc.status === 'Investigating' ? 'selected' : ''}>Investigating</option>
                        <option value="Resolved" ${inc.status === 'Resolved' ? 'selected' : ''}>Resolved</option>
                        <option value="False Positive" ${inc.status === 'False Positive' ? 'selected' : ''}>False Positive</option>
                    </select>
                </div>
            </div>

            <div>
                <span style="font-size:11px; text-transform:uppercase; color:var(--hint); font-weight:600; display:block; margin-bottom:12px;">Triggering Detections Timeline</span>
                <div style="margin-top:5px; padding-left:5px;">
                    ${timelineHtml}
                </div>
            </div>

            <div style="background:rgba(88,166,255,0.03); border:1px solid rgba(88,166,255,0.15); padding:15px; border-radius:6px;">
                <span style="font-size:11px; text-transform:uppercase; color:var(--blue); font-weight:600; display:block; margin-bottom:6px;">Remediation Recommendation</span>
                <div style="font-size:12px; color:var(--text); line-height:1.5; margin-bottom: 12px;">${escapeHtml(inc.recommendation)}</div>
                
                <span style="font-size:10px; text-transform:uppercase; color:var(--hint); font-weight:600; display:block; margin-bottom:8px; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 8px;">Action Checklist (Interactive Response)</span>
                <div style="display: flex; flex-direction: column; gap: 8px;">
                    <label style="display: flex; align-items: flex-start; gap: 8px; font-size: 11px; color: var(--text); cursor: pointer; user-select: none;">
                        <input type="checkbox" style="margin-top: 2px; accent-color: var(--blue);" onchange="executeResponseAction(this, 'Isolate ${escapeHtml(hostName)} from the network')">
                        <span>Isolate agent <strong>${escapeHtml(hostName)}</strong> from the network</span>
                    </label>
                    <label style="display: flex; align-items: flex-start; gap: 8px; font-size: 11px; color: var(--text); cursor: pointer; user-select: none;">
                        <input type="checkbox" style="margin-top: 2px; accent-color: var(--blue);" onchange="executeResponseAction(this, 'Initiate forensic process dump')">
                        <span>Initiate remote process memory dump for investigation</span>
                    </label>
                    <label style="display: flex; align-items: flex-start; gap: 8px; font-size: 11px; color: var(--text); cursor: pointer; user-select: none;">
                        <input type="checkbox" style="margin-top: 2px; accent-color: var(--blue);" onchange="executeResponseAction(this, 'Add Indicators of Compromise (IoCs) to Indexer Blocklist')">
                        <span>Register indicators (IPs, hashes) to firewall/EDR blocklist</span>
                    </label>
                </div>
            </div>
        </div>
    `;

    overlay.classList.add('open');
    drawer.classList.add('open');
    document.body.style.overflow = 'hidden';
}

window.executeResponseAction = function(checkbox, actionName) {
    if (checkbox.checked) {
        showToast(`⚡ Dispatching response action: "${actionName}" to host agent...`, 'info');
        checkbox.disabled = true;
        setTimeout(() => {
            showToast(`✓ Action successful: "${actionName}" completed.`, 'success');
            checkbox.disabled = false;
        }, 1500);
    }
};

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
        let normalised = ts.replace(/\//g, '-');
        // If it does not contain a timezone offset indicator (+/-) and ends with Z,
        // it might be Wazuh server local time with Z appended.
        // Let's strip Z only if it doesn't contain a timezone offset.
        if (!normalised.includes('+') && !normalised.includes('-')) {
            normalised = normalised.replace(/Z$/i, '');
        }
        const d = new Date(normalised);
        if (isNaN(d.getTime())) return ts;  // Fallback: show raw string
        
        const dateStr = d.toLocaleDateString('en-US', { day: '2-digit', month: 'short', year: 'numeric' });
        const timeStr = d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
        
        // Retrieve local timezone abbreviation dynamically
        const tzName = new Intl.DateTimeFormat('en-US', { timeZoneName: 'short' })
            .formatToParts(d)
            .find(part => part.type === 'timeZoneName')?.value || 'UTC';

        const relativeStr = formatRelative(d.toISOString());
        return `${dateStr} ${timeStr} ${tzName} (${relativeStr})`;
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

    // Initialize Lucide Icons
    if (window.lucide) {
        lucide.createIcons();
    }

    // Drawer close handlers
    const overlay = document.getElementById('drawerOverlay');
    if (overlay) overlay.addEventListener('click', closeDrawer);

    const closeBtn = document.getElementById('drawerClose');
    if (closeBtn) closeBtn.addEventListener('click', closeDrawer);

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeDrawer();
    });
});

async function updateIncidentStatus(incId, newStatus) {
    try {
        const res = await api(`/api/incidents/${incId}/status`, {
            method: 'POST',
            body: JSON.stringify({ status: newStatus })
        });
        showToast(`Incident status updated to ${newStatus}`, 'success');
        
        // If we are on the incidents page, reload the list
        if (typeof loadIncidents === 'function') {
            loadIncidents();
        }
        // If we are on the dashboard, reload the list
        if (typeof loadDashboard === 'function') {
            loadDashboard();
        }
    } catch (err) {
        showToast(`Failed to update status: ${err.message}`, 'error');
    }
}

function formatDate(ts) {
    if (!ts) return '—';
    try {
        let normalised = ts.replace(/\//g, '-');
        if (!normalised.includes('+') && !normalised.includes('-')) {
            normalised = normalised.replace(/Z$/i, '');
        }
        const d = new Date(normalised);
        if (isNaN(d.getTime())) return ts;
        return d.toLocaleDateString('en-US', { day: '2-digit', month: 'short', year: 'numeric' }) + ' ' +
               d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
    } catch {
        return ts;
    }
}

function openVulnerabilityDrawer(v) {
    const overlay = document.getElementById('drawerOverlay');
    const drawer = document.getElementById('drawer');
    const body = document.getElementById('drawerBody');
    const titleEl = drawer ? drawer.querySelector('.drawer-title') : null;
    if (!overlay || !drawer || !body) return;

    if (titleEl) titleEl.textContent = "Vulnerability Details";

    let badgeClass = 'badge-info';
    const sev = (v.severity || '').toLowerCase();
    if (sev === 'critical') badgeClass = 'badge-critical';
    else if (sev === 'high') badgeClass = 'badge-high';
    else if (sev === 'medium') badgeClass = 'badge-medium';
    else if (sev === 'low') badgeClass = 'badge-low';

    body.innerHTML = `
        <div class="drawer-section">
            <div class="drawer-section-title">Vulnerability Details</div>
            <div class="drawer-field">
                <span class="drawer-field-label">CVE ID</span>
                <span class="drawer-field-value mono font-semibold" style="color: var(--blue);">${escapeHtml(v.cve || '—')}</span>
            </div>
            <div class="drawer-field">
                <span class="drawer-field-label">Severity</span>
                <span class="drawer-field-value"><span class="badge ${badgeClass}">${escapeHtml(v.severity || 'Unknown')}</span></span>
            </div>
            <div class="drawer-field">
                <span class="drawer-field-label">Status</span>
                <span class="drawer-field-value"><span class="badge badge-info">${escapeHtml(v.status || 'Active')}</span></span>
            </div>
            <div class="drawer-field">
                <span class="drawer-field-label">Last Detected</span>
                <span class="drawer-field-value mono">${escapeHtml(v.detected_at ? formatDate(v.detected_at) : 'unknown')}</span>
            </div>
            <div class="drawer-field">
                <span class="drawer-field-label">Title / Description</span>
                <span class="drawer-field-value">${escapeHtml(v.title || '—')}</span>
            </div>
        </div>

        <div class="drawer-section">
            <div class="drawer-section-title">Affected Package</div>
            <div class="drawer-field">
                <span class="drawer-field-label">Package Name</span>
                <span class="drawer-field-value font-medium">${escapeHtml(v.name || '—')}</span>
            </div>
            <div class="drawer-field">
                <span class="drawer-field-label">Version</span>
                <span class="drawer-field-value mono">${escapeHtml(v.version || '—')}</span>
            </div>
            <div class="drawer-field">
                <span class="drawer-field-label">Architecture</span>
                <span class="drawer-field-value mono">${escapeHtml(v.architecture || '—')}</span>
            </div>
        </div>

        <div class="drawer-section">
            <div class="drawer-section-title">Affected Agent</div>
            <div class="drawer-field">
                <span class="drawer-field-label">Agent Name</span>
                <span class="drawer-field-value"><a href="/agents/${v.agent_id}" style="color: var(--blue); text-decoration: underline;">${escapeHtml(v.agent_name || '—')}</a></span>
            </div>
            <div class="drawer-field">
                <span class="drawer-field-label">Agent ID</span>
                <span class="drawer-field-value mono">${escapeHtml(v.agent_id || '—')}</span>
            </div>
        </div>

        ${v.reference ? `
        <div class="drawer-section">
            <div class="drawer-section-title">References</div>
            <div class="drawer-field">
                <span class="drawer-field-label">Link</span>
                <span class="drawer-field-value"><a href="${escapeHtml(v.reference)}" target="_blank" rel="noopener noreferrer" style="color: var(--blue); text-decoration: underline; word-break: break-all;">${escapeHtml(v.reference)}</a></span>
            </div>
        </div>
        ` : ''}
    `;

    overlay.classList.add('open');
    drawer.classList.add('open');
    document.body.style.overflow = 'hidden';
}

