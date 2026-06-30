/**
 * Live Activity Dashboard Logic
 * Polling, Tab Navigation, Process Tree, DNS Activity, File Operations, and Threat Timeline
 */

let activeTab = "processes";
let currentPage = 1;
const pageSize = 15;
let liveIntervalId = null;
let allEvents = [];
let _noSysmonMessage = null; // backend message when no events

document.addEventListener("DOMContentLoaded", () => {
    initAgentFilter();
    setupTabNavigation();
    fetchTelemetry();
    startLiveMode();
});

// Populate agents filter dropdown
async function initAgentFilter() {
    try {
        const data = await api("/api/agents");
        const select = document.getElementById("agentFilter");
        if (data.items) {
            data.items.forEach(agent => {
                const opt = document.createElement("option");
                opt.value = agent.id;
                opt.textContent = `${agent.name} (${agent.id})`;
                select.appendChild(opt);
            });
        }
    } catch (err) {
        console.error("Failed to fetch agents for filter", err);
    }
}

// Tab navigation handler
function setupTabNavigation() {
    const tabs = document.querySelectorAll(".live-tab");
    const subtabs = document.querySelectorAll(".live-sub-tab");

    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            tabs.forEach(t => t.classList.remove("active"));
            tab.classList.add("active");
            
            currentPage = 1;
            const tabName = tab.dataset.tab;
            
            if (tabName === "advanced") {
                const activeSub = document.querySelector(".live-sub-tab.active");
                const subtabName = activeSub ? activeSub.dataset.subtab : "feed";
                switchToSubtab(subtabName);
            } else {
                activeTab = tabName;
                
                document.querySelectorAll(".tab-view").forEach(view => {
                    view.style.display = "none";
                });
                const activeView = document.getElementById(`view_${tabName}`);
                if (activeView) activeView.style.display = "block";
                
                const titles = {
                    processes: "Live Process Creation Events (Event ID 1)",
                    dns: "Live DNS Queries (Event ID 22)",
                    files: "Live File Creation Events (Event ID 11)",
                    registry: "Live Registry Modifications (Event ID 13)",
                    network: "Live Network Connections (Event ID 3)"
                };
                document.getElementById("panelTitle").textContent = titles[tabName] || "Live Telemetry";
                
                const pag = document.getElementById("livePagination");
                if (pag) pag.style.display = "flex";
                
                fetchTelemetry();
            }
        });
    });

    function switchToSubtab(subtabName) {
        subtabs.forEach(st => {
            if (st.dataset.subtab === subtabName) st.classList.add("active");
            else st.classList.remove("active");
        });

        activeTab = subtabName === "feed" ? "advanced" : subtabName;
        currentPage = 1;

        document.querySelectorAll(".tab-view").forEach(view => {
            view.style.display = "none";
        });
        const viewAdvanced = document.getElementById("view_advanced");
        if (viewAdvanced) viewAdvanced.style.display = "block";

        document.querySelectorAll(".sub-tab-view").forEach(sv => {
            sv.style.display = "none";
        });
        const subIdMap = {
            feed: "subview_feed",
            tree: "subview_tree",
            access: "subview_access",
            dns_activity: "subview_dns_activity",
            file_activity: "subview_file_activity",
            timeline: "subview_timeline"
        };
        const activeSubView = document.getElementById(subIdMap[subtabName]);
        if (activeSubView) activeSubView.style.display = "block";

        const titles = {
            feed: "Advanced Sysmon Event Log Viewer",
            tree: "Reconstructed Endpoint Process Tree",
            access: "Live Process Access Events (Event ID 10)",
            dns_activity: "Domain Query Analytics",
            file_activity: "File Operation Metrics",
            timeline: "Chronological Threat Activity Timeline"
        };
        document.getElementById("panelTitle").textContent = titles[subtabName] || "Advanced Analysis";

        const pag = document.getElementById("livePagination");
        if (pag) {
            if (subtabName === "tree" || subtabName === "dns_activity" || subtabName === "file_activity" || subtabName === "timeline") {
                pag.style.display = "none";
            } else {
                pag.style.display = "flex";
            }
        }

        fetchTelemetry();
    }

    subtabs.forEach(subtab => {
        subtab.addEventListener("click", (e) => {
            e.stopPropagation();
            switchToSubtab(subtab.dataset.subtab);
        });
    });
}

// Start Live Mode polling loop
function startLiveMode() {
    if (liveIntervalId) clearInterval(liveIntervalId);
    liveIntervalId = setInterval(() => {
        fetchTelemetry(true);
    }, 5000);
}

// Filters change trigger
function changeFilters() {
    currentPage = 1;
    fetchTelemetry();
}

// Fetch telemetry data from backend
async function fetchTelemetry(isAutoRefresh = false) {
    if (!isAutoRefresh) {
        showLoadingState();
    }
    
    const agent = document.getElementById("agentFilter").value;
    const search = document.getElementById("liveSearch").value;
    const severity = document.getElementById("severityFilter").value;
    const hours = document.getElementById("timeRangeFilter").value;
    
    // Map tab to Sysmon Event ID
    let eventId = "";
    if (activeTab === "processes") eventId = "1";
    else if (activeTab === "dns") eventId = "22";
    else if (activeTab === "files") eventId = "11";
    else if (activeTab === "registry") eventId = "13";
    else if (activeTab === "network") eventId = "3";
    else if (activeTab === "access") eventId = "10";
    else if (activeTab === "tree") eventId = "1";
    else if (activeTab === "dns_activity") eventId = "22";
    else if (activeTab === "file_activity") eventId = "11";
    
    // Construct query parameters
    let url = `/api/sysmon/telemetry?limit=250`;
    if (eventId) url += `&event_id=${eventId}`;
    if (agent) url += `&agent=${agent}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;
    
    try {
        // Use shared api() wrapper — updates Last sync indicator and handles errors
        const data = await api(url);
        allEvents = data.items || [];
        _noSysmonMessage = data.message || null;
        
        // Check if the response itself contains an error
        if (data.error) {
            showErrorState(data.error);
            return;
        }
        
        // Dynamic post-filtering for time and severity
        filterAndRender(hours, severity);
    } catch (err) {
        console.error("Telemetry fetch failure", err);
        // Distinguish between a connection error and an empty result set
        if (err.message && err.message.includes('timed out')) {
            showErrorState('Connection to Wazuh timed out. The server may be overloaded.');
        } else {
            showErrorState(err.message || 'Unable to reach Wazuh backend.');
        }
    }
}

// Apply local client side filters and render target view
function filterAndRender(hours, severity) {
    const now = new Date();
    const cutoff = hours !== "all" ? new Date(now.getTime() - (hours * 60 * 60 * 1000)) : null;
    
    let filtered = allEvents.filter(evt => {
        // Time filter
        if (cutoff && evt.timestamp) {
            const evtTime = new Date(evt.timestamp);
            if (evtTime < cutoff) return false;
        }
        
        // Severity level filter
        if (severity) {
            const level = evt.rule ? parseInt(evt.rule.level || 0) : 0;
            if (severity === "high" && level < 8) return false;
            if (severity === "medium" && (level < 4 || level >= 8)) return false;
            if (severity === "low" && level >= 4) return false;
        }
        
        return true;
    });

    document.getElementById("eventBadgeCount").textContent = `${filtered.length} events`;
    
    // Reset pagination footer for empty cases
    if (!filtered.length) {
        const pageInfo = document.getElementById("pageInfo");
        if (pageInfo) pageInfo.textContent = `Showing 0-0 of 0 events`;
        const prev = document.getElementById("prevBtn");
        const next = document.getElementById("nextBtn");
        if (prev) prev.disabled = true;
        if (next) next.disabled = true;
    }
    
    // Render based on active tab view
    if (activeTab === "processes") renderProcesses(filtered);
    else if (activeTab === "dns") renderDns(filtered);
    else if (activeTab === "files") renderFiles(filtered);
    else if (activeTab === "registry") renderRegistry(filtered);
    else if (activeTab === "network") renderNetwork(filtered);
    else if (activeTab === "access") renderAccess(filtered);
    else if (activeTab === "advanced") renderAdvanced(filtered);
    else if (activeTab === "tree") renderProcessTree(filtered);
    else if (activeTab === "dns_activity") renderDnsAnalytics(filtered);
    else if (activeTab === "file_activity") renderFileOperations(filtered);
    else if (activeTab === "timeline") renderThreatTimeline(filtered);
}

// Show empty loading animation states
function showLoadingState() {
    const tbodies = ["processesTbody", "dnsTbody", "filesTbody", "registryTbody", "networkTbody", "accessTbody", "advancedTbody"];
    tbodies.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.innerHTML = `<tr><td colspan="10"><div class="empty-state"><div class="empty-icon">⏳</div><div class="empty-text">Loading fresh telemetry...</div></div></td></tr>`;
        }
    });
}

function showErrorState(message) {
    const tbodies = ["processesTbody", "dnsTbody", "filesTbody", "registryTbody", "networkTbody", "accessTbody", "advancedTbody"];
    const displayMsg = message || 'Connection to Wazuh API lost. Retrying...';
    tbodies.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.innerHTML = `<tr><td colspan="10"><div class="empty-state" style="color: var(--red);"><div class="empty-icon">⚠️</div><div class="empty-text">${escapeHtml(displayMsg)}</div></div></td></tr>`;
        }
    });
}

// Render paginated items helper
function getPaginatedItems(items) {
    const start = (currentPage - 1) * pageSize;
    const end = start + pageSize;
    const paginated = items.slice(start, end);
    
    // Update pagination footer
    const pageInfo = document.getElementById("pageInfo");
    if (pageInfo) {
        pageInfo.textContent = `Showing ${items.length ? start + 1 : 0}-${Math.min(end, items.length)} of ${items.length} events`;
    }
    
    document.getElementById("prevBtn").disabled = currentPage === 1;
    document.getElementById("nextBtn").disabled = end >= items.length;
    
    return paginated;
}

function prevPage() {
    if (currentPage > 1) {
        currentPage--;
        fetchTelemetry();
    }
}

function nextPage() {
    currentPage++;
    fetchTelemetry();
}

// One-click pivoting function
function pivotToLogs(field, value) {
    window.location.href = `/logs?q=${encodeURIComponent(field + ":" + value)}`;
}

// Row clicking to trigger Details Drawer
function bindRowClick(row, rawAlert) {
    row.style.cursor = "pointer";
    row.addEventListener("click", (e) => {
        if (e.target.classList.contains("pivot-link") || e.target.tagName === "BUTTON") {
            return; // ignore pivot triggers
        }
        
        // Open standard details drawer
        const drawer = document.getElementById("drawer");
        const overlay = document.getElementById("drawerOverlay");
        const body = document.getElementById("drawerBody");
        
        if (!drawer || !body) return;
        
        drawer.classList.add("open");
        if (overlay) overlay.classList.add("open");
        
        body.innerHTML = `
            <div style="padding: 15px; display:flex; flex-direction:column; gap:12px;">
                <div><strong>Event Description:</strong> ${rawAlert.rule.description}</div>
                <div><strong>Agent:</strong> ${rawAlert.agent.name} (${rawAlert.agent.id})</div>
                <div><strong>Rule ID:</strong> ${rawAlert.rule.id} (Level ${rawAlert.rule.level})</div>
                <div><strong>Timestamp:</strong> ${formatTime(rawAlert.timestamp)}</div>
                <hr style="border:0; border-top:1px solid var(--border);" />
                <div>
                    <strong>Sysmon Properties:</strong>
                    ${rawAlert.sysmon ? `
                        <div style="background:var(--surface); border:1px solid var(--border); border-radius:4px; padding:10px; margin-top:5px; font-family:monospace; font-size:11px; display:flex; flex-direction:column; gap:4px;">
                            ${Object.entries(rawAlert.sysmon).map(([k, v]) => v ? `<div><span style="color:var(--blue);">${k}:</span> ${v}</div>` : '').join('')}
                        </div>
                    ` : '<div style="color:var(--muted); font-size:11px;">No sysmon data block</div>'}
                </div>
                <hr style="border:0; border-top:1px solid var(--border);" />
                <div>
                    <strong>Raw JSON Event Payload:</strong>
                    <pre style="background:var(--surface); border:1px solid var(--border); border-radius:4px; padding:10px; overflow-x:auto; font-size:11px; margin-top:5px;"><code>${JSON.stringify(rawAlert.raw, null, 2)}</code></pre>
                </div>
            </div>
        `;
    });
}

/* ═══════════════════════ RENDERING ENGINES ═══════════════════════ */

// Tab 1: Processes
function renderProcesses(items) {
    const tbody = document.getElementById("processesTbody");
    tbody.innerHTML = "";
    
    if (!items.length) {
        const msg = _noSysmonMessage || 'No process creation events found. Sysmon Event ID 1 telemetry is not flowing from agents.';
        tbody.innerHTML = `<tr><td colspan="7"><div class="empty-state"><div class="empty-icon">📂</div><div class="empty-text">${escapeHtml(msg)}</div></div></td></tr>`;
        return;
    }
    
    getPaginatedItems(items).forEach(item => {
        const sys = item.sysmon || {};
        const tr = document.createElement("tr");
        
        tr.innerHTML = `
            <td class="mono">${formatTime(item.timestamp)}</td>
            <td><span class="badge" style="background:var(--panel);">${item.agent.name}</span></td>
            <td><strong class="pivot-link text-blue" onclick="pivotToLogs('process', '${sys.image}')" style="cursor:pointer; color:var(--blue);">${sys.image ? sys.image.split('\\').pop() : '—'}</strong></td>
            <td class="mono" style="font-size:11px; max-width:350px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${sys.command_line || ''}">${sys.command_line || '—'}</td>
            <td><span class="pivot-link" onclick="pivotToLogs('user', '${sys.user}')" style="cursor:pointer; color:var(--muted);">${sys.user || '—'}</span></td>
            <td class="mono" style="color:var(--muted);">${sys.parent_image ? sys.parent_image.split('\\').pop() : '—'}</td>
            <td>
                ${sys.mitre_technique ? `
                    <span class="badge" style="background:rgba(188,140,255,0.15); color:var(--purple); border:1px solid var(--purple);" title="${sys.mitre_name}">${sys.mitre_technique}</span>
                ` : '—'}
            </td>
        `;
        
        bindRowClick(tr, item);
        tbody.appendChild(tr);
    });
}

// Tab 2: DNS Queries
function renderDns(items) {
    const tbody = document.getElementById("dnsTbody");
    tbody.innerHTML = "";
    
    if (!items.length) {
        const msg = _noSysmonMessage || 'No DNS query events found. Sysmon Event ID 22 telemetry is not flowing from agents.';
        tbody.innerHTML = `<tr><td colspan="5"><div class="empty-state"><div class="empty-icon">🌐</div><div class="empty-text">${escapeHtml(msg)}</div></div></td></tr>`;
        return;
    }
    
    getPaginatedItems(items).forEach(item => {
        const sys = item.sysmon || {};
        const tr = document.createElement("tr");
        
        tr.innerHTML = `
            <td class="mono">${formatTime(item.timestamp)}</td>
            <td><span class="badge" style="background:var(--panel);">${item.agent.name}</span></td>
            <td><strong class="pivot-link text-blue" onclick="pivotToLogs('domain', '${sys.query_name}')" style="cursor:pointer; color:var(--blue);">${sys.query_name || '—'}</strong></td>
            <td><span class="badge" style="background:${sys.query_status === '0' || sys.query_status === 'SUCCESS' ? 'rgba(63,185,80,0.15); color:var(--green);' : 'rgba(248,81,73,0.15); color:var(--red);'}">${sys.query_status === '0' || sys.query_status === 'SUCCESS' ? 'SUCCESS' : 'ERROR ('+sys.query_status+')'}</span></td>
            <td class="mono" style="color:var(--muted);">${sys.image ? sys.image.split('\\').pop() : '—'}</td>
        `;
        
        bindRowClick(tr, item);
        tbody.appendChild(tr);
    });
}

// Tab 3: File Creations
function renderFiles(items) {
    const tbody = document.getElementById("filesTbody");
    tbody.innerHTML = "";
    
    if (!items.length) {
        const msg = _noSysmonMessage || 'No file creation events found. Sysmon Event ID 11 telemetry is not flowing from agents.';
        tbody.innerHTML = `<tr><td colspan="5"><div class="empty-state"><div class="empty-icon">📁</div><div class="empty-text">${escapeHtml(msg)}</div></div></td></tr>`;
        return;
    }
    
    getPaginatedItems(items).forEach(item => {
        const sys = item.sysmon || {};
        const tr = document.createElement("tr");
        
        tr.innerHTML = `
            <td class="mono">${formatTime(item.timestamp)}</td>
            <td><span class="badge" style="background:var(--panel);">${item.agent.name}</span></td>
            <td><strong class="pivot-link text-blue" onclick="pivotToLogs('file', '${sys.target_filename}')" style="cursor:pointer; color:var(--blue);">${sys.target_filename || '—'}</strong></td>
            <td class="mono" style="color:var(--muted);">${sys.image ? sys.image.split('\\').pop() : '—'}</td>
            <td><span class="pivot-link" onclick="pivotToLogs('user', '${sys.user}')" style="cursor:pointer; color:var(--muted);">${sys.user || '—'}</span></td>
        `;
        
        bindRowClick(tr, item);
        tbody.appendChild(tr);
    });
}

// Tab 4: Registry Changes
function renderRegistry(items) {
    const tbody = document.getElementById("registryTbody");
    tbody.innerHTML = "";
    
    if (!items.length) {
        const msg = _noSysmonMessage || 'No registry change events found. Sysmon Event ID 13 telemetry is not flowing from agents.';
        tbody.innerHTML = `<tr><td colspan="5"><div class="empty-state"><div class="empty-icon">🧠</div><div class="empty-text">${escapeHtml(msg)}</div></div></td></tr>`;
        return;
    }
    
    getPaginatedItems(items).forEach(item => {
        const sys = item.sysmon || {};
        const tr = document.createElement("tr");
        
        tr.innerHTML = `
            <td class="mono">${formatTime(item.timestamp)}</td>
            <td><span class="badge" style="background:var(--panel);">${item.agent.name}</span></td>
            <td class="mono" style="max-width:300px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${sys.target_object || ''}"><strong>${sys.target_object || '—'}</strong></td>
            <td class="mono" style="font-size:11px; max-width:250px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${sys.details || ''}">${sys.details || '—'}</td>
            <td class="mono" style="color:var(--muted);">${sys.image ? sys.image.split('\\').pop() : '—'}</td>
        `;
        
        bindRowClick(tr, item);
        tbody.appendChild(tr);
    });
}

// Tab 5: Network Connections
function renderNetwork(items) {
    const tbody = document.getElementById("networkTbody");
    tbody.innerHTML = "";
    
    if (!items.length) {
        const msg = _noSysmonMessage || 'No network connection events found. Sysmon Event ID 3 telemetry is not flowing from agents.';
        tbody.innerHTML = `<tr><td colspan="6"><div class="empty-state"><div class="empty-icon">🔌</div><div class="empty-text">${escapeHtml(msg)}</div></div></td></tr>`;
        return;
    }
    
    getPaginatedItems(items).forEach(item => {
        const sys = item.sysmon || {};
        const tr = document.createElement("tr");
        
        tr.innerHTML = `
            <td class="mono">${formatTime(item.timestamp)}</td>
            <td><span class="badge" style="background:var(--panel);">${item.agent.name}</span></td>
            <td class="mono"><strong>${sys.image ? sys.image.split('\\').pop() : '—'}</strong></td>
            <td class="mono" style="color:var(--muted);">${sys.src_ip || '—'}:${sys.src_port || '—'}</td>
            <td class="mono"><span class="pivot-link text-blue" onclick="pivotToLogs('ip', '${sys.dest_ip}')" style="cursor:pointer; color:var(--blue);">${sys.dest_ip || '—'}:${sys.dest_port || '—'}</span></td>
            <td><span class="badge" style="background:rgba(88,166,255,0.15); color:var(--blue);">${sys.protocol || 'TCP'}</span></td>
        `;
        
        bindRowClick(tr, item);
        tbody.appendChild(tr);
    });
}

// Tab 6: Process Access
function renderAccess(items) {
    const tbody = document.getElementById("accessTbody");
    tbody.innerHTML = "";
    
    if (!items.length) {
        const msg = _noSysmonMessage || 'No process access events found. Sysmon Event ID 10 telemetry is not flowing from agents.';
        tbody.innerHTML = `<tr><td colspan="5"><div class="empty-state"><div class="empty-icon">🔒</div><div class="empty-text">${escapeHtml(msg)}</div></div></td></tr>`;
        return;
    }
    
    getPaginatedItems(items).forEach(item => {
        const sys = item.sysmon || {};
        const tr = document.createElement("tr");
        
        tr.innerHTML = `
            <td class="mono">${formatTime(item.timestamp)}</td>
            <td><span class="badge" style="background:var(--panel);">${item.agent.name}</span></td>
            <td class="mono"><strong>${sys.source_image ? sys.source_image.split('\\').pop() : '—'}</strong></td>
            <td class="mono" style="color:var(--muted);">${sys.target_image ? sys.target_image.split('\\').pop() : '—'}</td>
            <td>
                ${sys.mitre_technique ? `
                    <span class="badge" style="background:rgba(188,140,255,0.15); color:var(--purple); border:1px solid var(--purple);" title="${sys.mitre_name}">${sys.mitre_technique}</span>
                ` : '—'}
            </td>
        `;
        
        bindRowClick(tr, item);
        tbody.appendChild(tr);
    });
}

// Tab 7: Advanced Viewer
function renderAdvanced(items) {
    const tbody = document.getElementById("advancedTbody");
    tbody.innerHTML = "";
    
    if (!items.length) {
        const msg = _noSysmonMessage || 'No Sysmon events found. Check that Sysmon is installed on endpoints and agents are forwarding Windows Event Logs.';
        tbody.innerHTML = `<tr><td colspan="8"><div class="empty-state"><div class="empty-icon">🔍</div><div class="empty-text">${escapeHtml(msg)}</div></div></td></tr>`;
        return;
    }
    
    getPaginatedItems(items).forEach(item => {
        const sys = item.sysmon || {};
        const tr = document.createElement("tr");
        
        // Grab specific details based on Event ID
        let detailText = "—";
        if (sys.event_id === "1") detailText = sys.command_line || '—';
        else if (sys.event_id === "3") detailText = `Connection: ${sys.dest_ip || '—'}:${sys.dest_port || '—'}`;
        else if (sys.event_id === "10") {
            const src = sys.source_image ? sys.source_image.split('\\').pop() : '—';
            const tgt = sys.target_image ? sys.target_image.split('\\').pop() : '—';
            detailText = `Access: ${src} -> ${tgt}`;
        }
        else if (sys.event_id === "11") detailText = `Created File: ${sys.target_filename || '—'}`;
        else if (sys.event_id === "13") detailText = `Registry Set: ${sys.target_object || '—'}`;
        else if (sys.event_id === "22") detailText = `DNS: ${sys.query_name || '—'}`;
        else detailText = item.rule ? item.rule.description || '—' : '—';
        
        let sevColor = "var(--info)";
        let lvl = item.rule.level;
        if (lvl >= 10) sevColor = "var(--critical)";
        else if (lvl >= 7) sevColor = "var(--high)";
        else if (lvl >= 4) sevColor = "var(--medium)";
        
        tr.innerHTML = `
            <td class="mono">${formatTime(item.timestamp)}</td>
            <td><span class="badge" style="background:var(--border);">${sys.event_id || '—'}</span></td>
            <td><span class="badge" style="background:var(--panel);">${item.agent.name}</span></td>
            <td class="mono"><strong>${sys.image ? sys.image.split('\\').pop() : '—'}</strong></td>
            <td class="mono" style="font-size:11px; max-width:350px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${detailText}">${detailText}</td>
            <td><span class="pivot-link" onclick="pivotToLogs('user', '${sys.user}')" style="cursor:pointer; color:var(--muted);">${sys.user || '—'}</span></td>
            <td>
                ${sys.mitre_technique ? `
                    <span class="badge" style="background:rgba(188,140,255,0.15); color:var(--purple); border:1px solid var(--purple);" title="${sys.mitre_name}">${sys.mitre_technique}</span>
                ` : '—'}
            </td>
            <td><span class="badge" style="background:${sevColor}; color:#fff;">Level ${lvl}</span></td>
        `;
        
        bindRowClick(tr, item);
        tbody.appendChild(tr);
    });
}

// Tab 8: Reconstructed Process Tree
function renderProcessTree(items) {
    const container = document.getElementById("treeContainer");
    container.innerHTML = "";
    
    if (!items.length) {
        container.innerHTML = `<div class="empty-state"><div class="empty-icon">🌳</div><div class="empty-text">No Process Create events (ID 1) available to build tree.</div></div>`;
        return;
    }
    
    // Group and link nodes by unique GUID or PID
    let nodes = {};
    items.forEach(item => {
        const sys = item.sysmon;
        if (!sys || !sys.image) return;
        
        const guid = sys.process_guid || sys.process_id;
        const parentGuid = sys.parent_process_guid || sys.parent_process_id;
        
        if (!guid) return;
        
        nodes[guid] = {
            guid: guid,
            parentGuid: parentGuid,
            name: sys.image.split('\\').pop(),
            path: sys.image,
            cmd: sys.command_line,
            user: sys.user,
            time: item.timestamp,
            children: []
        };
    });
    
    // Link parents to children
    let roots = [];
    Object.values(nodes).forEach(node => {
        if (node.parentGuid && nodes[node.parentGuid]) {
            nodes[node.parentGuid].children.push(node);
        } else {
            roots.push(node);
        }
    });
    
    if (!roots.length) {
        container.innerHTML = `<div class="empty-state"><div class="empty-icon">🌳</div><div class="empty-text">Process tree loops detected, failed to establish hierarchical root.</div></div>`;
        return;
    }
    
    // Recursively render tree node HTML
    function buildTreeNodeHtml(node) {
        return `
            <div class="tree-node">
                <div class="tree-box">
                    <div class="tree-title">${escapeHtml(node.name)}</div>
                    <div class="tree-meta">PID: ${escapeHtml(node.guid.replace(/{|}/g, '').substring(0, 8))}...</div>
                    <div class="tree-meta" style="color:var(--muted); max-width:220px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(node.cmd)}">${escapeHtml(node.cmd)}</div>
                    <div class="tree-meta" style="color:var(--hint);">User: ${escapeHtml(node.user)}</div>
                </div>
                ${node.children.length ? node.children.map(child => buildTreeNodeHtml(child)).join('') : ''}
            </div>
        `;
    }
    
    const treeWrapper = document.createElement("div");
    treeWrapper.style.overflowX = "auto";
    treeWrapper.innerHTML = roots.map(r => buildTreeNodeHtml(r)).join('<div style="height:30px; border-bottom:1px dashed var(--border); margin:20px 0;"></div>');
    container.appendChild(treeWrapper);
}

// Tab 9: Domain Query Analytics
function renderDnsAnalytics(items) {
    const tbody = document.getElementById("dnsStatsTbody");
    const grid = document.getElementById("dnsStatsGrid");
    
    tbody.innerHTML = "";
    grid.innerHTML = "";
    
    if (!items.length) {
        tbody.innerHTML = `<tr><td colspan="3"><div class="empty-state"><div class="empty-icon">📊</div><div class="empty-text">No DNS queries to analyze.</div></div></td></tr>`;
        return;
    }
    
    // Aggregate by domain
    let stats = {};
    let successCount = 0;
    let failCount = 0;
    
    items.forEach(item => {
        const sys = item.sysmon || {};
        const domain = sys.query_name;
        if (!domain) return;
        
        if (!stats[domain]) {
            stats[domain] = { domain: domain, count: 0, agents: new Set() };
        }
        stats[domain].count++;
        stats[domain].agents.add(item.agent.name);
        
        if (sys.query_status === '0' || sys.query_status === 'SUCCESS') {
            successCount++;
        } else {
            failCount++;
        }
    });
    
    // Render high-fidelity stat cards
    grid.innerHTML = `
        <div class="detail-info-card">
            <div class="detail-info-label">Total DNS Lookups</div>
            <div class="detail-info-value" style="color:var(--blue);">${items.length}</div>
        </div>
        <div class="detail-info-card">
            <div class="detail-info-label">Unique Domains Querying</div>
            <div class="detail-info-value" style="color:var(--purple);">${Object.keys(stats).length}</div>
        </div>
        <div class="detail-info-card">
            <div class="detail-info-label">Successful Resolutions</div>
            <div class="detail-info-value" style="color:var(--green);">${successCount}</div>
        </div>
        <div class="detail-info-card">
            <div class="detail-info-label">Failed Resolutions</div>
            <div class="detail-info-value" style="color:var(--red);">${failCount}</div>
        </div>
    `;
    
    // Sort domains by count desc
    const sorted = Object.values(stats).sort((a, b) => b.count - a.count);
    
    sorted.forEach(row => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td><strong style="color:var(--blue);">${escapeHtml(row.domain)}</strong></td>
            <td><span class="badge" style="background:var(--panel);">${row.count} times</span></td>
            <td>${Array.from(row.agents).map(name => `<span class="badge" style="background:var(--border); margin-right:4px;">${name}</span>`).join('')}</td>
        `;
        tbody.appendChild(tr);
    });
}

// Tab 10: File Operations
function renderFileOperations(items) {
    const tbody = document.getElementById("fileStatsTbody");
    const grid = document.getElementById("fileStatsGrid");
    
    tbody.innerHTML = "";
    grid.innerHTML = "";
    
    if (!items.length) {
        tbody.innerHTML = `<tr><td colspan="3"><div class="empty-state"><div class="empty-icon">📊</div><div class="empty-text">No File operations found.</div></div></td></tr>`;
        return;
    }
    
    // Aggregate by file name
    let stats = {};
    let exeFiles = 0;
    let tempFiles = 0;
    
    items.forEach(item => {
        const sys = item.sysmon || {};
        const filename = sys.target_filename;
        if (!filename) return;
        
        if (!stats[filename]) {
            stats[filename] = { file: filename, count: 0, processes: new Set() };
        }
        stats[filename].count++;
        if (sys.image) stats[filename].processes.add(sys.image.split('\\').pop());
        
        const fnLower = filename.toLowerCase();
        if (fnLower.endsWith(".exe") || fnLower.endsWith(".dll") || fnLower.endsWith(".bat") || fnLower.endsWith(".ps1")) {
            exeFiles++;
        }
        if (fnLower.includes("\\temp\\") || fnLower.includes("\\tmp\\") || fnLower.includes("appdata\\local\\temp")) {
            tempFiles++;
        }
    });
    
    // Render cards
    grid.innerHTML = `
        <div class="detail-info-card">
            <div class="detail-info-label">File Creation Events</div>
            <div class="detail-info-value" style="color:var(--blue);">${items.length}</div>
        </div>
        <div class="detail-info-card">
            <div class="detail-info-label">Executable File Creations</div>
            <div class="detail-info-value" style="color:var(--orange);">${exeFiles}</div>
        </div>
        <div class="detail-info-card">
            <div class="detail-info-label">Temp Directory Writes</div>
            <div class="detail-info-value" style="color:var(--yellow);">${tempFiles}</div>
        </div>
    `;
    
    const sorted = Object.values(stats).sort((a, b) => b.count - a.count);
    
    sorted.forEach(row => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td class="mono" style="font-size:11px;">${escapeHtml(row.file)}</td>
            <td><span class="badge" style="background:var(--panel);">${row.count}</span></td>
            <td>${Array.from(row.processes).map(p => `<span class="badge" style="background:var(--border); margin-right:4px;">${p}</span>`).join('')}</td>
        `;
        tbody.appendChild(tr);
    });
}

// Tab 11: Threat Timeline
function renderThreatTimeline(items) {
    const container = document.getElementById("seqTimeline");
    container.innerHTML = "";
    
    if (!items.length) {
        container.innerHTML = `<div class="empty-state"><div class="empty-icon">📈</div><div class="empty-text">No Sysmon events to generate a timeline.</div></div>`;
        return;
    }
    
    // Sort events by timestamp ascending
    const sorted = [...items].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    
    sorted.forEach(item => {
        const sys = item.sysmon || {};
        const div = document.createElement("div");
        div.classList.add("seq-item");
        
        let typeText = "System Action";
        let icon = "⚙️";
        let desc = item.rule.description;
        
        if (sys.event_id === "1") { 
            typeText = "Process Spawned"; icon = "🚀"; 
            const img = sys.image ? sys.image.split('\\').pop() : '—';
            const par = sys.parent_image ? sys.parent_image.split('\\').pop() : '—';
            desc = `Process <strong>${img}</strong> created by ${par} (User: ${sys.user || '—'})`; 
        }
        else if (sys.event_id === "3") { 
            typeText = "Network Connection Established"; icon = "🔌"; 
            const proc = sys.image ? sys.image.split('\\').pop() : '—';
            desc = `Network Connection: <strong>${proc}</strong> -> ${sys.dest_ip || '—'}:${sys.dest_port || '—'} (${sys.protocol || 'TCP'})`; 
        }
        else if (sys.event_id === "10") { 
            typeText = "Process Memory Injection/Access"; icon = "🔒"; 
            const src = sys.source_image ? sys.source_image.split('\\').pop() : '—';
            const tgt = sys.target_image ? sys.target_image.split('\\').pop() : '—';
            desc = `Process Access: <strong>${src}</strong> accessed memory of target ${tgt}`; 
        }
        else if (sys.event_id === "11") { 
            typeText = "File Created"; icon = "📁"; 
            const proc = sys.image ? sys.image.split('\\').pop() : '—';
            desc = `File Written: <strong>${sys.target_filename || '—'}</strong> by process ${proc}`; 
        }
        else if (sys.event_id === "13") { 
            typeText = "Registry Modification"; icon = "🧠"; 
            const proc = sys.image ? sys.image.split('\\').pop() : '—';
            desc = `Registry Value Set: <strong>${sys.target_object || '—'}</strong> by process ${proc}`; 
        }
        else if (sys.event_id === "22") { 
            typeText = "DNS Resolution Request"; icon = "🌐"; 
            const proc = sys.image ? sys.image.split('\\').pop() : '—';
            desc = `DNS Query: <strong>${sys.query_name || '—'}</strong> requested by process ${proc}`; 
        }
        
        div.innerHTML = `
            <div class="seq-dot"></div>
            <div class="seq-content" style="cursor:pointer;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:5px;">
                    <span style="font-weight:600; color:var(--blue);">${icon} ${typeText}</span>
                    <span style="font-size:11px; color:var(--muted); font-family:monospace;">${formatTime(item.timestamp)}</span>
                </div>
                <div style="font-size:12px; margin-bottom:5px;">${desc}</div>
                <div style="font-size:11px; color:var(--hint);">Agent: ${item.agent.name} (${item.agent.id}) | ID: ${sys.event_id || 'Wazuh'} ${sys.mitre_technique ? `| MITRE: <span style="color:var(--purple);">${sys.mitre_technique}</span>` : ''}</div>
            </div>
        `;
        
        div.querySelector(".seq-content").addEventListener("click", () => {
            // Trigger same details drawer
            const drawer = document.getElementById("drawer");
            const overlay = document.getElementById("drawerOverlay");
            const body = document.getElementById("drawerBody");
            if (drawer && body) {
                drawer.classList.add("open");
                if (overlay) overlay.classList.add("open");
                body.innerHTML = `
                    <div style="padding: 15px; display:flex; flex-direction:column; gap:12px;">
                        <div><strong>Timeline Stage:</strong> ${typeText}</div>
                        <div><strong>Agent:</strong> ${item.agent.name} (${item.agent.id})</div>
                        <div><strong>Timestamp:</strong> ${formatTime(item.timestamp)}</div>
                        <hr style="border:0; border-top:1px solid var(--border);" />
                        <pre style="background:var(--surface); border:1px solid var(--border); border-radius:4px; padding:10px; overflow-x:auto; font-size:11px;"><code>${JSON.stringify(item.raw, null, 2)}</code></pre>
                    </div>
                `;
            }
        });
        
        container.appendChild(div);
    });
}

// Helpers
function escapeHtml(unsafe) {
    if (!unsafe) return "";
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

function refreshPage() {
    fetchTelemetry();
}
