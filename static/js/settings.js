/* ═══════════════════════════════════════════════════════════════
   settings.js — Settings page logic
   API configuration, connection tests, and dashboard preferences
   ═══════════════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {
    loadSettings();

    // Form Event Listeners
    document.getElementById('settingsForm').addEventListener('submit', saveConnection);
    document.getElementById('preferencesForm').addEventListener('submit', savePreferences);
    document.getElementById('testBtn').addEventListener('click', testConnection);
});

async function loadSettings() {
    try {
        const data = await api('/api/settings');
        
        // Populate Wazuh API connection fields
        const wz = data.wazuh || {};
        document.getElementById('apiUrl').value = wz.api_url || '';
        document.getElementById('username').value = wz.username || '';
        document.getElementById('password').value = ''; // Leave password blank/redacted
        document.getElementById('password').placeholder = wz.password ? '••••••••' : 'Enter Password';
        document.getElementById('verifySsl').checked = !!wz.verify_ssl;

        // Populate Preferences fields
        const dash = data.dashboard || {};
        document.getElementById('refreshInterval').value = dash.refresh_interval || 30;
        document.getElementById('pageSize').value = dash.page_size || 20;

        // Render managers list
        renderManagers(data.managers || []);
    } catch (err) {
        toast('Error Loading Settings', err.message, 'error');
    }
}

function renderManagers(managers) {
    const list = document.getElementById('managerList');
    if (!list) return;

    if (!managers.length) {
        list.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon"><i data-lucide="monitor"></i></div>
                <div class="empty-text">No manager nodes configured</div>
            </div>`;
    if (window.lucide) lucide.createIcons();
        return;
    }

    list.innerHTML = managers.map(m => {
        const statusClass = m.active ? 'active-status' : 'inactive-status';
        const statusLabel = m.active ? 'Active' : 'Inactive';
        return `
            <div class="manager-card">
                <div class="manager-card-info">
                    <span class="manager-card-name">${escapeHtml(m.name || 'Unnamed Node')}</span>
                    <span class="manager-card-url">${escapeHtml(m.api_url || '—')} (${escapeHtml(m.username || '—')})</span>
                </div>
                <span class="manager-card-status ${statusClass}">${statusLabel}</span>
            </div>`;
    }).join('');
}

async function testConnection() {
    const testBtn = document.getElementById('testBtn');
    const apiUrl = document.getElementById('apiUrl').value.trim();
    const username = document.getElementById('username').value.trim();
    let password = document.getElementById('password').value;

    if (!apiUrl || !username) {
        toast('Validation Error', 'API URL and Username are required to test connection.', 'error');
        return;
    }

    testBtn.disabled = true;
    const originalText = testBtn.textContent;
    testBtn.textContent = 'Testing...';

    try {
        const res = await api('/api/test-connection', {
            method: 'POST',
            body: JSON.stringify({
                api_url: apiUrl,
                username: username,
                password: password || undefined // Will keep existing password if blank
            })
        });

        if (res.success) {
            toast('Success', 'Wazuh API connection test successful!', 'success');
        } else {
            toast('Connection Failed', res.error || 'Unknown error', 'error');
        }
    } catch (err) {
        toast('Connection Failed', err.message, 'error');
    } finally {
        testBtn.disabled = false;
        testBtn.textContent = originalText;
    }
}

async function saveConnection(e) {
    e.preventDefault();
    const saveBtn = document.getElementById('saveBtn');
    const apiUrl = document.getElementById('apiUrl').value.trim();
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const verifySsl = document.getElementById('verifySsl').checked;

    saveBtn.disabled = true;
    const originalText = saveBtn.textContent;
    saveBtn.textContent = 'Saving...';

    try {
        // First save the setting
        await api('/api/settings', {
            method: 'POST',
            body: JSON.stringify({
                wazuh: {
                    api_url: apiUrl,
                    username: username,
                    password: password || undefined, // keeps current if empty
                    verify_ssl: verifySsl
                }
            })
        });

        // Trigger a connect request
        const connRes = await api('/api/connect', { method: 'POST' });
        
        if (connRes.success) {
            toast('Saved & Connected', 'API credentials saved and connection established!', 'success');
        } else {
            toast('Saved with Warnings', `API credentials saved, but connection failed: ${connRes.error}`, 'warning');
        }

        // Update the global status dot
        if (typeof updateConnectionStatus === 'function') {
            updateConnectionStatus();
        }
        
        loadSettings(); // Reload to refresh managers list/redactions
    } catch (err) {
        toast('Save Failed', err.message, 'error');
    } finally {
        saveBtn.disabled = false;
        saveBtn.textContent = originalText;
    }
}

async function savePreferences(e) {
    e.preventDefault();
    const savePrefBtn = document.getElementById('savePrefBtn');
    const refreshInterval = parseInt(document.getElementById('refreshInterval').value, 10);
    const pageSize = parseInt(document.getElementById('pageSize').value, 10);

    savePrefBtn.disabled = true;
    const originalText = savePrefBtn.textContent;
    savePrefBtn.textContent = 'Saving...';

    try {
        await api('/api/settings', {
            method: 'POST',
            body: JSON.stringify({
                dashboard: {
                    refresh_interval: refreshInterval,
                    page_size: pageSize
                }
            })
        });
        toast('Success', 'Dashboard preferences updated successfully!', 'success');
        loadSettings();
    } catch (err) {
        toast('Save Failed', err.message, 'error');
    } finally {
        savePrefBtn.disabled = false;
        savePrefBtn.textContent = originalText;
    }
}
