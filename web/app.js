/* ═══════════════════════════════════════════════════════════════════════════════
 * WP Scanner Dashboard – app.js
 * Single-page application with client-side routing and full API integration
 * ═══════════════════════════════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {
    if (window.location.protocol === 'file:') {
        document.body.innerHTML = `<div style="display:flex;align-items:center;justify-content:center;height:100vh;text-align:center;font-family:Inter,sans-serif;color:#ef4444;padding:32px;">
            <div><h1 style="font-size:2rem;">Backend Offline</h1><p style="color:#94a3b8;margin-top:12px;">Run <code>python app.py</code> then visit <strong>http://localhost:5000</strong></p></div></div>`;
        return;
    }
    App.init();
});

/* ── Global App ─────────────────────────────────────────────────────────────── */

const App = {
    currentView: 'dashboard',
    chart: null,

    init() {
        this.setupNav();
        this.setupMobileMenu();
        this.setupTabs();
        this.checkServer();
        this.loadDashboard();
    },

    /* ── Navigation / SPA Router ─────────────────────────────────────────── */

    setupNav() {
        document.querySelectorAll('.nav-item[data-view]').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                this.navigateTo(item.dataset.view);
            });
        });
    },

    navigateTo(viewId) {
        // Hide all views
        document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
        // Deactivate all nav items
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

        // Show the target view
        const view = document.getElementById(`view-${viewId}`);
        if (view) {
            view.classList.add('active');
            // Small delay for CSS transition
            requestAnimationFrame(() => view.classList.add('active'));
        }

        // Activate the nav item
        const nav = document.querySelector(`.nav-item[data-view="${viewId}"]`);
        if (nav) nav.classList.add('active');

        this.currentView = viewId;

        // Close mobile sidebar
        document.getElementById('sidebar').classList.remove('open');
        document.getElementById('sidebarOverlay').classList.remove('open');

        // Load view-specific data
        this.onViewEnter(viewId);
    },

    onViewEnter(viewId) {
        switch (viewId) {
            case 'dashboard': this.loadDashboard(); break;
            case 'scan':      this.loadScanView(); break;
            case 'reports':   this.loadReports(); break;
            case 'targets':   this.loadTargets(); break;
            case 'settings':  this.loadSettings(); break;
        }
    },

    /* ── Mobile Menu ──────────────────────────────────────────────────────── */

    setupMobileMenu() {
        const btn = document.getElementById('hamburgerBtn');
        const sidebar = document.getElementById('sidebar');
        const overlay = document.getElementById('sidebarOverlay');

        btn.addEventListener('click', () => {
            sidebar.classList.toggle('open');
            overlay.classList.toggle('open');
        });
        overlay.addEventListener('click', () => {
            sidebar.classList.remove('open');
            overlay.classList.remove('open');
        });
    },

    /* ── Tabs (Settings) ──────────────────────────────────────────────────── */

    setupTabs() {
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
                document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
                btn.classList.add('active');
                document.getElementById(btn.dataset.tab).classList.add('active');
            });
        });
    },

    /* ── Server Status ────────────────────────────────────────────────────── */

    async checkServer() {
        const dot = document.getElementById('serverDot');
        const text = document.getElementById('serverStatusText');
        try {
            const res = await fetch('/api/targets');
            if (res.ok) {
                dot.classList.add('online');
                text.textContent = 'Server Online';
            } else {
                dot.classList.add('offline');
                text.textContent = 'Server Error';
            }
        } catch {
            dot.classList.add('offline');
            text.textContent = 'Server Offline';
        }
    },

    /* ═══════════════════════════════════════════════════════════════════════
     *  DASHBOARD VIEW
     * ═══════════════════════════════════════════════════════════════════════ */

    async loadDashboard() {
        // Bind refresh
        document.getElementById('refreshDashboard').onclick = () => this.loadDashboard();

        // Quick scan form
        this.setupQuickScan();

        // Load stats in parallel
        const [targets, reports, tools, chartData] = await Promise.all([
            this.api('/api/targets'),
            this.api('/api/reports'),
            this.api('/api/tools-status'),
            this.api('/api/monthly-stats'),
        ]);

        // Stats cards
        document.getElementById('statTargets').textContent = Array.isArray(targets) ? targets.length : 0;
        document.getElementById('statScans').textContent = Array.isArray(reports) ? reports.length : 0;

        const critCount = Array.isArray(reports)
            ? reports.reduce((sum, r) => sum + (r.severities?.critical || 0), 0)
            : 0;
        document.getElementById('statCritical').textContent = critCount;

        const toolCount = Array.isArray(tools) ? tools.filter(t => t.installed).length : 0;
        document.getElementById('statTools').textContent = `${toolCount}/9`;

        // Recent targets list
        const list = document.getElementById('dashTargetList');
        if (Array.isArray(targets) && targets.length > 0) {
            list.innerHTML = targets.slice(0, 5).map(t =>
                `<li>
                    <span class="target-label">${this.esc(t.label)}</span>
                    <span class="target-url-sm">${this.esc(t.url)}</span>
                </li>`
            ).join('');
        } else {
            list.innerHTML = '<li class="empty-state">No targets configured yet</li>';
        }

        // Chart
        this.renderChart(chartData);
    },

    setupQuickScan() {
        const form = document.getElementById('quickScanForm');
        form.onsubmit = async (e) => {
            e.preventDefault();
            const target = document.getElementById('quickTarget').value.trim();
            const mode = document.getElementById('quickMode').value;
            if (!target) return;
            await this.startScan(target, mode, 'quickScanStatus', 'quickScanBtn');
        };
    },

    renderChart(data) {
        const ctx = document.getElementById('monthlyChart');
        if (!ctx) return;

        if (this.chart) this.chart.destroy();

        Chart.defaults.color = '#94a3b8';
        Chart.defaults.font.family = 'Inter';

        const labels = data?.labels?.length > 0 ? data.labels : ['No data'];
        const hasDat = data?.datasets;

        this.chart = new Chart(ctx.getContext('2d'), {
            type: 'bar',
            data: {
                labels,
                datasets: [
                    { label: 'Critical', data: hasDat ? hasDat.critical : [0], backgroundColor: '#ef4444', borderRadius: 4 },
                    { label: 'High',     data: hasDat ? hasDat.high : [0],     backgroundColor: '#f97316', borderRadius: 4 },
                    { label: 'Medium',   data: hasDat ? hasDat.medium : [0],   backgroundColor: '#eab308', borderRadius: 4 },
                    { label: 'Low',      data: hasDat ? hasDat.low : [0],      backgroundColor: '#3b82f6', borderRadius: 4 },
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { usePointStyle: true, padding: 20 }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(15,17,26,0.95)',
                        titleColor: '#fff',
                        bodyColor: '#e2e8f0',
                        borderColor: 'rgba(255,255,255,0.1)',
                        borderWidth: 1,
                        padding: 12,
                        cornerRadius: 8,
                    }
                },
                scales: {
                    x: { stacked: true, grid: { color: 'rgba(255,255,255,0.04)', drawBorder: false } },
                    y: { stacked: true, grid: { color: 'rgba(255,255,255,0.04)', drawBorder: false }, beginAtZero: true }
                }
            }
        });
    },

    /* ═══════════════════════════════════════════════════════════════════════
     *  SCAN VIEW
     * ═══════════════════════════════════════════════════════════════════════ */

    async loadScanView() {
        // Populate target dropdown
        const targets = await this.api('/api/targets');
        const sel = document.getElementById('scanTargetSelect');
        sel.innerHTML = '<option value="">— pick saved target —</option>';
        if (Array.isArray(targets)) {
            targets.forEach(t => {
                sel.innerHTML += `<option value="${this.esc(t.url)}">${this.esc(t.label)}</option>`;
            });
        }
        sel.onchange = () => {
            if (sel.value) document.getElementById('scanTarget').value = sel.value;
        };

        // Tools list
        const tools = await this.api('/api/tools-status');
        const list = document.getElementById('toolsList');
        if (Array.isArray(tools)) {
            list.innerHTML = tools.map(t => `
                <li class="tool-item ${t.installed ? 'installed' : 'missing'}">
                    <span class="tool-dot ${t.installed ? 'online' : 'offline'}"></span>
                    <span class="tool-name">${this.esc(t.label)}</span>
                    <span class="tool-phase badge-${t.phase}">${t.phase}</span>
                    <span class="tool-status">${t.installed ? 'Ready' : 'Not Found'}</span>
                </li>
            `).join('');
        }

        // Scan form
        const form = document.getElementById('scanForm');
        form.onsubmit = async (e) => {
            e.preventDefault();
            const target = document.getElementById('scanTarget').value.trim();
            const mode = document.getElementById('scanMode').value;
            if (!target) return;
            await this.startScan(target, mode, 'scanFormStatus', 'scanSubmitBtn');
        };
    },

    async startScan(target, mode, statusId, btnId) {
        const btn = document.getElementById(btnId);
        const statusDiv = document.getElementById(statusId);
        const origHTML = btn.innerHTML;

        btn.innerHTML = '<span class="spinner"></span> Starting...';
        btn.disabled = true;
        statusDiv.className = 'scan-status-msg hidden';

        try {
            const res = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target, mode })
            });
            const result = await res.json();

            if (res.ok) {
                statusDiv.className = 'scan-status-msg success';
                statusDiv.textContent = '✓ ' + (result.message || 'Scan started');
                this.toast('Scan initiated successfully!', 'success');
            } else {
                statusDiv.className = 'scan-status-msg error';
                statusDiv.textContent = '✗ ' + (result.error || 'Failed');
                this.toast(result.error || 'Scan failed', 'error');
            }
        } catch {
            statusDiv.className = 'scan-status-msg error';
            statusDiv.textContent = '✗ Server connection error';
            this.toast('Connection error', 'error');
        } finally {
            btn.innerHTML = origHTML;
            btn.disabled = false;
        }
    },

    /* ═══════════════════════════════════════════════════════════════════════
     *  REPORTS VIEW
     * ═══════════════════════════════════════════════════════════════════════ */

    async loadReports() {
        document.getElementById('refreshReports').onclick = () => this.loadReports();

        const reports = await this.api('/api/reports');
        const container = document.getElementById('reportsList');

        if (!Array.isArray(reports) || reports.length === 0) {
            container.innerHTML = `
                <div class="empty-state-big">
                    <svg viewBox="0 0 24 24" width="48" height="48" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                    <h3>No Reports Yet</h3>
                    <p>Run a scan to generate your first report</p>
                </div>`;
            return;
        }

        container.innerHTML = reports.map(r => {
            const sev = r.severities || {};
            const total = (sev.critical || 0) + (sev.high || 0) + (sev.medium || 0) + (sev.low || 0);
            const date = new Date(r.modified * 1000).toLocaleString();

            return `
                <div class="report-card">
                    <div class="report-info">
                        <h4 class="report-name">${this.esc(r.folder || r.name)}</h4>
                        <span class="report-date">${date}</span>
                        <span class="report-size">${r.size_kb} KB</span>
                    </div>
                    <div class="report-badges">
                        ${sev.critical ? `<span class="badge badge-critical">${sev.critical} Critical</span>` : ''}
                        ${sev.high ? `<span class="badge badge-high">${sev.high} High</span>` : ''}
                        ${sev.medium ? `<span class="badge badge-medium">${sev.medium} Medium</span>` : ''}
                        ${sev.low ? `<span class="badge badge-low">${sev.low} Low</span>` : ''}
                        ${total === 0 ? '<span class="badge badge-clean">Clean</span>' : ''}
                    </div>
                    <a href="/api/reports/${encodeURIComponent(r.path)}" target="_blank" class="btn-ghost btn-sm">
                        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
                        Open
                    </a>
                </div>`;
        }).join('');
    },

    /* ═══════════════════════════════════════════════════════════════════════
     *  TARGETS VIEW
     * ═══════════════════════════════════════════════════════════════════════ */

    async loadTargets() {
        const targets = await this.api('/api/targets');
        const tbody = document.getElementById('targetsBody');

        if (!Array.isArray(targets) || targets.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No targets added yet. Use the form above to add one.</td></tr>';
        } else {
            tbody.innerHTML = targets.map((t, i) => `
                <tr>
                    <td>${i + 1}</td>
                    <td><strong>${this.esc(t.label)}</strong></td>
                    <td><a href="${this.esc(t.url)}" target="_blank" class="link-accent">${this.esc(t.url)}</a></td>
                    <td>${t.last_scanned || 'Never'}</td>
                    <td>
                        <button class="btn-ghost btn-sm btn-danger" onclick="App.deleteTarget(${i})">
                            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                            Delete
                        </button>
                    </td>
                </tr>
            `).join('');
        }

        // Add target form
        document.getElementById('addTargetForm').onsubmit = async (e) => {
            e.preventDefault();
            const url = document.getElementById('newTargetUrl').value.trim();
            const label = document.getElementById('newTargetLabel').value.trim();
            if (!url || !label) return;

            try {
                const res = await fetch('/api/targets', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url, label })
                });
                if (res.ok) {
                    this.toast('Target added!', 'success');
                    document.getElementById('newTargetUrl').value = '';
                    document.getElementById('newTargetLabel').value = '';
                    this.loadTargets();
                } else {
                    const err = await res.json();
                    this.toast(err.error || 'Failed to add target', 'error');
                }
            } catch {
                this.toast('Connection error', 'error');
            }
        };
    },

    async deleteTarget(index) {
        if (!confirm('Remove this target?')) return;
        try {
            const res = await fetch(`/api/targets/${index}`, { method: 'DELETE' });
            if (res.ok) {
                this.toast('Target removed', 'success');
                this.loadTargets();
            } else {
                this.toast('Failed to remove target', 'error');
            }
        } catch {
            this.toast('Connection error', 'error');
        }
    },

    /* ═══════════════════════════════════════════════════════════════════════
     *  SETTINGS VIEW
     * ═══════════════════════════════════════════════════════════════════════ */

    async loadSettings() {
        await Promise.all([
            this.loadConfigTab(),
            this.loadTokensTab(),
            this.setupPerformanceTab(),
        ]);
    },

    async loadConfigTab() {
        const config = await this.api('/api/config');
        const container = document.getElementById('configFields');

        if (!config || Object.keys(config).length === 0) {
            container.innerHTML = '<div class="empty-state">No configuration found</div>';
            return;
        }

        container.innerHTML = Object.entries(config).map(([key, val]) => {
            const label = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            const isArray = Array.isArray(val);
            const displayVal = isArray ? val.join(', ') : val;
            const inputType = typeof val === 'number' ? 'number' : typeof val === 'boolean' ? 'checkbox' : 'text';

            if (inputType === 'checkbox') {
                return `
                    <div class="config-field">
                        <label class="config-label">${label}</label>
                        <label class="toggle-switch">
                            <input type="checkbox" name="${key}" ${val ? 'checked' : ''} data-type="boolean">
                            <span class="toggle-slider"></span>
                        </label>
                    </div>`;
            }

            return `
                <div class="config-field">
                    <label class="config-label" for="cfg-${key}">${label}</label>
                    <input type="${inputType}" id="cfg-${key}" name="${key}" value="${this.esc(String(displayVal))}" 
                           data-type="${isArray ? 'array' : typeof val}" ${inputType === 'number' ? 'step="any"' : ''}>
                </div>`;
        }).join('');

        document.getElementById('configForm').onsubmit = async (e) => {
            e.preventDefault();
            const formData = {};
            container.querySelectorAll('input').forEach(input => {
                const key = input.name;
                const type = input.dataset.type;
                if (type === 'boolean') {
                    formData[key] = input.checked;
                } else if (type === 'number') {
                    formData[key] = Number(input.value);
                } else if (type === 'array') {
                    formData[key] = input.value.split(',').map(s => s.trim()).filter(Boolean);
                } else {
                    formData[key] = input.value;
                }
            });

            try {
                const res = await fetch('/api/config', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(formData)
                });
                if (res.ok) this.toast('Configuration saved!', 'success');
                else this.toast('Failed to save', 'error');
            } catch {
                this.toast('Connection error', 'error');
            }
        };
    },

    async loadTokensTab() {
        const tokens = await this.api('/api/tokens');

        if (tokens) {
            document.getElementById('tokenWpscan').value = tokens.wpscan_api_token || '';
            document.getElementById('tokenZap').value = tokens.zap_api_key || '';
        }

        document.getElementById('tokensForm').onsubmit = async (e) => {
            e.preventDefault();
            const body = {
                wpscan_api_token: document.getElementById('tokenWpscan').value,
                zap_api_key: document.getElementById('tokenZap').value,
            };
            try {
                const res = await fetch('/api/tokens', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                });
                if (res.ok) this.toast('Tokens saved!', 'success');
                else this.toast('Failed to save tokens', 'error');
            } catch {
                this.toast('Connection error', 'error');
            }
        };
    },

    setupPerformanceTab() {
        const cards = document.querySelectorAll('.profile-card');
        cards.forEach(card => {
            card.addEventListener('click', () => {
                cards.forEach(c => c.classList.remove('selected'));
                card.classList.add('selected');
            });
        });

        document.getElementById('applyProfileBtn').onclick = async () => {
            const selected = document.querySelector('.profile-card.selected');
            if (!selected) return;

            const profile = selected.dataset.profile;
            const config = await this.api('/api/config');
            if (!config) return;

            const profiles = {
                best:   { nuclei_rate_limit: 150, wpscan_max_threads: 5, nikto_pause_seconds: 0, whatweb_max_threads: 25, httpx_rate_limit: 150 },
                stable: { nuclei_rate_limit: 20,  wpscan_max_threads: 1, nikto_pause_seconds: 1, whatweb_max_threads: 5,  httpx_rate_limit: 10 },
                light:  { nuclei_rate_limit: 5,   wpscan_max_threads: 1, nikto_pause_seconds: 3, whatweb_max_threads: 1,  httpx_rate_limit: 2 },
            };

            Object.assign(config, profiles[profile] || profiles.stable);

            try {
                const res = await fetch('/api/config', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(config)
                });
                if (res.ok) {
                    this.toast(`Applied "${selected.querySelector('h4').textContent}" profile!`, 'success');
                    this.loadConfigTab(); // Refresh config fields
                } else {
                    this.toast('Failed to apply profile', 'error');
                }
            } catch {
                this.toast('Connection error', 'error');
            }
        };
    },

    /* ═══════════════════════════════════════════════════════════════════════
     *  UTILITIES
     * ═══════════════════════════════════════════════════════════════════════ */

    async api(url) {
        try {
            const res = await fetch(url);
            return await res.json();
        } catch {
            return null;
        }
    },

    esc(str) {
        const el = document.createElement('span');
        el.textContent = str;
        return el.innerHTML;
    },

    toast(message, type = 'info') {
        const container = document.getElementById('toastContainer');
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;

        const icons = {
            success: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>',
            error:   '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
            info:    '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
        };

        toast.innerHTML = `${icons[type] || icons.info}<span>${message}</span>`;
        container.appendChild(toast);

        // Trigger enter animation
        requestAnimationFrame(() => toast.classList.add('show'));

        setTimeout(() => {
            toast.classList.remove('show');
            toast.addEventListener('transitionend', () => toast.remove());
        }, 3500);
    },
};
