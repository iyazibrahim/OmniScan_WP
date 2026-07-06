document.addEventListener("DOMContentLoaded", () => {
    if (window.location.protocol === "file:") {
        document.body.innerHTML = `<div style="display:flex;align-items:center;justify-content:center;height:100vh;text-align:center;font-family:Inter,sans-serif;color:#ef4444;padding:32px;">
            <div><h1 style="font-size:2rem;">Backend Offline</h1><p style="color:#94a3b8;margin-top:12px;">Run <code>python app.py</code> then visit <strong>http://localhost:5000</strong></p></div></div>`;
        return;
    }

    App.init();

    // Close download dropdowns when clicking outside
    document.addEventListener("click", (e) => {
        if (e.target.closest("#hamburgerBtn")) {
            e.preventDefault();
            App.toggleMobileMenu();
            return;
        }

        if (e.target.id === "sidebarOverlay") {
            e.preventDefault();
            App.closeMobileMenu();
            return;
        }

        if (!e.target.closest(".dl-dropdown")) {
            document.querySelectorAll(".dl-menu.open").forEach((m) => m.classList.remove("open"));
        }
    });
});

// ── Global authenticated fetch (redirect to /login on 401) ───────────────────
async function _authedFetch(url, options) {
    const res = await fetch(url, options);
    if (res.status === 401) {
        window.location.href = "/login";
        return res;
    }
    return res;
}

const App = {
    currentView: "dashboard",
    chart: null,
    _chartData: null,
    _chartMode: "stacked",
    _reportFilter: "all",
    _reportSearch: "",
    _allReports: [],
    _dashRefreshTimer: null,
    activeScanId: null,
    scanPollingTimer: null,
    scanEstimates: null,
    assessmentCatalog: [],
    assessmentWorkbook: null,
    assessmentTarget: "",
    modules: {},
    monitoringRefreshTimer: null,
    monitoringDrawerOpen: false,
    monitoringFormDirty: false,
    monitoringSubView: "overview",
    monitoringCharts: {
        status: null,
        uptime: null,
        incidents: null,
    },

    async init() {
        this.setupNavigation();
        this.setupMobileMenu();
        this.setupTabs();
        this.checkServer();
        await this.loadModuleRegistry();
        this.navigateTo("dashboard");
    },

    setupNavigation() {
        const navItems = document.querySelectorAll(".nav-item");
        navItems.forEach((item) => {
            item.addEventListener("click", (event) => {
                event.preventDefault();
                const view = item.dataset.view;
                if (!view) return;
                this.navigateTo(view);
                if (window.innerWidth <= 1024) {
                    this.closeMobileMenu();
                }
            });
        });
    },

    async loadModuleRegistry() {
        const modules = await this.api("/api/modules");
        this.modules = modules && typeof modules === "object" ? modules : {};
        this.applyModuleVisibility();
    },

    applyModuleVisibility() {
        const modules = this.modules || {};
        document.querySelectorAll(".nav-item[data-view]").forEach((item) => {
            const view = item.dataset.view;
            const visible = modules[view] !== false;
            item.hidden = !visible;
            item.classList.toggle("module-hidden", !visible);
            const panel = document.getElementById(`view-${view}`);
            if (panel) {
                panel.dataset.moduleEnabled = visible ? "true" : "false";
            }
        });
    },

    navigateTo(view) {
        const previousView = this.currentView;
        if (this.modules?.[view] === false) {
            this.currentView = "dashboard";
            view = "dashboard";
        }
        if (view !== "monitoring") {
            this.stopMonitoringRefresh();
            this.closeMonitoringDrawer();
        }
        this.currentView = view;
        document.querySelectorAll(".nav-item").forEach((item) => {
            item.classList.toggle("active", item.dataset.view === view);
        });
        document.querySelectorAll(".view").forEach((panel) => panel.classList.remove("active"));
        const panel = document.getElementById(`view-${view}`);
        if (panel) {
            panel.classList.add("active");
        }

        if (view === "dashboard") {
            this.loadDashboard();
        } else if (view === "monitoring") {
            if (previousView !== "monitoring") {
                this.monitoringSubView = "overview";
            }
            this.loadMonitoringView();
        } else if (view === "scan") {
            this.loadScanView();
        } else if (view === "reports") {
            this.loadReports();
        } else if (view === "assessments") {
            this.loadAssessmentsView();
        } else if (view === "targets") {
            this.loadTargets();
        } else if (view === "settings") {
            this.loadSettings();
        }
    },

    setupMobileMenu() {
        const button = document.getElementById("hamburgerBtn");
        const sidebar = document.getElementById("sidebar");
        const overlay = document.getElementById("sidebarOverlay");
        if (!button || !sidebar || !overlay) return;
        button.setAttribute("aria-expanded", "false");
    },

    toggleMobileMenu(forceState) {
        const sidebar = document.getElementById("sidebar");
        const overlay = document.getElementById("sidebarOverlay");
        const button = document.getElementById("hamburgerBtn");
        if (!sidebar || !overlay) return;

        const nextState = typeof forceState === "boolean"
            ? forceState
            : !sidebar.classList.contains("open");

        sidebar.classList.toggle("open", nextState);
        overlay.classList.toggle("open", nextState);
        button?.setAttribute("aria-expanded", nextState ? "true" : "false");
    },

    closeMobileMenu() {
        this.toggleMobileMenu(false);
    },

    setupTabs() {
        document.querySelectorAll(".settings-tabs").forEach((group) => {
            if (group.dataset.bound === "true") {
                return;
            }
            group.dataset.bound = "true";

            group.addEventListener("click", (event) => {
                const button = event.target.closest(".tab-btn[data-tab]");
                if (!button) {
                    return;
                }

                const workspace = group.closest(".settings-workspace-grid");
                const panels = workspace ? workspace.querySelectorAll(".tab-panel") : document.querySelectorAll(".tab-panel");
                const targetPanel = document.getElementById(button.dataset.tab);
                if (!targetPanel) {
                    return;
                }

                group.querySelectorAll(".tab-btn").forEach((item) => item.classList.remove("active"));
                panels.forEach((panel) => panel.classList.remove("active"));
                button.classList.add("active");
                targetPanel.classList.add("active");
            });
        });
    },

    async checkServer() {
        const dot = document.getElementById("serverDot");
        const text = document.getElementById("serverStatusText");
        if (!dot || !text) return;

        dot.classList.remove("online", "offline");

        try {
            const response = await fetch("/api/targets");
            if (response.ok) {
                dot.classList.add("online");
                text.textContent = "Server Online";
            } else {
                dot.classList.add("offline");
                text.textContent = "API Unavailable";
            }
        } catch {
            dot.classList.add("offline");
            text.textContent = "Backend Offline";
        }
    },

    async loadDashboard() {
        document.getElementById("refreshDashboard").onclick = () => this.loadDashboard();
        const newScanBtn = document.getElementById("dashboardNewScan");
        if (newScanBtn) {
            newScanBtn.onclick = () => this.navigateTo("scan");
        }
        this.setupQuickScan();

        const [targets, reports, tools, chartData, jobs, insights] = await Promise.all([
            this.api("/api/targets"),
            this.api("/api/reports"),
            this.api("/api/tools-status"),
            this.api("/api/monthly-stats"),
            this.api("/api/scan-jobs"),
            this.api("/api/dashboard-insights"),
        ]);

        const ov = insights?.overview || {};
        document.getElementById("statRiskScore").textContent = `${Number(ov.risk_score || 0)}`;
        document.getElementById("statOpenFindings").textContent = `${Number(ov.open_findings || 0)}`;
        document.getElementById("statHighRiskAssets").textContent = `${Number(ov.high_risk_assets || 0)}`;
        document.getElementById("statPublicAssets").textContent = `${Number(ov.internet_facing_assets || 0)}`;
        document.getElementById("statNewFindings").textContent = `${Number(ov.new_findings_7d || 0)}`;
        const publicAssetsMeta = document.getElementById("statPublicAssetsMeta");
        if (publicAssetsMeta) {
            const publicCount = Number(ov.internet_facing_assets || 0);
            const trackedCount = Number(ov.tracked_assets || 0);
            const exposurePct = Number(ov.exposure_pct || 0);
            publicAssetsMeta.textContent = trackedCount > 0
                ? `${publicCount} of ${trackedCount} tracked assets are public-facing (${exposurePct}%).`
                : "Tracked assets currently exposed to the public internet.";
        }

        const recentTargets = document.getElementById("dashTargetList");
        if (Array.isArray(targets) && targets.length > 0) {
            recentTargets.innerHTML = targets.slice(0, 5).map((target) => `
                <li>
                    <span class="target-label">${this.esc(target.label)}</span>
                    <span class="target-url-sm">${this.esc(target.url)}</span>
                </li>
            `).join("");
        } else {
            recentTargets.innerHTML = '<li class="empty-state">No targets configured yet</li>';
        }

        this.renderActiveScansDash(jobs);
        this.renderChart(chartData);
        this.renderDashboardInsights(insights);
        this.renderDashboardMonitoring(insights?.monitoring || {});
        this.renderDashboardReports(reports?.reports || []);
    },

    renderDashboardMonitoring(monitoring) {
        const overview = monitoring?.overview || {};
        const statsNode = document.getElementById("dashboardMonitoringStats");
        if (statsNode) {
            statsNode.innerHTML = `
                <div class="workspace-signal-card">
                    <span class="signal-label">Healthy Assets</span>
                    <strong>${this.esc(String(overview.healthy_assets || 0))}</strong>
                    <p>Monitored assets currently reporting healthy state.</p>
                </div>
                <div class="workspace-signal-card">
                    <span class="signal-label">Active Incidents</span>
                    <strong>${this.esc(String(overview.active_incidents || 0))}</strong>
                    <p>Assets currently degraded or down.</p>
                </div>
                <div class="workspace-signal-card">
                    <span class="signal-label">24h Uptime</span>
                    <strong>${this.esc(String(overview.uptime_24h_pct || 0))}%</strong>
                    <p>Average estimated uptime across monitored assets.</p>
                </div>
                <div class="workspace-signal-card">
                    <span class="signal-label">Enabled Monitors</span>
                    <strong>${this.esc(String(overview.enabled_assets || 0))}</strong>
                    <p>Low-storage monitoring checks currently active.</p>
                </div>
            `;
        }

        const incidentNode = document.getElementById("dashboardIncidentList");
        const incidents = Array.isArray(monitoring?.incidents) ? monitoring.incidents : [];
        if (incidentNode) {
            incidentNode.innerHTML = incidents.length
                ? `<div class="metric-list">${incidents.slice(0, 6).map((item) => `
                    <div class="metric-item">
                        <span>${this.esc(item.label || item.asset_id || "Asset")} <small>${this.esc(item.status || "")}</small></span>
                        <strong>${this.esc(item.message || "-")}</strong>
                    </div>
                `).join("")}</div>`
                : '<div class="empty-state">No active monitoring incidents.</div>';
        }
    },

    renderDashboardInsights(insights) {
        const attention = Array.isArray(insights?.attention_now) ? insights.attention_now : [];
        const attentionBody = document.getElementById("attentionTableBody");
        if (attentionBody) {
            if (!attention.length) {
                attentionBody.innerHTML = '<tr><td colspan="7" class="empty-state">No priority vulnerabilities right now.</td></tr>';
            } else {
                attentionBody.innerHTML = attention.map((item) => {
                    const sev = (item.severity || "low").toLowerCase();
                    const sevBadge = `<span class="badge badge-${this.esc(sev)}">${this.esc(sev)}</span>`;
                    const exploitBadge = item.exploit_available
                        ? '<span class="badge-pill exploit-yes">Yes</span>'
                        : '<span class="badge-pill exploit-no">No</span>';
                    return `<tr>
                        <td>${this.esc(item.asset || "-")}</td>
                        <td>${this.esc(item.cve || "-")}</td>
                        <td>${sevBadge}</td>
                        <td>${this.esc(String(item.cvss ?? "-"))}</td>
                        <td>${exploitBadge}</td>
                        <td>${this.esc(item.sla || "-")}</td>
                        <td><strong>${this.esc(item.action || "Review")}</strong></td>
                    </tr>`;
                }).join("");
            }
        }

        const attackSurface = Array.isArray(insights?.attack_surface) ? insights.attack_surface : [];
        const attackNode = document.getElementById("attackSurfaceList");
        if (attackNode) {
            const maxCount = attackSurface.reduce((max, item) => Math.max(max, Number(item.vulnerability_count || 0)), 0) || 1;
            attackNode.innerHTML = attackSurface.length
                ? `<div class="surface-coverage-list">${attackSurface.map((item) => {
                    const vulnCount = Number(item.vulnerability_count || 0);
                    const assetCount = Number(item.asset_count || 0);
                    const widthPct = Math.max(12, Math.round((vulnCount / maxCount) * 100));
                    return `<div class="surface-row">
                        <div class="surface-row-head">
                            <span class="surface-label">${this.esc(item.category || "Surface")} <span class="surface-meta">${assetCount} assets</span></span>
                            <span class="surface-value">${this.esc(String(vulnCount))} findings</span>
                        </div>
                        <div class="surface-bar"><span style="width:${widthPct}%"></span></div>
                    </div>`;
                }).join("")}</div>`
                : '<div class="empty-state">No attack surface data yet.</div>';
        }

        const breakdown = insights?.vulnerability_breakdown || {};
        const cvss = breakdown.cvss_histogram || {};
        const topCwe = Array.isArray(breakdown.top_cwe) ? breakdown.top_cwe : [];
        const exploit = breakdown.exploit_availability || {};
        const breakdownNode = document.getElementById("vulnBreakdownList");
        if (breakdownNode) {
            breakdownNode.innerHTML = `
                <div class="metric-list">
                    <div class="metric-item"><span>CVSS 9-10</span><strong>${this.esc(String(cvss["9-10"] || 0))}</strong></div>
                    <div class="metric-item"><span>CVSS 7-8.9</span><strong>${this.esc(String(cvss["7-8.9"] || 0))}</strong></div>
                    <div class="metric-item"><span>CVSS 4-6</span><strong>${this.esc(String(cvss["4-6"] || 0))}</strong></div>
                    <div class="metric-item"><span>CVSS 0-3</span><strong>${this.esc(String(cvss["0-3"] || 0))}</strong></div>
                    <div class="metric-item"><span>Exploit Available</span><strong>${this.esc(String(exploit.yes || 0))}</strong></div>
                    <div class="metric-item"><span>Exploit Not Public</span><strong>${this.esc(String(exploit.no || 0))}</strong></div>
                    ${topCwe.slice(0, 4).map((row) => `<div class="metric-item"><span>${this.esc(row.cwe || "CWE")}</span><strong>${this.esc(String(row.count || 0))}</strong></div>`).join("")}
                </div>
            `;
        }

        const aging = insights?.aging_sla || {};
        const agingNode = document.getElementById("agingSlaList");
        if (agingNode) {
            agingNode.innerHTML = `
                <div class="metric-list">
                    <div class="metric-item"><span>&lt; 7 days</span><strong>${this.esc(String(aging.lt_7 || 0))}</strong></div>
                    <div class="metric-item"><span>7-30 days</span><strong>${this.esc(String(aging.d_7_30 || 0))}</strong></div>
                    <div class="metric-item"><span>&gt; 30 days</span><strong>${this.esc(String(aging.gt_30 || 0))}</strong></div>
                    <div class="metric-item"><span>SLA Breached</span><strong>${this.esc(String(aging.sla_breached || 0))}</strong></div>
                    <div class="metric-item"><span>SLA Compliance</span><strong>${this.esc(String(aging.sla_compliance_pct || 0))}%</strong></div>
                </div>
            `;
        }

        const topAssets = Array.isArray(insights?.top_assets) ? insights.top_assets : [];
        const topAssetsNode = document.getElementById("topAssetsList");
        if (topAssetsNode) {
            topAssetsNode.innerHTML = topAssets.length
                ? `<div class="metric-list">${topAssets.map((row) =>
                    `<div class="metric-item"><span>${this.esc(row.asset || "Asset")}</span><strong>${this.esc(String(row.risk_score || 0))}</strong></div>`
                ).join("")}</div>`
                : '<div class="empty-state">No asset risk ranking yet.</div>';
        }
    },

    renderDashboardReports(reports) {
        const node = document.getElementById("dashRecentReportsList");
        if (!node) return;

        const reportItems = Array.isArray(reports) ? reports.slice(0, 4) : [];
        if (!reportItems.length) {
            node.innerHTML = '<div class="empty-state">No reports available yet.</div>';
            return;
        }

        const sevBadge = (label, count) => {
            if (!count) return "";
            return `<span class="report-badge report-badge-${label}">${count} ${label}</span>`;
        };

        node.innerHTML = `<div class="report-feed">${reportItems.map((report) => {
            const sev = report.severities || {};
            const totalFindings = ["critical", "high", "medium", "low", "info"].reduce((sum, key) => sum + Number(sev[key] || 0), 0);
            const profile = report.profile || "auto";
            const lastScan = report.scan_started_at || "";
            return `<div class="report-feed-item">
                <div class="report-feed-top">
                    <div>
                        <div class="report-feed-title">${this.esc(report.target_url || report.name || "Untitled report")}</div>
                        <div class="report-feed-meta">${this.esc(profile)} profile${lastScan ? ` · ${this.esc(this._formatReportDate(report))}` : ""}</div>
                    </div>
                    <strong class="surface-value">${this.esc(String(totalFindings))}</strong>
                </div>
                <div class="report-findings-mix">
                    ${sevBadge("critical", Number(sev.critical || 0))}
                    ${sevBadge("high", Number(sev.high || 0))}
                    ${sevBadge("medium", Number(sev.medium || 0))}
                    ${sevBadge("low", Number(sev.low || 0))}
                    ${totalFindings === 0 ? '<span class="report-badge report-badge-clean">Clean</span>' : ""}
                </div>
                <div class="report-feed-actions">
                    <a href="/api/reports/${encodeURIComponent(report.path)}" target="_blank" class="btn-ghost btn-sm">Open</a>
                    <a href="/api/reports/${encodeURIComponent(report.path)}?dl=1" class="btn-ghost btn-sm" download>Download</a>
                </div>
            </div>`;
        }).join("")}</div>`;
    },

    renderActiveScansDash(jobs) {
        const list = document.getElementById("dashActiveScansList");
        const badge = document.getElementById("dashActiveScansBadge");
        if (!list) return;

        const allJobs = Array.isArray(jobs) ? jobs : [];
        const activeJobs = allJobs.filter((j) => j.status === "running" || j.status === "cancelling");
        const runningCount = activeJobs.length;

        if (badge) {
            badge.textContent = runningCount > 0 ? `${runningCount} running` : "0 running";
            badge.className = runningCount > 0 ? "badge badge-running" : "badge badge-neutral";
        }

        if (!activeJobs.length) {
            list.innerHTML = '<div class="empty-state">No active scans right now.</div>';
            return;
        }

        list.innerHTML = activeJobs.map((job) => {
            const statusClass = {running: "status-running", cancelling: "status-warn", completed: "status-done", cancelled: "status-warn", failed: "status-fail"}[job.status] || "status-done";
            const progress = Math.max(0, Math.min(100, Number(job.progress || 0)));
            const etaHtml = job.status === "running" && job.eta_label
                ? `<span class="active-scan-eta">ETA ${this.esc(job.eta_label)}</span>`
                : "";
            const goBtn = (job.status === "running" || job.status === "cancelling") && job.scan_id
                ? `<button class="btn-ghost btn-xs" onclick="App.jumpToScan('${this.esc(job.scan_id)}')">View</button>`
                : "";
            return `
                <div class="active-scan-row">
                    <div class="active-scan-info">
                        <span class="active-scan-dot ${statusClass}"></span>
                        <div class="active-scan-details">
                            <span class="active-scan-target" title="${this.esc(job.target || "")}">${this.esc(job.target || "Unknown")}</span>
                            <span class="active-scan-meta">${this.esc(job.mode || "")} · ${this.esc(job.profile || "")} · ${this.esc(job.elapsed_label || "")} elapsed</span>
                        </div>
                    </div>
                    <div class="active-scan-right">
                        ${etaHtml}
                        <span class="active-scan-pct">${progress}%</span>
                        ${goBtn}
                    </div>
                </div>
                <div class="active-scan-bar"><div style="width:${progress}%"></div></div>
            `;
        }).join("");

        // Auto-refresh dashboard while scans are running
        if (runningCount > 0 && this.currentView === "dashboard") {
            if (!this._dashRefreshTimer) {
                this._dashRefreshTimer = setInterval(() => {
                    if (this.currentView === "dashboard") {
                        this.api("/api/scan-jobs").then((j) => this.renderActiveScansDash(j));
                    } else {
                        clearInterval(this._dashRefreshTimer);
                        this._dashRefreshTimer = null;
                    }
                }, 5000);
            }
        } else if (this._dashRefreshTimer && runningCount === 0) {
            clearInterval(this._dashRefreshTimer);
            this._dashRefreshTimer = null;
        }
    },

    jumpToScan(scanId) {
        this.activeScanId = scanId;
        this.navigateTo("scan");
        if (this.activeScanId && !this.scanPollingTimer) {
            this.beginScanPolling(scanId);
        }
    },

    syncActiveScanFromJobs(jobs) {
        const activeJobs = Array.isArray(jobs)
            ? jobs.filter((job) => job.status === "running" || job.status === "cancelling")
            : [];
        if (!activeJobs.length || !activeJobs[0]?.scan_id) {
            return;
        }
        if (this.activeScanId !== activeJobs[0].scan_id || !this.scanPollingTimer) {
            this.beginScanPolling(activeJobs[0].scan_id);
        }
    },

    setupQuickScan() {
        const form = document.getElementById("quickScanForm");
        if (!form) return;
        form.onsubmit = async (event) => {
            event.preventDefault();
            const target = document.getElementById("quickTarget").value.trim();
            const mode = document.getElementById("quickMode").value;
            const profile = document.getElementById("quickProfile").value;
            if (!target) {
                return;
            }
            await this.startScan(target, mode, profile, "quickScanStatus", "quickScanBtn");
        };
    },

    setChartMode(mode) {
        this._chartMode = mode;
        const btnStacked = document.getElementById("chartModeStacked");
        const btnNorm = document.getElementById("chartModeNorm");
        if (btnStacked) btnStacked.classList.toggle("active", mode === "stacked");
        if (btnNorm) btnNorm.classList.toggle("active", mode === "normalized");
        if (this._chartData) this.renderChart(this._chartData);
    },

    renderChart(data) {
        this._chartData = data;
        const mode = this._chartMode || "stacked";
        const canvas = document.getElementById("monthlyChart");
        if (!canvas) return;
        if (typeof Chart === "undefined") {
            const subtitleNode = document.querySelector(".widget-chart .subtitle");
            if (subtitleNode) {
                subtitleNode.textContent = "Trend chart unavailable: Chart.js failed to load.";
            }
            return;
        }
        if (this.chart) this.chart.destroy();

        const subtitleNode = document.querySelector(".widget-chart .subtitle");
        if (subtitleNode) {
            subtitleNode.textContent = data?.insights?.summary || "Monthly severity distribution across all scans";
        }

        Chart.defaults.color = "#94a3b8";
        Chart.defaults.font.family = "Inter";

        const labels = data?.labels?.length ? data.labels : ["No data"];
        const raw = data?.datasets || {};
        const rawC = raw.critical || [];
        const rawH = raw.high || [];
        const rawM = raw.medium || [];
        const rawL = raw.low || [];
        const riskSeries = raw.risk_score || [];
        const newVulns = raw.new_vulns || [];
        const criticalIncidents = raw.critical_incidents || [];

        let dC, dH, dM, dL, yAxisLabel, tooltipCallbacks;
        if (mode === "normalized") {
            dC = []; dH = []; dM = []; dL = [];
            yAxisLabel = "Risk Score";
            tooltipCallbacks = {
                label: (ctx) => `${ctx.dataset.label}: ${ctx.parsed.y}`,
            };
        } else {
            dC = rawC; dH = rawH; dM = rawM; dL = rawL;
            yAxisLabel = "";
            tooltipCallbacks = {};
        }

        const scales = mode === "normalized"
            ? {
                x: { stacked: false, grid: { color: "rgba(255,255,255,0.04)", drawBorder: false } },
                yRisk: {
                    type: "linear",
                    axis: "y",
                    position: "left",
                    beginAtZero: true,
                    suggestedMax: 100,
                    grid: { color: "rgba(255,255,255,0.05)", drawBorder: false },
                    title: { display: true, text: "Risk Score", color: "#94a3b8" },
                },
                yVol: {
                    type: "linear",
                    axis: "y",
                    position: "right",
                    beginAtZero: true,
                    grid: { drawOnChartArea: false },
                    title: { display: true, text: "Vulnerability Count", color: "#94a3b8" },
                },
            }
            : {
                x: { stacked: true, grid: { color: "rgba(255,255,255,0.04)", drawBorder: false } },
                y: {
                    type: "linear",
                    axis: "y",
                    stacked: true,
                    grid: { color: "rgba(255,255,255,0.04)", drawBorder: false },
                    beginAtZero: true,
                    title: yAxisLabel ? { display: true, text: yAxisLabel, color: "#94a3b8" } : undefined,
                },
            };

        this.chart = new Chart(canvas.getContext("2d"), {
            type: "bar",
            data: {
                labels,
                datasets: mode === "normalized"
                    ? [
                        { label: "New Vulnerabilities", data: newVulns, backgroundColor: "rgba(59,130,246,0.55)", borderRadius: 4, yAxisID: "yVol" },
                        { label: "Critical Incidents", data: criticalIncidents, backgroundColor: "rgba(239,68,68,0.6)", borderRadius: 4, yAxisID: "yVol" },
                        { label: "Risk Score", data: riskSeries, type: "line", borderColor: "#f97316", pointBackgroundColor: "#f97316", tension: 0.35, fill: false, yAxisID: "yRisk" },
                    ]
                    : [
                        { label: "Critical", data: dC, backgroundColor: "#ef4444", borderRadius: 4 },
                        { label: "High",     data: dH, backgroundColor: "#f97316", borderRadius: 4 },
                        { label: "Medium",   data: dM, backgroundColor: "#eab308", borderRadius: 4 },
                        { label: "Low",      data: dL, backgroundColor: "#3b82f6", borderRadius: 4 },
                    ],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: "index", intersect: false },
                plugins: {
                    legend: { position: "bottom", labels: { usePointStyle: true, padding: 20 } },
                    tooltip: {
                        backgroundColor: "rgba(15,17,26,0.95)",
                        titleColor: "#fff",
                        bodyColor: "#e2e8f0",
                        borderColor: "rgba(255,255,255,0.1)",
                        borderWidth: 1,
                        padding: 12,
                        cornerRadius: 8,
                        callbacks: tooltipCallbacks,
                    },
                },
                scales,
            },
        });
    },

    async loadScanView() {
        const [targets, tools, estimates, jobs] = await Promise.all([
            this.api("/api/targets"),
            this.api("/api/tools-status"),
            this.api("/api/scan-estimates"),
            this.api("/api/scan-jobs"),
        ]);

        this.scanEstimates = estimates || null;
        const select = document.getElementById("scanTargetSelect");
        select.innerHTML = '<option value="">- pick saved target -</option>';

        if (Array.isArray(targets)) {
            targets.forEach((target) => {
                const option = document.createElement("option");
                option.value = target.url;
                option.textContent = `${target.label} (${target.profile || "auto"})`;
                option.dataset.profile = target.profile || "auto";
                select.appendChild(option);
            });
        }

        select.onchange = () => {
            if (!select.value) {
                return;
            }
            document.getElementById("scanTarget").value = select.value;
            const selectedOption = select.options[select.selectedIndex];
            if (selectedOption?.dataset.profile) {
                document.getElementById("scanProfile").value = selectedOption.dataset.profile;
            }
        };

        const list = document.getElementById("toolsList");
        if (Array.isArray(tools)) {
            list.innerHTML = tools.map((tool) => `
                <li class="tool-item ${tool.installed ? "installed" : "missing"}">
                    <span class="tool-dot ${tool.installed ? "online" : "offline"}"></span>
                    <span class="tool-name">${this.esc(tool.label)}</span>
                    <span class="tool-phase badge-${tool.phase}">${this.esc(tool.phase)}</span>
                    <span class="tool-status">${tool.installed ? "Ready" : "Not Found"}</span>
                </li>
            `).join("");
        }

        const toolsPanelBtn = document.getElementById("toggleToolsPanelBtn");
        const toolsPanelBody = document.getElementById("toolsPanelBody");
        if (toolsPanelBtn && toolsPanelBody) {
            toolsPanelBtn.onclick = () => {
                const collapsed = toolsPanelBody.classList.toggle("collapsed");
                toolsPanelBtn.textContent = collapsed ? "Show Tools" : "Hide Tools";
                toolsPanelBtn.setAttribute("aria-expanded", collapsed ? "false" : "true");
            };
        }

        const modeSelect = document.getElementById("scanMode");
        modeSelect.onchange = () => this.renderScanEstimateHint(modeSelect.value);
        this.renderScanEstimateHint(modeSelect.value);

        const form = document.getElementById("scanForm");
        form.onsubmit = async (event) => {
            event.preventDefault();
            const target = document.getElementById("scanTarget").value.trim();
            const mode = document.getElementById("scanMode").value;
            const profile = document.getElementById("scanProfile").value;
            if (!target) {
                return;
            }
            await this.startScan(target, mode, profile, "scanFormStatus", "scanSubmitBtn");
        };

        this.syncActiveScanFromJobs(jobs);
    },

    renderScanEstimateHint(mode) {
        const node = document.getElementById("scanEstimateHint");
        if (!node) {
            return;
        }

        const estimate = this.scanEstimates?.[mode];
        const label = estimate?.label || "~unknown";
        const source = estimate?.source === "historical" ? "based on previous scans" : "default baseline";
        node.textContent = `Estimated runtime for ${this.humanizeKey(mode)}: ${label} (${source})`;
    },

    stopScanPolling() {
        if (this.scanPollingTimer) {
            clearInterval(this.scanPollingTimer);
            this.scanPollingTimer = null;
        }
    },

    beginScanPolling(scanId) {
        this.activeScanId = scanId;
        this.stopScanPolling();
        this.pollScanStatus();
        this.scanPollingTimer = setInterval(() => this.pollScanStatus(), 2000);
    },

    async pollScanStatus() {
        if (!this.activeScanId) {
            return;
        }

        const status = await this.api(`/api/scan-status/${encodeURIComponent(this.activeScanId)}`);
        if (!status || status.error) {
            return;
        }

        this.renderScanProgress(status);

        if (status.status === "completed" || status.status === "failed" || status.status === "cancelled") {
            this.stopScanPolling();
            if (status.status === "completed") {
                this.toast("Scan completed.", "success");
                if (this.currentView === "reports") {
                    this.loadReports();
                }
            } else if (status.status === "cancelled") {
                this.toast("Scan was cancelled.", "success");
            } else {
                this.toast(status.message || "Scan failed", "error");
            }
        }
    },

    renderScanProgress(status) {
        const percent = Math.max(0, Math.min(100, Number(status.progress || 0)));
        const donut = document.getElementById("scanDonut");
        const percentNode = document.getElementById("scanProgressPercent");
        const stateNode = document.getElementById("scanRunState");
        const currentToolNode = document.getElementById("scanCurrentTool");
        const toolsNode = document.getElementById("scanToolProgress");
        const elapsedNode = document.getElementById("scanElapsed");
        const etaNode = document.getElementById("scanEta");
        const subtitleNode = document.getElementById("scanProgressSubtitle");
        const fillNode = document.getElementById("scanProgressBarFill");
        const cancelBtn = document.getElementById("scanCancelBtn");
        const toolEtaRow = document.getElementById("scanToolEtaRow");
        const toolEtaNode = document.getElementById("scanToolEta");

        if (donut) {
            donut.style.setProperty("--progress", String(percent));
        }
        if (percentNode) {
            percentNode.textContent = `${percent}%`;
        }
        if (stateNode) {
            stateNode.textContent = this.humanizeKey(status.status || "running");
        }
        if (currentToolNode) {
            currentToolNode.textContent = status.current_tool || "-";
        }
        if (toolsNode) {
            const missingCount = Array.isArray(status.missing_tools) ? status.missing_tools.length : 0;
            toolsNode.textContent = `${status.completed_tools || 0} / ${status.total_tools || 0} tools${missingCount ? ` · ${missingCount} unavailable` : ""}`;
        }
        if (elapsedNode) {
            elapsedNode.textContent = status.elapsed_label || "~0s";
        }
        if (etaNode) {
            etaNode.textContent = status.status === "running" ? (status.eta_label || "-") : "~0s";
        }
        if (subtitleNode) {
            const missingNames = Array.isArray(status.missing_tools) && status.missing_tools.length
                ? ` Missing: ${status.missing_tools.slice(0, 4).join(", ")}${status.missing_tools.length > 4 ? "..." : ""}`
                : "";
            subtitleNode.textContent = `${status.message || "Scan in progress"}${missingNames}`;
        }
        if (fillNode) {
            fillNode.style.width = `${percent}%`;
        }

        // Cancel button visibility
        if (cancelBtn) {
            const isActive = status.status === "running" || status.status === "cancelling";
            cancelBtn.style.display = isActive ? "" : "none";
            cancelBtn.disabled = status.status === "cancelling";
            cancelBtn.textContent = status.status === "cancelling" ? "Cancelling…" : "";
            if (status.status !== "cancelling") {
                cancelBtn.innerHTML = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg> Cancel`;
            }
        }

        // Tool-level ETA
        if (toolEtaRow && toolEtaNode) {
            const currentTool = status.current_tool;
            const toolEsts = this.scanEstimates?.tool_estimates;
            if (status.status === "running" && currentTool && toolEsts) {
                const toolKey = Object.keys(toolEsts).find((k) => k.toLowerCase() === currentTool.toLowerCase());
                const toolEst = toolKey ? toolEsts[toolKey] : null;
                if (toolEst) {
                    toolEtaRow.style.display = "";
                    toolEtaNode.textContent = `${toolEst.label} avg`;
                } else {
                    toolEtaRow.style.display = "none";
                }
            } else {
                toolEtaRow.style.display = "none";
            }
        }

        const activity = document.getElementById("scanActivityLog");
        if (activity) {
            const events = Array.isArray(status.events) ? status.events.slice(-8).reverse() : [];
            if (!events.length) {
                activity.innerHTML = '<div class="empty-state">No activity yet.</div>';
            } else {
                activity.innerHTML = events.map((item) => {
                    const message = this.esc(item.message || "");
                    const timeLabel = new Date((item.at || 0) * 1000).toLocaleTimeString();
                    return `<div class="scan-activity-item"><span>${message}</span><time>${this.esc(timeLabel)}</time></div>`;
                }).join("");
            }
        }
    },

    async cancelScan() {
        if (!this.activeScanId) return;
        const btn = document.getElementById("scanCancelBtn");
        if (btn) { btn.disabled = true; btn.textContent = "Cancelling…"; }
        try {
            await fetch(`/api/scan/${encodeURIComponent(this.activeScanId)}/cancel`, { method: "POST" });
            this.toast("Cancel requested. Stopping the active tool now.", "success");
        } catch {
            this.toast("Failed to send cancel request.", "error");
            if (btn) { btn.disabled = false; }
        }
    },

    async startScan(target, mode, profile, statusId, buttonId) {
        const button = document.getElementById(buttonId);
        const statusNode = document.getElementById(statusId);
        const originalHtml = button.innerHTML;

        button.innerHTML = '<span class="spinner"></span> Starting...';
        button.disabled = true;
        statusNode.className = "scan-status-msg hidden";

        try {
            const response = await fetch("/api/scan", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ target, mode, profile }),
            });
            const result = await response.json();

            if (response.ok) {
                statusNode.className = "scan-status-msg success";
                const eta = result.estimated_label ? ` ETA ${result.estimated_label}` : "";
                statusNode.textContent = `OK ${result.message || "Scan started"}.${eta}`;
                if (result.scan_id) {
                    this.beginScanPolling(result.scan_id);
                }
                this.toast("Scan initiated successfully.", "success");
            } else {
                statusNode.className = "scan-status-msg error";
                statusNode.textContent = `ERR ${result.error || "Failed"}`;
                this.toast(result.error || "Scan failed", "error");
            }
        } catch {
            statusNode.className = "scan-status-msg error";
            statusNode.textContent = "ERR Server connection error";
            this.toast("Connection error", "error");
        } finally {
            button.innerHTML = originalHtml;
            button.disabled = false;
        }
    },

    async loadReports() {
        document.getElementById("refreshReports").onclick = () => this.loadReports();
        const reportsResponse = await this.api("/api/reports");
        const reports = Array.isArray(reportsResponse)
            ? reportsResponse
            : (reportsResponse?.reports || []);
        const container = document.getElementById("reportsList");
        const toolbar = document.getElementById("reportsToolbar");

        if (!Array.isArray(reports) || reports.length === 0) {
            if (toolbar) toolbar.style.display = "none";
            container.innerHTML = `
                <div class="empty-state-big">
                    <svg viewBox="0 0 24 24" width="48" height="48" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
                    <h3>No Reports Yet</h3>
                    <p>Run a scan to generate your first report.</p>
                </div>`;
            this.renderReportsSidebar({ all: 0, critical: 0, high: 0, medium: 0, low: 0, clean: 0 }, [], []);
            return;
        }

        this._allReports = reports;
        this._reportGroups = this.groupReportsByTarget(reports);
        if (toolbar) toolbar.style.display = "";

        // Wire up filter tabs
        const tabContainer = document.getElementById("reportsFilterTabs");
        if (tabContainer && !tabContainer._wired) {
            tabContainer._wired = true;
            tabContainer.addEventListener("click", (e) => {
                const btn = e.target.closest(".filter-tab");
                if (!btn) return;
                tabContainer.querySelectorAll(".filter-tab").forEach((b) => b.classList.remove("active"));
                btn.classList.add("active");
                this._reportFilter = btn.dataset.sev || "all";
                this._renderFilteredReports();
            });
        }

        const searchInput = document.getElementById("reportsSearch");
        if (searchInput && !searchInput._wired) {
            searchInput._wired = true;
            searchInput.addEventListener("input", () => {
                this._reportSearch = searchInput.value.toLowerCase();
                this._renderFilteredReports();
            });
        }

        // Update tab badges
        const groups = this._reportGroups || [];
        const counts = { all: groups.length, critical: 0, high: 0, medium: 0, low: 0, clean: 0 };
        groups.forEach((group) => {
            const s = group.latest?.severities || {};
            if ((s.critical || 0) > 0) counts.critical++;
            if ((s.high || 0) > 0) counts.high++;
            if ((s.medium || 0) > 0) counts.medium++;
            if ((s.low || 0) > 0) counts.low++;
            if ((s.critical || 0) + (s.high || 0) + (s.medium || 0) + (s.low || 0) === 0) counts.clean++;
        });
        if (tabContainer) {
            tabContainer.querySelectorAll(".filter-tab").forEach((btn) => {
                const sev = btn.dataset.sev;
                const count = counts[sev] ?? 0;
                const base = btn.textContent.replace(/ \(\d+\)$/, "");
                btn.textContent = `${base} (${count})`;
            });
        }

        this.renderReportsSidebar(counts, reports, groups);
        this._reportFilter = this._reportFilter || "all";
        this._reportSearch = this._reportSearch || "";
        this._renderFilteredReports();
    },

    groupReportsByTarget(reports) {
        const grouped = new Map();
        reports.forEach((report) => {
            const target = (report.target_url || report.folder || report.name || "Unknown target").trim();
            const key = target.toLowerCase();
            if (!grouped.has(key)) {
                grouped.set(key, {
                    key,
                    target,
                    reports: [],
                });
            }
            grouped.get(key).reports.push(report);
        });

        return Array.from(grouped.values())
            .map((group, index) => {
                group.reports.sort((left, right) => (right.modified || 0) - (left.modified || 0));
                group.latest = group.reports[0] || null;
                group.id = `report-group-${index}`;
                return group;
            })
            .sort((left, right) => ((right.latest?.modified || 0) - (left.latest?.modified || 0)));
    },

    _reportStatusSummary(severities = {}) {
        const critical = severities.critical || 0;
        const high = severities.high || 0;
        const medium = severities.medium || 0;
        const low = severities.low || 0;

        if (critical > 0) {
            return { label: critical > 1 ? `${critical} Critical` : "Critical", className: "badge-critical" };
        }
        if (high > 0) {
            return { label: high > 1 ? `${high} High` : "High", className: "badge-high" };
        }
        if (medium > 0) {
            return { label: medium > 1 ? `${medium} Medium` : "Medium", className: "badge-medium" };
        }
        if (low > 0) {
            return { label: low > 1 ? `${low} Low` : "Low", className: "badge-low" };
        }
        return { label: "Clean", className: "badge-clean" };
    },

    _renderSeverityBadges(severities = {}) {
        const totalFindings = (severities.critical || 0) + (severities.high || 0) + (severities.medium || 0) + (severities.low || 0);
        return [
            severities.critical ? `<span class="badge badge-critical">${severities.critical} Critical</span>` : "",
            severities.high ? `<span class="badge badge-high">${severities.high} High</span>` : "",
            severities.medium ? `<span class="badge badge-medium">${severities.medium} Medium</span>` : "",
            severities.low ? `<span class="badge badge-low">${severities.low} Low</span>` : "",
            totalFindings === 0 ? '<span class="badge badge-clean">Clean</span>' : "",
        ].join("");
    },

    _formatReportDate(report) {
        const formatMyt = (value) => {
            const parsed = new Date(value);
            if (Number.isNaN(parsed.getTime())) {
                return null;
            }
            const parts = new Intl.DateTimeFormat("sv-SE", {
                timeZone: "Asia/Kuala_Lumpur",
                year: "numeric",
                month: "2-digit",
                day: "2-digit",
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
                hour12: false,
            }).formatToParts(parsed);
            const map = Object.fromEntries(parts.map((part) => [part.type, part.value]));
            return `${map.year}-${map.month}-${map.day} ${map.hour}:${map.minute}:${map.second} MYT`;
        };

        if (report.scan_started_at) {
            const formatted = formatMyt(report.scan_started_at);
            if (formatted) {
                return formatted;
            }
        }
        return formatMyt((report.modified || 0) * 1000) || new Date((report.modified || 0) * 1000).toLocaleString();
    },

    toggleReportHistory(groupId) {
        const panel = document.getElementById(groupId);
        if (!panel) return;
        const expanded = panel.classList.toggle("open");
        const toggle = document.querySelector(`[data-report-toggle="${groupId}"]`);
        if (toggle) {
            toggle.setAttribute("aria-expanded", expanded ? "true" : "false");
        }
    },

    async startReportScan(target, profile, button) {
        if (!target) {
            this.toast("Target URL is missing for this report.", "error");
            return;
        }
        const originalHtml = button.innerHTML;
        button.disabled = true;
        button.innerHTML = '<span class="spinner"></span> Starting...';

        try {
            const response = await fetch("/api/scan", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ target, mode: "full", profile: profile || "auto" }),
            });
            const result = await response.json();
            if (!response.ok) {
                this.toast(result.error || "Failed to start scan", "error");
                return;
            }
            if (result.scan_id) {
                this.beginScanPolling(result.scan_id);
            }
            this.toast(result.message || "Scan started", "success");
        } catch {
            this.toast("Connection error", "error");
        } finally {
            button.disabled = false;
            button.innerHTML = originalHtml;
        }
    },

    _renderFilteredReports() {
        const groups = this._reportGroups || [];
        const filter = this._reportFilter || "all";
        const search = this._reportSearch || "";
        const container = document.getElementById("reportsList");
        if (!container) return;

        const visible = groups.filter((group) => {
            const report = group.latest || {};
            const s = report.severities || {};
            const total = (s.critical || 0) + (s.high || 0) + (s.medium || 0) + (s.low || 0);
            let pass = true;
            if (filter === "critical") pass = (s.critical || 0) > 0;
            else if (filter === "high") pass = (s.high || 0) > 0;
            else if (filter === "medium") pass = (s.medium || 0) > 0;
            else if (filter === "low") pass = (s.low || 0) > 0;
            else if (filter === "clean") pass = total === 0;
            if (pass && search) {
                const haystack = [group.target, ...group.reports.map((item) => `${item.folder || ""} ${item.name || ""}`)].join(" ").toLowerCase();
                pass = haystack.includes(search);
            }
            return pass;
        });

        if (visible.length === 0) {
            container.innerHTML = `<div class="empty-state-big"><p>No reports match the current filter.</p></div>`;
            return;
        }

        container.innerHTML = `
            <div class="reports-summary-shell">
                <div class="reports-summary-head">
                    <div>
                        <h2>Website Report Summary</h2>
                        <p>Filters apply to unique website views. Expand a row to inspect historical scan runs.</p>
                    </div>
                    <div class="reports-summary-meta">Displaying ${visible.length} unique websites / ${(this._allReports || []).length} total reports</div>
                </div>
                <div class="report-groups-table">
                    <div class="report-groups-header">
                        <span>Website</span>
                        <span>Primary Status</span>
                        <span>Last Scan</span>
                        <span>Quick Actions</span>
                    </div>
                    ${visible.map((group) => {
                        const latest = group.latest || {};
                        const status = this._reportStatusSummary(latest.severities || {});
                        const historyId = `${group.id}-history`;
                        const latestDate = this._formatReportDate(latest);
                        const historyRows = group.reports.map((report) => {
                            const dlItems = [
                                { path: report.path, label: "HTML Report" },
                                ...(report.md_path ? [{ path: report.md_path, label: "Markdown" }] : []),
                                ...(report.json_path ? [{ path: report.json_path, label: "JSON Data" }] : []),
                                ...(report.csv_path ? [{ path: report.csv_path, label: "CSV Data" }] : []),
                                ...(report.sarif_path ? [{ path: report.sarif_path, label: "SARIF" }] : []),
                            ];
                            const dlMenu = dlItems.map((d) => `<a href="/api/reports/${encodeURIComponent(d.path)}?dl=1" class="dl-menu-item" download>${this.esc(d.label)}</a>`).join("");
                            const folder = report.folder || "";
                            const profile = report.profile ? this.esc(report.profile) : "Auto";
                            return `
                                <div class="report-history-row">
                                    <div class="report-history-cell">${this.esc(this._formatReportDate(report))}</div>
                                    <div class="report-history-cell">${profile}</div>
                                    <div class="report-history-cell report-history-badges">${this._renderSeverityBadges(report.severities || {})}</div>
                                    <div class="report-history-cell report-history-actions">
                                        <a href="/api/reports/${encodeURIComponent(report.path)}" target="_blank" class="btn-ghost btn-sm">Open</a>
                                        <div class="dl-dropdown">
                                            <button class="btn-ghost btn-sm dl-toggle" onclick="App.toggleDlMenu(this)">Download &#9662;</button>
                                            <div class="dl-menu">${dlMenu}</div>
                                        </div>
                                        <button class="btn-ghost btn-sm btn-danger" onclick="App.deleteReport('${this.esc(folder)}', this)" title="Delete report">Delete</button>
                                    </div>
                                </div>`;
                        }).join("");

                        return `
                            <div class="report-group-card">
                                <div class="report-group-row">
                                    <button class="report-group-toggle" data-report-toggle="${historyId}" aria-expanded="false" onclick="App.toggleReportHistory('${historyId}')">
                                        <span class="report-group-target">${this.esc(group.target)}</span>
                                        <span class="report-group-count">${group.reports.length} report${group.reports.length === 1 ? "" : "s"}</span>
                                    </button>
                                    <div class="report-group-status"><span class="badge ${status.className}">${this.esc(status.label)}</span></div>
                                    <div class="report-group-lastscan">${this.esc(latestDate)}</div>
                                    <div class="report-group-actions">
                                        <button class="btn-ghost btn-sm" onclick="App.toggleReportHistory('${historyId}')">View History</button>
                                        <button class="btn-ghost btn-sm" data-target="${this.esc(group.target)}" data-profile="${this.esc(latest.profile || "auto")}" onclick="App.startReportScan(this.dataset.target, this.dataset.profile, this)">Scan Now</button>
                                    </div>
                                </div>
                                <div class="report-history-panel" id="${historyId}">
                                    <div class="report-history-header">
                                        <span>Scan Date</span>
                                        <span>Profile</span>
                                        <span>Severity Profile</span>
                                        <span>Actions</span>
                                    </div>
                                    ${historyRows}
                                </div>
                            </div>`;
                        }).join("")}
                </div>
            </div>`;
    },

    renderReportsSidebar(counts, reports, groups) {
        const coverage = document.getElementById("reportsCoveragePanel");
        const exportsFeed = document.getElementById("reportsExportFeed");
        if (!coverage || !exportsFeed) return;

        const groupCount = groups.length || 0;
        const distribution = [
            { label: "Critical", value: counts.critical || 0, className: "critical" },
            { label: "High", value: counts.high || 0, className: "high" },
            { label: "Medium", value: counts.medium || 0, className: "medium" },
            { label: "Low", value: counts.low || 0, className: "low" },
            { label: "Clean", value: counts.clean || 0, className: "clean" },
        ];
        const maxValue = Math.max(...distribution.map((item) => item.value), 1);

        coverage.innerHTML = `
            <div class="metric-list">
                <div class="metric-item">
                    <span class="metric-label">Unique Targets</span>
                    <strong>${groupCount}</strong>
                </div>
                <div class="metric-item">
                    <span class="metric-label">Total Reports</span>
                    <strong>${reports.length}</strong>
                </div>
                <div class="metric-item">
                    <span class="metric-label">Clean Libraries</span>
                    <strong>${counts.clean || 0}</strong>
                </div>
            </div>
            <div class="surface-coverage-list">
                ${distribution.map((item) => `
                    <div class="surface-row">
                        <div class="surface-row-head">
                            <span class="surface-label surface-${item.className}">${item.label}</span>
                            <span class="surface-value">${item.value}</span>
                        </div>
                        <div class="surface-bar">
                            <span style="width:${groupCount ? (item.value / maxValue) * 100 : 0}%"></span>
                        </div>
                    </div>
                `).join("")}
            </div>
        `;

        const recent = [...reports]
            .sort((left, right) => (right.modified || 0) - (left.modified || 0))
            .slice(0, 5);

        exportsFeed.innerHTML = recent.length
            ? `<div class="report-feed">
                ${recent.map((report) => `
                    <div class="report-feed-item">
                        <div class="report-feed-top">
                            <div>
                                <div class="report-feed-title">${this.esc(report.name || report.folder || "Report Export")}</div>
                                <div class="report-feed-meta">${this.esc(this._formatReportDate(report))}</div>
                            </div>
                            <span class="badge badge-neutral">${this.esc(((report.path || "").split(".").pop() || "html").toUpperCase())}</span>
                        </div>
                        <div class="report-findings-mix">${this._renderSeverityBadges(report.severities || {})}</div>
                    </div>
                `).join("")}
            </div>`
            : '<div class="empty-state">No report exports available yet.</div>';
    },

    toggleDlMenu(btn) {
        const menu = btn.closest(".dl-dropdown").querySelector(".dl-menu");
        const isOpen = menu.classList.contains("open");
        // Close all open menus first
        document.querySelectorAll(".dl-menu.open").forEach((m) => m.classList.remove("open"));
        if (!isOpen) menu.classList.add("open");
    },

    async deleteReport(folder, btn) {
        if (!confirm(`Delete this report?\n\n"${folder}"\n\nThis cannot be undone.`)) return;
        btn.disabled = true;
        const res = await this.api("/api/reports/delete", {
            method: "DELETE",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ folder }),
        });
        if (res?.error) {
            this.toast(res.error, "error");
            btn.disabled = false;
        } else {
            this.toast("Report deleted.", "success");
            await this.loadReports();
        }
    },

    async startRenameReport(folder, currentName) {
        const nameEl = document.getElementById(`rn-${folder}`);
        if (!nameEl || nameEl.querySelector("input")) return;

        const input = document.createElement("input");
        input.type = "text";
        input.value = currentName;
        input.className = "rename-input";
        input.style.cssText = "font-size:inherit;font-weight:600;background:rgba(255,255,255,0.1);border:1px solid rgba(255,255,255,0.3);border-radius:4px;padding:2px 6px;color:inherit;min-width:180px;";

        const confirm = document.createElement("button");
        confirm.className = "btn-icon-xs";
        confirm.title = "Confirm";
        confirm.innerHTML = `<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="#22c55e" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>`;

        const cancel = document.createElement("button");
        cancel.className = "btn-icon-xs";
        cancel.title = "Cancel";
        cancel.innerHTML = `<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="#ef4444" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>`;

        const origContent = nameEl.innerHTML;
        nameEl.innerHTML = "";
        nameEl.appendChild(input);
        nameEl.appendChild(confirm);
        nameEl.appendChild(cancel);
        input.focus();
        input.select();

        const restore = () => { nameEl.innerHTML = origContent; };
        cancel.onclick = restore;

        const doRename = async () => {
            const newName = input.value.trim();
            if (!newName || newName === currentName) { restore(); return; }
            const res = await this.api("/api/reports/rename", {
                method: "PATCH",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ folder, name: newName }),
            });
            if (res?.error) {
                this.toast(res.error, "error");
                restore();
            } else {
                this.toast("Report renamed.", "success");
                await this.loadReports();
            }
        };

        confirm.onclick = doRename;
        input.addEventListener("keydown", (e) => {
            if (e.key === "Enter") doRename();
            if (e.key === "Escape") restore();
        });
    },

    async loadAssessmentsView() {
        document.getElementById("refreshAssessments").onclick = () => this.loadAssessmentsView();

        const [targets, catalog] = await Promise.all([
            this.api("/api/targets"),
            this.api("/api/assessments/catalog"),
        ]);

        this.assessmentCatalog = Array.isArray(catalog) ? catalog : [];
        const targetSelect = document.getElementById("assessmentTargetSelect");
        const targetInput = document.getElementById("assessmentTargetInput");
        const saveButton = document.getElementById("saveAssessmentBtn");

        targetSelect.innerHTML = '<option value="">Pick saved target</option>';
        if (Array.isArray(targets)) {
            targets.forEach((target) => {
                const option = document.createElement("option");
                option.value = target.url;
                option.textContent = `${target.label} (${target.profile || "auto"})`;
                targetSelect.appendChild(option);
            });
        }

        targetSelect.onchange = () => {
            if (targetSelect.value) {
                targetInput.value = targetSelect.value;
            }
        };

        document.getElementById("assessmentTargetForm").onsubmit = async (event) => {
            event.preventDefault();
            const target = targetInput.value.trim();
            if (!target) {
                this.toast("Enter a target URL first.", "error");
                return;
            }
            this.assessmentTarget = target;
            await this.fetchAssessmentWorkbook(target);
        };

        saveButton.onclick = async () => {
            await this.saveAssessmentWorkbook();
        };

        const preferredTarget = this.assessmentTarget || targetInput.value.trim() || (Array.isArray(targets) && targets[0] ? targets[0].url : "");
        if (preferredTarget) {
            this.assessmentTarget = preferredTarget;
            targetInput.value = preferredTarget;
            if (Array.isArray(targets) && targets.some((target) => target.url === preferredTarget)) {
                targetSelect.value = preferredTarget;
            }
            await this.fetchAssessmentWorkbook(preferredTarget);
        } else {
            this.assessmentWorkbook = null;
            this.renderAssessmentWorkspace();
        }
    },

    async fetchAssessmentWorkbook(target) {
        const data = await this.api(`/api/assessments?target=${encodeURIComponent(target)}`);
        if (!data?.workbook) {
            this.toast("Failed to load playbook workspace.", "error");
            return;
        }

        this.assessmentWorkbook = data.workbook;
        this.assessmentTarget = target;
        this.renderAssessmentWorkspace(data.summary || null);
    },

    renderAssessmentWorkspace(summaryOverride = null) {
        const container = document.getElementById("assessmentWorkspace");
        const workbook = this.assessmentWorkbook;

        if (!workbook) {
            container.innerHTML = `
                <div class="empty-state-big">
                    <svg viewBox="0 0 24 24" width="48" height="48" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 3l7 4v5c0 5-3.5 8-7 9-3.5-1-7-4-7-9V7l7-4z"></path><path d="M9 12l2 2 4-4"></path></svg>
                    <h3>No Playbook Loaded</h3>
                    <p>Select a saved target or enter a URL to start guided analyst testing.</p>
                </div>`;
            return;
        }

        const summary = summaryOverride || this.buildAssessmentSummary(workbook);
        const caseCards = (workbook.cases || []).map((item) => this.renderAssessmentCase(item)).join("");
        const notes = (workbook.operator_notes || []).map((note) => this.renderOperatorNote(note)).join("");
        const runs = (workbook.verification_runs || []).map((run) => this.renderVerificationRun(run)).join("");
        const coverageCards = Object.entries(summary.category_coverage || {}).map(([category, metrics]) => `
            <div class="coverage-card">
                <div class="coverage-title">${this.esc(category)}</div>
                <div class="coverage-metric">${metrics.confirmed || 0}/${metrics.total || 0}</div>
                <div class="coverage-caption">confirmed or fixed</div>
            </div>
        `).join("");

        container.innerHTML = `
            <div class="assessment-summary-grid">
                ${this.renderMetricCard("Target", this.assessmentTarget, "Current playbook")}
                ${this.renderMetricCard("Cases In Motion", String(this.sumCounts(summary.case_status, ["in_progress", "needs_evidence", "confirmed"])), "Manual scenarios under review")}
                ${this.renderMetricCard("Verified", String(this.sumCounts(summary.verification_status, ["confirmed", "reproduced", "fixed"])), "Cases reproduced or fixed")}
                ${this.renderMetricCard("Notes + Runs", `${summary.note_count || 0} / ${summary.verification_run_count || 0}`, "Operator notes and verification logs")}
            </div>

            <div class="assessment-layout">
                <div class="card assessment-primary-card">
                    <div class="card-header">
                        <h3>Assessment Narrative</h3>
                        <p class="subtitle">Record context, likely attack paths, and your retest plan</p>
                    </div>
                    <div class="assessment-field-grid">
                        <div class="form-group">
                            <label for="assessmentSummaryText">Executive Summary</label>
                            <textarea id="assessmentSummaryText" rows="4">${this.esc(workbook.summary || "")}</textarea>
                        </div>
                        <div class="form-group">
                            <label for="assessmentAuthContext">Authentication Context</label>
                            <textarea id="assessmentAuthContext" rows="4">${this.esc(workbook.auth_context_notes || "")}</textarea>
                        </div>
                        <div class="form-group">
                            <label for="assessmentAttackPaths">Attack Path Hypotheses</label>
                            <textarea id="assessmentAttackPaths" rows="4">${this.esc(workbook.attack_path_hypotheses || "")}</textarea>
                        </div>
                        <div class="form-group">
                            <label for="assessmentVerificationStrategy">Verification Strategy</label>
                            <textarea id="assessmentVerificationStrategy" rows="4">${this.esc(workbook.verification_strategy || "")}</textarea>
                        </div>
                    </div>
                </div>

                <div class="card assessment-side-card">
                    <div class="card-header">
                        <h3>Coverage Analytics</h3>
                        <p class="subtitle">Quick coverage snapshot by category and verification status</p>
                    </div>
                    <div class="coverage-grid">
                        ${coverageCards || '<div class="empty-state">No coverage data yet.</div>'}
                    </div>
                    <div class="assessment-status-list">
                        <div class="assessment-status-block">
                            <span class="status-title">Case Status</span>
                            ${this.renderKeyValueList(summary.case_status)}
                        </div>
                        <div class="assessment-status-block">
                            <span class="status-title">Verification Status</span>
                            ${this.renderKeyValueList(summary.verification_status)}
                        </div>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h3>Guided Manual Test Cases</h3>
                    <p class="subtitle">Expand only the test case you are working on to keep the page focused</p>
                </div>
                <div class="assessment-case-grid">
                    ${caseCards}
                </div>
            </div>

            <div class="assessment-layout">
                <div class="card assessment-primary-card">
                    <div class="card-header assessment-header-inline">
                        <div>
                            <h3>Operator Notes</h3>
                            <p class="subtitle">Capture observations, assumptions, dead ends, and analyst judgement</p>
                        </div>
                        <button type="button" class="btn-ghost" id="addAssessmentNoteBtn">
                            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14"></path><path d="M5 12h14"></path></svg>
                            Add Note
                        </button>
                    </div>
                    <div class="operator-note-list">
                        ${notes}
                    </div>
                </div>

                <div class="card assessment-side-card">
                    <div class="card-header assessment-header-inline">
                        <div>
                            <h3>Verification Runs</h3>
                            <p class="subtitle">Track retests, reproductions, and fix validation separately from scan evidence</p>
                        </div>
                        <button type="button" class="btn-ghost" id="addVerificationRunBtn">
                            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14"></path><path d="M5 12h14"></path></svg>
                            Add Run
                        </button>
                    </div>
                    <div class="verification-run-list">
                        ${runs || '<div class="empty-state">No verification runs logged yet.</div>'}
                    </div>
                </div>
            </div>
        `;

        const addNoteButton = document.getElementById("addAssessmentNoteBtn");
        const addRunButton = document.getElementById("addVerificationRunBtn");
        if (addNoteButton) {
            addNoteButton.onclick = () => this.addAssessmentNote();
        }
        if (addRunButton) {
            addRunButton.onclick = () => this.addVerificationRun();
        }
    },

    renderMetricCard(title, value, caption) {
        return `
            <div class="metric-card">
                <span class="metric-title">${this.esc(title)}</span>
                <strong class="metric-value">${this.esc(value)}</strong>
                <span class="metric-caption">${this.esc(caption)}</span>
            </div>
        `;
    },

    renderKeyValueList(obj) {
        const entries = Object.entries(obj || {});
        if (!entries.length) {
            return '<div class="empty-state">No data</div>';
        }

        return entries.map(([key, value]) => `
            <div class="status-row">
                <span>${this.esc(this.humanizeKey(key))}</span>
                <strong>${this.esc(String(value))}</strong>
            </div>
        `).join("");
    },

    renderAssessmentCase(item) {
        const guidedSteps = (item.guided_steps || []).map((step) => `<li>${this.esc(step)}</li>`).join("");
        const evidenceExpectations = (item.evidence_expectations || []).map((expectation) => `<li>${this.esc(expectation)}</li>`).join("");
        const isExpanded = ["in_progress", "needs_evidence", "confirmed"].includes(item.status || "");

        return `
            <details class="assessment-case" data-case-id="${this.esc(item.id)}" ${isExpanded ? "open" : ""}>
                <summary class="assessment-case-summary">
                    <div class="assessment-case-top">
                        <div>
                            <div class="assessment-case-meta">
                                <span class="badge badge-priority">${this.esc(item.priority || "medium")}</span>
                                <span class="badge badge-category">${this.esc(item.category || "General")}</span>
                            </div>
                            <h4>${this.esc(item.title || item.id)}</h4>
                            <p class="assessment-case-objective">${this.esc(item.objective || "")}</p>
                        </div>
                        <div class="assessment-case-selects">
                            <select class="case-status">
                                ${this.renderSelectOptions(["not_started", "in_progress", "needs_evidence", "confirmed", "fixed", "not_applicable"], item.status || "not_started")}
                            </select>
                            <select class="case-verification-status">
                                ${this.renderSelectOptions(["not_verified", "pending", "reproduced", "confirmed", "fixed", "false_positive"], item.verification_status || "not_verified")}
                            </select>
                        </div>
                    </div>
                </summary>
                <div class="assessment-case-body">
                    <p class="assessment-case-automation"><strong>Automation support:</strong> ${this.esc(item.automation_support || "")}</p>
                    <div class="assessment-detail-grid">
                        <div>
                            <span class="detail-title">Guided Steps</span>
                            <ul class="detail-list">${guidedSteps}</ul>
                        </div>
                        <div>
                            <span class="detail-title">Expected Evidence</span>
                            <ul class="detail-list">${evidenceExpectations}</ul>
                        </div>
                    </div>
                    <div class="assessment-field-grid compact-grid">
                        <div class="form-group">
                            <label>Owner</label>
                            <input type="text" class="case-owner" value="${this.esc(item.owner || "")}" placeholder="Analyst or tester name">
                        </div>
                        <div class="form-group">
                            <label>Last Tested At</label>
                            <input type="text" class="case-last-tested" value="${this.esc(item.last_tested_at || "")}" placeholder="2026-04-28T10:30:00Z">
                        </div>
                        <div class="form-group">
                            <label>Related Finding IDs</label>
                            <input type="text" class="case-related-findings" value="${this.esc((item.related_finding_ids || []).join(", "))}" placeholder="F-001, F-002">
                        </div>
                        <div class="form-group">
                            <label>Attack Path Link</label>
                            <input type="text" class="case-attack-path-link" value="${this.esc(item.attack_path_link || "")}" placeholder="Attack path name or reference">
                        </div>
                        <div class="form-group">
                            <label>Case Notes</label>
                            <textarea class="case-notes" rows="4">${this.esc(item.notes || "")}</textarea>
                        </div>
                        <div class="form-group">
                            <label>Evidence</label>
                            <textarea class="case-evidence" rows="4">${this.esc(item.evidence || "")}</textarea>
                        </div>
                        <div class="form-group">
                            <label>Retest Notes</label>
                            <textarea class="case-retest-notes" rows="3">${this.esc(item.retest_notes || "")}</textarea>
                        </div>
                        <div class="form-group">
                            <label>Remediation Advice</label>
                            <textarea class="case-remediation-advice" rows="3">${this.esc(item.remediation_advice || "")}</textarea>
                        </div>
                    </div>
                </div>
            </details>
        `;
    },

    renderOperatorNote(note) {
        return `
            <div class="operator-note" data-note-id="${this.esc(note.id)}" data-created-at="${this.esc(note.created_at || "")}">
                <div class="assessment-header-inline">
                    <input type="text" class="note-title" value="${this.esc(note.title || "")}" placeholder="Note title">
                    <select class="note-type">
                        ${this.renderSelectOptions(["context", "analysis", "risk", "follow_up"], note.type || "analysis")}
                    </select>
                </div>
                <div class="assessment-field-grid compact-grid">
                    <div class="form-group">
                        <label>Author</label>
                        <input type="text" class="note-author" value="${this.esc(note.author || "")}" placeholder="Analyst name">
                    </div>
                    <div class="form-group">
                        <label>Updated At</label>
                        <input type="text" class="note-updated-at" value="${this.esc(note.updated_at || "")}" placeholder="Auto-updated on save">
                    </div>
                    <div class="form-group note-body-group">
                        <label>Body</label>
                        <textarea class="note-body" rows="4">${this.esc(note.body || "")}</textarea>
                    </div>
                </div>
            </div>
        `;
    },

    renderVerificationRun(run) {
        return `
            <div class="verification-run" data-run-id="${this.esc(run.id)}" data-created-at="${this.esc(run.created_at || "")}">
                <div class="form-group">
                    <label>Run Title</label>
                    <input type="text" class="run-title" value="${this.esc(run.title || "")}" placeholder="Retest after auth fix">
                </div>
                <div class="assessment-field-grid compact-grid">
                    <div class="form-group">
                        <label>Scope</label>
                        <input type="text" class="run-scope" value="${this.esc(run.scope || "")}" placeholder="Admin API and export endpoints">
                    </div>
                    <div class="form-group">
                        <label>Outcome</label>
                        <select class="run-outcome">
                            ${this.renderSelectOptions(["pending", "confirmed", "reproduced", "fixed", "blocked"], run.outcome || "pending")}
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Related Case IDs</label>
                        <input type="text" class="run-related-cases" value="${this.esc((run.related_case_ids || []).join(", "))}" placeholder="real-access-control-testing">
                    </div>
                    <div class="form-group">
                        <label>Related Finding IDs</label>
                        <input type="text" class="run-related-findings" value="${this.esc((run.related_finding_ids || []).join(", "))}" placeholder="F-001, F-004">
                    </div>
                    <div class="form-group verification-notes-group">
                        <label>Run Notes</label>
                        <textarea class="run-notes" rows="4">${this.esc(run.notes || "")}</textarea>
                    </div>
                </div>
            </div>
        `;
    },

    renderSelectOptions(values, selectedValue) {
        return values.map((value) => {
            const selected = value === selectedValue ? "selected" : "";
            return `<option value="${this.esc(value)}" ${selected}>${this.esc(this.humanizeKey(value))}</option>`;
        }).join("");
    },

    addAssessmentNote() {
        if (!this.assessmentWorkbook) {
            this.toast("Load a workbook first.", "error");
            return;
        }

        if (document.getElementById("assessmentSummaryText")) {
            this.assessmentWorkbook = this.collectAssessmentWorkbook();
        }
        const timestamp = new Date().toISOString();
        this.assessmentWorkbook.operator_notes = this.assessmentWorkbook.operator_notes || [];
        this.assessmentWorkbook.operator_notes.push({
            id: `note-${Date.now()}`,
            created_at: timestamp,
            updated_at: timestamp,
            title: "",
            body: "",
            type: "analysis",
            author: "",
        });
        this.renderAssessmentWorkspace();
    },

    addVerificationRun() {
        if (!this.assessmentWorkbook) {
            this.toast("Load a workbook first.", "error");
            return;
        }

        if (document.getElementById("assessmentSummaryText")) {
            this.assessmentWorkbook = this.collectAssessmentWorkbook();
        }
        this.assessmentWorkbook.verification_runs = this.assessmentWorkbook.verification_runs || [];
        this.assessmentWorkbook.verification_runs.push({
            id: `verify-${Date.now()}`,
            created_at: new Date().toISOString(),
            title: "",
            scope: "",
            outcome: "pending",
            notes: "",
            related_case_ids: [],
            related_finding_ids: [],
        });
        this.renderAssessmentWorkspace();
    },

    async saveAssessmentWorkbook() {
        if (!this.assessmentWorkbook || !this.assessmentTarget) {
            this.toast("Load a workbook before saving.", "error");
            return;
        }

        const workbook = this.collectAssessmentWorkbook();
        try {
            const response = await fetch(`/api/assessments?target=${encodeURIComponent(this.assessmentTarget)}`, {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(workbook),
            });
            const result = await response.json();
            if (!response.ok || !result.workbook) {
                this.toast(result.error || "Failed to save workbook", "error");
                return;
            }

            this.assessmentWorkbook = result.workbook;
            this.renderAssessmentWorkspace(result.summary || null);
            this.toast("Assessment workbook saved.", "success");
        } catch {
            this.toast("Connection error", "error");
        }
    },

    collectAssessmentWorkbook() {
        const currentCases = new Map((this.assessmentWorkbook.cases || []).map((item) => [item.id, item]));

        const cases = Array.from(document.querySelectorAll(".assessment-case")).map((node) => {
            const id = node.dataset.caseId;
            const current = currentCases.get(id) || {};
            return {
                ...current,
                status: node.querySelector(".case-status")?.value || current.status || "not_started",
                verification_status: node.querySelector(".case-verification-status")?.value || current.verification_status || "not_verified",
                owner: node.querySelector(".case-owner")?.value.trim() || "",
                notes: node.querySelector(".case-notes")?.value.trim() || "",
                evidence: node.querySelector(".case-evidence")?.value.trim() || "",
                attack_path_link: node.querySelector(".case-attack-path-link")?.value.trim() || "",
                related_finding_ids: this.csvValues(node.querySelector(".case-related-findings")?.value || ""),
                last_tested_at: node.querySelector(".case-last-tested")?.value.trim() || "",
                retest_notes: node.querySelector(".case-retest-notes")?.value.trim() || "",
                remediation_advice: node.querySelector(".case-remediation-advice")?.value.trim() || "",
            };
        });

        const operatorNotes = Array.from(document.querySelectorAll(".operator-note")).map((node) => ({
            id: node.dataset.noteId || `note-${Date.now()}`,
            created_at: node.dataset.createdAt || new Date().toISOString(),
            updated_at: node.querySelector(".note-updated-at")?.value.trim() || new Date().toISOString(),
            title: node.querySelector(".note-title")?.value.trim() || "",
            body: node.querySelector(".note-body")?.value.trim() || "",
            type: node.querySelector(".note-type")?.value || "analysis",
            author: node.querySelector(".note-author")?.value.trim() || "",
        }));

        const verificationRuns = Array.from(document.querySelectorAll(".verification-run")).map((node) => ({
            id: node.dataset.runId || `verify-${Date.now()}`,
            created_at: node.dataset.createdAt || new Date().toISOString(),
            title: node.querySelector(".run-title")?.value.trim() || "",
            scope: node.querySelector(".run-scope")?.value.trim() || "",
            outcome: node.querySelector(".run-outcome")?.value || "pending",
            notes: node.querySelector(".run-notes")?.value.trim() || "",
            related_case_ids: this.csvValues(node.querySelector(".run-related-cases")?.value || ""),
            related_finding_ids: this.csvValues(node.querySelector(".run-related-findings")?.value || ""),
        }));

        return {
            ...this.assessmentWorkbook,
            target_url: this.assessmentTarget,
            summary: document.getElementById("assessmentSummaryText")?.value.trim() || "",
            auth_context_notes: document.getElementById("assessmentAuthContext")?.value.trim() || "",
            attack_path_hypotheses: document.getElementById("assessmentAttackPaths")?.value.trim() || "",
            verification_strategy: document.getElementById("assessmentVerificationStrategy")?.value.trim() || "",
            cases,
            operator_notes: operatorNotes,
            verification_runs: verificationRuns,
        };
    },

    buildAssessmentSummary(workbook) {
        const summary = {
            note_count: (workbook.operator_notes || []).length,
            verification_run_count: (workbook.verification_runs || []).length,
            case_status: {},
            verification_status: {},
            category_coverage: {},
        };

        (workbook.cases || []).forEach((item) => {
            const status = item.status || "not_started";
            const verification = item.verification_status || "not_verified";
            const category = item.category || "General";

            summary.case_status[status] = (summary.case_status[status] || 0) + 1;
            summary.verification_status[verification] = (summary.verification_status[verification] || 0) + 1;

            const coverage = summary.category_coverage[category] || { total: 0, confirmed: 0 };
            coverage.total += 1;
            if (["confirmed", "reproduced", "fixed"].includes(verification)) {
                coverage.confirmed += 1;
            }
            summary.category_coverage[category] = coverage;
        });

        return summary;
    },

    sumCounts(obj, keys) {
        return keys.reduce((sum, key) => sum + (obj?.[key] || 0), 0);
    },

    csvValues(value) {
        return value.split(",").map((item) => item.trim()).filter(Boolean);
    },

    humanizeKey(value) {
        return String(value || "")
            .replace(/_/g, " ")
            .replace(/\b\w/g, (char) => char.toUpperCase());
    },

    async loadTargets() {
        const targets = await this.api("/api/targets");
        const tbody = document.getElementById("targetsBody");

        if (!Array.isArray(targets) || targets.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No targets added yet. Use the form above to add one.</td></tr>';
        } else {
            tbody.innerHTML = targets.map((target, index) => `
                <tr>
                    <td>${index + 1}</td>
                    <td><strong>${this.esc(target.label)}</strong></td>
                    <td><a href="${this.esc(target.url)}" target="_blank" class="link-accent">${this.esc(target.url)}</a></td>
                    <td><span class="badge badge-neutral">${this.esc(target.profile || "auto")}</span></td>
                    <td>${this.esc(target.last_scanned || "Never")}</td>
                    <td>
                        <button class="btn-ghost btn-sm btn-danger" onclick="App.deleteTarget(${index})">
                            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                            Delete
                        </button>
                    </td>
                </tr>
            `).join("");
        }

        this.renderTargetOverview(Array.isArray(targets) ? targets : []);

        document.getElementById("addTargetForm").onsubmit = async (event) => {
            event.preventDefault();
            const url = document.getElementById("newTargetUrl").value.trim();
            const label = document.getElementById("newTargetLabel").value.trim();
            const profile = document.getElementById("newTargetProfile").value;

            if (!url || !label) {
                return;
            }

            try {
                const response = await fetch("/api/targets", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ url, label, profile }),
                });

                if (response.ok) {
                    this.toast("Target added.", "success");
                    document.getElementById("newTargetUrl").value = "";
                    document.getElementById("newTargetLabel").value = "";
                    this.loadTargets();
                } else {
                    const error = await response.json();
                    this.toast(error.error || "Failed to add target", "error");
                }
            } catch {
                this.toast("Connection error", "error");
            }
        };
    },

    renderTargetOverview(targets) {
        const total = targets.length;
        const webProfiles = new Set(["webapp", "wordpress", "joomla", "drupal"]);
        const profiles = new Map();
        let webCount = 0;
        let recentCount = 0;

        targets.forEach((target) => {
            const profile = String(target.profile || "auto").toLowerCase();
            profiles.set(profile, (profiles.get(profile) || 0) + 1);
            if (webProfiles.has(profile) || profile === "auto") webCount += 1;
            if (target.last_scanned && String(target.last_scanned).toLowerCase() !== "never") recentCount += 1;
        });

        const profileEntries = [...profiles.entries()].sort((left, right) => right[1] - left[1]);
        const maxCount = Math.max(...profileEntries.map((entry) => entry[1]), 1);

        const setText = (id, value) => {
            const node = document.getElementById(id);
            if (node) node.textContent = value;
        };

        setText("targetsTotalCount", String(total));
        setText("targetsWebCount", String(webCount));
        setText("targetsRecentCount", String(recentCount));
        setText("targetsProfilesCount", String(profileEntries.length));

        const profileMix = document.getElementById("targetsProfileMix");
        if (profileMix) {
            profileMix.innerHTML = profileEntries.length
                ? `<div class="surface-coverage-list">
                    ${profileEntries.map(([profile, count]) => `
                        <div class="surface-row">
                            <div class="surface-row-head">
                                <span class="surface-label">${this.esc(profile || "auto")}</span>
                                <span class="surface-value">${count}</span>
                            </div>
                            <div class="surface-bar">
                                <span style="width:${(count / maxCount) * 100}%"></span>
                            </div>
                        </div>
                    `).join("")}
                </div>`
                : '<div class="empty-state">No target profiles available yet.</div>';
        }

        const operationalNotes = document.getElementById("targetsOperationalNotes");
        if (operationalNotes) {
            const unscanned = total - recentCount;
            operationalNotes.innerHTML = `
                <div class="metric-list">
                    <div class="metric-item">
                        <span class="metric-label">Ready for Scan Center</span>
                        <strong>${total}</strong>
                    </div>
                    <div class="metric-item">
                        <span class="metric-label">Pending First Scan</span>
                        <strong>${unscanned}</strong>
                    </div>
                    <div class="metric-item">
                        <span class="metric-label">Auto or Web-Oriented</span>
                        <strong>${webCount}</strong>
                    </div>
                </div>
            `;
        }
    },

    async deleteTarget(index) {
        if (!confirm("Remove this target?")) {
            return;
        }

        try {
            const response = await fetch(`/api/targets/${index}`, { method: "DELETE" });
            if (response.ok) {
                this.toast("Target removed", "success");
                this.loadTargets();
            } else {
                this.toast("Failed to remove target", "error");
            }
        } catch {
            this.toast("Connection error", "error");
        }
    },

    async loadSettings() {
        await Promise.all([
            this.loadConfigTab(),
            this.loadTokensTab(),
            this.setupPerformanceTab(),
            this.loadModulesTab(),
            this.loadMonitoringSettingsTab(),
        ]);
    },

    async loadConfigTab() {
        const config = await this.api("/api/config");
        const container = document.getElementById("configFields");
        this.syncSettingsSummary(config || {});

        if (!config || Object.keys(config).length === 0) {
            container.innerHTML = '<div class="empty-state">No configuration found</div>';
            return;
        }

        container.innerHTML = Object.entries(config).map(([key, value]) => {
            const label = this.humanizeKey(key);
            const isArray = Array.isArray(value);
            const displayValue = isArray ? value.join(", ") : value;
            const inputType = typeof value === "number" ? "number" : typeof value === "boolean" ? "checkbox" : "text";

            if (inputType === "checkbox") {
                return `
                    <div class="config-field">
                        <label class="config-label">${label}</label>
                        <label class="toggle-switch">
                            <input type="checkbox" name="${key}" ${value ? "checked" : ""} data-type="boolean">
                            <span class="toggle-slider"></span>
                        </label>
                    </div>`;
            }

            return `
                <div class="config-field">
                    <label class="config-label" for="cfg-${key}">${label}</label>
                    <input type="${inputType}" id="cfg-${key}" name="${key}" value="${this.esc(String(displayValue))}" data-type="${isArray ? "array" : typeof value}" ${inputType === "number" ? 'step="any"' : ""}>
                </div>`;
        }).join("");

        document.getElementById("configForm").onsubmit = async (event) => {
            event.preventDefault();
            const payload = {};
            container.querySelectorAll("input").forEach((input) => {
                const key = input.name;
                const type = input.dataset.type;

                if (type === "boolean") {
                    payload[key] = input.checked;
                } else if (type === "number") {
                    payload[key] = Number(input.value);
                } else if (type === "array") {
                    payload[key] = input.value.split(",").map((item) => item.trim()).filter(Boolean);
                } else {
                    payload[key] = input.value;
                }
            });

            try {
                const response = await fetch("/api/config", {
                    method: "PUT",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload),
                });

                if (response.ok) {
                    this.toast("Configuration saved.", "success");
                } else {
                    this.toast("Failed to save configuration", "error");
                }
            } catch {
                this.toast("Connection error", "error");
            }
        };
    },

    syncSettingsSummary(config) {
        const text = (id, value) => {
            const node = document.getElementById(id);
            if (node) node.textContent = value;
        };

        const automationMode = config.adaptive_tool_selection
            ? "Adaptive"
            : (config.automation_scheduler ? "Scheduled" : "Manual");

        text("settingsProfileName", String(config.toolset_profile || "portable_core"));
        text("settingsAutomationMode", automationMode);
        text("settingsParallelTools", String(config.max_parallel_tools ?? 2));
        text("settingsHardTimeout", `${config.scan_hard_timeout_seconds ?? 2700}s`);
        text("settingsOutputFormats", "HTML, MD, JSON, SARIF, CSV");
    },

    async loadTokensTab() {
        const tokens = await this.api("/api/tokens");
        if (tokens) {
            document.getElementById("tokenWpscan").value = tokens.wpscan_api_token || "";
            document.getElementById("tokenZap").value = tokens.zap_api_key || "";
        }

        document.getElementById("tokensForm").onsubmit = async (event) => {
            event.preventDefault();
            const payload = {
                wpscan_api_token: document.getElementById("tokenWpscan").value,
                zap_api_key: document.getElementById("tokenZap").value,
            };

            try {
                const response = await fetch("/api/tokens", {
                    method: "PUT",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload),
                });
                if (response.ok) {
                    this.toast("Tokens saved.", "success");
                } else {
                    this.toast("Failed to save tokens", "error");
                }
            } catch {
                this.toast("Connection error", "error");
            }
        };
    },

    async loadModulesTab() {
        const modules = await this.api("/api/modules");
        const container = document.getElementById("modulesFields");
        if (!container) return;
        this.modules = modules && typeof modules === "object" ? modules : {};
        this.applyModuleVisibility();

        container.innerHTML = Object.entries(this.modules).map(([key, value]) => `
            <div class="config-field">
                <label class="config-label">${this.humanizeKey(key)}</label>
                <label class="toggle-switch">
                    <input type="checkbox" name="${key}" ${value ? "checked" : ""} data-type="boolean">
                    <span class="toggle-slider"></span>
                </label>
            </div>
        `).join("");

        document.getElementById("modulesForm").onsubmit = async (event) => {
            event.preventDefault();
            const payload = {};
            container.querySelectorAll("input[name]").forEach((input) => {
                payload[input.name] = input.checked;
            });
            try {
                const response = await fetch("/api/modules", {
                    method: "PUT",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload),
                });
                if (response.ok) {
                    this.modules = payload;
                    this.applyModuleVisibility();
                    if (this.modules[this.currentView] === false) {
                        this.navigateTo("dashboard");
                    }
                    this.toast("Module visibility updated.", "success");
                } else {
                    this.toast("Failed to save module visibility", "error");
                }
            } catch {
                this.toast("Connection error", "error");
            }
        };
    },

    async loadMonitoringSettingsTab() {
        const settings = await this.api("/api/monitoring/settings");
        const container = document.getElementById("monitoringSettingsFields");
        if (!container) return;
        const telegram = settings?.telegram || {};
        container.innerHTML = `
            <div class="config-field">
                <label class="config-label">Monitoring Enabled</label>
                <label class="toggle-switch">
                    <input type="checkbox" id="monitoringEnabled" ${settings?.enabled ? "checked" : ""}>
                    <span class="toggle-slider"></span>
                </label>
            </div>
            <div class="config-field">
                <label class="config-label" for="workerInterval">Worker Interval Seconds</label>
                <input type="number" id="workerInterval" min="5" value="${this.esc(String(settings?.worker_interval_seconds ?? 15))}">
            </div>
            <div class="config-field">
                <label class="config-label" for="defaultCheckInterval">Default Check Interval Seconds</label>
                <input type="number" id="defaultCheckInterval" min="30" value="${this.esc(String(settings?.default_check_interval_seconds ?? 300))}">
            </div>
            <div class="config-field">
                <label class="config-label" for="defaultTimeout">Default Timeout Seconds</label>
                <input type="number" id="defaultTimeout" min="2" value="${this.esc(String(settings?.default_timeout_seconds ?? 8))}">
            </div>
            <div class="config-field">
                <label class="config-label" for="heartbeatGraceMultiplier">Heartbeat Grace Multiplier</label>
                <input type="number" id="heartbeatGraceMultiplier" min="1" value="${this.esc(String(settings?.heartbeat_grace_multiplier ?? 2))}">
            </div>
            <div class="config-field">
                <label class="config-label" for="retentionDays">Retention Days</label>
                <input type="number" id="retentionDays" min="1" value="${this.esc(String(settings?.retention_days ?? 14))}">
            </div>
            <div class="config-field">
                <label class="config-label">Telegram Enabled</label>
                <label class="toggle-switch">
                    <input type="checkbox" id="telegramEnabled" ${telegram.enabled ? "checked" : ""}>
                    <span class="toggle-slider"></span>
                </label>
            </div>
            <div class="config-field">
                <label class="config-label" for="telegramBotToken">Telegram Bot Token</label>
                <input type="text" id="telegramBotToken" value="${this.esc(String(telegram.bot_token || ""))}">
            </div>
            <div class="config-field">
                <label class="config-label" for="telegramChatId">Telegram Chat ID</label>
                <input type="text" id="telegramChatId" value="${this.esc(String(telegram.chat_id || ""))}">
            </div>
            <div class="config-field">
                <label class="config-label">Notify On Up</label>
                <label class="toggle-switch">
                    <input type="checkbox" id="notifyOnUp" ${telegram.notify_on_up !== false ? "checked" : ""}>
                    <span class="toggle-slider"></span>
                </label>
            </div>
            <div class="config-field">
                <label class="config-label">Notify On Down</label>
                <label class="toggle-switch">
                    <input type="checkbox" id="notifyOnDown" ${telegram.notify_on_down !== false ? "checked" : ""}>
                    <span class="toggle-slider"></span>
                </label>
            </div>
            <div class="config-field">
                <label class="config-label">Notify On Degraded</label>
                <label class="toggle-switch">
                    <input type="checkbox" id="notifyOnDegraded" ${telegram.notify_on_degraded !== false ? "checked" : ""}>
                    <span class="toggle-slider"></span>
                </label>
            </div>
            <div class="config-field">
                <label class="config-label" for="telegramCooldown">Telegram Cooldown Seconds</label>
                <input type="number" id="telegramCooldown" min="0" value="${this.esc(String(telegram.cooldown_seconds ?? 300))}">
            </div>
        `;

        document.getElementById("monitoringSettingsForm").onsubmit = async (event) => {
            event.preventDefault();
            const payload = {
                enabled: document.getElementById("monitoringEnabled").checked,
                worker_interval_seconds: Number(document.getElementById("workerInterval").value || 15),
                default_check_interval_seconds: Number(document.getElementById("defaultCheckInterval").value || 300),
                default_timeout_seconds: Number(document.getElementById("defaultTimeout").value || 8),
                heartbeat_grace_multiplier: Number(document.getElementById("heartbeatGraceMultiplier").value || 2),
                retention_days: Number(document.getElementById("retentionDays").value || 14),
                telegram: {
                    enabled: document.getElementById("telegramEnabled").checked,
                    bot_token: document.getElementById("telegramBotToken").value.trim(),
                    chat_id: document.getElementById("telegramChatId").value.trim(),
                    notify_on_up: document.getElementById("notifyOnUp").checked,
                    notify_on_down: document.getElementById("notifyOnDown").checked,
                    notify_on_degraded: document.getElementById("notifyOnDegraded").checked,
                    cooldown_seconds: Number(document.getElementById("telegramCooldown").value || 300),
                },
            };

            try {
                const response = await fetch("/api/monitoring/settings", {
                    method: "PUT",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload),
                });
                if (response.ok) {
                    this.toast("Monitoring settings saved.", "success");
                } else {
                    this.toast("Failed to save monitoring settings", "error");
                }
            } catch {
                this.toast("Connection error", "error");
            }
        };

        document.getElementById("testTelegramBtn").onclick = async () => {
            try {
                const response = await fetch("/api/monitoring/test-telegram", { method: "POST" });
                const result = await response.json();
                this.toast(result.message || (result.success ? "Telegram ok" : "Telegram test failed"), result.success ? "success" : "error");
            } catch {
                this.toast("Connection error", "error");
            }
        };
    },

    async loadMonitoringView() {
        document.getElementById("monitoringRefreshBtn").onclick = () => this.loadMonitoringView(true);
        document.getElementById("monitoringAddBtn").onclick = () => this.openMonitoringDrawer();
        this.bindMonitoringTabs();
        this.bindMonitoringAssetForm();
        this.bindMonitoringDrawer();
        this.applyMonitoringSubView();

        if (this.monitoringSubView === "inventory") {
            await this.loadMonitoringInventory();
            this.stopMonitoringRefresh();
            return;
        }

        const [status, events] = await Promise.all([
            this.api("/api/monitoring/status"),
            this.api("/api/monitoring/events?limit=25"),
        ]);
        this.renderMonitoringOverview(status?.overview || {}, status);
        this.renderMonitoringStatusCharts(status || {});
        this.renderMonitoringIncidents(Array.isArray(status?.incidents) ? status.incidents : []);
        this.renderMonitoringEvents(Array.isArray(events) ? events : []);
        this.startMonitoringRefresh();
    },

    startMonitoringRefresh() {
        if (this.monitoringRefreshTimer) {
            clearInterval(this.monitoringRefreshTimer);
        }
        this.monitoringRefreshTimer = setInterval(() => {
            if (this.currentView !== "monitoring") {
                this.stopMonitoringRefresh();
                return;
            }
            if (this.monitoringSubView !== "overview") {
                this.stopMonitoringRefresh();
                return;
            }
            if (this.monitoringDrawerOpen) {
                return;
            }
            this.loadMonitoringView(true);
        }, 15000);
    },

    stopMonitoringRefresh() {
        if (this.monitoringRefreshTimer) {
            clearInterval(this.monitoringRefreshTimer);
            this.monitoringRefreshTimer = null;
        }
    },

    bindMonitoringDrawer() {
        const overlay = document.getElementById("monitoringDrawerOverlay");
        const closeBtn = document.getElementById("monitoringDrawerClose");
        if (overlay && overlay.dataset.bound !== "true") {
            overlay.dataset.bound = "true";
            overlay.addEventListener("click", () => this.closeMonitoringDrawer());
        }
        if (closeBtn && closeBtn.dataset.bound !== "true") {
            closeBtn.dataset.bound = "true";
            closeBtn.addEventListener("click", () => this.closeMonitoringDrawer());
        }
    },

    bindMonitoringTabs() {
        const group = document.getElementById("monitoringTabStrip");
        if (!group || group.dataset.bound === "true") return;
        group.dataset.bound = "true";
        group.addEventListener("click", async (event) => {
            const button = event.target.closest(".monitoring-tab-btn[data-monitoring-tab]");
            if (!button) return;
            const nextTab = button.dataset.monitoringTab;
            if (!nextTab || nextTab === this.monitoringSubView) return;
            this.monitoringSubView = nextTab;
            this.applyMonitoringSubView();
            if (nextTab === "inventory") {
                this.stopMonitoringRefresh();
                await this.loadMonitoringInventory();
                return;
            }
            await this.loadMonitoringView(true);
        });
    },

    applyMonitoringSubView() {
        document.querySelectorAll(".monitoring-tab-btn[data-monitoring-tab]").forEach((button) => {
            const active = button.dataset.monitoringTab === this.monitoringSubView;
            button.classList.toggle("active", active);
            button.setAttribute("aria-selected", active ? "true" : "false");
        });
        document.querySelectorAll(".monitoring-tab-panel[data-monitoring-panel]").forEach((panel) => {
            panel.classList.toggle("active", panel.dataset.monitoringPanel === this.monitoringSubView);
        });
    },

    async loadMonitoringInventory() {
        const assets = await this.api("/api/monitoring/assets");
        this.renderMonitoringAssets(Array.isArray(assets) ? assets : []);
    },

    openMonitoringDrawer(asset = null) {
        const drawer = document.getElementById("monitoringDrawer");
        const overlay = document.getElementById("monitoringDrawerOverlay");
        if (!drawer || !overlay) return;
        this.monitoringDrawerOpen = true;
        drawer.classList.add("open");
        overlay.classList.add("open");
        drawer.setAttribute("aria-hidden", "false");
        if (asset) {
            this.populateMonitoringDrawer(asset);
        } else {
            this.resetMonitoringAssetForm();
        }
    },

    closeMonitoringDrawer() {
        const drawer = document.getElementById("monitoringDrawer");
        const overlay = document.getElementById("monitoringDrawerOverlay");
        if (!drawer || !overlay) return;
        drawer.classList.remove("open");
        overlay.classList.remove("open");
        drawer.setAttribute("aria-hidden", "true");
        this.monitoringDrawerOpen = false;
        this.monitoringFormDirty = false;
    },

    populateMonitoringDrawer(asset) {
        document.getElementById("monitorAssetId").value = asset.id || "";
        document.getElementById("monitorLabel").value = asset.label || "";
        document.getElementById("monitorType").value = asset.asset_type || "website_http";
        document.getElementById("monitorTarget").value = asset.target || "";
        document.getElementById("monitorSiteName").value = asset.site_name || "";
        document.getElementById("monitorInterval").value = String(asset.check_interval_seconds || 300);
        document.getElementById("monitorTimeout").value = String(asset.timeout_seconds || 8);
        document.getElementById("monitorHeartbeatSeconds").value = String(asset.expected_heartbeat_seconds || 300);
        document.getElementById("monitorAgentId").value = asset.metadata?.agent_id || "";
        document.getElementById("monitorAgentSecret").value = asset.metadata?.agent_secret || "";
        document.getElementById("monitoringDrawerTitle").textContent = "Edit Monitor";
        document.getElementById("monitoringDrawerSubtitle").textContent = "Adjust the selected monitor without leaving the operations overview.";
        this.monitoringFormDirty = false;
    },

    renderMonitoringOverview(overview, statusPayload) {
        const node = document.getElementById("monitoringOverviewCards");
        if (!node) return;
        const generatedAt = statusPayload?.generated_at ? this._formatTimestamp(statusPayload.generated_at) : "Unknown";
        const lastEvaluated = overview?.last_evaluated_at ? this._formatTimestamp(overview.last_evaluated_at) : "No checks yet";
        node.innerHTML = `
            <div class="workspace-signal-card monitoring-operator-card">
                <span class="signal-label">Monitored Assets</span>
                <strong>${this.esc(String(overview.enabled_assets || 0))}</strong>
                <p>Enabled monitors currently scheduled.</p>
            </div>
            <div class="workspace-signal-card monitoring-operator-card">
                <span class="signal-label">Healthy Assets</span>
                <strong>${this.esc(String(overview.healthy_assets || 0))}</strong>
                <p>Assets currently holding a healthy state.</p>
            </div>
            <div class="workspace-signal-card monitoring-operator-card">
                <span class="signal-label">Active Incidents</span>
                <strong>${this.esc(String(overview.active_incidents || 0))}</strong>
                <p>Down or degraded assets requiring action.</p>
            </div>
            <div class="workspace-signal-card monitoring-operator-card">
                <span class="signal-label">Timing</span>
                <strong>${this.esc(String(overview.uptime_24h_pct || 0))}%</strong>
                <p>24h average uptime across monitored assets.</p>
                <div class="monitoring-meta-line">
                    <span class="monitoring-meta-pill">Last check pass: ${this.esc(lastEvaluated)}</span>
                    <span class="monitoring-meta-pill">UI updated: ${this.esc(generatedAt)}</span>
                </div>
            </div>
        `;
        const pill = document.getElementById("monitoringLastUpdatedPill");
        if (pill) {
            const label = pill.querySelector("span:last-child");
            if (label) {
                label.textContent = `Updated ${generatedAt}`;
            }
        }
    },

    renderMonitoringStatusCharts(status) {
        if (typeof Chart === "undefined") {
            return;
        }

        const breakdown = Array.isArray(status?.status_breakdown) ? status.status_breakdown : [];
        const uptimeTrend = Array.isArray(status?.uptime_trend) ? status.uptime_trend : [];
        const incidentTrend = Array.isArray(status?.incident_trend) ? status.incident_trend : [];

        this._renderMonitoringChart("status", "monitoringStatusChart", "doughnut", {
            labels: breakdown.map((item) => item.label || "Status"),
            datasets: [{
                data: breakdown.map((item) => Number(item.value || 0)),
                backgroundColor: ["#22c55e", "#f59e0b", "#ef4444", "#64748b"],
                borderColor: "rgba(15, 23, 42, 0.92)",
                borderWidth: 2,
            }],
        }, {
            cutout: "72%",
            plugins: {
                legend: { position: "bottom", labels: { color: "#94a3b8", usePointStyle: true, padding: 10, boxWidth: 8, font: { size: 11 } } },
            },
        });

        this._renderMonitoringChart("uptime", "monitoringUptimeChart", "line", {
            labels: uptimeTrend.map((item) => this._formatBucketLabel(item.bucket)),
            datasets: [{
                label: "Uptime %",
                data: uptimeTrend.map((item) => Number(item.uptime_pct || 0)),
                borderColor: "#60a5fa",
                backgroundColor: "rgba(96, 165, 250, 0.18)",
                fill: true,
                tension: 0.32,
            }],
        }, {
            plugins: { legend: { display: false } },
            scales: {
                y: { min: 0, max: 100, ticks: { color: "#94a3b8", maxTicksLimit: 4 }, grid: { color: "rgba(148, 163, 184, 0.08)" } },
                x: { ticks: { color: "#64748b", maxTicksLimit: 4 }, grid: { display: false } },
            },
        });

        this._renderMonitoringChart("incidents", "monitoringIncidentChart", "bar", {
            labels: incidentTrend.map((item) => this._formatBucketLabel(item.bucket)),
            datasets: [
                {
                    label: "Transitions",
                    data: incidentTrend.map((item) => Number(item.transitions || 0)),
                    backgroundColor: "rgba(248, 113, 113, 0.7)",
                    borderRadius: 8,
                },
                {
                    label: "Active Incidents",
                    data: incidentTrend.map((item) => Number(item.active_incidents || 0)),
                    type: "line",
                    borderColor: "#fbbf24",
                    backgroundColor: "rgba(251, 191, 36, 0.18)",
                    tension: 0.28,
                    yAxisID: "y",
                },
            ],
        }, {
            plugins: {
                legend: { position: "bottom", labels: { color: "#94a3b8", usePointStyle: true, padding: 10, boxWidth: 8, font: { size: 11 } } },
            },
            scales: {
                y: { beginAtZero: true, ticks: { color: "#94a3b8", maxTicksLimit: 4 }, grid: { color: "rgba(148, 163, 184, 0.08)" } },
                x: { ticks: { color: "#64748b", maxTicksLimit: 4 }, grid: { display: false } },
            },
        });
    },

    _renderMonitoringChart(key, canvasId, type, data, options) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        if (this.monitoringCharts[key]) {
            this.monitoringCharts[key].destroy();
        }
        Chart.defaults.color = "#94a3b8";
        Chart.defaults.font.family = "Inter";
        this.monitoringCharts[key] = new Chart(canvas.getContext("2d"), {
            type,
            data,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                ...options,
            },
        });
    },

    renderMonitoringAssets(assets) {
        const tbody = document.getElementById("monitoringAssetsBody");
        if (!tbody) return;
        if (!assets.length) {
            tbody.innerHTML = '<tr><td colspan="9" class="empty-state">No monitoring assets added yet.</td></tr>';
            return;
        }
        tbody.innerHTML = assets.map((asset) => {
            const state = asset.state || {};
            const status = String(state.status || "unknown").toLowerCase();
            const badgeClass = status === "healthy" ? "badge-running" : status === "down" ? "badge-critical" : "badge-neutral";
            const lastCheck = state.checked_at ? this._formatTimestamp(state.checked_at) : "Never";
            const interval = this._formatInterval(state.check_interval_seconds || asset.check_interval_seconds || 300);
            const nextDue = state.next_check_due_at ? this._formatTimestamp(state.next_check_due_at) : "Pending first run";
            return `
                <tr>
                    <td><strong>${this.esc(asset.label || "Asset")}</strong><br><small>${this.esc(asset.site_name || "")}</small></td>
                    <td><span class="badge badge-neutral">${this.esc(asset.asset_type || "")}</span></td>
                    <td>${this.esc(asset.target || "-")}</td>
                    <td><span class="badge ${badgeClass}">${this.esc(status)}</span></td>
                    <td>${this.esc(String(state.uptime_24h_pct || 0))}%</td>
                    <td>${this.esc(lastCheck)}</td>
                    <td>${this.esc(interval)}</td>
                    <td>${this.esc(nextDue)}</td>
                    <td>
                        <button class="btn-ghost btn-sm" onclick="App.editMonitoringAsset('${this.esc(asset.id)}')">Edit</button>
                        <button class="btn-ghost btn-sm btn-danger" onclick="App.deleteMonitoringAsset('${this.esc(asset.id)}')">Delete</button>
                    </td>
                </tr>
            `;
        }).join("");
        this._monitoringAssetsCache = assets;
    },

    renderMonitoringIncidents(incidents) {
        const node = document.getElementById("monitoringIncidents");
        if (!node) return;
        node.innerHTML = incidents.length
            ? incidents.map((item) => `
                <article class="incident-card">
                    <div class="incident-card-head">
                        <h4>${this.esc(item.label || "Asset")}</h4>
                        <span class="badge ${item.status === "down" ? "badge-critical" : "badge-neutral"}">${this.esc(item.status || "")}</span>
                    </div>
                    <p>${this.esc(item.message || "No detail available.")}</p>
                    <div class="monitoring-meta-line">
                        <span class="monitoring-meta-pill">${this.esc(item.asset_type || "")}</span>
                        <span class="monitoring-meta-pill">Changed ${this.esc(item.last_change_at ? this._formatTimestamp(item.last_change_at) : "Unknown")}</span>
                        <span class="monitoring-meta-pill">${this.esc(item.target || "No target recorded")}</span>
                    </div>
                </article>
            `).join("")
            : '<div class="empty-state">No active incidents.</div>';
    },

    renderMonitoringEvents(events) {
        const node = document.getElementById("monitoringEvents");
        if (!node) return;
        node.innerHTML = events.length
            ? events.map((item) => `
                <div class="event-row">
                    <div>
                        <strong>${this.esc(item.asset_label || item.asset_id || "Asset")}</strong>
                        <small>${this.esc(item.previous_status || "unknown")} -> ${this.esc(item.status || "unknown")} · ${this.esc(item.message || "No detail")}</small>
                    </div>
                    <div><strong>${this.esc(this._formatTimestamp(item.created_at))}</strong></div>
                </div>
            `).join("")
            : '<div class="empty-state">No monitoring events yet.</div>';
    },

    bindMonitoringAssetForm() {
        const form = document.getElementById("monitoringAssetForm");
        if (!form) return;
        if (form.dataset.bound !== "true") {
            form.dataset.bound = "true";
            form.addEventListener("input", () => {
                this.monitoringFormDirty = true;
            });
        }
        form.onsubmit = async (event) => {
            event.preventDefault();
            const assetType = document.getElementById("monitorType").value;
            const payload = {
                id: document.getElementById("monitorAssetId").value.trim() || undefined,
                label: document.getElementById("monitorLabel").value.trim(),
                asset_type: assetType,
                target: document.getElementById("monitorTarget").value.trim(),
                site_name: document.getElementById("monitorSiteName").value.trim(),
                check_interval_seconds: Number(document.getElementById("monitorInterval").value || 300),
                timeout_seconds: Number(document.getElementById("monitorTimeout").value || 8),
                expected_heartbeat_seconds: Number(document.getElementById("monitorHeartbeatSeconds").value || 300),
                metadata: {},
            };
            const agentId = document.getElementById("monitorAgentId").value.trim();
            const agentSecret = document.getElementById("monitorAgentSecret").value.trim();
            if (agentId) payload.metadata.agent_id = agentId;
            if (agentSecret) payload.metadata.agent_secret = agentSecret;
            try {
                const response = await fetch("/api/monitoring/assets", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload),
                });
                const result = await response.json();
                if (response.ok) {
                    this.toast("Monitoring asset saved.", "success");
                    this.resetMonitoringAssetForm();
                    this.closeMonitoringDrawer();
                    if (this.monitoringSubView === "inventory") {
                        this.loadMonitoringInventory();
                    } else {
                        this.loadMonitoringView();
                    }
                } else {
                    this.toast(result.error || "Failed to save monitoring asset", "error");
                }
            } catch {
                this.toast("Connection error", "error");
            }
        };
        document.getElementById("monitoringAssetReset").onclick = () => this.resetMonitoringAssetForm();
    },

    resetMonitoringAssetForm() {
        document.getElementById("monitoringAssetForm")?.reset();
        const hiddenId = document.getElementById("monitorAssetId");
        if (hiddenId) hiddenId.value = "";
        const drawerTitle = document.getElementById("monitoringDrawerTitle");
        const drawerSubtitle = document.getElementById("monitoringDrawerSubtitle");
        if (drawerTitle) drawerTitle.textContent = "Add Monitor";
        if (drawerSubtitle) drawerSubtitle.textContent = "Register a website, TCP host, heartbeat agent, WAN probe, or network site monitor.";
        const heartbeat = document.getElementById("monitorHeartbeatSeconds");
        if (heartbeat) heartbeat.value = "300";
        const interval = document.getElementById("monitorInterval");
        if (interval) interval.value = "300";
        const timeout = document.getElementById("monitorTimeout");
        if (timeout) timeout.value = "8";
        this.monitoringFormDirty = false;
    },

    editMonitoringAsset(assetId) {
        const assets = Array.isArray(this._monitoringAssetsCache) ? this._monitoringAssetsCache : [];
        const asset = assets.find((item) => item.id === assetId);
        if (!asset) return;
        this.openMonitoringDrawer(asset);
    },

    async deleteMonitoringAsset(assetId) {
        if (!confirm("Remove this monitoring asset?")) {
            return;
        }
        try {
            const response = await fetch(`/api/monitoring/assets/${encodeURIComponent(assetId)}`, { method: "DELETE" });
            if (response.ok) {
                this.toast("Monitoring asset removed", "success");
                if (this.monitoringSubView === "inventory") {
                    this.loadMonitoringInventory();
                } else {
                    this.loadMonitoringView();
                }
            } else {
                this.toast("Failed to remove monitoring asset", "error");
            }
        } catch {
            this.toast("Connection error", "error");
        }
    },

    _formatBucketLabel(value) {
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return "";
        return date.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
    },

    _formatInterval(value) {
        const seconds = Number(value || 0);
        if (seconds >= 3600) {
            return `${Math.round(seconds / 3600)}h`;
        }
        if (seconds >= 60) {
            return `${Math.round(seconds / 60)}m`;
        }
        return `${seconds}s`;
    },

    setupPerformanceTab() {
        const profiles = {
            vps2c2g: {
                label: "VPS Optimized",
                icon: "⚡",
                desc: "Recommended for 2 vCPU / 2 GB RAM VPS nodes. Deeper coverage with adaptive limits still enabled.",
                settings: {
                    toolset_profile: "deep_scan",
                    adaptive_tool_selection: true,
                    adaptive_parallelism: true,
                    automation_scheduler: true,
                    adaptive_skip_wpscan_low_confidence: false,
                    nuclei_rate_limit: 35,
                    nuclei_timeout_seconds: 3300,
                    nuclei_auto_scan_concurrency: 6,
                    nuclei_auto_scan_bulk_size: 8,
                    nuclei_request_timeout: 18,
                    wpscan_max_threads: 2,
                    nikto_pause_seconds: 0,
                    nikto_maxtime_seconds: 900,
                    nikto_timeout_seconds: 1080,
                    nikto_maxtime_wordpress_seconds: 960,
                    nikto_timeout_wordpress_seconds: 1080,
                    whatweb_max_threads: 10,
                    httpx_rate_limit: 40,
                    ffuf_threads: 45,
                    ffuf_maxtime_seconds: 540,
                    ffuf_timeout_seconds: 960,
                    feroxbuster_timeout_seconds: 900,
                    adaptive_sqlmap_min_params: 2,
                    adaptive_sqlmap_min_urls: 6,
                    adaptive_wapiti_min_html: 1,
                    adaptive_commix_min_params: 1,
                    run_wapiti_api: true,
                    scan_time_budget_passive_seconds: 3000,
                    scan_time_budget_active_seconds: 3300,
                    scan_time_budget_full_seconds: 4200,
                    scan_hard_timeout_seconds: 4200,
                    deadline_skip_grace_seconds: 240,
                    parallelism_boost_min_urls: 80,
                    max_parallel_tools: 3,
                    max_parallel_heavy_tools: 2,
                    max_parallel_tools_api: 3,
                    max_parallel_heavy_tools_api: 2,
                    max_parallel_tools_cap: 4,
                    max_parallel_heavy_tools_cap: 2,
                    timeout_per_tool_seconds: 900,
                },
            },
            stable: {
                label: "Stable",
                icon: "⚖️",
                desc: "Balanced speed and reliability. Safe for smaller office links and general web scans.",
                settings: { nuclei_rate_limit: 20, wpscan_max_threads: 1, nikto_pause_seconds: 1, whatweb_max_threads: 5, httpx_rate_limit: 10, parallel_scans: true, max_parallel_tools: 3, max_parallel_heavy_tools: 2 },
            },
            light: {
                label: "Lightweight",
                icon: "🪶",
                desc: "Very gentle. For slow or unstable internet connections.",
                settings: { nuclei_rate_limit: 5, wpscan_max_threads: 1, nikto_pause_seconds: 3, whatweb_max_threads: 1, httpx_rate_limit: 2, parallel_scans: false, max_parallel_tools: 1, max_parallel_heavy_tools: 1 },
            },
            wordpress: {
                label: "WordPress Deep",
                icon: "🔍",
                desc: "Thorough WPScan enumeration plus WordPress-specific detection depth.",
                settings: { nuclei_rate_limit: 25, wpscan_max_threads: 2, nikto_pause_seconds: 1, whatweb_max_threads: 5, httpx_rate_limit: 15, parallel_scans: true, max_parallel_tools: 3, max_parallel_heavy_tools: 2, nuclei_severity: "critical,high,medium,low" },
            },
            api: {
                label: "API / Web App",
                icon: "🌐",
                desc: "API-first posture with stronger HTTP, content, and validation coverage.",
                settings: { nuclei_rate_limit: 30, wpscan_max_threads: 0, nikto_pause_seconds: 2, whatweb_max_threads: 10, httpx_rate_limit: 30, parallel_scans: true, max_parallel_tools: 3, max_parallel_heavy_tools: 2 },
            },
            quick: {
                label: "Quick Recon",
                icon: "🚀",
                desc: "Passive-first baseline for a fast initial overview before deep validation.",
                settings: { nuclei_rate_limit: 15, wpscan_max_threads: 1, nikto_pause_seconds: 2, whatweb_max_threads: 5, httpx_rate_limit: 20, parallel_scans: true, max_parallel_tools: 3, max_parallel_heavy_tools: 1 },
            },
            aggressive: {
                label: "Aggressive Full",
                icon: "⚠️",
                desc: "Maximum coverage for authorized pentests. Very noisy - do not use on production without permission.",
                settings: { nuclei_rate_limit: 200, wpscan_max_threads: 5, nikto_pause_seconds: 0, whatweb_max_threads: 30, httpx_rate_limit: 200, parallel_scans: true, max_parallel_tools: 4, max_parallel_heavy_tools: 3 },
            },
        };

        // Render profile cards dynamically
        const container = document.getElementById("profileCards");
        if (container) {
            container.innerHTML = Object.entries(profiles).map(([key, p]) => `
                <button class="profile-card ${key === "vps2c2g" ? "selected" : ""}" data-profile="${key}">
                    <div class="profile-icon">${p.label.split(" ").map((word) => word[0]).join("").slice(0, 2).toUpperCase()}</div>
                    <h4>${p.label}</h4>
                    <p>${p.desc}</p>
                </button>
            `).join("");
        }

        const cards = document.querySelectorAll(".profile-card");
        cards.forEach((card) => {
            card.addEventListener("click", () => {
                cards.forEach((item) => item.classList.remove("selected"));
                card.classList.add("selected");
            });
        });

        document.getElementById("applyProfileBtn").onclick = async () => {
            const selected = document.querySelector(".profile-card.selected");
            if (!selected) return;

            const profile = selected.dataset.profile;
            const profileDef = profiles[profile];
            if (!profileDef) return;

            const config = await this.api("/api/config");
            if (!config) return;

            Object.assign(config, profileDef.settings);

            try {
                const response = await fetch("/api/config", {
                    method: "PUT",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(config),
                });
                if (response.ok) {
                    this.toast(`Applied "${profileDef.label}" profile.`, "success");
                    this.loadConfigTab();
                } else {
                    this.toast("Failed to apply profile", "error");
                }
            } catch {
                this.toast("Connection error", "error");
            }
        };
    },

    _formatTimestamp(value) {
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return String(value || "");
        return date.toLocaleString();
    },

    async api(url, options) {
        try {
            const response = await _authedFetch(url, options);
            return await response.json();
        } catch {
            return null;
        }
    },

    esc(value) {
        const node = document.createElement("span");
        node.textContent = value == null ? "" : String(value);
        return node.innerHTML;
    },

    toast(message, type = "info") {
        const container = document.getElementById("toastContainer");
        const toast = document.createElement("div");
        toast.className = `toast toast-${type}`;

        const icons = {
            success: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>',
            error: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>',
            info: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>',
        };

        toast.innerHTML = `${icons[type] || icons.info}<span>${this.esc(message)}</span>`;
        container.appendChild(toast);

        requestAnimationFrame(() => toast.classList.add("show"));

        setTimeout(() => {
            toast.classList.remove("show");
            toast.addEventListener("transitionend", () => toast.remove(), { once: true });
        }, 3500);
    },
};
