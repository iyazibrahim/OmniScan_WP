document.addEventListener("DOMContentLoaded", () => {
    if (window.location.protocol === "file:") {
        document.body.innerHTML = `<div style="display:flex;align-items:center;justify-content:center;height:100vh;text-align:center;font-family:Inter,sans-serif;color:#ef4444;padding:32px;">
            <div><h1 style="font-size:2rem;">Backend Offline</h1><p style="color:#94a3b8;margin-top:12px;">Run <code>python app.py</code> then visit <strong>http://localhost:5000</strong></p></div></div>`;
        return;
    }

    App.init();

    // Close download dropdowns when clicking outside
    document.addEventListener("click", (e) => {
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

    init() {
        this.setupNavigation();
        this.setupMobileMenu();
        this.checkServer();
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
                    const sidebar = document.getElementById("sidebar");
                    const overlay = document.getElementById("sidebarOverlay");
                    sidebar?.classList.remove("open");
                    overlay?.classList.remove("open");
                }
            });
        });
    },

    navigateTo(view) {
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

        button.addEventListener("click", () => {
            sidebar.classList.toggle("open");
            overlay.classList.toggle("open");
        });

        overlay.addEventListener("click", () => {
            sidebar.classList.remove("open");
            overlay.classList.remove("open");
        });
    },

    setupTabs() {
        document.querySelectorAll(".tab-btn").forEach((button) => {
            button.addEventListener("click", () => {
                document.querySelectorAll(".tab-btn").forEach((item) => item.classList.remove("active"));
                document.querySelectorAll(".tab-panel").forEach((panel) => panel.classList.remove("active"));
                button.classList.add("active");
                document.getElementById(button.dataset.tab).classList.add("active");
            });
        });
    },

    async checkServer() {
        const dot = document.getElementById("serverDot");
        const text = document.getElementById("serverStatusText");

        try {
            const response = await fetch("/api/targets");
            if (response.ok) {
                dot.classList.add("online");
                text.textContent = "Server Online";
            } else {
                dot.classList.add("offline");
                text.textContent = "Server Error";
            }
        } catch {
            dot.classList.add("offline");
            text.textContent = "Server Offline";
        }
    },

    async loadDashboard() {
        document.getElementById("refreshDashboard").onclick = () => this.loadDashboard();
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
        document.getElementById("statCriticalOpen").textContent = `${Number(ov.critical_open || 0)} | SLA ${Number(ov.critical_sla_breached || 0)}`;
        document.getElementById("statHighRiskAssets").textContent = `${Number(ov.high_risk_assets || 0)}`;
        document.getElementById("statMttr").textContent = ov.mttr_days != null ? `${ov.mttr_days}d` : "N/A";
        document.getElementById("statExposure").textContent = `${Number(ov.exposure_pct || 0)}%`;

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
            attackNode.innerHTML = attackSurface.length
                ? `<div class="metric-list">${attackSurface.map((item) =>
                    `<div class="metric-item"><span>${this.esc(item.category)} <span class="metric-muted">(${item.asset_count} assets)</span></span><strong>${item.vulnerability_count}</strong></div>`
                ).join("")}</div>`
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
                scales: {
                    x: { stacked: mode !== "normalized", grid: { color: "rgba(255,255,255,0.04)", drawBorder: false } },
                    y: mode === "normalized"
                        ? undefined
                        : {
                            stacked: true,
                            grid: { color: "rgba(255,255,255,0.04)", drawBorder: false },
                            beginAtZero: true,
                            title: yAxisLabel ? { display: true, text: yAxisLabel, color: "#94a3b8" } : undefined,
                        },
                    yRisk: mode === "normalized"
                        ? {
                            position: "left",
                            beginAtZero: true,
                            suggestedMax: 100,
                            grid: { color: "rgba(255,255,255,0.05)", drawBorder: false },
                            title: { display: true, text: "Risk Score", color: "#94a3b8" },
                        }
                        : undefined,
                    yVol: mode === "normalized"
                        ? {
                            position: "right",
                            beginAtZero: true,
                            grid: { drawOnChartArea: false },
                            title: { display: true, text: "Vulnerability Count", color: "#94a3b8" },
                        }
                        : undefined,
                },
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
        if (report.scan_started_at) {
            const parsed = new Date(report.scan_started_at);
            if (!Number.isNaN(parsed.getTime())) {
                return parsed.toLocaleString();
            }
        }
        return new Date((report.modified || 0) * 1000).toLocaleString();
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
        ]);
    },

    async loadConfigTab() {
        const config = await this.api("/api/config");
        const container = document.getElementById("configFields");

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

    setupPerformanceTab() {
        const profiles = {
            best: {
                label: "Best Performance",
                icon: "⚡",
                desc: "Max throughput. For servers with stable, fast connections.",
                settings: { nuclei_rate_limit: 150, wpscan_max_threads: 5, nikto_pause_seconds: 0, whatweb_max_threads: 25, httpx_rate_limit: 150, parallel_scans: true, max_parallel_tools: 4, max_parallel_heavy_tools: 3 },
            },
            stable: {
                label: "Stable",
                icon: "⚖️",
                desc: "Balanced speed and reliability. Safe for consumer routers.",
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
                desc: "Thorough WPScan enumeration + Nuclei WordPress templates. Best for WP targets.",
                settings: { nuclei_rate_limit: 25, wpscan_max_threads: 2, nikto_pause_seconds: 1, whatweb_max_threads: 5, httpx_rate_limit: 15, parallel_scans: true, max_parallel_tools: 3, max_parallel_heavy_tools: 2, nuclei_severity: "critical,high,medium,low" },
            },
            api: {
                label: "API / Web App",
                icon: "🌐",
                desc: "Skip WordPress-specific tools. Focus on HTTPX, Nuclei, and web tech detection.",
                settings: { nuclei_rate_limit: 30, wpscan_max_threads: 0, nikto_pause_seconds: 2, whatweb_max_threads: 10, httpx_rate_limit: 30, parallel_scans: true, max_parallel_tools: 3, max_parallel_heavy_tools: 2 },
            },
            quick: {
                label: "Quick Recon",
                icon: "🚀",
                desc: "Passive-only, fast results. Good for an initial overview before a deep scan.",
                settings: { nuclei_rate_limit: 15, wpscan_max_threads: 1, nikto_pause_seconds: 2, whatweb_max_threads: 5, httpx_rate_limit: 20, parallel_scans: true, max_parallel_tools: 3, max_parallel_heavy_tools: 1 },
            },
            aggressive: {
                label: "Aggressive Full",
                icon: "⚠️",
                desc: "Maximum coverage for authorized pentests. Very noisy — do not use on production without permission.",
                settings: { nuclei_rate_limit: 200, wpscan_max_threads: 5, nikto_pause_seconds: 0, whatweb_max_threads: 30, httpx_rate_limit: 200, parallel_scans: true, max_parallel_tools: 4, max_parallel_heavy_tools: 3 },
            },
        };

        // Render profile cards dynamically
        const container = document.getElementById("profileCards");
        if (container) {
            container.innerHTML = Object.entries(profiles).map(([key, p]) => `
                <button class="profile-card ${key === "stable" ? "selected" : ""}" data-profile="${key}">
                    <div class="profile-icon">${p.icon}</div>
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
