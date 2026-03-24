document.addEventListener('DOMContentLoaded', () => {
    if (window.location.protocol === 'file:') {
        alert("CRITICAL ERROR: You opened this file directly!\n\nYou must run the backend server first:\n1. Open your terminal\n2. Run: pip install flask\n3. Run: python app.py\n4. Visit http://localhost:5000 in your browser.");
        document.body.innerHTML = "<h1 style='text-align:center; padding-top: 50px; color: #ef4444;'>Backend Offline. Please run 'python app.py' and visit http://localhost:5000</h1>";
        return;
    }
    initDashboard();
});

async function initDashboard() {
    await fetchStatsAndRenderChart();
    await fetchTargets();
    setupScanForm();
}

async function fetchStatsAndRenderChart() {
    try {
        const response = await fetch('/api/monthly-stats');
        const data = await response.json();
        
        const ctx = document.getElementById('monthlyChart').getContext('2d');
        
        // Dark theme configuration for Chart.js
        Chart.defaults.color = '#94a3b8';
        Chart.defaults.font.family = 'Inter';
        
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: data.labels.length > 0 ? data.labels : ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
                datasets: [
                    {
                        label: 'Critical',
                        data: data.datasets ? data.datasets.critical : [0,0,0,0,0,0],
                        backgroundColor: '#ef4444',
                        borderRadius: 4,
                    },
                    {
                        label: 'High',
                        data: data.datasets ? data.datasets.high : [0,0,0,0,0,0],
                        backgroundColor: '#f97316',
                        borderRadius: 4,
                    },
                    {
                        label: 'Medium',
                        data: data.datasets ? data.datasets.medium : [0,0,0,0,0,0],
                        backgroundColor: '#f59e0b',
                        borderRadius: 4,
                    },
                    {
                        label: 'Low',
                        data: data.datasets ? data.datasets.low : [0,0,0,0,0,0],
                        backgroundColor: '#3b82f6',
                        borderRadius: 4,
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    mode: 'index',
                    intersect: false,
                },
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            usePointStyle: true,
                            padding: 20
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(30, 33, 48, 0.9)',
                        titleColor: '#fff',
                        bodyColor: '#e2e8f0',
                        borderColor: 'rgba(255,255,255,0.1)',
                        borderWidth: 1,
                        padding: 12
                    }
                },
                scales: {
                    x: {
                        stacked: true,
                        grid: {
                            color: 'rgba(255,255,255,0.05)',
                            drawBorder: false
                        }
                    },
                    y: {
                        stacked: true,
                        grid: {
                            color: 'rgba(255,255,255,0.05)',
                            drawBorder: false
                        },
                        beginAtZero: true
                    }
                }
            }
        });
    } catch (error) {
        console.error("Failed to load chart data:", error);
    }
}

async function fetchTargets() {
    const targetList = document.getElementById('targetList');
    try {
        const response = await fetch('/api/targets');
        const data = await response.json();
        
        targetList.innerHTML = '';
        
        if (data.length === 0) {
            targetList.innerHTML = '<li class="text-muted">No known targets.</li>';
            return;
        }
        
        data.forEach(target => {
            const li = document.createElement('li');
            li.innerHTML = `
                <span>${target.label}</span>
                <a href="${target.url}" target="_blank" class="target-url">${target.url}</a>
            `;
            
            // Add click-to-scan functionality
            li.style.cursor = 'pointer';
            li.addEventListener('click', () => {
                document.getElementById('targetUrl').value = target.url;
            });
            
            targetList.appendChild(li);
        });
        
    } catch (error) {
        targetList.innerHTML = '<li class="text-muted" style="color:#ef4444">Failed to load targets.</li>';
    }
}

function setupScanForm() {
    const form = document.getElementById('scanForm');
    const statusDiv = document.getElementById('scanStatus');
    const btn = document.getElementById('startScanBtn');
    
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const target = document.getElementById('targetUrl').value;
        const mode = document.getElementById('scanMode').value;
        
        if (!target) return;
        
        // UI Loading State
        btn.innerHTML = `<svg class="spinner" viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="2" x2="12" y2="6"></line><line x1="12" y1="18" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"></line><line x1="2" y1="12" x2="6" y2="12"></line><line x1="18" y1="12" x2="22" y2="12"></line><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"></line><line x1="16.24" y1="4.93" x2="19.07" y2="7.76"></line></svg> <span>Initiating Task...</span>`;
        btn.style.opacity = '0.7';
        btn.disabled = true;
        statusDiv.className = 'status-message hidden';
        
        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target, mode })
            });
            
            const result = await response.json();
            
            if (response.ok) {
                statusDiv.innerHTML = `<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none" style="margin-right:4px; vertical-align:middle"><polyline points="20 6 9 17 4 12"></polyline></svg> Scan Initiated in VM Background! Please check your terminal or reload this page later to see the new report.`;
                statusDiv.className = 'status-message';
                statusDiv.style.backgroundColor = 'rgba(16, 185, 129, 0.1)';
                statusDiv.style.color = '#10b981';
            } else {
                statusDiv.textContent = result.error || 'Failed to start scan';
                statusDiv.className = 'status-message';
                statusDiv.style.backgroundColor = 'rgba(239, 68, 68, 0.1)';
                statusDiv.style.color = '#ef4444';
            }
        } catch (error) {
            statusDiv.textContent = 'Server connection error';
            statusDiv.className = 'status-message';
            statusDiv.style.backgroundColor = 'rgba(239, 68, 68, 0.1)';
            statusDiv.style.color = '#ef4444';
        } finally {
            // Restore button
            btn.innerHTML = `<span>Initiate Sequence</span><svg viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>`;
            btn.style.opacity = '1';
            btn.disabled = false;
        }
    });
}
