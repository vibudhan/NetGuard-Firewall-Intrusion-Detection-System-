// Network Security Monitor Dashboard JavaScript
class NetworkSecurityDashboard {
    constructor() {
        this.socket = null;
        this.charts = {};
        this.liveFeedPaused = false;
        this.maxLiveFeedItems = 100;
        this.stats = {
            total_packets: 0,
            blocked_packets: 0,
            alerts_count: 0
        };
        
        this.initializeSocket();
        this.initializeCharts();
        this.initializeEventListeners();
        this.loadInitialData();
    }
    
    initializeSocket() {
        console.log('Initializing Socket.IO connection...');
        this.socket = io();
        
        this.socket.on('connect', () => {
            console.log('Connected to server');
            this.updateConnectionStatus(true);
            this.showToast('Connected to Network Security Monitor', 'success');
        });
        
        this.socket.on('disconnect', () => {
            console.log('Disconnected from server');
            this.updateConnectionStatus(false);
            this.showToast('Connection lost. Attempting to reconnect...', 'error');
        });
        
        this.socket.on('connected', (data) => {
            console.log('Server connection confirmed:', data);
            this.updateStats(data.stats);
            this.updateAlerts(data.recent_alerts || []);
        });
        
        this.socket.on('packet_processed', (data) => {
            this.handlePacketProcessed(data);
        });
        
        this.socket.on('stats_update', (data) => {
            this.updateStats(data.stats);
            this.updateAlerts(data.recent_alerts || []);
        });
        
        this.socket.on('rule_added', (data) => {
            this.showToast(`Firewall rule added: ${data.rule.description}`, 'info');
            this.loadFirewallRules();
        });
        
        this.socket.on('rule_removed', (data) => {
            this.showToast('Firewall rule removed', 'info');
            this.loadFirewallRules();
        });
    }
    
    initializeCharts() {
        // Traffic Analysis Chart
        const trafficCtx = document.getElementById('traffic-chart');
        if (trafficCtx) {
            this.charts.traffic = new Chart(trafficCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [
                        {
                            label: 'Total Packets',
                            data: [],
                            borderColor: '#0d6efd',
                            backgroundColor: 'rgba(13, 110, 253, 0.1)',
                            tension: 0.4
                        },
                        {
                            label: 'Blocked Packets',
                            data: [],
                            borderColor: '#dc3545',
                            backgroundColor: 'rgba(220, 53, 69, 0.1)',
                            tension: 0.4
                        },
                        {
                            label: 'Alerts',
                            data: [],
                            borderColor: '#ffc107',
                            backgroundColor: 'rgba(255, 193, 7, 0.1)',
                            tension: 0.4
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: {
                            display: true,
                            title: { display: true, text: 'Time' }
                        },
                        y: {
                            display: true,
                            title: { display: true, text: 'Count' },
                            beginAtZero: true
                        }
                    },
                    plugins: {
                        legend: { position: 'top' },
                        tooltip: { mode: 'index', intersect: false }
                    }
                }
            });
        }
        
        // Protocol Distribution Chart
        const protocolCtx = document.getElementById('protocol-chart');
        if (protocolCtx) {
            this.charts.protocol = new Chart(protocolCtx, {
                type: 'doughnut',
                data: {
                    labels: ['TCP', 'UDP', 'ICMP'],
                    datasets: [{
                        data: [0, 0, 0],
                        backgroundColor: [
                            '#0d6efd',
                            '#198754',
                            '#fd7e14'
                        ],
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'bottom' },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = total > 0 ? Math.round((context.parsed * 100) / total) : 0;
                                    return `${context.label}: ${context.parsed} (${percentage}%)`;
                                }
                            }
                        }
                    }
                }
            });
        }
        
        // Initialize chart update intervals
        this.updateChartsInterval = setInterval(() => {
            this.updateCharts();
        }, 5000);
    }
    
    initializeEventListeners() {
        // Add rule form
        const addRuleForm = document.getElementById('add-rule-form');
        if (addRuleForm) {
            addRuleForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.addFirewallRule();
            });
        }
        
        // Alert severity filter
        const severityFilter = document.getElementById('alert-severity-filter');
        if (severityFilter) {
            severityFilter.addEventListener('change', () => {
                this.filterAlerts(severityFilter.value);
            });
        }
        
        // Navigation scroll behavior
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({ behavior: 'smooth' });
                }
            });
        });
    }
    
    async loadInitialData() {
        try {
            const response = await fetch('/api/stats');
            const data = await response.json();
            
            this.updateStats(data.stats);
            this.updateAlerts(data.alerts || []);
            this.updateFirewallRules(data.rules || []);
            
        } catch (error) {
            console.error('Failed to load initial data:', error);
            this.showToast('Failed to load initial data', 'error');
        }
    }
    
    handlePacketProcessed(data) {
        if (!this.liveFeedPaused) {
            this.addLiveActivity(data);
        }
        
        // Handle threats
        if (data.threats && data.threats.length > 0) {
            data.threats.forEach(threat => {
                this.showThreatToast(threat);
            });
        }
        
        // Update real-time stats
        if (data.stats) {
            this.updateRealTimeStats(data.stats);
        }
    }
    
    addLiveActivity(data) {
        const liveFeed = document.getElementById('live-activity');
        if (!liveFeed) return;
        
        const timestamp = new Date().toLocaleTimeString();
        const packet = data.packet;
        const blocked = data.blocked;
        const threats = data.threats || [];
        
        let cssClass = 'allowed';
        let icon = 'fa-check-circle';
        let status = 'ALLOWED';
        
        if (blocked) {
            cssClass = 'blocked';
            icon = 'fa-ban';
            status = 'BLOCKED';
        } else if (threats.length > 0) {
            cssClass = 'threat';
            icon = 'fa-exclamation-triangle';
            status = 'THREAT';
        }
        
        const activityItem = document.createElement('div');
        activityItem.className = `activity-item ${cssClass} new-item`;
        activityItem.innerHTML = `
            <div class="d-flex justify-content-between align-items-start">
                <div class="flex-grow-1">
                    <div class="d-flex align-items-center mb-1">
                        <i class="fas ${icon} me-2"></i>
                        <strong>${status}</strong>
                        <span class="badge badge-sm bg-secondary ms-2">${packet.protocol}</span>
                        <small class="text-muted ms-auto">${timestamp}</small>
                    </div>
                    <div class="text-muted small">
                        ${packet.src_ip}:${packet.src_port} → ${packet.dst_ip}:${packet.dst_port}
                        ${packet.size ? `(${packet.size} bytes)` : ''}
                    </div>
                    ${threats.length > 0 ? `
                        <div class="mt-1">
                            ${threats.map(t => `<span class="badge bg-warning me-1">${t.type}</span>`).join('')}
                        </div>
                    ` : ''}
                    ${blocked ? `
                        <div class="text-danger small mt-1">
                            <i class="fas fa-info-circle me-1"></i>${blocked.reason}
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
        
        liveFeed.insertBefore(activityItem, liveFeed.firstChild);
        
        // Remove animation class after animation completes
        setTimeout(() => {
            activityItem.classList.remove('new-item');
        }, 500);
        
        // Limit the number of items
        while (liveFeed.children.length > this.maxLiveFeedItems) {
            liveFeed.removeChild(liveFeed.lastChild);
        }
    }
    
    updateStats(stats) {
        if (!stats) return;
        
        this.stats = { ...stats };
        
        // Update stat cards
        document.getElementById('total-packets').textContent = 
            stats.total_packets?.toLocaleString() || '0';
        document.getElementById('blocked-packets').textContent = 
            stats.blocked_packets?.toLocaleString() || '0';
        document.getElementById('active-alerts').textContent = 
            stats.alerts_count?.toLocaleString() || '0';
        
        // Calculate and update block rate
        const blockRate = stats.total_packets > 0 ? 
            Math.round((stats.blocked_packets / stats.total_packets) * 100) : 0;
        document.getElementById('block-rate').textContent = `${blockRate}%`;
        
        // Update alert badge
        const alertBadge = document.getElementById('alert-badge');
        if (alertBadge) {
            alertBadge.textContent = stats.alerts_count || '0';
        }
        
        // Update top IPs and ports
        this.updateTopActivity(stats.top_ips, stats.top_ports);
        
        // Update protocol chart
        if (this.charts.protocol && stats.protocol_stats) {
            this.charts.protocol.data.datasets[0].data = [
                stats.protocol_stats.TCP || 0,
                stats.protocol_stats.UDP || 0,
                stats.protocol_stats.ICMP || 0
            ];
            this.charts.protocol.update('none');
        }
    }
    
    updateRealTimeStats(stats) {
        // Update only the counters for real-time updates
        document.getElementById('total-packets').textContent = 
            stats.total?.toLocaleString() || '0';
        document.getElementById('blocked-packets').textContent = 
            stats.blocked?.toLocaleString() || '0';
        document.getElementById('active-alerts').textContent = 
            stats.alerts?.toLocaleString() || '0';
        
        const blockRate = stats.total > 0 ? 
            Math.round((stats.blocked / stats.total) * 100) : 0;
        document.getElementById('block-rate').textContent = `${blockRate}%`;
    }
    
    updateTopActivity(topIps, topPorts) {
        // Update top IPs
        const topIpsContainer = document.getElementById('top-ips');
        if (topIpsContainer && topIps) {
            const maxCount = Math.max(...Object.values(topIps));
            topIpsContainer.innerHTML = Object.entries(topIps)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 5)
                .map(([ip, count]) => {
                    const percentage = maxCount > 0 ? (count / maxCount) * 100 : 0;
                    return `
                        <div class="activity-list-item">
                            <div>
                                <div class="fw-bold">${ip}</div>
                                <small class="text-muted">${count} packets</small>
                            </div>
                            <div class="activity-progress">
                                <div class="activity-progress-bar" style="width: ${percentage}%"></div>
                            </div>
                        </div>
                    `;
                }).join('') || '<p class="text-muted">No data available</p>';
        }
        
        // Update top ports
        const topPortsContainer = document.getElementById('top-ports');
        if (topPortsContainer && topPorts) {
            const maxCount = Math.max(...Object.values(topPorts));
            topPortsContainer.innerHTML = Object.entries(topPorts)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 5)
                .map(([port, count]) => {
                    const percentage = maxCount > 0 ? (count / maxCount) * 100 : 0;
                    const portName = this.getPortName(port);
                    return `
                        <div class="activity-list-item">
                            <div>
                                <div class="fw-bold">${port} ${portName ? `(${portName})` : ''}</div>
                                <small class="text-muted">${count} connections</small>
                            </div>
                            <div class="activity-progress">
                                <div class="activity-progress-bar" style="width: ${percentage}%"></div>
                            </div>
                        </div>
                    `;
                }).join('') || '<p class="text-muted">No data available</p>';
        }
    }
    
    updateAlerts(alerts) {
        const alertsTable = document.getElementById('alerts-table');
        const noAlertsDiv = document.getElementById('no-alerts');
        
        if (!alertsTable) return;
        
        if (!alerts || alerts.length === 0) {
            alertsTable.innerHTML = '';
            if (noAlertsDiv) noAlertsDiv.style.display = 'block';
            return;
        }
        
        if (noAlertsDiv) noAlertsDiv.style.display = 'none';
        
        alertsTable.innerHTML = alerts.map(alert => {
            const timestamp = new Date(alert.timestamp).toLocaleString();
            const severityClass = `severity-${alert.severity}`;
            const severityIcon = this.getSeverityIcon(alert.severity);
            
            return `
                <tr>
                    <td>
                        <small class="text-muted">${timestamp}</small>
                    </td>
                    <td>
                        <span class="badge ${severityClass}">
                            <i class="fas ${severityIcon} me-1"></i>${alert.severity.toUpperCase()}
                        </span>
                    </td>
                    <td>${alert.type}</td>
                    <td>
                        <small>${alert.description}</small>
                    </td>
                    <td>
                        <div class="alert-actions">
                            <button class="btn btn-sm btn-outline-secondary" 
                                    onclick="dashboard.acknowledgeAlert('${alert.id}')">
                                <i class="fas fa-check"></i>
                            </button>
                            <button class="btn btn-sm btn-outline-info" 
                                    onclick="dashboard.viewAlertDetails('${alert.id}')">
                                <i class="fas fa-info"></i>
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');
    }
    
    updateFirewallRules(rules) {
        const rulesTable = document.getElementById('firewall-rules-table');
        if (!rulesTable) return;
        
        if (!rules || rules.length === 0) {
            rulesTable.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No firewall rules configured</td></tr>';
            return;
        }
        
        rulesTable.innerHTML = rules.map(rule => {
            const statusClass = rule.enabled ? 'rule-enabled' : 'rule-disabled';
            const statusIcon = rule.enabled ? 'fa-check-circle' : 'fa-times-circle';
            const actionClass = rule.action === 'block' ? 'text-danger' : 'text-success';
            
            return `
                <tr>
                    <td>${rule.priority}</td>
                    <td>
                        <span class="badge bg-secondary">${rule.type.toUpperCase()}</span>
                    </td>
                    <td><code>${rule.value}</code></td>
                    <td>
                        <span class="${actionClass} fw-bold">${rule.action.toUpperCase()}</span>
                    </td>
                    <td>
                        <small>${rule.description || 'No description'}</small>
                    </td>
                    <td>
                        <span class="badge bg-info">${rule.hit_count || 0}</span>
                    </td>
                    <td>
                        <span class="${statusClass}">
                            <i class="fas ${statusIcon} me-1"></i>
                            ${rule.enabled ? 'Enabled' : 'Disabled'}
                        </span>
                    </td>
                    <td>
                        <button class="btn btn-sm btn-outline-danger" 
                                onclick="dashboard.removeRule('${rule.id}')" 
                                title="Delete Rule">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                </tr>
            `;
        }).join('');
    }
    
    async addFirewallRule() {
        const ruleType = document.getElementById('rule-type').value;
        const ruleValue = document.getElementById('rule-value').value;
        const ruleAction = document.getElementById('rule-action').value;
        const ruleDescription = document.getElementById('rule-description').value;
        
        if (!ruleType || !ruleValue || !ruleAction) {
            this.showToast('Please fill in all required fields', 'error');
            return;
        }
        
        try {
            const response = await fetch('/api/rules', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    type: ruleType,
                    value: ruleValue,
                    action: ruleAction,
                    description: ruleDescription
                })
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.showToast('Firewall rule added successfully', 'success');
                document.getElementById('add-rule-form').reset();
                
                // Close modal
                const modal = bootstrap.Modal.getInstance(document.getElementById('add-rule-modal'));
                if (modal) modal.hide();
                
                // Reload rules
                this.loadFirewallRules();
            } else {
                this.showToast(`Failed to add rule: ${result.error || 'Unknown error'}`, 'error');
            }
        } catch (error) {
            console.error('Error adding rule:', error);
            this.showToast('Error adding firewall rule', 'error');
        }
    }
    
    async removeRule(ruleId) {
        if (!confirm('Are you sure you want to delete this firewall rule?')) {
            return;
        }
        
        try {
            const response = await fetch(`/api/rules?id=${ruleId}`, {
                method: 'DELETE'
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.showToast('Firewall rule removed successfully', 'success');
                this.loadFirewallRules();
            } else {
                this.showToast('Failed to remove firewall rule', 'error');
            }
        } catch (error) {
            console.error('Error removing rule:', error);
            this.showToast('Error removing firewall rule', 'error');
        }
    }
    
    async loadFirewallRules() {
        try {
            const response = await fetch('/api/rules');
            const data = await response.json();
            this.updateFirewallRules(data.rules);
        } catch (error) {
            console.error('Error loading firewall rules:', error);
        }
    }
    
    updateCharts() {
        if (this.charts.traffic) {
            const now = new Date().toLocaleTimeString();
            const data = this.charts.traffic.data;
            
            // Add new data point
            data.labels.push(now);
            data.datasets[0].data.push(this.stats.total_packets || 0);
            data.datasets[1].data.push(this.stats.blocked_packets || 0);
            data.datasets[2].data.push(this.stats.alerts_count || 0);
            
            // Keep only last 20 data points
            if (data.labels.length > 20) {
                data.labels.shift();
                data.datasets.forEach(dataset => dataset.data.shift());
            }
            
            this.charts.traffic.update('none');
        }
    }
    
    updateConnectionStatus(connected) {
        const statusIcon = document.getElementById('connection-status');
        const statusText = document.getElementById('connection-text');
        
        if (statusIcon && statusText) {
            if (connected) {
                statusIcon.className = 'fas fa-circle text-success me-1';
                statusText.textContent = 'Connected';
            } else {
                statusIcon.className = 'fas fa-circle text-danger me-1';
                statusText.textContent = 'Disconnected';
            }
        }
    }
    
    showToast(message, type = 'info') {
        const toastContainer = document.getElementById('toast-container');
        if (!toastContainer) return;
        
        const toastId = 'toast-' + Date.now();
        const toastColors = {
            success: 'bg-success',
            error: 'bg-danger',
            warning: 'bg-warning',
            info: 'bg-info'
        };
        
        const toastHtml = `
            <div id="${toastId}" class="toast" role="alert">
                <div class="toast-header ${toastColors[type]} text-white">
                    <strong class="me-auto">Network Security Monitor</strong>
                    <small class="text-white-50">now</small>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast"></button>
                </div>
                <div class="toast-body">
                    ${message}
                </div>
            </div>
        `;
        
        toastContainer.insertAdjacentHTML('beforeend', toastHtml);
        const toastElement = document.getElementById(toastId);
        const toast = new bootstrap.Toast(toastElement);
        toast.show();
        
        // Remove toast element after it's hidden
        toastElement.addEventListener('hidden.bs.toast', () => {
            toastElement.remove();
        });
    }
    
    showThreatToast(threat) {
        const severityColors = {
            critical: 'bg-dark',
            high: 'bg-danger',
            medium: 'bg-warning',
            low: 'bg-success'
        };
        
        const toastContainer = document.getElementById('toast-container');
        if (!toastContainer) return;
        
        const toastId = 'threat-toast-' + Date.now();
        const toastHtml = `
            <div id="${toastId}" class="toast alert-toast alert-${threat.severity}" role="alert">
                <div class="toast-header ${severityColors[threat.severity]} text-white">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    <strong class="me-auto">${threat.type}</strong>
                    <small class="text-white-50">${threat.severity.toUpperCase()}</small>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast"></button>
                </div>
                <div class="toast-body">
                    ${threat.description}
                </div>
            </div>
        `;
        
        toastContainer.insertAdjacentHTML('beforeend', toastHtml);
        const toastElement = document.getElementById(toastId);
        const toast = new bootstrap.Toast(toastElement, { delay: 8000 });
        toast.show();
        
        toastElement.addEventListener('hidden.bs.toast', () => {
            toastElement.remove();
        });
    }
    
    getSeverityIcon(severity) {
        const icons = {
            critical: 'fa-exclamation-circle',
            high: 'fa-shield-exclamation',
            medium: 'fa-exclamation-triangle',
            low: 'fa-info-circle'
        };
        return icons[severity] || 'fa-info-circle';
    }
    
    getPortName(port) {
        const portNames = {
            '22': 'SSH',
            '23': 'Telnet',
            '25': 'SMTP',
            '53': 'DNS',
            '80': 'HTTP',
            '110': 'POP3',
            '143': 'IMAP',
            '443': 'HTTPS',
            '993': 'IMAPS',
            '995': 'POP3S',
            '3389': 'RDP',
            '5432': 'PostgreSQL',
            '3306': 'MySQL'
        };
        return portNames[port] || '';
    }
    
    // Utility methods for UI interactions
    pauseLiveFeed() {
        this.liveFeedPaused = !this.liveFeedPaused;
        const pauseBtn = document.getElementById('pause-btn');
        if (pauseBtn) {
            if (this.liveFeedPaused) {
                pauseBtn.innerHTML = '<i class="fas fa-play me-1"></i>Resume';
                pauseBtn.classList.add('btn-warning');
                pauseBtn.classList.remove('btn-outline-secondary');
            } else {
                pauseBtn.innerHTML = '<i class="fas fa-pause me-1"></i>Pause';
                pauseBtn.classList.remove('btn-warning');
                pauseBtn.classList.add('btn-outline-secondary');
            }
        }
    }
    
    clearLiveFeed() {
        const liveFeed = document.getElementById('live-activity');
        if (liveFeed) {
            liveFeed.innerHTML = '';
        }
    }
    
    filterAlerts(severity) {
        // This would typically filter the alerts display
        // For now, we'll just reload with the filter
        console.log('Filtering alerts by severity:', severity);
    }
    
    acknowledgeAlert(alertId) {
        console.log('Acknowledging alert:', alertId);
        this.showToast('Alert acknowledged', 'success');
    }
    
    viewAlertDetails(alertId) {
        console.log('Viewing alert details:', alertId);
        // This would show a detailed modal
    }
}

// Global functions for window scope
window.pauseLiveFeed = function() {
    if (window.dashboard) window.dashboard.pauseLiveFeed();
};

window.clearLiveFeed = function() {
    if (window.dashboard) window.dashboard.clearLiveFeed();
};

window.exportAlerts = async function() {
    try {
        const response = await fetch('/api/alerts/export');
        const data = await response.json();
        
        const blob = new Blob([JSON.stringify(data, null, 2)], { 
            type: 'application/json' 
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `security-alerts-${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        URL.revokeObjectURL(url);
        
        if (window.dashboard) {
            window.dashboard.showToast('Alerts exported successfully', 'success');
        }
    } catch (error) {
        console.error('Error exporting alerts:', error);
        if (window.dashboard) {
            window.dashboard.showToast('Error exporting alerts', 'error');
        }
    }
};

// Initialize dashboard
function initializeDashboard() {
    window.dashboard = new NetworkSecurityDashboard();
}
