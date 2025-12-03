/**
 * WiFi Security Educator v2.0.0
 * Main JavaScript Application
 */

// ========== GLOBAL VARIABLES ==========
const API_BASE = '/api/v1';
let currentScan = null;
let currentAnalysis = null;

// ========== UTILITY FUNCTIONS ==========
class Utils {
    static showLoading(element, message = 'Loading...') {
        if (element) {
            element.innerHTML = `
                <div class="text-center py-4">
                    <div class="spinner-border text-primary" role="status">
                        <span class="visually-hidden">Loading...</span>
                    </div>
                    <p class="mt-2 text-muted">${message}</p>
                </div>
            `;
        }
    }

    static showError(element, message) {
        if (element) {
            element.innerHTML = `
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle"></i>
                    <strong>Error:</strong> ${message}
                </div>
            `;
        }
        console.error(message);
    }

    static showSuccess(element, message) {
        if (element) {
            element.innerHTML = `
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i>
                    ${message}
                </div>
            `;
        }
    }

    static formatDateTime(dateString) {
        const date = new Date(dateString);
        return date.toLocaleString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    static formatSignalStrength(dbm) {
        if (dbm >= -50) return { level: 'Excellent', color: 'success', bars: 5 };
        if (dbm >= -60) return { level: 'Good', color: 'success', bars: 4 };
        if (dbm >= -70) return { level: 'Fair', color: 'warning', bars: 3 };
        if (dbm >= -80) return { level: 'Weak', color: 'warning', bars: 2 };
        return { level: 'Poor', color: 'danger', bars: 1 };
    }

    static formatSecurityScore(score) {
        if (score >= 80) return { level: 'Very Secure', class: 'badge-security-safe', color: '#20c997' };
        if (score >= 60) return { level: 'Secure', class: 'badge-security-low', color: '#198754' };
        if (score >= 40) return { level: 'Moderate', class: 'badge-security-medium', color: '#ffc107' };
        if (score >= 20) return { level: 'Risky', class: 'badge-security-high', color: '#fd7e14' };
        return { level: 'Critical', class: 'badge-security-critical', color: '#dc3545' };
    }

    static copyToClipboard(text) {
        navigator.clipboard.writeText(text)
            .then(() => this.showNotification('Copied to clipboard!', 'success'))
            .catch(err => this.showNotification('Failed to copy', 'error'));
    }

    static showNotification(message, type = 'info', duration = 3000) {
        // Remove existing notifications
        const existing = document.querySelector('.app-notification');
        if (existing) existing.remove();

        // Create notification element
        const notification = document.createElement('div');
        notification.className = `app-notification alert alert-${type} alert-dismissible fade show`;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 9999;
            min-width: 300px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            animation: slideInRight 0.3s ease;
        `;

        const icon = type === 'success' ? 'fa-check-circle' :
                    type === 'error' ? 'fa-times-circle' :
                    type === 'warning' ? 'fa-exclamation-triangle' : 'fa-info-circle';

        notification.innerHTML = `
            <div class="d-flex align-items-center">
                <i class="fas ${icon} me-2 fs-5"></i>
                <div class="flex-grow-1">${message}</div>
                <button type="button" class="btn-close" onclick="this.parentElement.parentElement.remove()"></button>
            </div>
        `;

        document.body.appendChild(notification);

        // Auto remove after duration
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, duration);
    }

    static animateValue(element, start, end, duration) {
        let startTimestamp = null;
        const step = (timestamp) => {
            if (!startTimestamp) startTimestamp = timestamp;
            const progress = Math.min((timestamp - startTimestamp) / duration, 1);
            const value = Math.floor(progress * (end - start) + start);
            element.textContent = value;
            if (progress < 1) {
                window.requestAnimationFrame(step);
            }
        };
        window.requestAnimationFrame(step);
    }
}

// ========== SCAN MODULE ==========
class ScanModule {
    static async startScan() {
        const scanBtn = document.getElementById('scanBtn');
        const scanResults = document.getElementById('scanResults');
        
        if (!scanBtn || !scanResults) return;

        // Update UI
        scanBtn.disabled = true;
        scanBtn.innerHTML = '<i class="fas fa-sync-alt fa-spin"></i> Scanning...';
        
        Utils.showLoading(scanResults, 'Scanning for WiFi networks...');

        try {
            const response = await fetch(`${API_BASE}/scan`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            const data = await response.json();

            if (data.success) {
                currentScan = data.data;
                this.displayScanResults(currentScan);
                Utils.showNotification(`Found ${data.data.networks_found} networks`, 'success');
            } else {
                Utils.showError(scanResults, data.message);
            }
        } catch (error) {
            Utils.showError(scanResults, 'Network error: ' + error.message);
        } finally {
            scanBtn.disabled = false;
            scanBtn.innerHTML = '<i class="fas fa-wifi"></i> Start Scan';
        }
    }

    static displayScanResults(scanData) {
        const scanResults = document.getElementById('scanResults');
        if (!scanResults) return;

        let html = `
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i>
                Scan completed in ${scanData.duration_ms}ms
            </div>
            
            <div class="row">
        `;

        scanData.networks.forEach((network, index) => {
            const signal = Utils.formatSignalStrength(network.signal);
            const security = Utils.formatSecurityScore(network.security_score);
            
            html += `
                <div class="col-md-6 col-lg-4 mb-4">
                    <div class="network-card ${network.encryption === 'OPEN' ? 'unencrypted' : 'encrypted'}">
                        <div class="d-flex justify-content-between align-items-start mb-3">
                            <div>
                                <h5 class="mb-1">${network.ssid}</h5>
                                <small class="text-muted">${network.bssid}</small>
                            </div>
                            <span class="badge ${security.class}">${security.level}</span>
                        </div>
                        
                        <div class="mb-3">
                            <div class="d-flex justify-content-between mb-2">
                                <small class="text-muted">Signal: ${signal.level}</small>
                                <small class="text-muted">${network.signal} dBm</small>
                            </div>
                            <div class="signal-strength">
                                ${Array(5).fill().map((_, i) => `
                                    <div class="signal-bar ${i < signal.bars ? signal.color : ''}" 
                                         style="height: ${(i+1)*4 + 12}px"></div>
                                `).join('')}
                            </div>
                        </div>
                        
                        <div class="row mb-3">
                            <div class="col-6">
                                <small><i class="fas fa-shield-alt"></i> ${network.encryption}</small>
                            </div>
                            <div class="col-6 text-end">
                                <small><i class="fas fa-broadcast-tower"></i> Ch ${network.channel}</small>
                            </div>
                        </div>
                        
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <small class="text-muted">${network.vendor || 'Unknown'} • ${network.frequency}</small>
                            </div>
                            <button class="btn btn-sm btn-outline-primary analyze-network-btn" 
                                    data-network-id="${index + 1}">
                                <i class="fas fa-search"></i> Analyze
                            </button>
                        </div>
                    </div>
                </div>
            `;
        });

        html += '</div>';
        scanResults.innerHTML = html;

        // Re-bind analyze buttons
        document.querySelectorAll('.analyze-network-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const networkId = e.target.closest('button').dataset.networkId;
                AnalysisModule.analyzeNetwork(networkId);
            });
        });
    }

    static clearScanResults() {
        const scanResults = document.getElementById('scanResults');
        if (scanResults) {
            scanResults.innerHTML = `
                <div class="alert alert-info">
                    <i class="fas fa-info-circle"></i>
                    Click "Start Scan" to begin scanning for WiFi networks.
                </div>
            `;
        }
    }
}

// ========== ANALYSIS MODULE ==========
class AnalysisModule {
    static async analyzeNetwork(networkId) {
        const modalElement = document.getElementById('analysisModal');
        const modalBody = document.getElementById('analysisModalBody');
        
        if (!modalElement || !modalBody) return;

        Utils.showLoading(modalBody, 'Analyzing network security...');

        // Show modal
        const modal = new bootstrap.Modal(modalElement);
        modal.show();

        try {
            const response = await fetch(`${API_BASE}/analyze/${networkId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            const data = await response.json();

            if (data.success) {
                currentAnalysis = data.analysis;
                this.displayAnalysis(currentAnalysis);
            } else {
                Utils.showError(modalBody, data.message);
            }
        } catch (error) {
            Utils.showError(modalBody, 'Analysis error: ' + error.message);
        }
    }

    static displayAnalysis(analysis) {
        const modalBody = document.getElementById('analysisModalBody');
        if (!modalBody) return;

        const network = analysis.network;
        const security = Utils.formatSecurityScore(network.security_score || 75);

        let checksHtml = '';
        analysis.checks.forEach(check => {
            const icon = check.status === 'PASS' ? 'fa-check-circle text-success' :
                        check.status === 'FAIL' ? 'fa-times-circle text-danger' :
                        'fa-exclamation-triangle text-warning';
            
            checksHtml += `
                <div class="d-flex justify-content-between align-items-center py-2 border-bottom">
                    <div>
                        <i class="fas ${icon} me-2"></i>
                        ${check.name}
                    </div>
                    <div>
                        <span class="badge ${check.status === 'PASS' ? 'bg-success' : 
                                         check.status === 'FAIL' ? 'bg-danger' : 'bg-warning'}">
                            ${check.status}
                        </span>
                        <small class="text-muted ms-2">${check.weight} pts</small>
                    </div>
                </div>
            `;
        });

        let recHtml = '';
        analysis.recommendations.forEach(rec => {
            recHtml += `<li class="mb-2"><i class="fas fa-chevron-right text-primary me-2"></i>${rec}</li>`;
        });

        modalBody.innerHTML = `
            <div class="analysis-result">
                <div class="text-center mb-4">
                    <h4>${network.ssid || 'Unknown Network'}</h4>
                    <span class="badge ${security.class}">${security.level}</span>
                </div>
                
                <div class="mb-4">
                    <h6><i class="fas fa-clipboard-check me-2"></i>Security Checks</h6>
                    ${checksHtml}
                    
                    <div class="mt-3">
                        <div class="d-flex justify-content-between mb-2">
                            <strong>Overall Security Score:</strong>
                            <strong>${network.security_score || 75}/100</strong>
                        </div>
                        <div class="progress" style="height: 10px;">
                            <div class="progress-bar" style="width: ${network.security_score || 75}%; background: ${security.color}"></div>
                        </div>
                    </div>
                </div>
                
                <div class="mb-4">
                    <h6><i class="fas fa-lightbulb me-2"></i>Recommendations</h6>
                    <ul class="list-unstyled ps-3">
                        ${recHtml}
                    </ul>
                </div>
                
                <div class="alert alert-info">
                    <i class="fas fa-info-circle me-2"></i>
                    Threat Level: <strong class="text-uppercase">${analysis.threat_level}</strong>
                </div>
            </div>
        `;
    }
}

// ========== PASSWORD GENERATOR MODULE ==========
class PasswordGenerator {
    static async generatePassword() {
        const generateBtn = document.getElementById('generatePasswordBtn');
        const passwordResult = document.getElementById('passwordResult');
        
        if (!generateBtn || !passwordResult) return;

        generateBtn.disabled = true;
        generateBtn.innerHTML = '<i class="fas fa-sync-alt fa-spin"></i> Generating...';
        Utils.showLoading(passwordResult, 'Generating secure password...');

        try {
            const response = await fetch(`${API_BASE}/generate-password`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    length: 16,
                    include_symbols: true,
                    include_numbers: true
                })
            });

            const data = await response.json();

            if (data.success) {
                this.displayPasswordResult(data);
                Utils.showNotification('Password generated!', 'success');
            } else {
                Utils.showError(passwordResult, data.message);
            }
        } catch (error) {
            Utils.showError(passwordResult, 'Generation error: ' + error.message);
        } finally {
            generateBtn.disabled = false;
            generateBtn.innerHTML = '<i class="fas fa-key"></i> Generate Password';
        }
    }

    static displayPasswordResult(data) {
        const passwordResult = document.getElementById('passwordResult');
        if (!passwordResult) return;

        const strengthClass = data.strength === 'STRONG' ? 'badge-security-safe' :
                            data.strength === 'MEDIUM' ? 'badge-security-medium' :
                            'badge-security-high';

        passwordResult.innerHTML = `
            <div class="password-result">
                <h5><i class="fas fa-key me-2"></i>Generated Password</h5>
                
                <div class="input-group mb-3">
                    <input type="text" 
                           class="form-control form-control-lg" 
                           value="${data.password}" 
                           id="generatedPassword" 
                           readonly
                           style="font-family: monospace; font-size: 1.2rem;">
                    <button class="btn btn-outline-secondary" type="button" onclick="copyPassword()">
                        <i class="fas fa-copy"></i> Copy
                    </button>
                </div>
                
                <div class="row">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-body">
                                <h6>Password Details</h6>
                                <ul class="list-unstyled">
                                    <li><i class="fas fa-ruler me-2"></i>Length: ${data.length} characters</li>
                                    <li><i class="fas fa-shield-alt me-2"></i>Strength: 
                                        <span class="badge ${strengthClass}">${data.strength}</span>
                                    </li>
                                    <li><i class="fas fa-chart-line me-2"></i>Score: ${data.score}/100</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-body">
                                <h6>Hashes</h6>
                                <small class="text-muted">MD5: ${data.hash_md5}</small><br>
                                <small class="text-muted">SHA256: ${data.hash_sha256.substring(0, 32)}...</small>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="alert alert-info mt-3">
                    <i class="fas fa-lightbulb me-2"></i>
                    <strong>Tip:</strong> Use a password manager to store this password securely.
                </div>
            </div>
        `;
    }

    static copyPassword() {
        const passwordField = document.getElementById('generatedPassword');
        if (passwordField) {
            Utils.copyToClipboard(passwordField.value);
        }
    }
}

// ========== REPORT MODULE ==========
class ReportModule {
    static async generateReport() {
        const generateBtn = document.getElementById('generateReportBtn');
        const reportTitle = document.getElementById('reportTitle');
        const reportResult = document.getElementById('reportResult');
        
        if (!generateBtn || !reportResult) return;

        generateBtn.disabled = true;
        generateBtn.innerHTML = '<i class="fas fa-sync-alt fa-spin"></i> Generating...';
        Utils.showLoading(reportResult, 'Generating security report...');

        try {
            const response = await fetch(`${API_BASE}/generate-report`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    title: reportTitle ? reportTitle.value : 'WiFi Security Report'
                })
            });

            const data = await response.json();

            if (data.success) {
                this.displayReportResult(data);
                Utils.showNotification('Report generated successfully!', 'success');
            } else {
                Utils.showError(reportResult, data.message);
            }
        } catch (error) {
            Utils.showError(reportResult, 'Report error: ' + error.message);
        } finally {
            generateBtn.disabled = false;
            generateBtn.innerHTML = '<i class="fas fa-file-pdf"></i> Generate Report';
        }
    }

    static displayReportResult(data) {
        const reportResult = document.getElementById('reportResult');
        if (!reportResult) return;

        reportResult.innerHTML = `
            <div class="report-result">
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i>
                    Report generated successfully!
                </div>
                
                <div class="card">
                    <div class="card-body">
                        <h5><i class="fas fa-file-alt me-2"></i>Report Details</h5>
                        <ul class="list-unstyled">
                            <li><strong>Report ID:</strong> ${data.report_id}</li>
                            <li><strong>Generated:</strong> ${new Date().toLocaleString()}</li>
                            <li><strong>Download:</strong> 
                                <a href="${data.download_url}" class="btn btn-sm btn-primary ms-2">
                                    <i class="fas fa-download"></i> Download JSON
                                </a>
                            </li>
                        </ul>
                        
                        <div class="mt-3">
                            <button class="btn btn-outline-primary" onclick="viewReport('${data.report_id}')">
                                <i class="fas fa-eye"></i> View Report
                            </button>
                            <button class="btn btn-outline-success ms-2" onclick="shareReport('${data.report_id}')">
                                <i class="fas fa-share"></i> Share
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    static viewReport(reportId) {
        window.location.href = `/report/${reportId}`;
    }

    static shareReport(reportId) {
        const url = `${window.location.origin}/report/${reportId}`;
        if (navigator.share) {
            navigator.share({
                title: 'WiFi Security Report',
                text: 'Check out this WiFi security report',
                url: url
            });
        } else {
            Utils.copyToClipboard(url);
        }
    }
}

// ========== DASHBOARD MODULE ==========
class DashboardModule {
    static async loadStats() {
        const statsElement = document.getElementById('statsContainer');
        if (!statsElement) return;

        try {
            const response = await fetch(`${API_BASE}/status`);
            const data = await response.json();

            if (data.status === 'online') {
                this.updateStats(data);
            }
        } catch (error) {
            console.error('Failed to load stats:', error);
        }
    }

    static updateStats(data) {
        // Update stats counters with animation
        const elements = {
            'totalScans': data.scans_count,
            'networksFound': data.networks_found || 0,
            'reportsCount': data.reports_count
        };

        Object.keys(elements).forEach(key => {
            const element = document.getElementById(key);
            if (element) {
                const current = parseInt(element.textContent) || 0;
                const target = elements[key];
                
                if (current !== target) {
                    Utils.animateValue(element, current, target, 1000);
                }
            }
        });

        // Update server status
        const serverStatus = document.getElementById('serverStatus');
        if (serverStatus) {
            serverStatus.innerHTML = `
                <span class="badge bg-success">ONLINE</span>
                <small class="text-muted ms-2">v${data.version}</small>
            `;
        }
    }
}

// ========== SETTINGS MODULE ==========
class SettingsModule {
    static async clearAllData() {
        if (!confirm('Are you sure you want to clear ALL data? This cannot be undone.')) {
            return;
        }

        try {
            const response = await fetch(`${API_BASE}/clear-data`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            const data = await response.json();

            if (data.success) {
                Utils.showNotification('All data cleared successfully!', 'success');
                
                // Clear UI elements
                ScanModule.clearScanResults();
                
                // Reload dashboard if on dashboard page
                if (document.getElementById('statsContainer')) {
                    DashboardModule.loadStats();
                }
            } else {
                Utils.showNotification('Failed to clear data: ' + data.message, 'error');
            }
        } catch (error) {
            Utils.showNotification('Clear data error: ' + error.message, 'error');
        }
    }

    static exportData() {
        const data = {
            scans: currentScan,
            analysis: currentAnalysis,
            timestamp: new Date().toISOString(),
            version: '2.0.0'
        };

        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `wifi-security-data-${new Date().getTime()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        Utils.showNotification('Data exported successfully!', 'success');
    }

    static importData() {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = '.json';
        
        input.onchange = (e) => {
            const file = e.target.files[0];
            const reader = new FileReader();
            
            reader.onload = (event) => {
                try {
                    const data = JSON.parse(event.target.result);
                    
                    // Validate data structure
                    if (data.scans && data.version) {
                        currentScan = data.scans;
                        currentAnalysis = data.analysis;
                        
                        // Update UI if on scan page
                        if (document.getElementById('scanResults')) {
                            ScanModule.displayScanResults(currentScan);
                        }
                        
                        Utils.showNotification('Data imported successfully!', 'success');
                    } else {
                        throw new Error('Invalid data format');
                    }
                } catch (error) {
                    Utils.showNotification('Failed to import data: ' + error.message, 'error');
                }
            };
            
            reader.readAsText(file);
        };
        
        input.click();
    }
}

// ========== INITIALIZATION ==========
document.addEventListener('DOMContentLoaded', function() {
    console.log('WiFi Security Educator v2.0.0 loaded');
    
    // Initialize modules based on current page
    initializePage();
    
    // Load dashboard stats if on dashboard
    if (document.getElementById('statsContainer')) {
        DashboardModule.loadStats();
        // Refresh stats every 30 seconds
        setInterval(() => DashboardModule.loadStats(), 30000);
    }
    
    // Check server status
    checkServerStatus();
});

function initializePage() {
    // Bind scan button
    const scanBtn = document.getElementById('scanBtn');
    if (scanBtn) {
        scanBtn.addEventListener('click', () => ScanModule.startScan());
    }
    
    // Bind generate password button
    const generatePasswordBtn = document.getElementById('generatePasswordBtn');
    if (generatePasswordBtn) {
        generatePasswordBtn.addEventListener('click', () => PasswordGenerator.generatePassword());
    }
    
    // Bind generate report button
    const generateReportBtn = document.getElementById('generateReportBtn');
    if (generateReportBtn) {
        generateReportBtn.addEventListener('click', () => ReportModule.generateReport());
    }
    
    // Bind clear data button
    const clearDataBtn = document.getElementById('clearDataBtn');
    if (clearDataBtn) {
        clearDataBtn.addEventListener('click', () => SettingsModule.clearAllData());
    }
    
    // Bind export button
    const exportBtn = document.getElementById('exportDataBtn');
    if (exportBtn) {
        exportBtn.addEventListener('click', () => SettingsModule.exportData());
    }
    
    // Bind import button
    const importBtn = document.getElementById('importDataBtn');
    if (importBtn) {
        importBtn.addEventListener('click', () => SettingsModule.importData());
    }
    
    // Bind analyze buttons dynamically
    document.addEventListener('click', (e) => {
        if (e.target.closest('.analyze-network-btn')) {
            const networkId = e.target.closest('.analyze-network-btn').dataset.networkId;
            AnalysisModule.analyzeNetwork(networkId);
        }
    });
}

async function checkServerStatus() {
    try {
        const response = await fetch(`${API_BASE}/status`);
        const data = await response.json();
        
        if (data.status === 'online') {
            console.log('Server status: ONLINE', data);
        }
    } catch (error) {
        console.warn('Server status check failed:', error);
        Utils.showNotification('Cannot connect to server', 'warning', 5000);
    }
}

// ========== GLOBAL EXPORTS ==========
window.ScanModule = ScanModule;
window.AnalysisModule = AnalysisModule;
window.PasswordGenerator = PasswordGenerator;
window.ReportModule = ReportModule;
window.DashboardModule = DashboardModule;
window.SettingsModule = SettingsModule;
window.Utils = Utils;

// Convenience functions for HTML onclick attributes
window.startScan = () => ScanModule.startScan();
window.analyzeNetwork = (id) => AnalysisModule.analyzeNetwork(id);
window.generatePassword = () => PasswordGenerator.generatePassword();
window.generateReport = () => ReportModule.generateReport();
window.clearAllData = () => SettingsModule.clearAllData();
window.copyPassword = () => PasswordGenerator.copyPassword();
window.viewReport = (id) => ReportModule.viewReport(id);
window.shareReport = (id) => ReportModule.shareReport(id);
window.showNotification = (msg, type) => Utils.showNotification(msg, type);

// Add CSS for animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideInRight {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    
    .network-card {
        transition: all 0.3s ease;
    }
    
    .network-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 10px 25px rgba(0,0,0,0.1);
    }
    
    .signal-bar {
        transition: all 0.3s ease;
    }
`;
document.head.appendChild(style);

console.log('Application initialized successfully!');