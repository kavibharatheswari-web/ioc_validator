const API_URL = 'http://localhost:5000/api';
let authToken = localStorage.getItem('authToken');
let currentAnalysisIds = [];
let currentAnalysisResults = []; // Store current analysis results
let allHistoryData = []; // Store all history for filtering

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
    // Load dark mode preference
    const darkMode = localStorage.getItem('darkMode') === 'true';
    if (darkMode) {
        document.body.classList.add('dark-mode');
    }
    
    // Update dark mode button text
    updateDarkModeButton();
    
    if (authToken) {
        showApp();
        loadTimezoneSetting();  // Load timezone first
        loadDashboard();
        loadHistory();
        loadApiKeys();
        loadRetentionSetting();
    } else {
        showAuth();
    }

    // File input change handler
    document.getElementById('iocFile').addEventListener('change', (e) => {
        const fileName = e.target.files[0]?.name || 'No file chosen';
        document.getElementById('fileName').textContent = fileName;
    });
});

// Auth Functions
function showAuth() {
    document.getElementById('authSection').style.display = 'flex';
    document.getElementById('appSection').style.display = 'none';
    document.getElementById('mainNavbar').style.display = 'none';
    document.getElementById('authDarkModeToggle').style.display = 'block';
}
function showApp() {
    document.getElementById('authSection').style.display = 'none';
    document.getElementById('appSection').style.display = 'block';
    document.getElementById('mainNavbar').style.display = 'block';
    document.getElementById('authDarkModeToggle').style.display = 'none';
    updateDarkModeButton();
}

function showRegister() {
    document.getElementById('loginForm').style.display = 'none';
    document.getElementById('registerForm').style.display = 'block';
    document.getElementById('forgotPasswordForm').style.display = 'none';
}

function showLogin() {
    document.getElementById('loginForm').style.display = 'block';
    document.getElementById('registerForm').style.display = 'none';
    document.getElementById('forgotPasswordForm').style.display = 'none';
}

function showForgotPassword() {
    document.getElementById('loginForm').style.display = 'none';
    document.getElementById('registerForm').style.display = 'none';
    document.getElementById('forgotPasswordForm').style.display = 'block';
}

async function login(event) {
    event.preventDefault();
    
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;
    
    try {
        const response = await fetch(`${API_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            authToken = data.token;
            localStorage.setItem('authToken', authToken);
            showApp();
            loadDashboard();
            loadHistory();
            loadApiKeys();
            showNotification('Login successful!', 'success');
        } else {
            showNotification(data.error || 'Login failed', 'error');
        }
    } catch (error) {
        showNotification('Network error', 'error');
    }
}

async function register(event) {
    event.preventDefault();
    
    const username = document.getElementById('registerUsername').value;
    const email = document.getElementById('registerEmail').value;
    const password = document.getElementById('registerPassword').value;
    
    try {
        const response = await fetch(`${API_URL}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showNotification('Registration successful! Please login.', 'success');
            showLogin();
        } else {
            showNotification(data.error || 'Registration failed', 'error');
        }
    } catch (error) {
        showNotification('Network error', 'error');
    }
}

async function forgotPassword(event) {
    event.preventDefault();
    
    const email = document.getElementById('forgotEmail').value;
    
    try {
        const response = await fetch(`${API_URL}/forgot-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showNotification(data.message, 'success');
            // Show login form after 2 seconds
            setTimeout(() => {
                showLogin();
            }, 2000);
        } else {
            showNotification(data.error || 'Failed to send recovery email', 'error');
        }
    } catch (error) {
        showNotification('Network error', 'error');
    }
}

function logout() {
    authToken = null;
    localStorage.removeItem('authToken');
    showAuth();
    showNotification('Logged out successfully', 'success');
}

// Navigation
function showSection(sectionId) {
    document.querySelectorAll('.section').forEach(section => {
        section.classList.remove('active');
    });
    document.getElementById(sectionId).classList.add('active');
    
    // Show/hide dark mode toggle based on the current section
    const darkModeBtn = document.getElementById('darkModeBtn');
    if (darkModeBtn) {
        if (sectionId === 'history') {
            darkModeBtn.style.display = 'none';
        } else {
            darkModeBtn.style.display = 'inline-block';
        }
    }
    
    if (sectionId === 'dashboard') {
        loadDashboard();
    } else if (sectionId === 'history') {
        loadHistory();
    } else if (sectionId === 'settings') {
        loadApiKeys();
    }
}

// Tab switching
function switchTab(tabName, event) {
    if (event) {
        event.preventDefault();
    }
    
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.remove('active');
    });
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    
    // Find and activate the clicked tab
    document.querySelectorAll('.tab').forEach(tab => {
        if (tab.textContent.toLowerCase().includes(tabName)) {
            tab.classList.add('active');
        }
    });
    
    document.getElementById(`${tabName}Tab`).classList.add('active');
}

// Dashboard
async function loadDashboard() {
    try {
        const response = await fetch(`${API_URL}/history`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        if (response.ok) {
            const analyses = await response.json();
            
            // Filter last 24 hours data for stats
            const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
            const last24Hours = analyses.filter(a => new Date(a.analyzed_at) >= twentyFourHoursAgo);
            
            // Remove duplicates from 24h data - keep only most recent per IOC
            const unique24Hours = [];
            const seen24hIOCs = new Set();
            
            for (const analysis of last24Hours) {
                if (!seen24hIOCs.has(analysis.ioc)) {
                    seen24hIOCs.add(analysis.ioc);
                    unique24Hours.push(analysis);
                }
            }
            
            // Calculate stats from unique IOCs in last 24 hours
            const critical = unique24Hours.filter(a => a.severity === 'Critical').length;
            const high = unique24Hours.filter(a => a.severity === 'High').length;
            const medium = unique24Hours.filter(a => a.severity === 'Medium').length;
            const low = unique24Hours.filter(a => a.severity === 'Low').length;
            const clean = unique24Hours.filter(a => a.severity === 'Info').length;
            
            document.getElementById('criticalCount').textContent = critical;
            document.getElementById('highCount').textContent = high;
            document.getElementById('mediumCount').textContent = medium;
            document.getElementById('lowCount').textContent = low;
            document.getElementById('cleanCount').textContent = clean;
            
            // Remove duplicates - keep only most recent per IOC
            const uniqueAnalyses = [];
            const seenIOCs = new Set();
            
            for (const analysis of analyses) {
                if (!seenIOCs.has(analysis.ioc)) {
                    seenIOCs.add(analysis.ioc);
                    uniqueAnalyses.push(analysis);
                }
            }
            
            // Sort by severity (high to low) and get top 20
            const severityOrder = {'Critical': 5, 'High': 4, 'Medium': 3, 'Low': 2, 'Info': 1};
            const sortedAnalyses = uniqueAnalyses.sort((a, b) => {
                const severityDiff = severityOrder[b.severity] - severityOrder[a.severity];
                if (severityDiff !== 0) return severityDiff;
                // If same severity, sort by threat score
                return b.threat_score - a.threat_score;
            }).slice(0, 20);
            
            // Show top 20 by severity
            const recentDiv = document.getElementById('recentAnalyses');
            if (sortedAnalyses.length > 0) {
                const recentHtml = sortedAnalyses.map(a => `
                    <div class="stat-card">
                        <div class="stat-content" style="width: 100%;">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <div style="flex: 1;">
                                    <strong>${a.ioc}</strong>
                                    <p style="color: #7f8c8d; margin-top: 0.25rem; font-size: 0.85rem;">
                                        ${a.type} | Score: ${a.threat_score}/100 | ${formatTimestamp(a.analyzed_at)}
                                    </p>
                                </div>
                                <div style="display: flex; gap: 0.5rem; align-items: center;">
                                    <span class="severity-badge severity-${a.severity.toLowerCase()}">${a.severity}</span>
                                    <button class="btn btn-primary" style="padding: 0.25rem 0.5rem; font-size: 0.85rem;" onclick="viewHistoryReport(${a.id})">
                                        View
                                    </button>
                                    <button class="btn btn-secondary" style="padding: 0.25rem 0.5rem; font-size: 0.85rem;" onclick="downloadSingleIOC(${a.id})">
                                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                                            <polyline points="7 10 12 15 17 10"></polyline>
                                            <line x1="12" y1="15" x2="12" y2="3"></line>
                                        </svg>
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                `).join('');
                recentDiv.innerHTML = recentHtml;
            } else {
                recentDiv.innerHTML = '<p style="color: #7f8c8d;">No analyses yet. Start analyzing IOCs!</p>';
            }
        }
    } catch (error) {
        console.error('Error loading dashboard:', error);
    }
}

// Analyze IOCs
async function analyzeText(event) {
    event.preventDefault();
    
    const text = document.getElementById('iocText').value;
    const iocs = text.split('\n').filter(line => line.trim());
    
    if (iocs.length === 0) {
        showNotification('Please enter at least one IOC', 'error');
        return;
    }
    
    await performAnalysis({ iocs });
}

async function analyzeFile(event) {
    event.preventDefault();
    
    const fileInput = document.getElementById('iocFile');
    const file = fileInput.files[0];
    
    if (!file) {
        showNotification('Please select a file', 'error');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', file);
    
    showLoading(true);
    
    try {
        const response = await fetch(`${API_URL}/analyze`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${authToken}` },
            body: formData
        });
        
        const data = await response.json();
        
        if (response.ok) {
            displayResults(data.results);
            showNotification('Analysis complete!', 'success');
        } else {
            showNotification(data.error || 'Analysis failed', 'error');
        }
    } catch (error) {
        showNotification('Network error', 'error');
    } finally {
        showLoading(false);
    }
}

async function performAnalysis(payload) {
    showLoading(true);
    
    try {
        const response = await fetch(`${API_URL}/analyze`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });
        
        const data = await response.json();
        
        if (response.ok) {
            displayResults(data.results);
            showNotification('Analysis complete!', 'success');
            loadDashboard(); // Refresh dashboard stats
        } else {
            showNotification(data.error || 'Analysis failed', 'error');
        }
    } catch (error) {
        showNotification('Network error', 'error');
    } finally {
        showLoading(false);
    }
}

function displayResults(results) {
    const tbody = document.getElementById('resultsBody');
    const resultsSection = document.getElementById('resultsSection');
    
    currentAnalysisIds = results.map((_, idx) => idx);
    currentAnalysisResults = results; // Store results for download
    
    const html = results.map((result, idx) => `
        <tr>
            <td>${result.ioc}</td>
            <td>${result.type}</td>
            <td>${result.threat_score}</td>
            <td><span class="severity-badge severity-${result.severity.toLowerCase()}">${result.severity}</span></td>
            <td>${result.threat_category}</td>
            <td>
                <button class="btn btn-primary" onclick="showDetailedReportByIndex(${idx})" style="margin-right: 0.5rem;">
                    View Details
                </button>
                <button class="btn btn-secondary" onclick="downloadResultPDF(${idx})" title="Download PDF">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                        <polyline points="7 10 12 15 17 10"></polyline>
                        <line x1="12" y1="15" x2="12" y2="3"></line>
                    </svg>
                </button>
            </td>
        </tr>
    `).join('');
    
    tbody.innerHTML = html;
    resultsSection.style.display = 'block';
}

// History
async function loadHistory() {
    try {
        const response = await fetch(`${API_URL}/history`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        if (response.ok) {
            const analyses = await response.json();
            
            // Remove duplicates - keep only the most recent analysis for each unique IOC
            const uniqueAnalyses = [];
            const seenIOCs = new Set();
            
            for (const analysis of analyses) {
                if (!seenIOCs.has(analysis.ioc)) {
                    seenIOCs.add(analysis.ioc);
                    uniqueAnalyses.push(analysis);
                }
            }
            
            // Store for filtering
            allHistoryData = uniqueAnalyses;
            
            // Display all
            displayHistory(allHistoryData);
        }
    } catch (error) {
        console.error('Error loading history:', error);
    }
}

function displayHistory(analyses) {
    const tbody = document.getElementById('historyBody');
    
    if (analyses.length > 0) {
        const html = analyses.map(a => `
            <tr>
                <td>
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <span>${a.ioc}</span>
                        <button class="btn-icon" onclick="copyToClipboard('${a.ioc}')" title="Copy IOC">
                            📋
                        </button>
                    </div>
                </td>
                <td>${a.type}</td>
                <td>${a.threat_score}</td>
                <td><span class="severity-badge severity-${a.severity.toLowerCase()}">${a.severity}</span></td>
                <td>${a.threat_category}</td>
                <td>${formatTimestamp(a.analyzed_at)}</td>
                <td>
                    <button class="btn btn-primary" onclick="viewHistoryReport(${a.id})" style="margin-right: 0.5rem;">
                        View
                    </button>
                    <button class="btn btn-secondary" onclick="downloadSingleIOC(${a.id})">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                            <polyline points="7 10 12 15 17 10"></polyline>
                            <line x1="12" y1="15" x2="12" y2="3"></line>
                        </svg>
                    </button>
                </td>
            </tr>
        `).join('');
        tbody.innerHTML = html;
    } else {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: #7f8c8d;">No results found</td></tr>';
    }
}

// Filter history
function filterHistory() {
    const searchText = document.getElementById('searchIOC').value.toLowerCase();
    const severityFilter = document.getElementById('filterSeverity').value;
    const typeFilter = document.getElementById('filterType').value;
    
    let filtered = allHistoryData;
    
    // Apply search
    if (searchText) {
        filtered = filtered.filter(a => a.ioc.toLowerCase().includes(searchText));
    }
    
    // Apply severity filter
    if (severityFilter) {
        filtered = filtered.filter(a => a.severity === severityFilter);
    }
    
    // Apply type filter
    if (typeFilter) {
        filtered = filtered.filter(a => a.type === typeFilter);
    }
    
    displayHistory(filtered);
}

// Clear filters
function clearFilters() {
    document.getElementById('searchIOC').value = '';
    document.getElementById('filterSeverity').value = '';
    document.getElementById('filterType').value = '';
    displayHistory(allHistoryData);
}

// Copy to clipboard
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showNotification('IOC copied to clipboard!', 'success');
    }).catch(err => {
        showNotification('Failed to copy', 'error');
    });
}

// Export history to CSV
function exportHistoryCSV() {
    if (allHistoryData.length === 0) {
        showNotification('No data to export', 'error');
        return;
    }
    
    // Get currently displayed data (respects filters)
    const searchText = document.getElementById('searchIOC').value.toLowerCase();
    const severityFilter = document.getElementById('filterSeverity').value;
    const typeFilter = document.getElementById('filterType').value;
    
    let dataToExport = allHistoryData;
    
    if (searchText) {
        dataToExport = dataToExport.filter(a => a.ioc.toLowerCase().includes(searchText));
    }
    if (severityFilter) {
        dataToExport = dataToExport.filter(a => a.severity === severityFilter);
    }
    if (typeFilter) {
        dataToExport = dataToExport.filter(a => a.type === typeFilter);
    }
    
    // Create CSV content
    const headers = ['IOC', 'Type', 'Threat Score', 'Severity', 'Category', 'Date'];
    const csvContent = [
        headers.join(','),
        ...dataToExport.map(a => [
            `"${a.ioc}"`,
            a.type,
            a.threat_score,
            a.severity,
            `"${a.threat_category}"`,
            new Date(a.analyzed_at).toISOString()
        ].join(','))
    ].join('\\n');
    
    // Download
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ioc_history_${Date.now()}.csv`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
    
    showNotification('CSV exported successfully!', 'success');
}

// Dark mode toggle
function toggleDarkMode() {
    document.body.classList.toggle('dark-mode');
    const isDark = document.body.classList.contains('dark-mode');
    localStorage.setItem('darkMode', isDark);
    updateDarkModeButton();
    showNotification(isDark ? 'Dark mode enabled' : 'Light mode enabled', 'success');
}

// Update dark mode button text
function updateDarkModeButton() {
    const isDark = document.body.classList.contains('dark-mode');
    const btn = document.getElementById('darkModeBtn');
    if (btn) {
        btn.textContent = isDark ? '☀️ Light Mode' : '🌙 Dark Mode';
    }
    // Update all dark mode buttons
    const authBtn = document.querySelector('#authDarkModeToggle button');
    if (authBtn) {
        authBtn.textContent = isDark ? '☀️ Light Mode' : '🌙 Dark Mode';
    }
}

async function viewHistoryReport(analysisId) {
    try {
        const response = await fetch(`${API_URL}/report/${analysisId}`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        if (response.ok) {
            const report = await response.json();
            showDetailedReport(report);
        }
    } catch (error) {
        showNotification('Error loading report', 'error');
    }
}

// Download single IOC report as PDF
async function downloadSingleIOC(analysisId) {
    try {
        showNotification('Generating PDF report...', 'info');
        
        const response = await fetch(`${API_URL}/export-single/${analysisId}`, {
            method: 'POST',
            headers: { 
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `ioc_report_${analysisId}_${Date.now()}.pdf`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            showNotification('PDF downloaded successfully!', 'success');
        } else {
            showNotification('Failed to generate PDF', 'error');
        }
    } catch (error) {
        console.error('Error downloading PDF:', error);
        showNotification('Error downloading PDF', 'error');
    }
}

// Helper function to show detailed report by index
function showDetailedReportByIndex(idx) {
    if (currentAnalysisResults[idx]) {
        showDetailedReport(currentAnalysisResults[idx]);
    }
}

// Detailed Report Modal
function showDetailedReport(result) {
    const modal = document.getElementById('reportModal');
    const modalBody = document.getElementById('modalBody');
    
    // Detection Summary Section
    let detectionSummaryHtml = '';
    if (result.detection_summary) {
        const summary = result.detection_summary;
        detectionSummaryHtml = `
            <div style="margin: 1.5rem 0; padding: 1rem; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 8px;">
                <h3 style="margin-bottom: 0.5rem;">🔍 Detection Summary</h3>
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.5rem;">
                    <p><strong>Malicious Detections:</strong> <span style="color: #e74c3c; font-weight: bold;">${summary.malicious_count || 0}</span></p>
                    <p><strong>Suspicious Detections:</strong> <span style="color: #f39c12; font-weight: bold;">${summary.suspicious_count || 0}</span></p>
                    <p><strong>Abuse Confidence:</strong> <span style="color: #3498db; font-weight: bold;">${summary.abuse_score || 0}%</span></p>
                    <p><strong>Tools Checked:</strong> <span style="color: #2ecc71; font-weight: bold;">${summary.tools_checked || 0}</span></p>
                </div>
            </div>
        `;
    }
    
    // Tool Analysis Results
    let detailsHtml = '<h3>📋 Tool Analysis Results:</h3><div style="margin-top: 1rem;">';
    
    for (const [tool, data] of Object.entries(result.details)) {
        if (typeof data === 'object' && !data.error) {
            detailsHtml += `
                <div style="margin-bottom: 1rem; padding: 1rem; background: #f8f9fa; border-radius: 8px; border-left: 3px solid var(--primary);">
                    <h4 style="color: var(--secondary); margin-bottom: 0.5rem;">🔧 ${tool.toUpperCase()}</h4>
            `;
            
            // Special handling for domain age
            if (tool === 'domain_age' && !data.error) {
                const riskColors = {
                    'CRITICAL': '#e74c3c',
                    'HIGH': '#e67e22',
                    'MEDIUM': '#f39c12',
                    'LOW': '#27ae60'
                };
                const riskColor = riskColors[data.risk_level] || '#95a5a6';
                
                detailsHtml += `
                    <div style="background: ${data.risk_level === 'CRITICAL' || data.risk_level === 'HIGH' ? '#ffe6e6' : '#f0f0f0'}; 
                                padding: 1rem; border-radius: 8px; border-left: 4px solid ${riskColor};">
                        <p style="margin: 0.5rem 0;"><strong>Created:</strong> <span style="font-size: 1.1em; font-weight: bold;">${data.creation_date}</span></p>
                        <p style="margin: 0.5rem 0;"><strong>Age:</strong> <span style="font-size: 1.1em; font-weight: bold;">${data.age_display}</span> (${data.age_days} days)</p>
                        <p style="margin: 0.5rem 0;"><strong>Risk Level:</strong> <span style="color: ${riskColor}; font-weight: bold; font-size: 1.1em;">${data.risk_level}</span></p>
                        <p style="margin: 0.5rem 0; color: ${riskColor}; font-weight: 600;">${data.risk_note}</p>
                        ${data.registrar ? `<p style="margin: 0.5rem 0;"><strong>Registrar:</strong> ${data.registrar}</p>` : ''}
                        ${data.risk_level === 'CRITICAL' || data.risk_level === 'HIGH' ? `
                            <div style="margin-top: 1rem; padding: 0.75rem; background: white; border-radius: 4px;">
                                <strong style="color: #e74c3c;">⚠️ WARNING:</strong> Newly registered domains are frequently used for:
                                <ul style="margin: 0.5rem 0; padding-left: 1.5rem;">
                                    <li>Phishing campaigns</li>
                                    <li>Malware distribution</li>
                                    <li>Scam websites</li>
                                    <li>Credential harvesting</li>
                                </ul>
                                <p style="margin-top: 0.5rem; font-weight: 600;">Recommendation: Block or monitor closely!</p>
                            </div>
                        ` : ''}
                    </div>
                `;
            }
            // Special handling for redirections
            else if (tool === 'redirections' && data.redirects && data.redirects.length > 0) {
                detailsHtml += `
                    <p><strong>Redirect Count:</strong> <span style="color: #f39c12; font-weight: bold;">${data.redirect_count}</span></p>
                    <p><strong>Final URL:</strong> <code style="background: #e9ecef; padding: 0.2rem 0.5rem; border-radius: 3px;">${data.final_url}</code></p>
                    <div style="margin-top: 0.5rem;">
                        <strong>Redirection Chain:</strong>
                        <ol style="margin: 0.5rem 0; padding-left: 1.5rem;">
                            ${data.redirects.map(r => `
                                <li style="margin: 0.25rem 0;">
                                    <span style="color: #3498db;">[${r.status_code}]</span> 
                                    <code style="font-size: 0.85rem;">${r.url}</code>
                                    ${r.location ? `→ <code style="font-size: 0.85rem;">${r.location}</code>` : ''}
                                </li>
                            `).join('')}
                        </ol>
                    </div>
                    ${data.http_referrers && data.http_referrers.length > 0 ? `
                        <p><strong>HTTP Referrers:</strong> ${data.http_referrers.join(', ')}</p>
                    ` : ''}
                `;
            }
            // Special handling for URLQuery
            else if (tool === 'urlquery') {
                detailsHtml += `<p><strong>Status:</strong> ${data.status}</p>`;
                if (data.redirects && data.redirects.length > 0) {
                    detailsHtml += `<p><strong>Redirects Found:</strong> ${data.redirects.length}</p>`;
                }
                if (data.http_referrer) {
                    detailsHtml += `<p><strong>HTTP Referrer:</strong> <code>${data.http_referrer}</code></p>`;
                }
                if (data.final_url) {
                    detailsHtml += `<p><strong>Final URL:</strong> <code>${data.final_url}</code></p>`;
                }
                if (data.link) {
                    detailsHtml += `<p><strong>Report:</strong> <a href="${data.link}" target="_blank" style="color: var(--primary);">View Full Report</a></p>`;
                }
            }
            // Special handling for ANY.RUN
            else if (tool === 'anyrun') {
                if (data.verdict) {
                    const verdictColor = data.verdict === 'malicious' ? '#e74c3c' : data.verdict === 'suspicious' ? '#f39c12' : '#2ecc71';
                    detailsHtml += `<p><strong>Verdict:</strong> <span style="color: ${verdictColor}; font-weight: bold;">${data.verdict.toUpperCase()}</span></p>`;
                }
                if (data.threat_level) {
                    detailsHtml += `<p><strong>Threat Level:</strong> ${data.threat_level}</p>`;
                }
                if (data.malware_families && data.malware_families.length > 0) {
                    detailsHtml += `<p><strong>Malware Families:</strong> ${data.malware_families.join(', ')}</p>`;
                }
                if (data.tags && data.tags.length > 0) {
                    detailsHtml += `<p><strong>Tags:</strong> ${data.tags.join(', ')}</p>`;
                }
                if (data.link) {
                    detailsHtml += `<p><strong>Analysis:</strong> <a href="${data.link}" target="_blank" style="color: var(--primary);">View Interactive Analysis</a></p>`;
                }
            }
            // Special handling for Zscaler tools
            else if (tool === 'zscaler_content' || tool === 'zscaler_category') {
                for (const [key, value] of Object.entries(data)) {
                    if (key === 'link') {
                        detailsHtml += `<p><strong>${formatKey(key)}:</strong> <a href="${value}" target="_blank" style="color: var(--primary);">${value}</a></p>`;
                    } else if (key === 'risk_score' || key === 'risk_level') {
                        const color = value > 75 || value === 'High' ? '#e74c3c' : value > 50 || value === 'Medium' ? '#f39c12' : '#2ecc71';
                        detailsHtml += `<p><strong>${formatKey(key)}:</strong> <span style="color: ${color}; font-weight: bold;">${value}</span></p>`;
                    } else if (key === 'threats' && Array.isArray(value) && value.length > 0) {
                        detailsHtml += `<p><strong>Threats:</strong> <span style="color: #e74c3c;">${value.join(', ')}</span></p>`;
                    } else if (key === 'categories' && Array.isArray(value)) {
                        detailsHtml += `<p><strong>Categories:</strong> ${value.join(', ')}</p>`;
                    } else if (typeof value !== 'object') {
                        detailsHtml += `<p><strong>${formatKey(key)}:</strong> ${value}</p>`;
                    }
                }
            }
            // Default handling for other tools
            else {
                for (const [key, value] of Object.entries(data)) {
                    if (key === 'link' || key.includes('link') || key.includes('_link')) {
                        detailsHtml += `<p><strong>${formatKey(key)}:</strong> <a href="${value}" target="_blank" style="color: var(--primary);">${value}</a></p>`;
                    } else if (key === 'malicious' && value > 0) {
                        detailsHtml += `<p><strong>${formatKey(key)}:</strong> <span style="color: #e74c3c; font-weight: bold;">${value}</span></p>`;
                    } else if (key === 'suspicious' && value > 0) {
                        detailsHtml += `<p><strong>${formatKey(key)}:</strong> <span style="color: #f39c12; font-weight: bold;">${value}</span></p>`;
                    } else if (key === 'abuse_confidence_score') {
                        const color = value > 75 ? '#e74c3c' : value > 50 ? '#f39c12' : '#3498db';
                        detailsHtml += `<p><strong>${formatKey(key)}:</strong> <span style="color: ${color}; font-weight: bold;">${value}%</span></p>`;
                    } else if (key === 'verdict' && value === 'malicious') {
                        detailsHtml += `<p><strong>${formatKey(key)}:</strong> <span style="color: #e74c3c; font-weight: bold;">${value.toUpperCase()}</span></p>`;
                    } else if (key === 'risk_level') {
                        const color = value === 'High' ? '#e74c3c' : value === 'Medium' ? '#f39c12' : '#2ecc71';
                        detailsHtml += `<p><strong>${formatKey(key)}:</strong> <span style="color: ${color}; font-weight: bold;">${value}</span></p>`;
                    } else if (typeof value === 'object') {
                        detailsHtml += `<p><strong>${formatKey(key)}:</strong> ${JSON.stringify(value)}</p>`;
                    } else {
                        detailsHtml += `<p><strong>${formatKey(key)}:</strong> ${value}</p>`;
                    }
                }
            }
            
            detailsHtml += '</div>';
        }
    }
    
    detailsHtml += '</div>';
    
    // Format AI recommendation with line breaks
    const formattedRecommendation = result.ai_recommendation ? 
        result.ai_recommendation.replace(/\n/g, '<br>') : 'No recommendation available';
    
    // IOC Context Section (for SOC investigation)
    let iocContextHtml = '';
    if (result.ioc_context && result.ioc_context !== 'No additional context available') {
        iocContextHtml = `
            <div style="margin: 1.5rem 0; padding: 1rem; background: #ffe6e6; border-left: 4px solid #e74c3c; border-radius: 8px;">
                <h3 style="margin-bottom: 0.5rem;">🎯 IOC Context & Threat Intelligence</h3>
                <p style="white-space: pre-wrap; font-weight: 500;">${result.ioc_context}</p>
                ${result.first_seen ? `<p style="margin-top: 0.5rem;"><strong>First Seen:</strong> ${result.first_seen}</p>` : ''}
                ${result.last_seen ? `<p><strong>Last Seen:</strong> ${result.last_seen}</p>` : ''}
            </div>
        `;
    }
    
    // Parse and display campaigns if available
    let campaignsHtml = '';
    try {
        const campaigns = result.campaign_info ? JSON.parse(result.campaign_info) : [];
        if (campaigns && campaigns.length > 0) {
            campaignsHtml = `
                <div style="margin: 1.5rem 0; padding: 1rem; background: #fff3cd; border-radius: 8px;">
                    <h3>🚨 Related Cyber Attack Campaigns:</h3>
                    ${campaigns.map(c => `
                        <div style="margin: 0.5rem 0; padding: 0.5rem; background: white; border-radius: 4px;">
                            <h4 style="color: #e74c3c; margin: 0;">${c.name}</h4>
                            ${c.description ? `<p style="margin: 0.25rem 0; font-size: 0.9rem;">${c.description}</p>` : ''}
                            ${c.created ? `<p style="margin: 0; font-size: 0.85rem; color: #7f8c8d;">Created: ${c.created}</p>` : ''}
                        </div>
                    `).join('')}
                </div>
            `;
        }
    } catch (e) {}
    
    // Parse and display malware families
    let malwareHtml = '';
    try {
        const malware = result.associated_malware ? JSON.parse(result.associated_malware) : [];
        if (malware && malware.length > 0) {
            malwareHtml = `
                <div style="margin: 1.5rem 0; padding: 1rem; background: #f8d7da; border-radius: 8px;">
                    <h3>🦠 Associated Malware Families:</h3>
                    <p style="font-weight: 500;">${malware.join(', ')}</p>
                </div>
            `;
        }
    } catch (e) {}
    
    // Parse and display tags
    let tagsHtml = '';
    try {
        const tags = result.tags ? JSON.parse(result.tags) : [];
        if (tags && tags.length > 0) {
            tagsHtml = `
                <div style="margin: 1.5rem 0; padding: 1rem; background: #d1ecf1; border-radius: 8px;">
                    <h3>🏷️ Threat Intelligence Tags:</h3>
                    <div style="display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.5rem;">
                        ${tags.map(tag => `<span style="background: #17a2b8; color: white; padding: 0.25rem 0.75rem; border-radius: 15px; font-size: 0.85rem;">${tag}</span>`).join('')}
                    </div>
                </div>
            `;
        }
    } catch (e) {}
    
    modalBody.innerHTML = `
        <h2 style="color: var(--secondary);">${result.ioc}</h2>
        <div style="margin: 1.5rem 0; padding: 1rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 8px;">
            <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem;">
                <p><strong>Type:</strong> ${result.type.toUpperCase()}</p>
                <p><strong>Threat Score:</strong> <span style="font-size: 1.2rem; font-weight: bold;">${result.threat_score}/100</span></p>
                <p><strong>Severity:</strong> <span class="severity-badge severity-${result.severity.toLowerCase()}">${result.severity}</span></p>
                <p><strong>Category:</strong> ${result.threat_category}</p>
                <p style="grid-column: 1 / -1;"><strong>Threat Type:</strong> ${result.threat_type}</p>
            </div>
        </div>
        
        ${iocContextHtml}
        ${campaignsHtml}
        ${malwareHtml}
        ${tagsHtml}
        ${detectionSummaryHtml}
        
        <div style="margin: 1.5rem 0; padding: 1rem; background: #e8f4fd; border-radius: 8px;">
            <h3>🤖 AI Analysis Summary:</h3>
            <p style="white-space: pre-wrap;">${result.ai_summary}</p>
        </div>
        
        <div style="margin: 1.5rem 0; padding: 1rem; background: #fef5e7; border-radius: 8px;">
            <h3>💡 AI Recommendation:</h3>
            <p style="white-space: pre-wrap;">${formattedRecommendation}</p>
        </div>
        
        ${detailsHtml}
    `;
    
    modal.style.display = 'block';
}

// Helper function to format keys
function formatKey(key) {
    return key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

function closeModal() {
    document.getElementById('reportModal').style.display = 'none';
}

// Severity Popup Modal
async function showSeverityPopup(severity) {
    try {
        const response = await fetch(`${API_URL}/severity/${severity}`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        if (response.ok) {
            const iocs = await response.json();
            const modal = document.getElementById('severityModal');
            const modalBody = document.getElementById('severityModalBody');
            
            if (iocs.length === 0) {
                modalBody.innerHTML = `
                    <h2>${severity} IOCs (Last 24 Hours)</h2>
                    <p style="text-align: center; color: #7f8c8d; padding: 2rem;">No ${severity} IOCs found in the last 24 hours.</p>
                `;
            } else {
                const tableHtml = `
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                        <h2>${severity} IOCs (Last 24 Hours)</h2>
                        <button class="btn btn-primary" onclick="downloadSeverityCSV('${severity}')">
                            📥 Download CSV
                        </button>
                    </div>
                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>IOC</th>
                                    <th>Type</th>
                                    <th>Score</th>
                                    <th>Category</th>
                                    <th>Threat Type</th>
                                    <th>Date</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${iocs.map(ioc => `
                                    <tr>
                                        <td>
                                            <div style="display: flex; align-items: center; gap: 0.5rem;">
                                                <span>${ioc.ioc}</span>
                                                <button class="btn-icon" onclick="copyToClipboard('${ioc.ioc}')" title="Copy">
                                                    📋
                                                </button>
                                            </div>
                                        </td>
                                        <td>${ioc.type}</td>
                                        <td>${ioc.threat_score}</td>
                                        <td>${ioc.threat_category}</td>
                                        <td>${ioc.threat_type}</td>
                                        <td>${formatTimestamp(ioc.analyzed_at)}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                    <div style="margin-top: 1rem; text-align: center; color: #7f8c8d;">
                        <p>Total: ${iocs.length} IOC(s)</p>
                    </div>
                `;
                modalBody.innerHTML = tableHtml;
            }
            
            modal.style.display = 'block';
        }
    } catch (error) {
        console.error('Error loading severity IOCs:', error);
        showNotification('Error loading IOCs', 'error');
    }
}

function closeSeverityModal() {
    document.getElementById('severityModal').style.display = 'none';
}

// Download severity IOCs as CSV
async function downloadSeverityCSV(severity) {
    try {
        const response = await fetch(`${API_URL}/severity/${severity}`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        if (response.ok) {
            const iocs = await response.json();
            
            if (iocs.length === 0) {
                showNotification('No data to export', 'error');
                return;
            }
            
            // Create CSV content
            const headers = ['IOC', 'Type', 'Threat Score', 'Severity', 'Category', 'Threat Type', 'Date'];
            const csvContent = [
                headers.join(','),
                ...iocs.map(ioc => [
                    `"${ioc.ioc}"`,
                    ioc.type,
                    ioc.threat_score,
                    ioc.severity,
                    `"${ioc.threat_category}"`,
                    `"${ioc.threat_type}"`,
                    new Date(ioc.analyzed_at).toISOString()
                ].join(','))
            ].join('\\n');
            
            // Download
            const blob = new Blob([csvContent], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${severity.toLowerCase()}_iocs_${Date.now()}.csv`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            
            showNotification('CSV downloaded successfully!', 'success');
        }
    } catch (error) {
        console.error('Error downloading CSV:', error);
        showNotification('Error downloading CSV', 'error');
    }
}

// API Key Management
async function loadApiKeys() {
    try {
        const response = await fetch(`${API_URL}/keys`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        if (response.ok) {
            const keys = await response.json();
            const listDiv = document.getElementById('apiKeysList');
            
            if (keys.length > 0) {
                const html = keys.map(key => `
                    <div class="api-key-item">
                        <div>
                            <strong>${key.service_name}</strong>
                            <p style="color: #7f8c8d; font-size: 0.875rem;">Added: ${new Date(key.created_at).toLocaleDateString()}</p>
                        </div>
                        <button class="btn btn-danger" onclick="deleteApiKey(${key.id})">Delete</button>
                    </div>
                `).join('');
                listDiv.innerHTML = html;
            } else {
                listDiv.innerHTML = '<p style="color: #7f8c8d;">No API keys configured yet.</p>';
            }
        }
    } catch (error) {
        console.error('Error loading API keys:', error);
    }
}

async function addApiKey(event) {
    event.preventDefault();
    
    const serviceName = document.getElementById('serviceName').value;
    const apiKey = document.getElementById('apiKey').value;
    
    try {
        const response = await fetch(`${API_URL}/keys`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ service_name: serviceName, api_key: apiKey })
        });
        
        if (response.ok) {
            showNotification('API key saved successfully', 'success');
            document.getElementById('serviceName').value = '';
            document.getElementById('apiKey').value = '';
            loadApiKeys();
        } else {
            showNotification('Failed to save API key', 'error');
        }
    } catch (error) {
        showNotification('Network error', 'error');
    }
}

async function deleteApiKey(keyId) {
    if (!confirm('Are you sure you want to delete this API key?')) {
        return;
    }
    
    try {
        const response = await fetch(`${API_URL}/keys/${keyId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        if (response.ok) {
            showNotification('API key deleted', 'success');
            loadApiKeys();
        } else {
            showNotification('Failed to delete API key', 'error');
        }
    } catch (error) {
        showNotification('Network error', 'error');
    }
}

// History Retention Settings
async function loadRetentionSetting() {
    try {
        const response = await fetch(`${API_URL}/settings/retention`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        if (response.ok) {
            const data = await response.json();
            const weeks = data.retention_weeks || 1;
            document.getElementById('retentionWeeks').value = weeks;
            document.getElementById('currentRetention').textContent = `${weeks} week${weeks > 1 ? 's' : ''}`;
        }
    } catch (error) {
        console.error('Error loading retention setting:', error);
    }
}

async function updateRetentionSetting() {
    const weeks = parseInt(document.getElementById('retentionWeeks').value);
    
    try {
        const response = await fetch(`${API_URL}/settings/retention`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ retention_weeks: weeks })
        });
        
        if (response.ok) {
            const data = await response.json();
            document.getElementById('currentRetention').textContent = `${data.retention_weeks} week${data.retention_weeks > 1 ? 's' : ''}`;
            showNotification(`History retention set to ${data.retention_weeks} week${data.retention_weeks > 1 ? 's' : ''}`, 'success');
        } else {
            showNotification('Failed to update retention setting', 'error');
        }
    } catch (error) {
        console.error('Error updating retention setting:', error);
        showNotification('Network error', 'error');
    }
}

// Timezone Settings
let userTimezone = 'UTC';

async function loadTimezoneSetting() {
    try {
        const response = await fetch(`${API_URL}/settings/timezone`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        if (response.ok) {
            const data = await response.json();
            userTimezone = data.timezone || 'UTC';
            document.getElementById('timezoneSelect').value = userTimezone;
            document.getElementById('currentTimezone').textContent = userTimezone;
        }
    } catch (error) {
        console.error('Error loading timezone setting:', error);
    }
}

async function updateTimezoneSetting() {
    const timezone = document.getElementById('timezoneSelect').value;
    
    try {
        const response = await fetch(`${API_URL}/settings/timezone`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ timezone: timezone })
        });
        
        if (response.ok) {
            const data = await response.json();
            userTimezone = data.timezone;
            document.getElementById('currentTimezone').textContent = userTimezone;
            showNotification(`Timezone set to ${userTimezone}`, 'success');
            
            // Reload current page to update all timestamps
            const currentSection = document.querySelector('.section.active').id;
            if (currentSection === 'dashboard') {
                loadDashboard();
            } else if (currentSection === 'history') {
                loadHistory();
            }
        } else {
            showNotification('Failed to update timezone setting', 'error');
        }
    } catch (error) {
        console.error('Error updating timezone setting:', error);
        showNotification('Network error', 'error');
    }
}

// Format timestamp in user's timezone
function formatTimestamp(timestamp) {
    try {
        const date = new Date(timestamp);
        return date.toLocaleString('en-US', {
            timeZone: userTimezone,
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        }) + ` (${userTimezone})`;
    } catch (error) {
        // Fallback to default formatting
        return new Date(timestamp).toLocaleString();
    }
}

// Export PDF
async function exportPDF() {
    try {
        const response = await fetch(`${API_URL}/export/pdf`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ analysis_ids: currentAnalysisIds })
        });
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `ioc_report_${new Date().getTime()}.pdf`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            showNotification('PDF exported successfully', 'success');
        } else {
            showNotification('Failed to export PDF', 'error');
        }
    } catch (error) {
        showNotification('Network error', 'error');
    }
}

// Download single result PDF from analysis results
async function downloadResultPDF(idx) {
    if (!currentAnalysisResults[idx]) {
        showNotification('Result not found', 'error');
        return;
    }
    
    const result = currentAnalysisResults[idx];
    
    // Create a simple text-based PDF content
    const pdfContent = `
IOC Analysis Report
==================

IOC: ${result.ioc}
Type: ${result.type}
Threat Score: ${result.threat_score}/100
Severity: ${result.severity}
Category: ${result.threat_category}
Threat Type: ${result.threat_type}

Analysis Date: ${new Date().toLocaleString()}

---
Generated by IOC Validator
    `.trim();
    
    // Create a blob and download
    const blob = new Blob([pdfContent], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ioc_${result.ioc.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
    
    showNotification('Report downloaded successfully!', 'success');
}

// Utility Functions
function showLoading(show) {
    const overlay = document.getElementById('loadingOverlay');
    if (show) {
        overlay.classList.add('active');
    } else {
        overlay.classList.remove('active');
    }
}

function showNotification(message, type) {
    // Simple alert for now - can be enhanced with a toast library
    const icon = type === 'success' ? '✓' : '✗';
    alert(`${icon} ${message}`);
}

// Close modal when clicking outside
window.onclick = function(event) {
    const modal = document.getElementById('reportModal');
    if (event.target === modal) {
        closeModal();
    }
}
