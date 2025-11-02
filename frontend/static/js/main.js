// Main JavaScript for Security Scanner

class SecurityScanner {
    constructor() {
        this.apiBase = '/api';
        this.init();
    }

    init() {
        console.log('Security Scanner initialized');
        this.attachEventListeners();
    }

    attachEventListeners() {
        // Port Scanner
        const portScanForm = document.getElementById('port-scan-form');
        if (portScanForm) {
            portScanForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.performPortScan();
            });
        }

        // SQL Injection Scanner
        const sqlForm = document.getElementById('sql-scan-form');
        if (sqlForm) {
            sqlForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.performSQLScan();
            });
        }

        // XSS Scanner
        const xssForm = document.getElementById('xss-scan-form');
        if (xssForm) {
            xssForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.performXSSScan();
            });
        }

        // Password Checker
        const passwordForm = document.getElementById('password-check-form');
        if (passwordForm) {
            passwordForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.checkPassword();
            });
        }

        // SSL Checker
        const sslForm = document.getElementById('ssl-check-form');
        if (sslForm) {
            sslForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.checkSSL();
            });
        }
    }

    async performPortScan() {
        const target = document.getElementById('port-target').value;
        const resultsDiv = document.getElementById('port-results');
        const loadingDiv = document.getElementById('port-loading');

        this.showLoading(loadingDiv);
        this.hideResults(resultsDiv);

        try {
            const response = await fetch(`${this.apiBase}/scan/port`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ target })
            });

            const data = await response.json();

            this.hideLoading(loadingDiv);

            if (data.success) {
                this.displayPortResults(data.results, resultsDiv);
                this.showAlert('Port scan completed successfully', 'success');
            } else {
                this.showAlert(data.error || 'Scan failed', 'error');
            }
        } catch (error) {
            this.hideLoading(loadingDiv);
            this.showAlert('Error performing scan: ' + error.message, 'error');
        }
    }

    async performSQLScan() {
        const url = document.getElementById('sql-url').value;
        const resultsDiv = document.getElementById('sql-results');
        const loadingDiv = document.getElementById('sql-loading');

        this.showLoading(loadingDiv);
        this.hideResults(resultsDiv);

        try {
            const response = await fetch(`${this.apiBase}/scan/sql-injection`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url })
            });

            const data = await response.json();

            this.hideLoading(loadingDiv);

            if (data.success) {
                this.displaySQLResults(data.results, resultsDiv);
                this.showAlert('SQL injection scan completed', 'success');
            } else {
                this.showAlert(data.error || 'Scan failed', 'error');
            }
        } catch (error) {
            this.hideLoading(loadingDiv);
            this.showAlert('Error performing scan: ' + error.message, 'error');
        }
    }

    async performXSSScan() {
        const url = document.getElementById('xss-url').value;
        const resultsDiv = document.getElementById('xss-results');
        const loadingDiv = document.getElementById('xss-loading');

        this.showLoading(loadingDiv);
        this.hideResults(resultsDiv);

        try {
            const response = await fetch(`${this.apiBase}/scan/xss`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url })
            });

            const data = await response.json();

            this.hideLoading(loadingDiv);

            if (data.success) {
                this.displayXSSResults(data.results, resultsDiv);
                this.showAlert('XSS scan completed', 'success');
            } else {
                this.showAlert(data.error || 'Scan failed', 'error');
            }
        } catch (error) {
            this.hideLoading(loadingDiv);
            this.showAlert('Error performing scan: ' + error.message, 'error');
        }
    }

    async checkPassword() {
        const password = document.getElementById('password-input').value;
        const resultsDiv = document.getElementById('password-results');

        try {
            const response = await fetch(`${this.apiBase}/scan/password`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ password })
            });

            const data = await response.json();

            if (data.success) {
                this.displayPasswordResults(data.results, resultsDiv);
            } else {
                this.showAlert(data.error || 'Check failed', 'error');
            }
        } catch (error) {
            this.showAlert('Error checking password: ' + error.message, 'error');
        }
    }

    async checkSSL() {
        const url = document.getElementById('ssl-url').value;
        const resultsDiv = document.getElementById('ssl-results');
        const loadingDiv = document.getElementById('ssl-loading');

        this.showLoading(loadingDiv);
        this.hideResults(resultsDiv);

        try {
            const response = await fetch(`${this.apiBase}/scan/ssl`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url })
            });

            const data = await response.json();

            this.hideLoading(loadingDiv);

            if (data.success) {
                this.displaySSLResults(data.results, resultsDiv);
                this.showAlert('SSL check completed', 'success');
            } else {
                this.showAlert(data.error || 'Check failed', 'error');
            }
        } catch (error) {
            this.hideLoading(loadingDiv);
            this.showAlert('Error checking SSL: ' + error.message, 'error');
        }
    }

    displayPortResults(results, container) {
        let html = `
            <h3>Port Scan Results</h3>
            <p><strong>Target:</strong> ${results.target}</p>
            <p><strong>Risk Level:</strong> <span class="risk-badge risk-${results.risk_level}">${results.risk_level}</span></p>
            <p><strong>Ports Scanned:</strong> ${results.ports_scanned}</p>
            <p><strong>Open Ports:</strong> ${results.total_open_ports}</p>
        `;

        if (results.open_ports && results.open_ports.length > 0) {
            html += '<h4>Open Ports:</h4><ul class="vulnerability-list">';
            results.open_ports.forEach(port => {
                html += `
                    <li class="vulnerability-item">
                        <strong>Port ${port.port}:</strong> ${port.service}
                    </li>
                `;
            });
            html += '</ul>';
        }

        if (results.vulnerabilities && results.vulnerabilities.length > 0) {
            html += '<h4>Vulnerabilities:</h4><ul class="vulnerability-list">';
            results.vulnerabilities.forEach(vuln => {
                html += `
                    <li class="vulnerability-item">
                        <h4>${vuln.service} (Port ${vuln.port})</h4>
                        <p><strong>Severity:</strong> <span class="risk-badge risk-${vuln.severity}">${vuln.severity}</span></p>
                        <p>${vuln.description}</p>
                    </li>
                `;
            });
            html += '</ul>';
        }

        container.innerHTML = html;
        this.showResults(container);
    }

    displaySQLResults(results, container) {
        let html = `
            <h3>SQL Injection Scan Results</h3>
            <p><strong>URL:</strong> ${results.url}</p>
            <p><strong>Risk Level:</strong> <span class="risk-badge risk-${results.risk_level}">${results.risk_level}</span></p>
            <p><strong>Parameters Tested:</strong> ${results.tested_parameters}</p>
        `;

        if (results.vulnerabilities && results.vulnerabilities.length > 0) {
            html += `<h4>Vulnerabilities Found: ${results.vulnerabilities.length}</h4>`;
            html += '<ul class="vulnerability-list">';
            results.vulnerabilities.forEach(vuln => {
                html += `
                    <li class="vulnerability-item">
                        <h4>${vuln.parameter}</h4>
                        <p><strong>Severity:</strong> <span class="risk-badge risk-${vuln.severity}">${vuln.severity}</span></p>
                        <p>${vuln.description}</p>
                        <p><strong>Payload:</strong> <code>${vuln.payload}</code></p>
                    </li>
                `;
            });
            html += '</ul>';
        } else {
            html += '<p class="alert alert-success">No SQL injection vulnerabilities found!</p>';
        }

        container.innerHTML = html;
        this.showResults(container);
    }

    displayXSSResults(results, container) {
        let html = `
            <h3>XSS Scan Results</h3>
            <p><strong>URL:</strong> ${results.url}</p>
            <p><strong>Risk Level:</strong> <span class="risk-badge risk-${results.risk_level}">${results.risk_level}</span></p>
        `;

        if (results.vulnerabilities && results.vulnerabilities.length > 0) {
            html += `<h4>Vulnerabilities Found: ${results.vulnerabilities.length}</h4>`;
            html += '<ul class="vulnerability-list">';
            results.vulnerabilities.forEach(vuln => {
                html += `
                    <li class="vulnerability-item">
                        <h4>${vuln.type.replace('_', ' ').toUpperCase()}</h4>
                        <p><strong>Severity:</strong> <span class="risk-badge risk-${vuln.severity}">${vuln.severity}</span></p>
                        <p>${vuln.description}</p>
                        ${vuln.parameter ? `<p><strong>Parameter:</strong> ${vuln.parameter}</p>` : ''}
                        ${vuln.input_name ? `<p><strong>Input:</strong> ${vuln.input_name}</p>` : ''}
                    </li>
                `;
            });
            html += '</ul>';
        } else {
            html += '<p class="alert alert-success">No XSS vulnerabilities found!</p>';
        }

        container.innerHTML = html;
        this.showResults(container);
    }

    displayPasswordResults(results, container) {
        let html = `
            <div class="password-strength">
                <h3>Password Strength Analysis</h3>
                <p><strong>Strength:</strong> <span class="risk-badge risk-${results.strength_level === 'strong' ? 'low' : results.strength_level === 'medium' ? 'medium' : 'high'}">${results.strength_level}</span></p>
                <p><strong>Score:</strong> ${results.strength_score}/100</p>
                
                <div class="strength-bar">
                    <div class="strength-fill strength-${results.strength_level}" style="width: ${results.strength_score}%"></div>
                </div>
                
                <p><strong>Entropy:</strong> ${results.entropy} bits</p>
                <p><strong>Estimated Crack Time:</strong> ${results.crack_time}</p>
        `;

        if (results.issues && results.issues.length > 0) {
            html += '<h4>Issues:</h4><ul>';
            results.issues.forEach(issue => {
                html += `<li class="failed">${issue}</li>`;
            });
            html += '</ul>';
        }

        if (results.suggestions && results.suggestions.length > 0) {
            html += '<h4>Suggestions:</h4><ul>';
            results.suggestions.forEach(suggestion => {
                html += `<li>${suggestion}</li>`;
            });
            html += '</ul>';
        }

        html += '</div>';

        container.innerHTML = html;
        this.showResults(container);
    }

    displaySSLResults(results, container) {
        let html = `
            <h3>SSL/TLS Certificate Check</h3>
            <p><strong>URL:</strong> ${results.url}</p>
            <p><strong>Has SSL:</strong> ${results.has_ssl ? 'Yes' : 'No'}</p>
            <p><strong>Valid:</strong> ${results.valid ? 'Yes' : 'No'}</p>
            <p><strong>Risk Level:</strong> <span class="risk-badge risk-${results.risk_level}">${results.risk_level}</span></p>
        `;

        if (results.has_ssl && results.certificate_info) {
            html += '<h4>Certificate Information:</h4>';
            html += `<p><strong>Common Name:</strong> ${results.certificate_info.common_name}</p>`;
            html += `<p><strong>Issuer:</strong> ${results.certificate_info.issuer}</p>`;
            html += `<p><strong>Valid Until:</strong> ${results.certificate_info.not_after}</p>`;
            if (results.days_until_expiry !== undefined) {
                html += `<p><strong>Days Until Expiry:</strong> ${results.days_until_expiry}</p>`;
            }
        }

        if (results.vulnerabilities && results.vulnerabilities.length > 0) {
            html += '<h4>Issues Found:</h4><ul class="vulnerability-list">';
            results.vulnerabilities.forEach(vuln => {
                html += `
                    <li class="vulnerability-item">
                        <h4>${vuln.issue}</h4>
                        <p><strong>Severity:</strong> <span class="risk-badge risk-${vuln.severity}">${vuln.severity}</span></p>
                        <p>${vuln.description}</p>
                    </li>
                `;
            });
            html += '</ul>';
        } else if (results.has_ssl) {
            html += '<p class="alert alert-success">No SSL/TLS issues found!</p>';
        }

        if (results.error) {
            html += `<p class="alert alert-error">${results.error}</p>`;
        }

        container.innerHTML = html;
        this.showResults(container);
    }

    showLoading(element) {
        if (element) {
            element.classList.add('show');
        }
    }

    hideLoading(element) {
        if (element) {
            element.classList.remove('show');
        }
    }

    showResults(element) {
        if (element) {
            element.classList.add('show');
        }
    }

    hideResults(element) {
        if (element) {
            element.classList.remove('show');
        }
    }

    showAlert(message, type = 'info') {
        // Create alert element
        const alert = document.createElement('div');
        alert.className = `alert alert-${type}`;
        alert.textContent = message;

        // Insert at top of content
        const content = document.querySelector('.content');
        if (content) {
            content.insertBefore(alert, content.firstChild);

            // Auto remove after 5 seconds
            setTimeout(() => {
                alert.remove();
            }, 5000);
        }
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new SecurityScanner();
});