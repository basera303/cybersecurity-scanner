from datetime import datetime
import json

class ReportGenerator:
    """Generate security scan reports"""
    
    @staticmethod
    def generate_text_report(scan_result):
        """Generate plain text report"""
        report = []
        report.append("=" * 70)
        report.append("SECURITY SCAN REPORT")
        report.append("=" * 70)
        report.append(f"\nScan Type: {scan_result.scan_type}")
        report.append(f"Target: {scan_result.target}")
        report.append(f"Status: {scan_result.status}")
        report.append(f"Risk Level: {scan_result.risk_level.upper()}")
        report.append(f"Vulnerabilities Found: {scan_result.vulnerabilities_found}")
        report.append(f"Scan Date: {scan_result.created_at}")
        
        if scan_result.results:
            results = json.loads(scan_result.results)
            report.append("\n" + "-" * 70)
            report.append("DETAILED RESULTS")
            report.append("-" * 70)
            
            if 'vulnerabilities' in results:
                report.append(f"\nVulnerabilities:")
                for vuln in results['vulnerabilities']:
                    report.append(f"\n  - Severity: {vuln.get('severity', 'N/A')}")
                    report.append(f"    Description: {vuln.get('description', 'N/A')}")
            
            if 'open_ports' in results:
                report.append(f"\nOpen Ports:")
                for port in results['open_ports']:
                    report.append(f"  - Port {port['port']}: {port['service']}")
        
        report.append("\n" + "=" * 70)
        
        return "\n".join(report)
    
    @staticmethod
    def generate_html_report(scan_result):
        """Generate HTML report"""
        results = json.loads(scan_result.results) if scan_result.results else {}
        
        risk_colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#28a745',
            'info': '#17a2b8'
        }
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #343a40; color: white; padding: 20px; }}
                .risk-badge {{ 
                    display: inline-block; 
                    padding: 5px 10px; 
                    border-radius: 3px; 
                    color: white;
                    background: {risk_colors.get(scan_result.risk_level, '#6c757d')};
                }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #dee2e6; }}
                .vulnerability {{ 
                    background: #f8f9fa; 
                    margin: 10px 0; 
                    padding: 10px; 
                    border-left: 4px solid #dc3545;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Security Scan Report</h1>
            </div>
            
            <div class="section">
                <h2>Scan Information</h2>
                <p><strong>Scan Type:</strong> {scan_result.scan_type}</p>
                <p><strong>Target:</strong> {scan_result.target}</p>
                <p><strong>Status:</strong> {scan_result.status}</p>
                <p><strong>Risk Level:</strong> <span class="risk-badge">{scan_result.risk_level.upper()}</span></p>
                <p><strong>Vulnerabilities Found:</strong> {scan_result.vulnerabilities_found}</p>
                <p><strong>Scan Date:</strong> {scan_result.created_at}</p>
            </div>
            
            <div class="section">
                <h2>Detailed Results</h2>
                <pre>{json.dumps(results, indent=2)}</pre>
            </div>
        </body>
        </html>
        """
        
        return html
    
    @staticmethod
    def generate_json_report(scan_result):
        """Generate JSON report"""
        return json.dumps(scan_result.to_dict(), indent=2)