import socket
import concurrent.futures
from datetime import datetime

class PortScanner:
    """Port scanning functionality"""
    
    COMMON_PORTS = {
        20: 'FTP Data',
        21: 'FTP Control',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        8080: 'HTTP Proxy',
        8443: 'HTTPS Alt'
    }
    
    def __init__(self, target, timeout=1):
        self.target = target
        self.timeout = timeout
        self.open_ports = []
        
    def scan_port(self, port):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                service = self.COMMON_PORTS.get(port, 'Unknown')
                return {
                    'port': port,
                    'status': 'open',
                    'service': service
                }
            return None
        except socket.gaierror:
            return None
        except socket.error:
            return None
    
    def scan(self, ports=None, max_workers=100):
        """Scan multiple ports"""
        if ports is None:
            ports = list(self.COMMON_PORTS.keys())
        
        results = {
            'target': self.target,
            'scan_time': datetime.utcnow().isoformat(),
            'ports_scanned': len(ports),
            'open_ports': [],
            'vulnerabilities': []
        }
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:
                    results['open_ports'].append(result)
                    
                    # Check for vulnerable services
                    if result['port'] in [23, 21, 445]:  # Telnet, FTP, SMB
                        results['vulnerabilities'].append({
                            'port': result['port'],
                            'service': result['service'],
                            'severity': 'high',
                            'description': f"Potentially insecure service {result['service']} detected"
                        })
        
        results['total_open_ports'] = len(results['open_ports'])
        results['risk_level'] = self._calculate_risk(results)
        
        return results
    
    def _calculate_risk(self, results):
        """Calculate risk level based on findings"""
        vuln_count = len(results['vulnerabilities'])
        open_count = len(results['open_ports'])
        
        if vuln_count > 3 or open_count > 10:
            return 'critical'
        elif vuln_count > 1 or open_count > 5:
            return 'high'
        elif vuln_count > 0 or open_count > 2:
            return 'medium'
        else:
            return 'low'