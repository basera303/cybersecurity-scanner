import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

class SSLChecker:
    """SSL/TLS certificate checker"""
    
    def __init__(self, url, timeout=5):
        self.url = url
        self.timeout = timeout
        
    def check(self):
        """Check SSL certificate"""
        results = {
            'url': self.url,
            'has_ssl': False,
            'valid': False,
            'vulnerabilities': [],
            'certificate_info': {}
        }
        
        try:
            # Parse hostname
            parsed = urlparse(self.url)
            hostname = parsed.hostname or parsed.path
            port = parsed.port or 443
            
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    results['has_ssl'] = True
                    results['certificate_info'] = self._parse_certificate(cert)
                    results['protocol_version'] = ssock.version()
                    results['cipher'] = ssock.cipher()
                    
                    # Validate certificate
                    results['valid'] = True
                    
                    # Check expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    results['days_until_expiry'] = days_until_expiry
                    
                    if days_until_expiry < 0:
                        results['vulnerabilities'].append({
                            'severity': 'critical',
                            'issue': 'Certificate expired',
                            'description': f'Certificate expired {abs(days_until_expiry)} days ago'
                        })
                        results['valid'] = False
                    elif days_until_expiry < 30:
                        results['vulnerabilities'].append({
                            'severity': 'medium',
                            'issue': 'Certificate expiring soon',
                            'description': f'Certificate expires in {days_until_expiry} days'
                        })
                    
                    # Check protocol version
                    if results['protocol_version'] in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                        results['vulnerabilities'].append({
                            'severity': 'high',
                            'issue': 'Outdated TLS version',
                            'description': f'Using {results["protocol_version"]}, upgrade to TLSv1.2 or higher'
                        })
                    
                    # Check cipher strength
                    cipher_name = results['cipher'][0]
                    if 'RC4' in cipher_name or 'DES' in cipher_name:
                        results['vulnerabilities'].append({
                            'severity': 'high',
                            'issue': 'Weak cipher',
                            'description': f'Weak cipher {cipher_name} detected'
                        })
            
            results['risk_level'] = self._calculate_risk(results)
            
        except ssl.SSLError as e:
            results['error'] = f'SSL Error: {str(e)}'
            results['vulnerabilities'].append({
                'severity': 'critical',
                'issue': 'SSL Error',
                'description': str(e)
            })
            results['risk_level'] = 'critical'
            
        except socket.gaierror:
            results['error'] = 'Unable to resolve hostname'
            results['risk_level'] = 'unknown'
            
        except Exception as e:
            results['error'] = f'Error: {str(e)}'
            results['risk_level'] = 'unknown'
        
        return results
    
    def _parse_certificate(self, cert):
        """Parse certificate information"""
        info = {}
        
        if 'subject' in cert:
            subject = dict(x[0] for x in cert['subject'])
            info['common_name'] = subject.get('commonName', '')
            info['organization'] = subject.get('organizationName', '')
        
        if 'issuer' in cert:
            issuer = dict(x[0] for x in cert['issuer'])
            info['issuer'] = issuer.get('commonName', '')
        
        info['version'] = cert.get('version', '')
        info['serial_number'] = cert.get('serialNumber', '')
        info['not_before'] = cert.get('notBefore', '')
        info['not_after'] = cert.get('notAfter', '')
        
        if 'subjectAltName' in cert:
            info['subject_alt_names'] = [x[1] for x in cert['subjectAltName']]
        
        return info
    
    def _calculate_risk(self, results):
        """Calculate risk level"""
        if not results['has_ssl']:
            return 'critical'
        
        vuln_count = len(results['vulnerabilities'])
        
        # Check severity
        critical = sum(1 for v in results['vulnerabilities'] if v['severity'] == 'critical')
        high = sum(1 for v in results['vulnerabilities'] if v['severity'] == 'high')
        
        if critical > 0:
            return 'critical'
        elif high > 0:
            return 'high'
        elif vuln_count > 0:
            return 'medium'
        else:
            return 'low'