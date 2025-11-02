import requests
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

class SQLInjectionScanner:
    """SQL Injection vulnerability scanner"""
    
    SQL_ERRORS = [
        r"SQL syntax.*?MySQL",
        r"Warning.*?\Wmysqli?_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your (MySQL|MariaDB) server version",
        r"Unknown column '[^ ]+' in 'field list'",
        r"MySqlClient\.",
        r"com\.mysql\.jdbc\.exceptions",
        r"SQLServerException",
        r"SqlException",
        r"SQL Server.*?Driver",
        r"Warning.*?\Wmssql_",
        r"Microsoft OLE DB Provider for SQL Server",
        r"Unclosed quotation mark after the character string",
        r"PostgreSQL.*?ERROR",
        r"Warning.*?\Wpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError:",
        r"Oracle error",
        r"Oracle.*?Driver",
        r"Warning.*?\Woci_",
        r"Warning.*?\Wora_",
        r"sqlite3.OperationalError:",
        r"SQLite/JDBCDriver",
        r"SQLite.Exception"
    ]
    
    PAYLOADS = [
        "'",
        "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR '1'='1' --",
        "\" OR \"1\"=\"1\" --",
        "' OR '1'='1' /*",
        "admin'--",
        "admin' #",
        "admin'/*",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "1' AND '1'='1",
        "1' AND '1'='2"
    ]
    
    def __init__(self, url, timeout=5):
        self.url = url
        self.timeout = timeout
        
    def scan(self):
        """Perform SQL injection scan"""
        results = {
            'url': self.url,
            'vulnerabilities': [],
            'tested_parameters': 0,
            'vulnerable_parameters': []
        }
        
        try:
            # Parse URL
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)
            
            if not params:
                results['status'] = 'no_parameters'
                results['risk_level'] = 'info'
                return results
            
            # Test each parameter
            for param_name in params.keys():
                results['tested_parameters'] += 1
                
                for payload in self.PAYLOADS:
                    if self._test_payload(param_name, payload):
                        vulnerability = {
                            'parameter': param_name,
                            'payload': payload,
                            'severity': 'critical',
                            'description': f'SQL Injection vulnerability detected in parameter: {param_name}'
                        }
                        results['vulnerabilities'].append(vulnerability)
                        results['vulnerable_parameters'].append(param_name)
                        break  # Found vulnerability, move to next parameter
            
            results['risk_level'] = self._calculate_risk(results)
            
        except Exception as e:
            results['error'] = str(e)
            results['risk_level'] = 'unknown'
        
        return results
    
    def _test_payload(self, param_name, payload):
        """Test a single payload on a parameter"""
        try:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)
            
            # Inject payload
            params[param_name] = payload
            
            # Rebuild URL
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment
            ))
            
            # Make request
            response = requests.get(new_url, timeout=self.timeout)
            
            # Check for SQL errors in response
            for error_pattern in self.SQL_ERRORS:
                if re.search(error_pattern, response.text, re.IGNORECASE):
                    return True
            
            return False
            
        except Exception:
            return False
    
    def _calculate_risk(self, results):
        """Calculate risk level"""
        vuln_count = len(results['vulnerabilities'])
        
        if vuln_count > 0:
            return 'critical'
        else:
            return 'low'