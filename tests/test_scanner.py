import pytest
from backend.scanners.port_scanner import PortScanner
from backend.scanners.sql_injection import SQLInjectionScanner
from backend.scanners.xss_scanner import XSSScanner
from backend.scanners.password_checker import PasswordChecker
from backend.scanners.ssl_checker import SSLChecker

class TestScanners:
    """Test suite for all scanner components"""
    
    def test_port_scanner_valid(self):
        """Test port scanner with valid target"""
        scanner = PortScanner('localhost', timeout=0.1)
        results = scanner.scan(ports=[22, 80, 443])
        
        assert isinstance(results, dict)
        assert 'target' in results
        assert 'open_ports' in results
        assert 'vulnerabilities' in results
        
    def test_port_scanner_invalid(self):
        """Test port scanner with invalid target"""
        scanner = PortScanner('invalid.hostname.localhost', timeout=0.1)
        results = scanner.scan(ports=[80])
        
        assert isinstance(results, dict)
        assert len(results.get('open_ports', [])) == 0
    
    def test_sql_scanner_valid(self):
        """Test SQL injection scanner with test URL"""
        # Using a test URL that won't actually be vulnerable
        scanner = SQLInjectionScanner('https://example.com', timeout=1)
        results = scanner.scan()
        
        assert isinstance(results, dict)
        assert 'url' in results
        assert 'vulnerabilities' in results
    
    def test_sql_scanner_invalid_url(self):
        """Test SQL injection scanner with invalid URL"""
        scanner = SQLInjectionScanner('invalid_url', timeout=1)
        results = scanner.scan()
        
        assert isinstance(results, dict)
        assert 'error' in results or 'vulnerabilities' in results
    
    def test_xss_scanner_valid(self):
        """Test XSS scanner with test URL"""
        scanner = XSSScanner('https://example.com', timeout=1)
        results = scanner.scan()
        
        assert isinstance(results, dict)
        assert 'url' in results
        assert 'vulnerabilities' in results
    
    def test_password_checker_strong(self):
        """Test password checker with strong password"""
        checker = PasswordChecker()
        results = checker.check('Str0ngP@ssw0rd!2024')
        
        assert isinstance(results, dict)
        assert results['strength_score'] >= 80
        assert results['strength_level'] == 'strong'
        assert results['checks']['length']
        assert results['checks']['uppercase']
        assert results['checks']['lowercase']
        assert results['checks']['numbers']
        assert results['checks']['special_chars']
        assert results['checks']['common_password']
    
    def test_password_checker_weak(self):
        """Test password checker with weak password"""
        checker = PasswordChecker()
        results = checker.check('password123')
        
        assert isinstance(results, dict)
        assert results['strength_score'] < 60
        assert results['strength_level'] in ['weak', 'very_weak']
        assert not results['checks']['uppercase']
        assert not results['checks']['special_chars']
        assert not results['checks']['common_password']
    
    def test_ssl_checker_valid(self):
        """Test SSL checker with valid domain"""
        checker = SSLChecker('https://example.com', timeout=5)
        results = checker.check()
        
        assert isinstance(results, dict)
        assert 'has_ssl' in results
        assert 'valid' in results
        assert 'certificate_info' in results
    
    @pytest.mark.skip(reason="This test may fail due to network conditions")
    def test_ssl_checker_invalid(self):
        """Test SSL checker with invalid domain"""
        checker = SSLChecker('https://invalid.domain.notexists', timeout=2)
        results = checker.check()
        
        assert isinstance(results, dict)
        assert 'error' in results or 'has_ssl' in results
    
    def test_risk_calculation(self):
        """Test risk level calculations across scanners"""
        # Password checker risk levels
        checker = PasswordChecker()
        
        # Very weak password
        weak_results = checker.check('123456')
        assert weak_results['strength_level'] == 'very_weak'
        
        # Medium password
        medium_results = checker.check('Password123')
        assert medium_results['strength_level'] == 'medium'
        
        # Strong password
        strong_results = checker.check('Str0ngP@ss!2024')
        assert strong_results['strength_level'] == 'strong'

if __name__ == '__main__':
    pytest.main([__file__])