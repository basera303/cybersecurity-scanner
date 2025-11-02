from .port_scanner import PortScanner
from .sql_injection import SQLInjectionScanner
from .xss_scanner import XSSScanner
from .password_checker import PasswordChecker
from .ssl_checker import SSLChecker

__all__ = [
    'PortScanner',
    'SQLInjectionScanner', 
    'XSSScanner',
    'PasswordChecker',
    'SSLChecker'
]


"""
Scanner package containing all vulnerability scanning modules.

This package provides implementations for various security scanners:
- Port scanning
- SQL injection detection
- XSS vulnerability scanning
- Password strength analysis
- SSL/TLS certificate checking
"""

from .port_scanner import PortScanner
from .sql_injection import SQLInjectionScanner
from .xss_scanner import XSSScanner
from .password_checker import PasswordChecker
from .ssl_checker import SSLChecker

__all__ = [
    'PortScanner',
    'SQLInjectionScanner', 
    'XSSScanner',
    'PasswordChecker',
    'SSLChecker'
]

def get_all_scanners():
    """Return a list of all available scanner classes"""
    return [
        PortScanner,
        SQLInjectionScanner,
        XSSScanner,
        PasswordChecker,
        SSLChecker
    ]

def get_scanner_by_type(scan_type):
    """Get scanner class by scan type name"""
    scanners = {
        'port_scan': PortScanner,
        'sql_injection': SQLInjectionScanner,
        'xss': XSSScanner,
        'password': PasswordChecker,
        'ssl_check': SSLChecker
    }
    return scanners.get(scan_type)