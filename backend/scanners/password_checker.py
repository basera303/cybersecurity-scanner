import re
import math
from collections import Counter

class PasswordChecker:
    """Password strength analyzer"""
    
    COMMON_PASSWORDS = [
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
        'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
        'bailey', 'passw0rd', 'shadow', '123123', '654321',
        'superman', 'qazwsx', 'michael', 'football'
    ]
    
    def __init__(self):
        pass
    
    def check(self, password):
        """Analyze password strength"""
        results = {
            'password_length': len(password),
            'strength_score': 0,
            'strength_level': '',
            'entropy': 0,
            'issues': [],
            'suggestions': [],
            'checks': {}
        }
        
        # Perform various checks
        results['checks']['length'] = self._check_length(password)
        results['checks']['uppercase'] = self._has_uppercase(password)
        results['checks']['lowercase'] = self._has_lowercase(password)
        results['checks']['numbers'] = self._has_numbers(password)
        results['checks']['special_chars'] = self._has_special_chars(password)
        results['checks']['common_password'] = not self._is_common(password)
        results['checks']['sequential'] = not self._has_sequential(password)
        results['checks']['repeated'] = not self._has_repeated(password)
        
        # Calculate entropy
        results['entropy'] = self._calculate_entropy(password)
        
        # Calculate score
        score = 0
        if results['checks']['length']:
            score += 20
        if results['checks']['uppercase']:
            score += 15
        if results['checks']['lowercase']:
            score += 15
        if results['checks']['numbers']:
            score += 15
        if results['checks']['special_chars']:
            score += 20
        if results['checks']['common_password']:
            score += 10
        if results['checks']['sequential']:
            score += 5
        
        results['strength_score'] = min(score, 100)
        
        # Determine strength level
        if score >= 80:
            results['strength_level'] = 'strong'
        elif score >= 60:
            results['strength_level'] = 'medium'
        elif score >= 40:
            results['strength_level'] = 'weak'
        else:
            results['strength_level'] = 'very_weak'
        
        # Add issues and suggestions
        if not results['checks']['length']:
            results['issues'].append('Password is too short')
            results['suggestions'].append('Use at least 12 characters')
        
        if not results['checks']['uppercase']:
            results['issues'].append('No uppercase letters')
            results['suggestions'].append('Add uppercase letters (A-Z)')
        
        if not results['checks']['lowercase']:
            results['issues'].append('No lowercase letters')
            results['suggestions'].append('Add lowercase letters (a-z)')
        
        if not results['checks']['numbers']:
            results['issues'].append('No numbers')
            results['suggestions'].append('Add numbers (0-9)')
        
        if not results['checks']['special_chars']:
            results['issues'].append('No special characters')
            results['suggestions'].append('Add special characters (!@#$%^&*)')
        
        if not results['checks']['common_password']:
            results['issues'].append('This is a commonly used password')
            results['suggestions'].append('Use a unique password')
        
        if not results['checks']['sequential']:
            results['issues'].append('Contains sequential characters')
            results['suggestions'].append('Avoid sequential patterns')
        
        # Calculate estimated crack time
        results['crack_time'] = self._estimate_crack_time(results['entropy'])
        
        return results
    
    def _check_length(self, password):
        """Check if password meets minimum length"""
        return len(password) >= 12
    
    def _has_uppercase(self, password):
        """Check for uppercase letters"""
        return bool(re.search(r'[A-Z]', password))
    
    def _has_lowercase(self, password):
        """Check for lowercase letters"""
        return bool(re.search(r'[a-z]', password))
    
    def _has_numbers(self, password):
        """Check for numbers"""
        return bool(re.search(r'\d', password))
    
    def _has_special_chars(self, password):
        """Check for special characters"""
        return bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password))
    
    def _is_common(self, password):
        """Check if password is commonly used"""
        return password.lower() in self.COMMON_PASSWORDS
    
    def _has_sequential(self, password):
        """Check for sequential characters"""
        sequences = ['abc', '123', 'qwe', 'asd', 'zxc']
        password_lower = password.lower()
        return any(seq in password_lower for seq in sequences)
    
    def _has_repeated(self, password):
        """Check for repeated characters"""
        return bool(re.search(r'(.)\1{2,}', password))
    
    def _calculate_entropy(self, password):
        """Calculate password entropy"""
        # Determine character set size
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            charset_size += 32
        
        if charset_size == 0:
            return 0
        
        # Entropy = log2(charset_size^length)
        entropy = len(password) * math.log2(charset_size)
        return round(entropy, 2)
    
    def _estimate_crack_time(self, entropy):
        """Estimate time to crack password"""
        # Assuming 1 billion guesses per second
        guesses_per_second = 1e9
        possible_combinations = 2 ** entropy
        seconds = possible_combinations / guesses_per_second
        
        if seconds < 60:
            return f"{seconds:.2f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.2f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.2f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.2f} days"
        else:
            years = seconds / 31536000
            if years > 1e6:
                return "millions of years"
            return f"{years:.2f} years"