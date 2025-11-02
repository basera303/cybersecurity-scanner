from backend.database import db
from datetime import datetime
import json

class ScanResult(db.Model):
    """Model for storing scan results"""
    __tablename__ = 'scan_results'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_type = db.Column(db.String(50), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default='pending')
    results = db.Column(db.Text)  # JSON stored as text
    vulnerabilities_found = db.Column(db.Integer, default=0)
    risk_level = db.Column(db.String(20), default='low')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    
    def to_dict(self):
        """Convert model to dictionary"""
        return {
            'id': self.id,
            'scan_type': self.scan_type,
            'target': self.target,
            'status': self.status,
            'results': json.loads(self.results) if self.results else {},
            'vulnerabilities_found': self.vulnerabilities_found,
            'risk_level': self.risk_level,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }
    
    def set_results(self, results_dict):
        """Set results from dictionary"""
        self.results = json.dumps(results_dict)

class User(db.Model):
    """Model for users (optional authentication)"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at.isoformat()
        }