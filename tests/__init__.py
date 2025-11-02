import pytest
import json
from backend.app import app
from backend.models import ScanResult, db

class TestAPI:
    """Test suite for API endpoints"""
    
    @pytest.fixture
    def client(self):
        """Setup test client"""
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        
        with app.app_context():
            db.create_all()
        
        with app.test_client() as client:
            yield client
            
        with app.app_context():
            db.drop_all()
    
    def test_home_page(self, client):
        """Test home page loads"""
        response = client.get('/')
        assert response.status_code == 200
        assert b'Security Scanner' in response.data
    
    def test_dashboard_page(self, client):
        """Test dashboard page loads"""
        response = client.get('/dashboard')
        assert response.status_code == 200
        assert b'Dashboard' in response.data
    
    def test_port_scan_api(self, client):
        """Test port scan API endpoint"""
        response = client.post(
            '/api/scan/port',
            json={'target': 'localhost'},
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
        assert 'scan_id' in data
        assert 'results' in data
    
    def test_sql_scan_api(self, client):
        """Test SQL injection scan API endpoint"""
        response = client.post(
            '/api/scan/sql-injection',
            json={'url': 'https://example.com'},
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
        assert 'scan_id' in data
        assert 'results' in data
    
    def test_xss_scan_api(self, client):
        """Test XSS scan API endpoint"""
        response = client.post(
            '/api/scan/xss',
            json={'url': 'https://example.com'},
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
        assert 'scan_id' in data
        assert 'results' in data
    
    def test_password_check_api(self, client):
        """Test password check API endpoint"""
        response = client.post(
            '/api/scan/password',
            json={'password': 'test123'},
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
        assert 'results' in data
        assert 'strength_score' in data['results']
    
    def test_ssl_check_api(self, client):
        """Test SSL check API endpoint"""
        response = client.post(
            '/api/scan/ssl',
            json={'url': 'https://example.com'},
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
        assert 'scan_id' in data
        assert 'results' in data
    
    def test_get_scans_api(self, client):
        """Test get scans API endpoint"""
        # First create a scan
        client.post(
            '/api/scan/port',
            json={'target': 'localhost'},
            content_type='application/json'
        )
        
        # Get scans
        response = client.get('/api/scans')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
        assert 'scans' in data
        assert len(data['scans']) > 0
    
    def test_get_scan_api(self, client):
        """Test get specific scan API endpoint"""
        # Create a scan
        create_response = client.post(
            '/api/scan/port',
            json={'target': 'localhost'},
            content_type='application/json'
        )
        create_data = json.loads(create_response.data)
        scan_id = create_data['scan_id']
        
        # Get specific scan
        response = client.get(f'/api/scans/{scan_id}')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
        assert 'scan' in data
        assert data['scan']['id'] == scan_id
    
    def test_get_stats_api(self, client):
        """Test get stats API endpoint"""
        response = client.get('/api/stats')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
        assert 'stats' in data
        assert 'total_scans' in data['stats']

if __name__ == '__main__':
    pytest.main([__file__])