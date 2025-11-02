from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from datetime import datetime
import json

from backend.config import Config
from backend.database import db, init_db
from backend.models import ScanResult
from backend.scanners import (
    PortScanner, SQLInjectionScanner, 
    XSSScanner, PasswordChecker, SSLChecker
)
from backend.utils.report_generator import ReportGenerator
from backend.utils.logger import setup_logger

# Initialize Flask app
app = Flask(__name__, 
            template_folder='../frontend/templates',
            static_folder='../frontend/static')
app.config.from_object(Config)

# Initialize extensions
CORS(app, origins=Config.ALLOWED_ORIGINS)
init_db(app)

# Setup logger
logger = setup_logger()

# Routes
@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    """Dashboard page"""
    scans = ScanResult.query.order_by(ScanResult.created_at.desc()).limit(10).all()
    return render_template('dashboard.html', scans=scans)

@app.route('/api/scan/port', methods=['POST'])
def scan_ports():
    """Port scanning endpoint"""
    try:
        data = request.get_json()
        target = data.get('target')
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        # Create scan record
        scan = ScanResult(
            scan_type='port_scan',
            target=target,
            status='running'
        )
        db.session.add(scan)
        db.session.commit()
        
        # Perform scan
        scanner = PortScanner(target, timeout=Config.TIMEOUT)
        results = scanner.scan()
        
        # Update scan record
        scan.status = 'completed'
        scan.set_results(results)
        scan.vulnerabilities_found = len(results.get('vulnerabilities', []))
        scan.risk_level = results.get('risk_level', 'low')
        scan.completed_at = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"Port scan completed for {target}")
        
        return jsonify({
            'success': True,
            'scan_id': scan.id,
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Port scan error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/sql-injection', methods=['POST'])
def scan_sql_injection():
    """SQL injection scanning endpoint"""
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Create scan record
        scan = ScanResult(
            scan_type='sql_injection',
            target=url,
            status='running'
        )
        db.session.add(scan)
        db.session.commit()
        
        # Perform scan
        scanner = SQLInjectionScanner(url, timeout=Config.TIMEOUT)
        results = scanner.scan()
        
        # Update scan record
        scan.status = 'completed'
        scan.set_results(results)
        scan.vulnerabilities_found = len(results.get('vulnerabilities', []))
        scan.risk_level = results.get('risk_level', 'low')
        scan.completed_at = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"SQL injection scan completed for {url}")
        
        return jsonify({
            'success': True,
            'scan_id': scan.id,
            'results': results
        })
        
    except Exception as e:
        logger.error(f"SQL injection scan error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/xss', methods=['POST'])
def scan_xss():
    """XSS scanning endpoint"""
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Create scan record
        scan = ScanResult(
            scan_type='xss',
            target=url,
            status='running'
        )
        db.session.add(scan)
        db.session.commit()
        
        # Perform scan
        scanner = XSSScanner(url, timeout=Config.TIMEOUT)
        results = scanner.scan()
        
        # Update scan record
        scan.status = 'completed'
        scan.set_results(results)
        scan.vulnerabilities_found = len(results.get('vulnerabilities', []))
        scan.risk_level = results.get('risk_level', 'low')
        scan.completed_at = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"XSS scan completed for {url}")
        
        return jsonify({
            'success': True,
            'scan_id': scan.id,
            'results': results
        })
        
    except Exception as e:
        logger.error(f"XSS scan error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/password', methods=['POST'])
def check_password():
    """Password strength checking endpoint"""
    try:
        data = request.get_json()
        password = data.get('password')
        
        if not password:
            return jsonify({'error': 'Password is required'}), 400
        
        # Perform check
        checker = PasswordChecker()
        results = checker.check(password)
        
        logger.info("Password strength check completed")
        
        return jsonify({
            'success': True,
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Password check error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/ssl', methods=['POST'])
def check_ssl():
    """SSL certificate checking endpoint"""
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Create scan record
        scan = ScanResult(
            scan_type='ssl_check',
            target=url,
            status='running'
        )
        db.session.add(scan)
        db.session.commit()
        
        # Perform check
        checker = SSLChecker(url, timeout=Config.TIMEOUT)
        results = checker.check()
        
        # Update scan record
        scan.status = 'completed'
        scan.set_results(results)
        scan.vulnerabilities_found = len(results.get('vulnerabilities', []))
        scan.risk_level = results.get('risk_level', 'low')
        scan.completed_at = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"SSL check completed for {url}")
        
        return jsonify({
            'success': True,
            'scan_id': scan.id,
            'results': results
        })
        
    except Exception as e:
        logger.error(f"SSL check error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans', methods=['GET'])
def get_scans():
    """Get all scans"""
    try:
        scans = ScanResult.query.order_by(ScanResult.created_at.desc()).all()
        return jsonify({
            'success': True,
            'scans': [scan.to_dict() for scan in scans]
        })
    except Exception as e:
        logger.error(f"Get scans error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans/<int:scan_id>', methods=['GET'])
def get_scan(scan_id):
    """Get specific scan"""
    try:
        scan = ScanResult.query.get_or_404(scan_id)
        return jsonify({
            'success': True,
            'scan': scan.to_dict()
        })
    except Exception as e:
        logger.error(f"Get scan error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans/<int:scan_id>/report', methods=['GET'])
def generate_report(scan_id):
    """Generate report for scan"""
    try:
        scan = ScanResult.query.get_or_404(scan_id)
        report_format = request.args.get('format', 'json')
        
        if report_format == 'text':
            report = ReportGenerator.generate_text_report(scan)
            return report, 200, {'Content-Type': 'text/plain'}
        elif report_format == 'html':
            report = ReportGenerator.generate_html_report(scan)
            return report, 200, {'Content-Type': 'text/html'}
        else:
            report = ReportGenerator.generate_json_report(scan)
            return report, 200, {'Content-Type': 'application/json'}
            
    except Exception as e:
        logger.error(f"Report generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get statistics"""
    try:
        total_scans = ScanResult.query.count()
        
        stats = {
            'total_scans': total_scans,
            'scans_by_type': {},
            'scans_by_risk': {},
            'recent_scans': []
        }
        
        # Scans by type
        scan_types = db.session.query(
            ScanResult.scan_type, 
            db.func.count(ScanResult.id)
        ).group_by(ScanResult.scan_type).all()
        
        stats['scans_by_type'] = {st: count for st, count in scan_types}
        
        # Scans by risk level
        risk_levels = db.session.query(
            ScanResult.risk_level,
            db.func.count(ScanResult.id)
        ).group_by(ScanResult.risk_level).all()
        
        stats['scans_by_risk'] = {rl: count for rl, count in risk_levels}
        
        # Recent scans
        recent = ScanResult.query.order_by(
            ScanResult.created_at.desc()
        ).limit(5).all()
        
        stats['recent_scans'] = [scan.to_dict() for scan in recent]
        
        return jsonify({
            'success': True,
            'stats': stats
        })
        
    except Exception as e:
        logger.error(f"Get stats error: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG
    )