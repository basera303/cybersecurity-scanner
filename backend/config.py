import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Application configuration"""
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///security_scanner.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    HOST = os.getenv('HOST', '0.0.0.0')
    PORT = int(os.getenv('PORT', 5000))
    DEBUG = os.getenv('FLASK_ENV') == 'development'
    
    # Scanner settings
    MAX_PORTS = 1000
    TIMEOUT = 5
    MAX_THREADS = 100
    
    # Security settings
    ALLOWED_ORIGINS = ['http://localhost:5000', 'http://127.0.0.1:5000']