import os
from datetime import timedelta

# Security Settings
SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key')  # Change this in production
JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)

# Database Settings
DATABASE_URL = os.getenv('DATABASE_URL', 'database.db')
DATABASE_POOL_SIZE = 5
DATABASE_MAX_OVERFLOW = 10

# Security Headers
SECURITY_HEADERS = {
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'X-XSS-Protection': '1; mode=block',
    'Content-Security-Policy': "default-src 'self'"
}

# Rate Limiting
RATE_LIMIT_DEFAULT = "200 per day"
RATE_LIMIT_STORAGE_URL = "memory://"

# Password Policy
PASSWORD_MIN_LENGTH = 8
PASSWORD_HISTORY_SIZE = 5
PASSWORD_EXPIRY_DAYS = 90
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_MINUTES = 15

# Session Settings
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
PERMANENT_SESSION_LIFETIME = timedelta(hours=1)

# Email Settings
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USERNAME = os.getenv('SMTP_USERNAME', '')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '') 