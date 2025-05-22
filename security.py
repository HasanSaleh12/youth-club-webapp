from functools import wraps
from flask import request, jsonify, current_app
import jwt
from datetime import datetime, timedelta
import sqlite3
from config import SECURITY_HEADERS, SECRET_KEY, JWT_ACCESS_TOKEN_EXPIRES

def add_security_headers(response):
    """Add security headers to all responses"""
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    return response

def token_required(f):
    """Decorator to protect routes with JWT authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'message': 'Invalid token format'}), 401

        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            current_user_id = data['user_id']
            
            # Check if token is expired
            if datetime.fromtimestamp(data['exp']) < datetime.now():
                return jsonify({'message': 'Token has expired'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401

        return f(current_user_id, *args, **kwargs)
    return decorated

def validate_input(data, required_fields):
    """Validate input data for required fields and sanitize input"""
    if not isinstance(data, dict):
        return False, "Invalid input format"
        
    for field in required_fields:
        if field not in data:
            return False, f"Missing required field: {field}"
        if not isinstance(data[field], str) or not data[field].strip():
            return False, f"Invalid value for field: {field}"
            
    return True, "Input is valid"

def get_db_connection():
    """Create a database connection with proper error handling"""
    try:
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        current_app.logger.error(f"Database connection error: {str(e)}")
        raise

def log_security_event(event_type, user_id, details):
    """Log security-related events"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO security_logs (event_type, user_id, details, timestamp)
            VALUES (?, ?, ?, ?)
        ''', (event_type, user_id, details, datetime.now().isoformat()))
        conn.commit()
    except Exception as e:
        current_app.logger.error(f"Failed to log security event: {str(e)}")
    finally:
        if conn:
            conn.close()

def check_rate_limit(ip_address, endpoint):
    """Check if the request exceeds rate limits"""
    # This is a simplified version. In production, use a proper rate limiting solution
    # like Redis or a dedicated rate limiting service
    return True  # Placeholder for actual rate limiting logic 