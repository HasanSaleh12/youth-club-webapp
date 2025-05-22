from flask import Flask, request, jsonify, send_file, render_template, redirect, url_for
import sqlite3
import bcrypt
import jwt
import datetime
import qrcode
import base64
import io
from PIL import Image
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
from datetime import datetime, timedelta
from secrets import token_urlsafe  # For generating secure tokens
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import pyotp
import os
from io import BytesIO
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Get SECRET_KEY from environment variable
SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("No SECRET_KEY set for Flask application. Please set it in your .env file.")

# Create static folder if it doesn't exist
if not os.path.exists('static'):
    os.makedirs('static')

# Add logo to static folder if it doesn't exist
if not os.path.exists('static/logo.png'):
    # Create a simple placeholder logo
    img = Image.new('RGB', (200, 200), color='blue')
    img.save('static/logo.png')

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

limiter.init_app(app)

# Add this to track login attempts
login_attempts = {}

# ✅ Create the database and users and attendance tables
def init_db():
    print("Initializing database...")  # Debug print
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Create users table with reset token fields
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users
        (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE,
            password TEXT,
            role TEXT NOT NULL,
            age INTEGER,
            emergency_contact TEXT,
            failed_attempts INTEGER DEFAULT 0,
            lockout_until TEXT,
            reset_token TEXT,
            reset_token_expiry TEXT,
            totp_secret TEXT
        )
    ''')
    print("Checked/created users table")  # Debug print
    
    # Create parent_child table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS parent_child
        (
            parent_id INTEGER,
            child_id INTEGER,
            FOREIGN KEY (parent_id) REFERENCES users (id),
            FOREIGN KEY (child_id) REFERENCES users (id),
            PRIMARY KEY (parent_id, child_id)
        )
    ''')
    print("Checked/created parent_child table")  # Debug print
    
    # Create attendance table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attendance
        (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            check_in_time TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    print("Checked/created attendance table")

    # Create notifications table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications
        (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            message TEXT NOT NULL,
            type TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            read INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    print("Checked/created notifications table")  # Debug print
    
    conn.commit()
    conn.close()
    print("Database initialization complete")  # Debug print


# ✅ Register Route
@app.route('/register', methods=['POST'])
@limiter.limit("3 per hour")  # Limit registration attempts
def register():
    try:
        # Get and validate required fields
        required_fields = ['name', 'email', 'password', 'role']
        if not all(field in request.json for field in required_fields):
            return jsonify({'message': 'Missing required fields'}), 400

        name = request.json['name']
        email = request.json['email']
        password = request.json['password']
        role = request.json['role']

        # Name validation
        if not name or len(name.strip()) < 2:
            return jsonify({'message': 'Name must be at least 2 characters long'}), 400
        if not re.match(r'^[a-zA-Z\s-]+$', name):
            return jsonify({'message': 'Name can only contain letters, spaces, and hyphens'}), 400

        # Email validation
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, email):
            return jsonify({'message': 'Invalid email format. Must be a valid email address.'}), 400

        # Password validation
        if len(password) < 8:
            return jsonify({'message': 'Password must be at least 8 characters long'}), 400
        if not re.search(r"[A-Z]", password):
            return jsonify({'message': 'Password must contain at least one uppercase letter'}), 400
        if not re.search(r"[a-z]", password):
            return jsonify({'message': 'Password must contain at least one lowercase letter'}), 400
        if not re.search(r"\d", password):
            return jsonify({'message': 'Password must contain at least one number'}), 400

        # Validate role
        valid_roles = ['parent', 'admin']
        if role not in valid_roles:
            return jsonify({'message': f'Invalid role. Must be one of: {", ".join(valid_roles)}'}), 400

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO users (name, email, password, role) 
                VALUES (?, ?, ?, ?)
            """, (name, email, hashed_password, role))
            conn.commit()

            user_id = cursor.lastrowid

            # Generate QR code for parent
            qr = qrcode.make(f"user_id:{user_id}")
            buffer = io.BytesIO()
            qr.save(buffer, format='PNG')
            buffer.seek(0)
            qr_b64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

            return jsonify({
                'message': 'Registration successful!',
                'user_id': user_id,
                'qr_code_base64': qr_b64,
                'role': role
            })
            
        except sqlite3.IntegrityError:
            return jsonify({'message': 'Email already exists.'}), 409
            
        finally:
            conn.close()
        
    except Exception as e:
        return jsonify({'message': f'Server error occurred: {str(e)}'}), 500


# ✅ Login route
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Stricter limit for login attempts
def login():
    conn = None
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        totp_code = data.get('totp_code')  # Get 2FA code if provided

        if not email or not password:
            return jsonify({
                'message': 'Email and password are required'
            }), 400

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        # Check if user exists
        cursor.execute('SELECT id, password, role, failed_attempts, lockout_until, totp_secret FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()

        if not user:
            return jsonify({
                'message': 'Invalid email or password',
                'attempts_remaining': 5
            }), 401

        user_id, stored_hash, role, failed_attempts, lockout_until, totp_secret = user
        failed_attempts = failed_attempts or 0

        # Check if account is locked
        if lockout_until and datetime.now() < datetime.fromisoformat(lockout_until):
            return jsonify({
                'message': 'Account is locked. Try again later.',
                'locked_until': lockout_until
            }), 403

        # Verify password
        if not bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            # Increment failed attempts
            new_attempts = failed_attempts + 1
            
            # Lock account if too many failed attempts
            lockout_time = None
            if new_attempts >= 5:
                lockout_time = (datetime.now() + timedelta(minutes=5)).isoformat()

            cursor.execute(
                'UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE id = ?',
                (new_attempts, lockout_time, user_id)
            )
            conn.commit()

            return jsonify({
                'message': 'Invalid email or password',
                'attempts_remaining': max(5 - new_attempts, 0)
            }), 401

        # If 2FA is enabled for user
        if totp_secret:
            # If no TOTP code provided, return need_2fa flag
            if not totp_code:
                return jsonify({
                    'message': '2FA code required',
                    'need_2fa': True,
                    'temp_token': jwt.encode({
                        'user_id': user_id,
                        'exp': datetime.now() + timedelta(minutes=5),
                        'type': '2fa_pending'
                    }, SECRET_KEY)
                }), 200

            # Verify TOTP code
            totp = pyotp.TOTP(totp_secret)
            if not totp.verify(totp_code):
                return jsonify({
                    'message': 'Invalid 2FA code',
                    'need_2fa': True
                }), 401

        # Reset failed attempts on successful login
        cursor.execute('UPDATE users SET failed_attempts = 0, lockout_until = NULL WHERE id = ?', (user_id,))
        conn.commit()

        # Generate token
        token = jwt.encode({
            'user_id': user_id,
            'exp': datetime.now() + timedelta(hours=24)
        }, SECRET_KEY)

        return jsonify({
            'token': token,
            'role': role
        })

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({
            'message': 'Login failed',
            'error': str(e)
        }), 500
    finally:
        if conn:
            conn.close()


# ✅ Parent's and Admin/Volunteer Attendance Viewing
@app.route('/attendance', methods=['GET'])
def view_attendance():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return jsonify({'message': 'Missing or invalid token'}), 401

    token = token.split()[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
        
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # Get user's role
        cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
        user_data = cursor.fetchone()
        
        if not user_data:
            conn.close()
            return jsonify({'message': 'User not found'}), 404
            
        role = user_data[0]
        
        if role == 'admin':
            # Get all attendance records for admin
            cursor.execute("""
                SELECT u.name, a.check_in_time, p.name as parent_name 
                FROM attendance a
                JOIN users u ON a.user_id = u.id
                LEFT JOIN parent_child pc ON u.id = pc.child_id
                LEFT JOIN users p ON pc.parent_id = p.id
                WHERE DATE(a.check_in_time) = DATE('now')
                ORDER BY a.check_in_time DESC
            """)
        else:
            # Get attendance for parent's children only
            cursor.execute("""
                SELECT u.name, a.check_in_time 
                FROM attendance a
                JOIN users u ON a.user_id = u.id
                JOIN parent_child pc ON u.id = pc.child_id
                WHERE pc.parent_id = ?
                AND DATE(a.check_in_time) >= DATE('now', '-30 days')
                ORDER BY a.check_in_time DESC
            """, (user_id,))
            
            attendance_records = cursor.fetchall()
            conn.close()
            
            return jsonify({
                'attendance': [
                    {
                        'name': record[0],
                    'check_in_time': record[1],
                    'parent_name': record[2] if role == 'admin' and len(record) > 2 else None
                    } for record in attendance_records
                ]
            })
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500


# ✅ Admin/Volunteer Attendance Viewing
@app.route('/admin/attendance', methods=['GET'])
def admin_attendance():
    token = request.headers.get('Authorization').split()[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
        role = get_user_role(user_id)

        if role != 'admin' and role != 'volunteer':  # Admins and volunteers can access this
            return jsonify({'message': 'Unauthorized'}), 403

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.name, a.check_in_time, p.name as parent_name, u.id as child_id
            FROM attendance a
            JOIN users u ON a.user_id = u.id
            LEFT JOIN parent_child pc ON u.id = pc.child_id
            LEFT JOIN users p ON pc.parent_id = p.id
            WHERE DATE(a.check_in_time) = DATE('now')
            ORDER BY a.check_in_time DESC
        """)
        attendance_records = cursor.fetchall()
        conn.close()

        return jsonify({'attendance': attendance_records})
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401


# ✅ Scan QR Code and Record Attendance
@app.route('/scan_qr', methods=['POST'])
def scan_qr():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return jsonify({'message': 'Missing or invalid token'}), 401

    token = token.split()[1]
    try:
        # Decode the token and get the user role
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
        
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # Check user role
        cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
        user_role = cursor.fetchone()
        
        if not user_role:
            conn.close()
            return jsonify({'message': 'User not found'}), 404
            
        if user_role[0] not in ['admin', 'volunteer']:
            conn.close()
            return jsonify({'message': f'Unauthorized. Your role is {user_role[0]}, but need to be admin or volunteer'}), 403

        # Get the scanned QR code data
        qr_data = request.json.get('qr_data')
        if not qr_data:
            return jsonify({'message': 'QR code data missing'}), 400

        # Get child ID from QR (now QR codes are generated for children)
        try:
            child_id = int(qr_data.split(':')[1])
        except (ValueError, IndexError):
            return jsonify({'message': 'Invalid QR code format'}), 400

        # Verify the child exists and get their information
        cursor.execute("""
            SELECT u.id, u.name
            FROM users u
            WHERE u.id = ? AND u.role = 'child'
        """, (child_id,))
        
        child = cursor.fetchone()
        
        if not child:
            return jsonify({'message': 'Child not found or invalid QR code'}), 404

        # Record attendance for the child
        cursor.execute("""
            INSERT INTO attendance (user_id, check_in_time)
            VALUES (?, datetime('now'))
        """, (child_id,))
        
        conn.commit()
        conn.close()

        # Send notification to parent
        notify_parent_of_attendance(child_id, "check_in")

        return jsonify({
            'message': f'Attendance recorded successfully for {child[1]}',
            'child_id': child[0],
            'child_name': child[1]
        }), 200

    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500


# ✅ Helper function to get user role
def get_user_role(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE id=?", (user_id,))
    role = cursor.fetchone()
    conn.close()
    return role[0] if role else None


# ✅ Parent Analytics
@app.route('/parent/analytics/<int:child_id>', methods=['GET'])
def parent_analytics(child_id):
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return jsonify({'message': 'Missing or invalid token'}), 401

    token = token.split()[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
        
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # Verify parent has access to this child
        cursor.execute("""
            SELECT 1 FROM parent_child 
            WHERE parent_id = ? AND child_id = ?
        """, (user_id, child_id))
        
        if not cursor.fetchone():
            conn.close()
            return jsonify({'message': 'Unauthorized access'}), 403
        
        # Get last 30 days attendance
        cursor.execute("""
            SELECT 
                strftime('%Y-%m-%d', check_in_time) as date,
                COUNT(*) as attendance_count
            FROM attendance 
            WHERE user_id = ? 
            AND check_in_time >= date('now', '-30 days')
            GROUP BY date
            ORDER BY date DESC
        """, (child_id,))
        
        attendance_data = cursor.fetchall()
        
        # Calculate total visits and attendance rate
        total_visits = len(attendance_data)
        attendance_rate = f"{(total_visits / 30) * 100:.1f}%"
        
        conn.close()
        
        return jsonify({
            'attendance_history': attendance_data,
            'total_visits': total_visits,
            'attendance_rate': attendance_rate
        })
    except Exception as e:
        return jsonify({'message': str(e)}), 500


# ✅ Admin Analytics
@app.route('/admin/analytics', methods=['GET'])
def admin_analytics():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return jsonify({'message': 'Missing or invalid token'}), 401

    token = token.split()[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
        role = get_user_role(user_id)
        
        if role != 'admin':
            return jsonify({'message': 'Unauthorized'}), 403
            
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # Get daily stats for the last 30 days
        cursor.execute("""
            SELECT 
                date(check_in_time) as date,
                COUNT(DISTINCT user_id) as unique_attendees,
                COUNT(*) as total_visits,
                strftime('%H', check_in_time) as hour
            FROM attendance 
            WHERE check_in_time >= date('now', '-30 days')
            GROUP BY date(check_in_time)
            ORDER BY date DESC
        """)
        
        daily_stats = cursor.fetchall()

        # Calculate time distribution
        cursor.execute("""
            SELECT 
                CASE 
                    WHEN cast(strftime('%H', check_in_time) as integer) < 12 THEN 'morning'
                    WHEN cast(strftime('%H', check_in_time) as integer) < 17 THEN 'afternoon'
                    ELSE 'evening'
                END as period,
                COUNT(*) as count
            FROM attendance
            WHERE date(check_in_time) = date('now')
            GROUP BY period
        """)
        distribution_data = cursor.fetchall()
        
        distribution = {
            'morning': 0,
            'afternoon': 0,
            'evening': 0
        }
        for period, count in distribution_data:
            distribution[period] = count

        # Calculate trends
        today_count = next((stat[2] for stat in daily_stats if stat[0] == datetime.now().strftime('%Y-%m-%d')), 0)
        yesterday_count = next((stat[2] for stat in daily_stats if stat[0] == (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')), 0)
        today_trend = ((today_count - yesterday_count) / yesterday_count * 100) if yesterday_count > 0 else 0

        weekly_avg = sum(stat[2] for stat in daily_stats[:7]) / min(len(daily_stats), 7) if daily_stats else 0
        prev_weekly_avg = sum(stat[2] for stat in daily_stats[7:14]) / min(len(daily_stats[7:]), 7) if len(daily_stats) > 7 else 0
        weekly_trend = ((weekly_avg - prev_weekly_avg) / prev_weekly_avg * 100) if prev_weekly_avg > 0 else 0

        monthly_total = sum(stat[2] for stat in daily_stats[:30])
        prev_month_total = sum(stat[2] for stat in daily_stats[30:60]) if len(daily_stats) > 30 else 0
        monthly_trend = ((monthly_total - prev_month_total) / prev_month_total * 100) if prev_month_total > 0 else 0

        # Get active children count
        cursor.execute("""
            SELECT COUNT(DISTINCT user_id) 
            FROM attendance 
            WHERE check_in_time >= date('now', '-7 days')
        """)
        active_children = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'child'")
        total_children = cursor.fetchone()[0]
        children_trend = (active_children / total_children * 100) if total_children > 0 else 0

        conn.close()
        
        return jsonify({
            'daily_stats': [
                [stat[0], stat[1], stat[2]] for stat in daily_stats
            ],
            'distribution': distribution,
            'today_attendance': today_count,
            'weekly_average': round(weekly_avg, 1),
            'monthly_total': monthly_total,
            'active_children': active_children,
            'today_trend': round(today_trend, 1),
            'weekly_trend': round(weekly_trend, 1),
            'monthly_trend': round(monthly_trend, 1),
            'children_trend': round(children_trend, 1)
        })
    except Exception as e:
        print(f"Analytics error: {str(e)}")  # Debug log
        return jsonify({'message': str(e)}), 500


# ✅ Attendance Stats
@app.route('/attendance/stats', methods=['GET'])
def attendance_stats():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return jsonify({'message': 'Missing or invalid token'}), 401

    token = token.split()[1]

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
        role = get_user_role(user_id)

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        if role == 'parent':
            # Get stats for parent's children using parent_child relationship
            cursor.execute("""
                SELECT 
                    u.name,
                    COUNT(a.id) as total_visits,
                    MAX(a.check_in_time) as last_visit
                FROM users u
                JOIN parent_child pc ON u.id = pc.child_id
                LEFT JOIN attendance a ON u.id = a.user_id
                WHERE pc.parent_id = ? AND u.role = 'child'
                GROUP BY u.id, u.name
            """, (user_id,))
        elif role in ['admin', 'volunteer']:
            # Get overall stats
            cursor.execute("""
                SELECT 
                    COUNT(DISTINCT user_id) as unique_visitors,
                    COUNT(*) as total_visits,
                    date(check_in_time) as visit_date
                FROM attendance
                WHERE check_in_time >= date('now', '-30 days')
                GROUP BY date(check_in_time)
                ORDER BY visit_date DESC
            """)
        else:
            return jsonify({'message': 'Unauthorized'}), 403

        stats = cursor.fetchall()
        conn.close()

        if role == 'parent':
            return jsonify({
                'children_stats': [
                    {
                        'name': row[0],
                        'total_visits': row[1],
                        'last_visit': row[2]
                    } for row in stats
                ]
            })
        else:  # admin/volunteer
            return jsonify({
                'attendance_stats': [
                    {
                        'date': row[2],
                        'unique_visitors': row[0],
                        'total_visits': row[1]
                    } for row in stats
                ]
            })

    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401
    except Exception as e:
        return jsonify({'message': str(e)}), 500


# ✅ Parent Children
@app.route('/parent/children', methods=['GET'])
def get_children():
    # Get token from Authorization header
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'message': 'No token provided'}), 401
    
    token = auth_header.split(' ')[1]
    try:
        # Verify token
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = decoded['user_id']
        
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # Check user role
        cursor.execute('SELECT role FROM users WHERE id = ?', (user_id,))
        user_role = cursor.fetchone()
        
        if not user_role:
            return jsonify({'message': 'User not found'}), 404
            
        # If admin, get all children
        if user_role[0] == 'admin':
            cursor.execute('''
                SELECT u.id, u.name, u.age, u.emergency_contact, pc.parent_id
                FROM users u
                LEFT JOIN parent_child pc ON u.id = pc.child_id
                WHERE u.role = 'child'
            ''')
        else:
            # For parents, only get their children
            cursor.execute('''
                SELECT u.id, u.name, u.age, u.emergency_contact, pc.parent_id
                FROM users u
                JOIN parent_child pc ON u.id = pc.child_id
                WHERE pc.parent_id = ? AND u.role = 'child'
            ''', (user_id,))
        
        children = cursor.fetchall()
        
        # Format the response
        children_list = []
        for child in children:
            # Generate QR code for each child with the correct format
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr_data = f"user_id:{child[0]}"  # Format: user_id:CHILD_ID
            qr.add_data(qr_data)
            qr.make(fit=True)
            
            # Create QR code image
            qr_image = qr.make_image(fill_color="black", back_color="white")
            
            # Convert QR code to base64
            buffered = BytesIO()
            qr_image.save(buffered, format="PNG")
            qr_code_base64 = base64.b64encode(buffered.getvalue()).decode()
            
            children_list.append({
                'child_id': child[0],
                'name': child[1],
                'age': child[2],
                'emergency_contact': child[3],
                'qr_code_base64': qr_code_base64
            })
        
        return jsonify({'children': children_list})
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401
    except Exception as e:
        print(f"Error in get_children: {str(e)}")
        return jsonify({'message': 'An error occurred'}), 500
    finally:
        if conn:
            conn.close()


# ✅ Add additional child to parent
@app.route('/parent/add_child', methods=['POST'])
def add_child():
    print('Received add_child request')  # Debug log
    
    # Check Content-Type header
    if not request.is_json:
        print('Invalid Content-Type')  # Debug log
        return jsonify({'message': 'Content-Type must be application/json'}), 400
    
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        print('Missing or invalid token')  # Debug log
        return jsonify({'message': 'Missing or invalid token'}), 401

    token = token.split()[1]
    try:
        # Verify parent token
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        parent_id = payload['user_id']
        print(f'Parent ID: {parent_id}')  # Debug log
        
        # Get child details from request
        data = request.get_json()
        print(f'Request data: {data}')  # Debug log
        
        required_fields = ['name', 'age', 'emergency_contact']
        if not all(field in data for field in required_fields):
            missing_fields = [field for field in required_fields if field not in data]
            print(f'Missing fields: {missing_fields}')  # Debug log
            return jsonify({'message': f'Missing required fields: {", ".join(missing_fields)}'}), 400

        name = data['name']
        age = data['age']
        emergency_contact = data['emergency_contact']

        # Validate data
        if not name or len(name.strip()) < 2:
            return jsonify({'message': 'Name must be at least 2 characters long'}), 400
        if not isinstance(age, int) or age < 0 or age > 18:
            return jsonify({'message': 'Age must be a number between 0 and 18'}), 400
        if not emergency_contact or len(emergency_contact.strip()) < 10:
            return jsonify({'message': 'Valid emergency contact number is required'}), 400

        # Verify user is a parent
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (parent_id,))
        role = cursor.fetchone()
        
        if not role or role[0] != 'parent':
            print(f'Invalid role: {role[0] if role else None}')  # Debug log
            conn.close()
            return jsonify({'message': 'Only parents can add children'}), 403

        # Create child user
        cursor.execute("""
            INSERT INTO users (name, role, age, emergency_contact)
            VALUES (?, 'child', ?, ?)
        """, (name, age, emergency_contact))
        
        child_id = cursor.lastrowid
        print(f'Created child with ID: {child_id}')  # Debug log

        # Create parent-child relationship
        cursor.execute("""
            INSERT INTO parent_child (parent_id, child_id)
            VALUES (?, ?)
        """, (parent_id, child_id))
        print(f'Created parent-child relationship: parent={parent_id}, child={child_id}')  # Debug log

        # Generate QR code for child
        qr = qrcode.make(f"user_id:{child_id}")
        buffer = io.BytesIO()
        qr.save(buffer, format='PNG')
        buffer.seek(0)
        qr_b64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

        conn.commit()
        conn.close()

        print('Successfully added child')  # Debug log
        return jsonify({
            'message': 'Child added successfully',
            'child_id': child_id,
            'child_name': name,
            'qr_code_base64': qr_b64
        })

    except jwt.ExpiredSignatureError:
        print('Token expired')  # Debug log
        return jsonify({'message': 'Token has expired. Please log in again.'}), 401
    except jwt.InvalidTokenError:
        print('Invalid token')  # Debug log
        return jsonify({'message': 'Invalid token. Please log in again.'}), 401
    except Exception as e:
        print(f'Error: {str(e)}')  # Debug log
        return jsonify({'message': f'An error occurred: {str(e)}'}), 500


# ✅ Register child
@app.route('/register/child', methods=['POST'])
def register_child():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return jsonify({'message': 'Missing or invalid token'}), 401

    token = token.split()[1]

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        parent_id = payload['user_id']
        role = get_user_role(parent_id)
        if role != 'parent':
            return jsonify({'message': 'Unauthorized'}), 403

        name = request.json['name']
        age = request.json.get('age')
        emergency_contact = request.json.get('emergency_contact')

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (name, role, age, emergency_contact)
            VALUES (?, 'child', ?, ?)
        """, (name, age, emergency_contact))
        child_id = cursor.lastrowid

        cursor.execute("""
            INSERT INTO parent_child (parent_id, child_id)
            VALUES (?, ?)
        """, (parent_id, child_id))

        conn.commit()
        conn.close()

        return jsonify({
            'message': 'Child registered successfully',
            'child_id': child_id
        })
    
    except Exception as e:
        return jsonify({'message': str(e)}), 500


# ✅ Check role
@app.route('/check_role', methods=['GET'])
def check_role():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return jsonify({'message': 'Missing or invalid token'}), 401

    token = token.split()[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
        
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
        role = cursor.fetchone()
        conn.close()
        
        if role:
            return jsonify({'user_id': user_id, 'role': role[0]})
        return jsonify({'message': 'User not found'}), 404
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500


# ✅ Request password reset
@app.route('/request-password-reset', methods=['POST'])
@limiter.limit("3 per hour")  # Limit password reset requests
def request_password_reset():
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'message': 'Email is required'}), 400

        if not validate_email(email):
            return jsonify({'message': 'Invalid email format'}), 400

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute('SELECT id, name FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        
        if user:
            user_id, user_name = user
            # Generate secure reset token with expiration
            reset_token = token_urlsafe(32)
            reset_expiry = (datetime.now() + timedelta(hours=1)).isoformat()
            
            # Store reset token in database
            cursor.execute('''
                UPDATE users 
                SET reset_token = ?, 
                    reset_token_expiry = ?,
                    failed_attempts = 0,
                    lockout_until = NULL
                WHERE email = ?
            ''', (reset_token, reset_expiry, email))
            conn.commit()
            
            # In production, send actual email here
            reset_link = f"http://127.0.0.1:5000/reset-password?token={reset_token}"
            subject = "Password Reset Request - Youth Club"
            message = f"""
            Hello {user_name},

            You have requested to reset your password. Click the link below to reset your password:

            {reset_link}

            This link will expire in 1 hour.

            If you did not request this password reset, please ignore this email.

            Best regards,
            Youth Club Team
            """
            
            # Send email notification
            send_email_notification(email, subject, message)
        
        # Always return the same message whether user exists or not
        return jsonify({
            'message': 'If your email is registered, you will receive a reset link'
        }), 200
        
    except Exception as e:
        return jsonify({'message': 'An error occurred processing your request'}), 500
    finally:
        if conn:
            conn.close()


# ✅ Reset password
@app.route('/reset-password', methods=['POST'])
@limiter.limit("3 per hour")  # Limit password reset attempts
def reset_password():
    try:
        data = request.get_json()
        token = data.get('token')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')
        
        if not token or not new_password or not confirm_password:
            return jsonify({'message': 'Token, new password, and confirmation password are required'}), 400
            
        if new_password != confirm_password:
            return jsonify({'message': 'Passwords do not match'}), 400
            
        # Validate password complexity
        is_valid, message = validate_password_complexity(new_password)
        if not is_valid:
            return jsonify({'message': message}), 400

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # Check if token exists and is valid
        cursor.execute('''
            SELECT id, email 
            FROM users 
            WHERE reset_token = ? 
            AND reset_token_expiry > ?
            AND reset_token_expiry IS NOT NULL
        ''', (token, datetime.now().isoformat()))
        
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'message': 'Invalid or expired reset token'}), 400
            
        user_id, email = user
            
        # Update password and clear reset token
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute('''
            UPDATE users 
            SET password = ?, 
                reset_token = NULL, 
                reset_token_expiry = NULL,
                failed_attempts = 0,
                lockout_until = NULL
            WHERE id = ?
        ''', (hashed_password, user_id))
        
        conn.commit()

        # Send confirmation email
        subject = "Password Reset Successful - Youth Club"
        message = f"""
        Hello,

        Your password has been successfully reset.

        If you did not make this change, please contact us immediately.

        Best regards,
        Youth Club Team
        """
        send_email_notification(email, subject, message)
        
        return jsonify({'message': 'Password has been reset successfully'}), 200
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500
    finally:
        if conn:
            conn.close()


# ✅ Enable 2FA
@app.route('/enable-2fa', methods=['POST'])
def enable_2fa():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return jsonify({'message': 'Missing or invalid token'}), 401

    token = token.split()[1]
    try:
        # Verify user token
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
        
        # Generate secret key for user
        secret = pyotp.random_base32()
        
        # Create TOTP object
        totp = pyotp.TOTP(secret)
        
        # Generate QR code
        provisioning_uri = totp.provisioning_uri(
            name=f"FYC_App:User{user_id}",
            issuer_name="FYC_App"
        )
        
        # Store secret in database
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET totp_secret = ? WHERE id = ?', (secret, user_id))
        conn.commit()
        conn.close()

        return jsonify({
            'message': 'Scan this QR code with your authenticator app',
            'qr_code': provisioning_uri,
            'secret': secret  # For manual entry if QR code doesn't work
        })

    except Exception as e:
        return jsonify({'message': str(e)}), 500


# ✅ Verify 2FA code
@app.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    try:
        data = request.get_json()
        temp_token = data.get('temp_token')
        totp_code = data.get('totp_code')

        if not temp_token or not totp_code:
            return jsonify({'message': 'Token and 2FA code are required'}), 400

        try:
            # Verify temp token
            payload = jwt.decode(temp_token, SECRET_KEY, algorithms=['HS256'])
            if payload.get('type') != '2fa_pending':
                return jsonify({'message': 'Invalid token type'}), 401

            user_id = payload['user_id']

            # Get user's TOTP secret
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute('SELECT totp_secret, role FROM users WHERE id = ?', (user_id,))
            result = cursor.fetchone()

            if not result or not result[0]:
                return jsonify({'message': 'User not found or 2FA not enabled'}), 404

            totp_secret, role = result

            # Verify TOTP code
            totp = pyotp.TOTP(totp_secret)
            if not totp.verify(totp_code):
                return jsonify({'message': 'Invalid 2FA code'}), 401

            # Generate new full access token
            token = jwt.encode({
                'user_id': user_id,
                'exp': datetime.now() + timedelta(hours=24)
            }, SECRET_KEY)

            return jsonify({
                'token': token,
                'role': role
            })

        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401

    except Exception as e:
        return jsonify({'message': str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()


# Notification helper functions
def send_email_notification(to_email, subject, message):
    try:
        # Configure these with your email settings
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        sender_email = "your-email@gmail.com"  # Replace with your email
        sender_password = "your-app-password"   # Replace with your app password

        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = to_email
        msg['Subject'] = subject

        msg.attach(MIMEText(message, 'plain'))

        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Failed to send email: {str(e)}")
        return False

def create_notification(user_id, message, notification_type):
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO notifications (user_id, message, type)
            VALUES (?, ?, ?)
        """, (user_id, message, notification_type))
        conn.commit()
        return True
    except Exception as e:
        print(f"Failed to create notification: {str(e)}")
        return False
    finally:
        if conn:
            conn.close()

def notify_parent_of_attendance(child_id, event_type):
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # Get child and parent information
        cursor.execute("""
            SELECT c.name, p.id, p.email
            FROM users c
            JOIN parent_child pc ON c.id = pc.child_id
            JOIN users p ON p.id = pc.parent_id
            WHERE c.id = ?
        """, (child_id,))
        
        child_info = cursor.fetchone()
        if child_info:
            child_name, parent_id, parent_email = child_info
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Create message based on event type
            if event_type == "check_in":
                message = f"Your child {child_name} has checked in at {timestamp}"
            else:
                message = f"Your child {child_name} has checked out at {timestamp}"
            
            # Create in-app notification
            create_notification(parent_id, message, "attendance")
            
            # Send email notification
            subject = f"Youth Club Attendance Update - {child_name}"
            send_email_notification(parent_email, subject, message)
            
        return True
    except Exception as e:
        print(f"Failed to notify parent: {str(e)}")
        return False
    finally:
        if conn:
            conn.close()

# Notification endpoints
@app.route('/notifications', methods=['GET'])
def get_notifications():
    try:
        user_id = request.args.get('user_id')
        if not user_id:
            return jsonify({'message': 'User ID is required'}), 400

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, message, type, created_at, read
            FROM notifications
            WHERE user_id = ?
            ORDER BY created_at DESC
        """, (user_id,))
        
        notifications = cursor.fetchall()
        
        return jsonify({
            'notifications': [
                {
                    'id': n[0],
                    'message': n[1],
                    'type': n[2],
                    'created_at': n[3],
                    'read': bool(n[4])
                }
                for n in notifications
            ]
        })
    except Exception as e:
        return jsonify({'message': f'Error fetching notifications: {str(e)}'}), 500
    finally:
        if conn:
            conn.close()

@app.route('/notifications/mark-read', methods=['POST'])
def mark_notifications_read():
    try:
        data = request.get_json()
        notification_ids = data.get('notification_ids', [])
        
        if not notification_ids:
            return jsonify({'message': 'No notification IDs provided'}), 400
            
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE notifications
            SET read = 1
            WHERE id IN ({})
        """.format(','.join('?' * len(notification_ids))), notification_ids)
        
        conn.commit()
        return jsonify({'message': 'Notifications marked as read'})
    except Exception as e:
        return jsonify({'message': f'Error marking notifications as read: {str(e)}'}), 500
    finally:
        if conn:
            conn.close()

# ✅ Dashboard Routes
@app.route('/')
def index():
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    token = request.args.get('token')
    if not token:
        return redirect(url_for('index'))
    
    try:
        # Decode and verify the token
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
        
        # Get user role
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return redirect(url_for('index'))
            
        role = result[0]
        print(f"User role: {role}, Token: {token}")  # Debug print
        
        if role == 'admin':
            return render_template('admin_dashboard.html', token=token)
        elif role == 'parent':
            return render_template('parent_dashboard.html', token=token)
        else:
            return redirect(url_for('index'))
            
    except Exception as e:
        print(f"Dashboard error: {str(e)}")  # Debug print
        return redirect(url_for('index'))

@app.route('/admin_dashboard')
def admin_dashboard():
    # Get token from request
    token = request.args.get('token')
    if not token:
        return redirect(url_for('login'))
    
    try:
        # Verify token and check if user is admin
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = decoded['user_id']
        
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        cursor.execute('SELECT role FROM users WHERE id = ?', (user_id,))
        user_role = cursor.fetchone()
        
        if not user_role or user_role[0] != 'admin':
            return redirect(url_for('login'))
        
        return render_template('admin_dashboard.html', token=token)
    except:
        return redirect(url_for('login'))

@app.route('/parent/dashboard')
def parent_dashboard():
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        # Handle AJAX request
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'message': 'Missing or invalid token'}), 401
        token = token.split()[1]
    else:
        # Handle regular request
        token = request.args.get('token')
        if not token:
            return redirect(url_for('index'))
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
        role = get_user_role(user_id)
        
        if role != 'parent':
            return redirect(url_for('index'))
            
        return render_template('parent_dashboard.html', token=token)
    except jwt.ExpiredSignatureError:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'message': 'Token expired'}), 401
        return redirect(url_for('index'))
    except jwt.InvalidTokenError:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'message': 'Invalid token'}), 401
        return redirect(url_for('index'))
    except Exception as e:
        print(f"Parent dashboard error: {str(e)}")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'message': str(e)}), 500
        return redirect(url_for('index'))

# ✅ New Admin Report Endpoint
@app.route('/admin/report')
def generate_report():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return jsonify({'message': 'Missing or invalid token'}), 401
        
    token = token.split()[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
        role = get_user_role(user_id)
        
        if role != 'admin':
            return jsonify({'message': 'Unauthorized'}), 403
            
        report_type = request.args.get('type', 'daily')
        date = request.args.get('date', datetime.now().strftime('%Y-%m-%d'))
        
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        if report_type == 'daily':
            cursor.execute("""
                SELECT 
                    u.name,
                    a.check_in_time,
                    p.name as parent_name
                FROM attendance a
                JOIN users u ON a.user_id = u.id
                JOIN parent_child pc ON u.id = pc.child_id
                JOIN users p ON pc.parent_id = p.id
                WHERE date(a.check_in_time) = ?
                ORDER BY a.check_in_time
            """, (date,))
        elif report_type == 'weekly':
            cursor.execute("""
                SELECT 
                    date(a.check_in_time) as date,
                    COUNT(DISTINCT a.user_id) as unique_children,
                    COUNT(*) as total_visits
                FROM attendance a
                WHERE date(a.check_in_time) >= date(?, '-6 days')
                AND date(a.check_in_time) <= date(?)
                GROUP BY date(a.check_in_time)
                ORDER BY date
            """, (date, date))
        else:  # monthly
            cursor.execute("""
                SELECT 
                    date(a.check_in_time) as date,
                    COUNT(DISTINCT a.user_id) as unique_children,
                    COUNT(*) as total_visits
                FROM attendance a
                WHERE strftime('%Y-%m', a.check_in_time) = strftime('%Y-%m', ?)
                GROUP BY date(a.check_in_time)
                ORDER BY date
            """, (date,))
            
        report_data = cursor.fetchall()
        conn.close()
        
        # Format data based on report type
        if report_type == 'daily':
            return jsonify({
                'type': 'daily',
                'date': date,
                'attendance': [
                    {
                        'child_name': record[0],
                        'check_in_time': record[1],
                        'parent_name': record[2]
                    } for record in report_data
                ]
            })
        else:
            return jsonify({
                'type': report_type,
                'date': date,
                'attendance': [
                    {
                        'date': record[0],
                        'unique_children': record[1],
                        'total_visits': record[2]
                    } for record in report_data
                ]
            })
            
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# Health check route
@app.route('/health')
def health_check():
    return jsonify({'status': 'ok', 'message': 'Server is running'})

# Simple delete route for admin
@app.route('/admin/delete_child/<int:child_id>', methods=['DELETE'])
def admin_delete_child(child_id):
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return jsonify({'message': 'No token provided'}), 401
    
    token = token.split(' ')[1]
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        admin_id = decoded['user_id']
        
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # Check if user is admin
        cursor.execute('SELECT role FROM users WHERE id = ?', (admin_id,))
        user_role = cursor.fetchone()
        
        if not user_role or user_role[0] != 'admin':
            conn.close()
            return jsonify({'message': 'Only administrators can delete children'}), 403
        
        # Check if child exists
        cursor.execute('SELECT id, name FROM users WHERE id = ? AND role = "child"', (child_id,))
        child = cursor.fetchone()
        
        if not child:
            conn.close()
            return jsonify({'message': 'Child not found'}), 404
        
        # Delete child and related records
        cursor.execute('DELETE FROM attendance WHERE user_id = ?', (child_id,))
        cursor.execute('DELETE FROM parent_child WHERE child_id = ?', (child_id,))
        cursor.execute('DELETE FROM notifications WHERE user_id = ?', (child_id,))
        cursor.execute('DELETE FROM users WHERE id = ?', (child_id,))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Child deleted successfully'})
    except Exception as e:
        if 'conn' in locals():
            conn.close()
        return jsonify({'message': str(e)}), 500

# Alias for parent route
@app.route('/parent/delete_child/<int:child_id>', methods=['DELETE'])
def delete_child(child_id):
    return admin_delete_child(child_id)

# ✅ Remove attendance record
@app.route('/admin/remove_attendance', methods=['POST'])
def remove_attendance():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return jsonify({'message': 'Missing or invalid token'}), 401

    token = token.split()[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
        role = get_user_role(user_id)

        if role != 'admin':
            return jsonify({'message': 'Unauthorized'}), 403

        data = request.get_json()
        child_id = data.get('child_id')
        check_in_time = data.get('check_in_time')

        if not child_id or not check_in_time:
            return jsonify({'message': 'Child ID and check-in time are required'}), 400

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        # Delete the attendance record
        cursor.execute("""
            DELETE FROM attendance 
            WHERE user_id = ? 
            AND check_in_time = ?
            AND DATE(check_in_time) = DATE('now')
        """, (child_id, check_in_time))

        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'message': 'No matching attendance record found'}), 404

        conn.commit()
        conn.close()

        return jsonify({'message': 'Attendance record removed successfully'})

    except Exception as e:
        return jsonify({'message': str(e)}), 500

# ✅ Change password route
@app.route('/change-password', methods=['POST'])
@limiter.limit("5 per hour")  # Limit password change attempts
def change_password():
    try:
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'message': 'Missing or invalid token'}), 401

        token = auth_header.split()[1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            user_id = payload['user_id']
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401

        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')

        if not all([current_password, new_password, confirm_password]):
            return jsonify({'message': 'All password fields are required'}), 400

        if new_password != confirm_password:
            return jsonify({'message': 'New passwords do not match'}), 400

        # Validate password complexity
        is_valid, message = validate_password_complexity(new_password)
        if not is_valid:
            return jsonify({'message': message}), 400

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        # Get current password hash
        cursor.execute('SELECT password, email FROM users WHERE id = ?', (user_id,))
        result = cursor.fetchone()
        if not result:
            return jsonify({'message': 'User not found'}), 404

        stored_hash, email = result

        # Verify current password
        if not bcrypt.checkpw(current_password.encode('utf-8'), stored_hash):
            return jsonify({'message': 'Current password is incorrect'}), 401

        # Update password
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, user_id))
        conn.commit()

        # Send confirmation email
        subject = "Password Changed - Youth Club"
        message = f"""
        Hello,

        Your password has been successfully changed.

        If you did not make this change, please contact us immediately.

        Best regards,
        Youth Club Team
        """
        send_email_notification(email, subject, message)

        return jsonify({'message': 'Password changed successfully'}), 200

    except Exception as e:
        return jsonify({'message': str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()

# ✅ Run app
if __name__ == '__main__':
    init_db()
    app.run(debug=True)

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number"
    return True, "Password is valid"

def validate_name(name):
    if not name or len(name.strip()) < 2:
        return False, "Name must be at least 2 characters long"
    if not re.match(r'^[a-zA-Z\s-]+$', name):
        return False, "Name can only contain letters, spaces, and hyphens"
    return True, "Name is valid"

# Add session management middleware
@app.before_request
def before_request():
    # Skip session check for static files and login/register routes
    if request.path.startswith('/static/') or request.path in ['/login', '/register', '/request-password-reset', '/reset-password']:
        return

    # Check for token in protected routes
    if request.path.startswith('/admin/') or request.path.startswith('/parent/'):
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'message': 'Missing or invalid token'}), 401

        try:
            token = token.split()[1]
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            
            # Check if token is expired
            if datetime.fromtimestamp(payload['exp']) < datetime.now():
                return jsonify({'message': 'Token has expired'}), 401
                
            # Add user info to request context
            request.user_id = payload['user_id']
            request.user_role = get_user_role(payload['user_id'])
            
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        except Exception as e:
            return jsonify({'message': str(e)}), 500

# Add input validation middleware
@app.before_request
def validate_input():
    if request.is_json:
        # Sanitize JSON input
        data = request.get_json()
        if data:
            sanitized_data = {}
            for key, value in data.items():
                if isinstance(value, str):
                    # Remove any potentially harmful characters
                    sanitized_value = re.sub(r'[<>]', '', value)
                    sanitized_data[key] = sanitized_value
                else:
                    sanitized_data[key] = value
            request._cached_json = sanitized_data

# Add security headers middleware
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';"
    return response

# Add password complexity validation
def validate_password_complexity(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"

# Add email validation
def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Add name validation
def validate_name(name):
    if not name or len(name.strip()) < 2:
        return False, "Name must be at least 2 characters long"
    if not re.match(r'^[a-zA-Z\s-]+$', name):
        return False, "Name can only contain letters, spaces, and hyphens"
    return True, "Name is valid"
