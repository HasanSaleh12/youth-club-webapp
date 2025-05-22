# Youth Club Management System

A comprehensive web application for managing youth club activities, attendance, and parent communications.

## Features

- 🔐 Secure Authentication System
  - JWT-based authentication
  - Two-factor authentication (2FA)
  - Password reset functionality
  - Role-based access control

- 👥 User Management
  - Parent accounts
  - Admin accounts
  - Child profiles
  - Parent-child relationship management

- 📱 QR Code Attendance System
  - QR code generation for children
  - Real-time attendance tracking
  - Automated parent notifications

- 📊 Analytics & Reporting
  - Attendance statistics
  - Daily/weekly/monthly reports
  - Parent dashboard
  - Admin analytics

- 📧 Communication System
  - Email notifications
  - In-app notifications
  - Automated attendance alerts

## Tech Stack

- Backend: Python/Flask
- Database: SQLite
- Authentication: JWT, bcrypt
- QR Code: qrcode
- 2FA: pyotp
- Rate Limiting: Flask-Limiter

## Prerequisites

- Python 3.8+
- pip (Python package manager)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/youth-club-management.git
cd youth-club-management
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
Create a `.env` file in the backend directory with the following variables:
```
# Generate a secure secret key using Python:
# python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY=your-generated-secret-key

# Email configuration
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# Application settings
FLASK_ENV=development
FLASK_DEBUG=1
```



5. Initialize the database:
```bash
python backend/app.py
```

## Running the Application

1. Start the Flask server:
```bash
python backend/app.py
```

2. Access the application at `http://localhost:5000`

## API Documentation

### Authentication Endpoints

- `POST /register` - Register a new user
- `POST /login` - User login
- `POST /request-password-reset` - Request password reset
- `POST /reset-password` - Reset password
- `POST /enable-2fa` - Enable two-factor authentication
- `POST /verify-2fa` - Verify 2FA code

### Parent Endpoints

- `GET /parent/children` - Get list of children
- `POST /parent/add_child` - Add a new child
- `GET /parent/analytics/<child_id>` - Get child analytics
- `GET /parent/dashboard` - Access parent dashboard

### Admin Endpoints

- `GET /admin/attendance` - View attendance records
- `GET /admin/analytics` - Access admin analytics
- `POST /admin/remove_attendance` - Remove attendance record
- `DELETE /admin/delete_child/<child_id>` - Delete child record

## Security Features

- Rate limiting on sensitive endpoints
- Input validation and sanitization
- Secure password hashing
- JWT token-based authentication
- Two-factor authentication
- Email verification
- SQL injection prevention
- XSS protection

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Flask framework
- SQLite database
- JWT for authentication
- QR Code generation library
- All other open-source libraries used in this project 
