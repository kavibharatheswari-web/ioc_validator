from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import jwt
import os
import re
from models import db, User, APIKey, AnalysisResult
from ioc_analyzer import IOCAnalyzer
from pdf_generator import generate_pdf_report
import json

app = Flask(__name__, static_folder='static', static_url_path='')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ioc_validator.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Email configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@iocvalidator.com')

CORS(app)
db.init_app(app)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Initialize database
with app.app_context():
    try:
        db.create_all()
        print("✓ Database tables created successfully!")
    except Exception as e:
        print(f"✗ Database creation error: {e}")

# Helper function to validate email
def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Authentication Routes
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Validate email format
    if not is_valid_email(data['email']):
        return jsonify({'error': 'Invalid email format'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already registered'}), 400
    
    # Generate verification token
    verification_token = jwt.encode({
        'email': data['email'],
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm='HS256')
    
    user = User(
        email=data['email'],
        username=data['username'],
        password_hash=generate_password_hash(data['password']),
        is_verified=False,
        verification_token=verification_token
    )
    
    db.session.add(user)
    db.session.commit()
    
    # Send verification email
    try:
        if app.config['MAIL_USERNAME']:
            verification_link = f"http://localhost:5000/verify/{verification_token}"
            msg = Message('IOC Validator - Verify Your Email', recipients=[user.email])
            msg.html = f'''
<html>
<body style="font-family: Arial, sans-serif; padding: 20px; background-color: #f4f4f4;">
    <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
        <div style="text-align: center; margin-bottom: 30px;">
            <h1 style="color: #3498db; margin: 0;">🛡️ IOC Validator</h1>
            <p style="color: #7f8c8d; margin-top: 10px;">Advanced Threat Intelligence Platform</p>
        </div>
        
        <h2 style="color: #2c3e50;">Welcome, {user.username}!</h2>
        
        <p style="color: #34495e; line-height: 1.6;">
            Thank you for registering with IOC Validator. To complete your registration and start analyzing threats, 
            please verify your email address by clicking the button below:
        </p>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="{verification_link}" 
               style="display: inline-block; padding: 15px 30px; background-color: #3498db; color: white; 
                      text-decoration: none; border-radius: 5px; font-weight: bold; font-size: 16px;">
                ✓ Verify Email Address
            </a>
        </div>
        
        <p style="color: #7f8c8d; font-size: 14px; margin-top: 30px;">
            Or copy and paste this link into your browser:<br>
            <a href="{verification_link}" style="color: #3498db; word-break: break-all;">{verification_link}</a>
        </p>
        
        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ecf0f1;">
            <p style="color: #95a5a6; font-size: 12px; margin: 5px 0;">
                This verification link will expire in 24 hours.
            </p>
            <p style="color: #95a5a6; font-size: 12px; margin: 5px 0;">
                If you didn't create an account, please ignore this email.
            </p>
        </div>
        
        <div style="text-align: center; margin-top: 30px;">
            <p style="color: #7f8c8d; font-size: 14px;">
                Best regards,<br>
                <strong>IOC Validator Team</strong>
            </p>
        </div>
    </div>
</body>
</html>
'''
            mail.send(msg)
            return jsonify({
                'message': 'Registration successful! Please check your email to verify your account.',
                'email_sent': True
            }), 201
        else:
            # Email not configured - auto-verify for development
            user.is_verified = True
            db.session.commit()
            return jsonify({
                'message': 'User registered successfully (email verification disabled in development)',
                'email_sent': False
            }), 201
    except Exception as e:
        print(f"Email error: {e}")
        # Auto-verify if email fails
        user.is_verified = True
        db.session.commit()
        return jsonify({
            'message': 'User registered successfully (email verification unavailable)',
            'email_sent': False
        }), 201

@app.route('/verify/<token>', methods=['GET'])
def verify_email(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        email = payload['email']
        
        user = User.query.filter_by(email=email, verification_token=token).first()
        if user:
            user.is_verified = True
            user.verification_token = None
            db.session.commit()
            
            # Return HTML page with success message
            return '''
<html>
<head>
    <title>Email Verified - IOC Validator</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f4f4; padding: 50px; text-align: center; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #3498db; }
        .success { color: #27ae60; font-size: 48px; }
        a { display: inline-block; margin-top: 20px; padding: 15px 30px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="success">✓</div>
        <h1>Email Verified Successfully!</h1>
        <p>Your email has been verified. You can now login to IOC Validator.</p>
        <a href="http://localhost:5000">Go to Login</a>
    </div>
</body>
</html>
'''
        else:
            return '''
<html>
<head>
    <title>Verification Failed - IOC Validator</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f4f4; padding: 50px; text-align: center; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #e74c3c; }
        .error { color: #e74c3c; font-size: 48px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="error">✗</div>
        <h1>Verification Failed</h1>
        <p>Invalid or expired verification link.</p>
    </div>
</body>
</html>
'''
    except:
        return '''
<html>
<head>
    <title>Verification Failed - IOC Validator</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f4f4; padding: 50px; text-align: center; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #e74c3c; }
        .error { color: #e74c3c; font-size: 48px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="error">✗</div>
        <h1>Verification Failed</h1>
        <p>Invalid or expired verification link.</p>
    </div>
</body>
</html>
'''

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    
    if user and check_password_hash(user.password_hash, data['password']):
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.utcnow() + timedelta(days=7)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({
            'token': token,
            'user': {
                'id': user.id,
                'email': user.email,
                'username': user.username
            }
        }), 200
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email', '')
    
    if not is_valid_email(email):
        return jsonify({'error': 'Invalid email format'}), 400
    
    user = User.query.filter_by(email=email).first()
    
    if not user:
        return jsonify({'message': 'If the email exists, password recovery instructions have been sent'}), 200
    
    try:
        reset_token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.utcnow() + timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        msg = Message('IOC Validator - Password Recovery', recipients=[user.email])
        msg.html = f'''
<html>
<body style="font-family: Arial, sans-serif; padding: 20px;">
    <h2 style="color: #3498db;">IOC Validator - Password Recovery</h2>
    <p>Hello <strong>{user.username}</strong>,</p>
    <p>You requested password recovery for your IOC Validator account.</p>
    <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <p><strong>Your account details:</strong></p>
        <p>Email: {user.email}</p>
        <p>Username: {user.username}</p>
    </div>
    <p>Please contact your administrator for password reset assistance.</p>
    <p style="color: #7f8c8d; font-size: 0.9em;">This request will expire in 1 hour.</p>
    <p>If you didn't request this, please ignore this email.</p>
    <p>Best regards,<br><strong>IOC Validator Team</strong></p>
</body>
</html>
'''
        
        if app.config['MAIL_USERNAME']:
            mail.send(msg)
            return jsonify({'message': 'Password recovery email sent successfully'}), 200
        else:
            return jsonify({'message': 'Email sent (email not configured for production)', 'token': reset_token}), 200
            
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'error': 'Failed to send recovery email'}), 500

# API Key Management Routes
@app.route('/api/keys', methods=['GET'])
def get_api_keys():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        
        keys = APIKey.query.filter_by(user_id=user_id).all()
        return jsonify([{
            'id': key.id,
            'service_name': key.service_name,
            'created_at': key.created_at.isoformat()
        } for key in keys]), 200
    except:
        return jsonify({'error': 'Unauthorized'}), 401

@app.route('/api/keys', methods=['POST'])
def add_api_key():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        
        data = request.get_json()
        
        # Check if key already exists
        existing = APIKey.query.filter_by(
            user_id=user_id,
            service_name=data['service_name']
        ).first()
        
        if existing:
            existing.api_key = data['api_key']
            db.session.commit()
        else:
            key = APIKey(
                user_id=user_id,
                service_name=data['service_name'],
                api_key=data['api_key']
            )
            db.session.add(key)
            db.session.commit()
        
        return jsonify({'message': 'API key saved successfully'}), 200
    except:
        return jsonify({'error': 'Unauthorized'}), 401

@app.route('/api/keys/<int:key_id>', methods=['DELETE'])
def delete_api_key(key_id):
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        
        key = APIKey.query.filter_by(id=key_id, user_id=user_id).first()
        if key:
            db.session.delete(key)
            db.session.commit()
            return jsonify({'message': 'API key deleted'}), 200
        
        return jsonify({'error': 'Key not found'}), 404
    except:
        return jsonify({'error': 'Unauthorized'}), 401

# User Settings Routes
@app.route('/api/settings/retention', methods=['GET'])
def get_retention_setting():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        
        user = User.query.get(user_id)
        if user:
            return jsonify({
                'retention_weeks': user.history_retention_weeks or 1
            }), 200
        
        return jsonify({'error': 'User not found'}), 404
    except:
        return jsonify({'error': 'Unauthorized'}), 401

@app.route('/api/settings/retention', methods=['PUT'])
def update_retention_setting():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        
        data = request.get_json()
        retention_weeks = data.get('retention_weeks', 1)
        
        # Validate: must be between 1 and 5
        retention_weeks = max(1, min(5, int(retention_weeks)))
        
        user = User.query.get(user_id)
        if user:
            user.history_retention_weeks = retention_weeks
            db.session.commit()
            return jsonify({
                'message': 'Retention setting updated',
                'retention_weeks': retention_weeks
            }), 200
        
        return jsonify({'error': 'User not found'}), 404
    except:
        return jsonify({'error': 'Unauthorized'}), 401

# Timezone Settings Routes
@app.route('/api/settings/timezone', methods=['GET'])
def get_timezone_setting():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        
        user = User.query.get(user_id)
        if user:
            return jsonify({
                'timezone': user.timezone or 'UTC'
            }), 200
        
        return jsonify({'error': 'User not found'}), 404
    except:
        return jsonify({'error': 'Unauthorized'}), 401

@app.route('/api/settings/timezone', methods=['PUT'])
def update_timezone_setting():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        
        data = request.get_json()
        timezone = data.get('timezone', 'UTC')
        
        user = User.query.get(user_id)
        if user:
            user.timezone = timezone
            db.session.commit()
            return jsonify({
                'message': 'Timezone setting updated',
                'timezone': timezone
            }), 200
        
        return jsonify({'error': 'User not found'}), 404
    except:
        return jsonify({'error': 'Unauthorized'}), 401

# IOC Analysis Routes
@app.route('/api/analyze', methods=['POST'])
def analyze_ioc():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        
        # Get user's API keys
        api_keys = {key.service_name: key.api_key 
                   for key in APIKey.query.filter_by(user_id=user_id).all()}
        
        # Handle file upload or text input
        iocs = []
        if 'file' in request.files:
            file = request.files['file']
            content = file.read().decode('utf-8')
            iocs = [line.strip() for line in content.split('\n') if line.strip()]
        else:
            data = request.get_json()
            iocs = data.get('iocs', [])
        
        # Analyze IOCs
        analyzer = IOCAnalyzer(api_keys)
        results = []
        
        for ioc in iocs:
            result = analyzer.analyze(ioc)
            
            # Save to database
            analysis = AnalysisResult(
                user_id=user_id,
                ioc=ioc,
                ioc_type=result['type'],
                threat_category=result['threat_category'],
                threat_score=result['threat_score'],
                threat_type=result['threat_type'],
                severity=result['severity'],
                detailed_results=json.dumps(result['details']),
                ai_summary=result['ai_summary'],
                ai_recommendation=result['ai_recommendation'],
                # SOC investigation context
                ioc_context=result.get('ioc_context', ''),
                first_seen=result.get('first_seen'),
                last_seen=result.get('last_seen'),
                associated_malware=result.get('associated_malware', '[]'),
                campaign_info=result.get('campaign_info', '[]'),
                tags=result.get('tags', '[]')
            )
            db.session.add(analysis)
            results.append(result)
        
        db.session.commit()
        
        return jsonify({'results': results}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/history', methods=['GET'])
def get_history():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        
        # Get user's retention setting
        user = User.query.get(user_id)
        retention_weeks = user.history_retention_weeks if user and user.history_retention_weeks else 1
        retention_weeks = max(1, min(5, retention_weeks))  # Ensure between 1-5 weeks
        
        # Delete data older than retention period
        retention_date = datetime.now() - timedelta(weeks=retention_weeks)
        AnalysisResult.query.filter(
            AnalysisResult.user_id == user_id,
            AnalysisResult.analyzed_at < retention_date
        ).delete()
        db.session.commit()
        
        # Get data within retention period
        analyses = AnalysisResult.query.filter(
            AnalysisResult.user_id == user_id,
            AnalysisResult.analyzed_at >= retention_date
        ).order_by(AnalysisResult.analyzed_at.desc()).all()
        
        return jsonify([{
            'id': a.id,
            'ioc': a.ioc,
            'type': a.ioc_type,
            'threat_category': a.threat_category,
            'threat_score': a.threat_score,
            'severity': a.severity,
            'analyzed_at': a.analyzed_at.isoformat()
        } for a in analyses]), 200
    except:
        return jsonify({'error': 'Unauthorized'}), 401

@app.route('/api/severity/<severity>', methods=['GET'])
def get_by_severity(severity):
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        
        # Get last 24 hours data for specified severity
        twenty_four_hours_ago = datetime.now() - timedelta(hours=24)
        analyses = AnalysisResult.query.filter(
            AnalysisResult.user_id == user_id,
            AnalysisResult.severity == severity,
            AnalysisResult.analyzed_at >= twenty_four_hours_ago
        ).order_by(AnalysisResult.analyzed_at.desc()).all()
        
        # Remove duplicates - keep only most recent per IOC
        unique_analyses = []
        seen_iocs = set()
        
        for analysis in analyses:
            if analysis.ioc not in seen_iocs:
                seen_iocs.add(analysis.ioc)
                unique_analyses.append(analysis)
        
        return jsonify([{
            'id': a.id,
            'ioc': a.ioc,
            'type': a.ioc_type,
            'threat_category': a.threat_category,
            'threat_score': a.threat_score,
            'severity': a.severity,
            'threat_type': a.threat_type,
            'analyzed_at': a.analyzed_at.isoformat()
        } for a in unique_analyses]), 200
    except:
        return jsonify({'error': 'Unauthorized'}), 401

@app.route('/api/report/<int:analysis_id>', methods=['GET'])
def get_detailed_report(analysis_id):
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        
        analysis = AnalysisResult.query.filter_by(id=analysis_id, user_id=user_id).first()
        if not analysis:
            return jsonify({'error': 'Report not found'}), 404
        
        return jsonify({
            'ioc': analysis.ioc,
            'type': analysis.ioc_type,
            'threat_category': analysis.threat_category,
            'threat_score': analysis.threat_score,
            'threat_type': analysis.threat_type,
            'severity': analysis.severity,
            'details': json.loads(analysis.detailed_results),
            'ai_summary': analysis.ai_summary,
            'ai_recommendation': analysis.ai_recommendation,
            'analyzed_at': analysis.analyzed_at.isoformat()
        }), 200
    except:
        return jsonify({'error': 'Unauthorized'}), 401

@app.route('/api/export/pdf', methods=['POST'])
def export_pdf():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        
        data = request.get_json()
        analysis_ids = data.get('analysis_ids', [])
        
        analyses = AnalysisResult.query.filter(
            AnalysisResult.id.in_(analysis_ids),
            AnalysisResult.user_id == user_id
        ).all()
        
        pdf_path = generate_pdf_report(analyses)
        
        return send_file(pdf_path, as_attachment=True, 
                        download_name=f'ioc_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf')
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export-single/<int:analysis_id>', methods=['POST'])
def export_single_ioc(analysis_id):
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        
        # Get single analysis
        analysis = AnalysisResult.query.filter_by(
            id=analysis_id,
            user_id=user_id
        ).first()
        
        if not analysis:
            return jsonify({'error': 'Analysis not found'}), 404
        
        # Generate PDF for single IOC
        pdf_path = generate_pdf_report([analysis])
        
        return send_file(pdf_path, as_attachment=True, 
                        download_name=f'ioc_{analysis.ioc}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf')
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/')
def index():
    return app.send_static_file('index.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
