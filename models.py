from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    history_retention_weeks = db.Column(db.Integer, default=1)  # Default 1 week, max 5 weeks
    timezone = db.Column(db.String(50), default='UTC')  # User's timezone (e.g., 'Asia/Kolkata', 'America/New_York')
    is_verified = db.Column(db.Boolean, default=False)  # Email verification status
    verification_token = db.Column(db.String(200))  # Token for email verification
    
    api_keys = db.relationship('APIKey', backref='user', lazy=True, cascade='all, delete-orphan')
    analyses = db.relationship('AnalysisResult', backref='user', lazy=True, cascade='all, delete-orphan')

class APIKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service_name = db.Column(db.String(50), nullable=False)
    api_key = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AnalysisResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ioc = db.Column(db.String(500), nullable=False)
    ioc_type = db.Column(db.String(50), nullable=False)
    threat_category = db.Column(db.String(100))
    threat_score = db.Column(db.Float)
    threat_type = db.Column(db.String(100))
    severity = db.Column(db.String(20))
    detailed_results = db.Column(db.Text)
    ai_summary = db.Column(db.Text)
    ai_recommendation = db.Column(db.Text)
    analyzed_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # New fields for SOC investigation
    ioc_context = db.Column(db.Text)  # Context about the IOC (campaigns, malware families, etc.)
    first_seen = db.Column(db.String(100))  # When the IOC was first seen
    last_seen = db.Column(db.String(100))  # When the IOC was last seen
    associated_malware = db.Column(db.Text)  # Associated malware families
    campaign_info = db.Column(db.Text)  # Related cyber attack campaigns
    tags = db.Column(db.Text)  # Tags from threat intelligence
