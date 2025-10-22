#!/usr/bin/env python3
"""
Create a demo user account for testing
Username: demo
Email: demo@iocvalidator.com
Password: Demo123!
"""

from app import app, db
from models import User
from werkzeug.security import generate_password_hash

def create_demo_user():
    """Create demo user account"""
    with app.app_context():
        # Check if demo user already exists
        existing_user = User.query.filter_by(email='demo@iocvalidator.com').first()
        
        if existing_user:
            print("⚠️  Demo user already exists!")
            print(f"   Email: demo@iocvalidator.com")
            print(f"   Password: Demo123!")
            return
        
        # Create demo user
        demo_user = User(
            email='demo@iocvalidator.com',
            username='demo',
            password_hash=generate_password_hash('Demo123!')
        )
        
        db.session.add(demo_user)
        db.session.commit()
        
        print("✅ Demo user created successfully!")
        print("")
        print("=" * 60)
        print("Demo Account Credentials:")
        print("=" * 60)
        print("Email:    demo@iocvalidator.com")
        print("Password: Demo123!")
        print("=" * 60)
        print("")
        print("You can now login with these credentials at:")
        print("http://localhost:5000")
        print("")

if __name__ == "__main__":
    create_demo_user()
