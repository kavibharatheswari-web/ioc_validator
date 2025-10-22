#!/usr/bin/env python3
"""Initialize the database"""
from app import app, db

with app.app_context():
    db.create_all()
    print("✓ Database initialized successfully!")
    print("✓ Tables created: User, APIKey, AnalysisResult")
