#!/usr/bin/env python3
"""
Database migration script to add history_retention_weeks column
"""

from app import app, db
from sqlalchemy import text

def migrate_database():
    """Add history_retention_weeks column to User table"""
    with app.app_context():
        try:
            # Check if column already exists
            inspector = db.inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('user')]
            
            if 'history_retention_weeks' not in columns:
                print("Adding history_retention_weeks column to user table...")
                db.session.execute(text('ALTER TABLE user ADD COLUMN history_retention_weeks INTEGER DEFAULT 1'))
                db.session.commit()
                print("✅ Column added successfully!")
            else:
                print("Column history_retention_weeks already exists, skipping")
            
            print("\n✅ Database migration completed successfully!")
            print("Users can now configure history retention (1-5 weeks)")
            
        except Exception as e:
            print(f"\n❌ Migration failed: {e}")
            db.session.rollback()

if __name__ == "__main__":
    migrate_database()
