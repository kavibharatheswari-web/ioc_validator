#!/usr/bin/env python3
"""
Database migration script to add new SOC investigation fields
"""

from app import app, db
from sqlalchemy import text

def migrate_database():
    """Add new columns to AnalysisResult table"""
    with app.app_context():
        try:
            # Check if columns already exist
            inspector = db.inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('analysis_result')]
            
            new_columns = [
                ('ioc_context', 'TEXT'),
                ('first_seen', 'VARCHAR(100)'),
                ('last_seen', 'VARCHAR(100)'),
                ('associated_malware', 'TEXT'),
                ('campaign_info', 'TEXT'),
                ('tags', 'TEXT')
            ]
            
            for col_name, col_type in new_columns:
                if col_name not in columns:
                    print(f"Adding column: {col_name}")
                    db.session.execute(text(f'ALTER TABLE analysis_result ADD COLUMN {col_name} {col_type}'))
                else:
                    print(f"Column {col_name} already exists, skipping")
            
            db.session.commit()
            print("\n✅ Database migration completed successfully!")
            print("New SOC investigation fields added:")
            print("  - ioc_context")
            print("  - first_seen")
            print("  - last_seen")
            print("  - associated_malware")
            print("  - campaign_info")
            print("  - tags")
            
        except Exception as e:
            print(f"\n❌ Migration failed: {e}")
            db.session.rollback()

if __name__ == "__main__":
    migrate_database()
