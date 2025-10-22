#!/usr/bin/env python3
"""
Migration script to add timezone column to user table
"""

import sqlite3

def migrate():
    try:
        conn = sqlite3.connect('ioc_validator.db')
        cursor = conn.cursor()
        
        print("Adding timezone column to user table...")
        
        # Check if column already exists
        cursor.execute("PRAGMA table_info(user)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'timezone' not in columns:
            cursor.execute("ALTER TABLE user ADD COLUMN timezone VARCHAR(50) DEFAULT 'UTC'")
            conn.commit()
            print("✅ Column added successfully!")
        else:
            print("ℹ️  Column already exists")
        
        conn.close()
        print("\n✅ Database migration completed successfully!")
        print("Users can now configure their timezone in Settings")
        
    except Exception as e:
        print(f"❌ Error during migration: {e}")
        return False
    
    return True

if __name__ == "__main__":
    migrate()
