#!/usr/bin/env python3
"""
Backup the IOC Validator database
Creates a timestamped backup of the database file
"""

import shutil
import os
from datetime import datetime

def backup_database():
    """Create a backup of the database"""
    db_file = 'ioc_validator.db'
    
    if not os.path.exists(db_file):
        print("❌ Database file not found!")
        print("   Make sure the database has been initialized.")
        return
    
    # Create backups directory if it doesn't exist
    backup_dir = 'backups'
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    
    # Create timestamped backup filename
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_file = os.path.join(backup_dir, f'ioc_validator_backup_{timestamp}.db')
    
    # Copy database file
    try:
        shutil.copy2(db_file, backup_file)
        file_size = os.path.getsize(backup_file)
        
        print("✅ Database backup created successfully!")
        print("")
        print("=" * 60)
        print(f"Backup File: {backup_file}")
        print(f"Size: {file_size:,} bytes")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        print("")
        print("To restore this backup:")
        print(f"  cp {backup_file} ioc_validator.db")
        print("")
        
    except Exception as e:
        print(f"❌ Backup failed: {e}")

if __name__ == "__main__":
    backup_database()
