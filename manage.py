#!/usr/bin/env python3
"""
IOC Validator Management CLI
Provides commands for managing the application
"""

import sys
import os
from datetime import datetime

def show_help():
    """Display help information"""
    print("""
╔══════════════════════════════════════════════════════════════╗
║         IOC Validator - Management CLI                      ║
╚══════════════════════════════════════════════════════════════╝

Usage: python manage.py <command>

Available Commands:

  📊 Database Management:
    init          Initialize the database
    backup        Create database backup
    stats         Show database statistics
    export        Export results to CSV
    reset         Reset database (WARNING: deletes all data)

  👤 User Management:
    create-demo   Create demo user account
    list-users    List all users

  🧪 Testing:
    test          Run IOC analyzer tests
    verify        Verify installation

  🚀 Application:
    start         Start the application
    status        Check if app is running

  📚 Documentation:
    docs          Open documentation in browser
    help          Show this help message

Examples:
  python manage.py init
  python manage.py create-demo
  python manage.py stats
  python manage.py start

For more information, see README.md
""")

def init_database():
    """Initialize database"""
    print("Initializing database...")
    os.system("python init_db.py")

def backup_database():
    """Backup database"""
    print("Creating database backup...")
    os.system("python backup_database.py")

def show_stats():
    """Show statistics"""
    os.system("python stats.py")

def export_results():
    """Export results"""
    os.system("python export_results.py")

def reset_database():
    """Reset database"""
    print("\n⚠️  WARNING: This will delete ALL data!")
    response = input("Are you sure? Type 'yes' to confirm: ")
    
    if response.lower() == 'yes':
        if os.path.exists('ioc_validator.db'):
            os.remove('ioc_validator.db')
            print("✅ Database deleted")
        print("Initializing new database...")
        os.system("python init_db.py")
    else:
        print("❌ Operation cancelled")

def create_demo():
    """Create demo user"""
    os.system("python create_demo_user.py")

def list_users():
    """List all users"""
    from app import app, db
    from models import User
    
    with app.app_context():
        users = User.query.all()
        
        if not users:
            print("\n⚠️  No users found in database\n")
            return
        
        print("\n" + "=" * 60)
        print("Registered Users")
        print("=" * 60)
        
        for user in users:
            print(f"\n👤 {user.username}")
            print(f"   Email: {user.email}")
            print(f"   ID: {user.id}")
            print(f"   Joined: {user.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
        
        print("\n" + "=" * 60 + "\n")

def run_tests():
    """Run tests"""
    os.system("python test_ioc_analyzer.py")

def verify_setup():
    """Verify setup"""
    os.system("python verify_setup.py")

def start_app():
    """Start application"""
    print("Starting IOC Validator...")
    print("Access at: http://localhost:5000")
    print("Press Ctrl+C to stop\n")
    os.system("python app.py")

def check_status():
    """Check if app is running"""
    import socket
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', 5000))
    sock.close()
    
    if result == 0:
        print("✅ Application is RUNNING on http://localhost:5000")
    else:
        print("❌ Application is NOT running")
        print("   Start with: python manage.py start")

def open_docs():
    """Open documentation"""
    import webbrowser
    
    docs = [
        ('START_HERE.md', 'Quick Start Guide'),
        ('INSTALLATION_COMPLETE.md', 'Complete Installation Guide'),
        ('README.md', 'Full Documentation'),
        ('QUICK_START.md', 'Quick Reference'),
    ]
    
    print("\n📚 Available Documentation:\n")
    for i, (file, desc) in enumerate(docs, 1):
        print(f"  {i}. {desc} ({file})")
    
    print("\nDocumentation files are in the project directory.")
    print("Open them with your favorite text editor.\n")

def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        show_help()
        return
    
    command = sys.argv[1].lower()
    
    commands = {
        'help': show_help,
        'init': init_database,
        'backup': backup_database,
        'stats': show_stats,
        'export': export_results,
        'reset': reset_database,
        'create-demo': create_demo,
        'list-users': list_users,
        'test': run_tests,
        'verify': verify_setup,
        'start': start_app,
        'status': check_status,
        'docs': open_docs,
    }
    
    if command in commands:
        try:
            commands[command]()
        except KeyboardInterrupt:
            print("\n\n⚠️  Operation cancelled by user\n")
        except Exception as e:
            print(f"\n❌ Error: {e}\n")
    else:
        print(f"\n❌ Unknown command: {command}")
        print("   Run 'python manage.py help' for available commands\n")

if __name__ == "__main__":
    main()
