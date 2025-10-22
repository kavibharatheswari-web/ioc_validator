#!/usr/bin/env python3
"""
Setup Verification Script for IOC Validator
Checks if all components are properly configured
"""

import sys
import os

def check_files():
    """Check if all required files exist"""
    required_files = [
        'app.py',
        'models.py',
        'ioc_analyzer.py',
        'ai_analyzer.py',
        'pdf_generator.py',
        'requirements.txt',
        'static/index.html',
        'static/styles.css',
        'static/app.js'
    ]
    
    print("Checking required files...")
    missing = []
    for file in required_files:
        if os.path.exists(file):
            print(f"  ✓ {file}")
        else:
            print(f"  ✗ {file} - MISSING")
            missing.append(file)
    
    return len(missing) == 0

def check_python_version():
    """Check Python version"""
    print("\nChecking Python version...")
    version = sys.version_info
    if version.major >= 3 and version.minor >= 8:
        print(f"  ✓ Python {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print(f"  ✗ Python {version.major}.{version.minor}.{version.micro} - Need 3.8+")
        return False

def check_dependencies():
    """Check if dependencies can be imported"""
    print("\nChecking dependencies...")
    dependencies = [
        ('flask', 'Flask'),
        ('flask_cors', 'Flask-CORS'),
        ('flask_login', 'Flask-Login'),
        ('flask_sqlalchemy', 'Flask-SQLAlchemy'),
        ('requests', 'Requests'),
        ('jwt', 'PyJWT'),
        ('werkzeug', 'Werkzeug'),
        ('reportlab', 'ReportLab'),
        ('validators', 'Validators')
    ]
    
    all_ok = True
    for module, name in dependencies:
        try:
            __import__(module)
            print(f"  ✓ {name}")
        except ImportError:
            print(f"  ✗ {name} - NOT INSTALLED")
            all_ok = False
    
    # Check optional dependencies
    print("\nChecking optional dependencies (AI features)...")
    try:
        import transformers
        print("  ✓ Transformers")
    except ImportError:
        print("  ⚠ Transformers - NOT INSTALLED (AI features disabled)")
    
    try:
        import torch
        print("  ✓ PyTorch")
    except ImportError:
        print("  ⚠ PyTorch - NOT INSTALLED (AI features disabled)")
    
    return all_ok

def check_database():
    """Check if database can be initialized"""
    print("\nChecking database...")
    try:
        from app import app, db
        with app.app_context():
            db.create_all()
        print("  ✓ Database initialized successfully")
        return True
    except Exception as e:
        print(f"  ✗ Database error: {e}")
        return False

def main():
    """Run all checks"""
    print("=" * 50)
    print("IOC Validator - Setup Verification")
    print("=" * 50)
    
    checks = [
        ("Files", check_files()),
        ("Python Version", check_python_version()),
        ("Dependencies", check_dependencies()),
        ("Database", check_database())
    ]
    
    print("\n" + "=" * 50)
    print("Summary")
    print("=" * 50)
    
    all_passed = True
    for name, passed in checks:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{name}: {status}")
        if not passed:
            all_passed = False
    
    print("\n" + "=" * 50)
    if all_passed:
        print("✓ All checks passed! Ready to run.")
        print("\nTo start the application:")
        print("  python app.py")
        print("\nThen open: http://localhost:5000")
    else:
        print("✗ Some checks failed. Please fix the issues above.")
        print("\nTo install dependencies:")
        print("  pip install -r requirements.txt")
    print("=" * 50)
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())
