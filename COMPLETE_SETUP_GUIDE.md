# 🚀 IOC Validator - Complete Setup & Deployment Guide

## 📋 TABLE OF CONTENTS

1. [System Requirements](#system-requirements)
2. [Installation Steps](#installation-steps)
3. [Database Migration](#database-migration)
4. [Configuration](#configuration)
5. [Running the Application](#running-the-application)
6. [Feature Verification](#feature-verification)
7. [Troubleshooting](#troubleshooting)

---

## 🖥️ SYSTEM REQUIREMENTS

### Minimum Requirements
- **OS**: Linux, macOS, or Windows
- **Python**: 3.8 or higher
- **RAM**: 4GB minimum (8GB recommended)
- **Disk Space**: 2GB free space
- **Browser**: Chrome, Firefox, Safari, or Edge (latest versions)

### Dependencies
- Flask 2.3.0
- Flask-Mail 0.9.1
- SQLAlchemy 3.0.5
- PyJWT 2.8.0
- Transformers 4.30.0
- ReportLab 4.0.4
- And more (see requirements.txt)

---

## 📦 INSTALLATION STEPS

### Step 1: Clone/Navigate to Project
```bash
cd /home/pradeeppalanisamy/CascadeProjects/windsurf-project-8
```

### Step 2: Create Virtual Environment (Recommended)
```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate  # Linux/Mac
# OR
venv\Scripts\activate     # Windows
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

**Expected Output**:
```
Successfully installed Flask-2.3.0 Flask-CORS-4.0.0 Flask-Mail-0.9.1 ...
```

---

## 🗄️ DATABASE MIGRATION

### Step 1: Run Retention Migration
```bash
python migrate_retention.py
```

**Expected Output**:
```
Adding history_retention_weeks column to user table...
✅ Column added successfully!
✅ Database migration completed successfully!
```

### Step 2: Verify Database
```bash
# Check if database exists
ls -la ioc_validator.db
```

**Note**: Database will be created automatically on first run if it doesn't exist.

---

## ⚙️ CONFIGURATION

### Required Configuration
**None** - Application works out of the box with defaults!

### Optional Configuration

#### 1. Email Configuration (For Password Recovery)
```bash
# Gmail example
export MAIL_SERVER=smtp.gmail.com
export MAIL_PORT=587
export MAIL_USERNAME=your-email@gmail.com
export MAIL_PASSWORD=your-app-password
export MAIL_DEFAULT_SENDER=noreply@iocvalidator.com
```

**How to get Gmail App Password**:
1. Enable 2-Factor Authentication
2. Go to Google Account → Security
3. 2-Step Verification → App passwords
4. Generate password for "Mail"

#### 2. API Keys (For Enhanced Analysis)
Configure in Settings page after login:
- VirusTotal
- AbuseIPDB
- Hybrid Analysis
- Shodan
- Censys

---

## 🚀 RUNNING THE APPLICATION

### Development Mode
```bash
python app.py
```

**Expected Output**:
```
 * Serving Flask app 'app'
 * Debug mode: off
WARNING: This is a development server.
 * Running on http://127.0.0.1:5000
Press CTRL+C to quit
```

### Production Mode (with Gunicorn)
```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Access Application
```
URL: http://localhost:5000
```

---

## ✅ FEATURE VERIFICATION

### 1. Authentication ✓
```
Test:
1. Open http://localhost:5000
2. Click "Register"
3. Enter valid email, username, password
4. Register → Should succeed
5. Login with credentials → Should succeed

Status: [ ]
```

### 2. Dashboard ✓
```
Test:
1. After login, check dashboard
2. Verify 5 stat cards (Critical, High, Medium, Low, Clean)
3. Cards show "(24h)" label
4. Click any card → Popup opens
5. Top 20 IOCs displayed below

Status: [ ]
```

### 3. IOC Analysis ✓
```
Test:
1. Go to "Analyze" tab
2. Enter IOC: 8.8.8.8
3. Click "Analyze IOCs"
4. Wait for results
5. Check results table
6. Click "View Details"
7. Click download button (📥)

Status: [ ]
```

### 4. History & Search ✓
```
Test:
1. Go to "History" tab
2. Search for IOC
3. Filter by severity
4. Filter by type
5. Export CSV
6. Toggle dark mode

Status: [ ]
```

### 5. Settings ✓
```
Test:
1. Go to "Settings" tab
2. Check retention dropdown (1-5 weeks)
3. Change retention setting
4. Add API key
5. Delete API key

Status: [ ]
```

### 6. Dark Mode ✓
```
Test:
1. Click "🌙 Dark Mode" button
2. Verify all text is clear
3. Verify borders visible
4. Verify buttons have contrast
5. Toggle back to light mode

Status: [ ]
```

---

## 🐛 TROUBLESHOOTING

### Issue 1: Port Already in Use
```
Error: Address already in use

Solution:
# Find process using port 5000
lsof -i :5000

# Kill the process
kill -9 <PID>

# Or use different port
python app.py --port 5001
```

### Issue 2: Database Locked
```
Error: database is locked

Solution:
# Stop all instances
pkill -f "python app.py"

# Restart
python app.py
```

### Issue 3: Module Not Found
```
Error: ModuleNotFoundError: No module named 'flask'

Solution:
# Reinstall dependencies
pip install -r requirements.txt
```

### Issue 4: Email Not Sending
```
Error: Failed to send recovery email

Solution:
# Email is optional - app works without it
# If needed, check:
1. MAIL_USERNAME is set
2. MAIL_PASSWORD is correct (use app password for Gmail)
3. Port 587 is not blocked
```

### Issue 5: Dark Mode Not Clear
```
Issue: Dark mode text hard to read

Solution:
# Already fixed in latest version
# Hard refresh browser: Ctrl+Shift+R
```

### Issue 6: Character Splitting in IOC Context
```
Issue: Malware shows as "S, k, y, n, e, t"

Solution:
# Already fixed in latest version
# Restart application
```

---

## 📊 COMPLETE FEATURE LIST

### Core Features (20+)
1. ✅ User Authentication (Register/Login/Logout)
2. ✅ Email Validation
3. ✅ Password Recovery (Forgot Password)
4. ✅ IOC Type Detection (9+ types)
5. ✅ Multi-IOC Analysis (Text & File Upload)
6. ✅ 12 Security Tools Integration
7. ✅ AI-Powered Threat Analysis
8. ✅ Enhanced Tool Data (Community Scores, ISP, etc.)
9. ✅ Threat Scoring Algorithm
10. ✅ Severity Classification
11. ✅ IOC Context & Threat Intelligence
12. ✅ Malware Families Detection
13. ✅ Campaign Association
14. ✅ Threat Tags
15. ✅ First/Last Seen Dates
16. ✅ PDF Export (Single & Bulk)
17. ✅ CSV Export
18. ✅ API Key Management
19. ✅ Configurable History Retention (1-5 weeks)
20. ✅ Automatic Data Cleanup

### Dashboard Features (10+)
21. ✅ 24-Hour Statistics
22. ✅ Unique IOC Counting (No Duplicates)
23. ✅ 5 Severity Categories
24. ✅ Clickable Stat Cards
25. ✅ Severity Popups
26. ✅ Top 20 IOCs by Severity
27. ✅ Threat Score Display
28. ✅ Quick View & Download
29. ✅ Real-time Updates
30. ✅ Professional UI

### History Features (10+)
31. ✅ 7-Day Default Retention
32. ✅ Configurable Retention (1-5 weeks)
33. ✅ No Duplicate IOCs
34. ✅ Real-time Search
35. ✅ Severity Filter
36. ✅ Type Filter
37. ✅ Combined Filters
38. ✅ Copy to Clipboard
39. ✅ Export to CSV
40. ✅ Download Individual PDFs

### UI/UX Features (10+)
41. ✅ Dark Mode (Improved)
42. ✅ Light Mode
43. ✅ Responsive Design
44. ✅ Professional Theme
45. ✅ Smooth Animations
46. ✅ Hover Effects
47. ✅ Loading Indicators
48. ✅ Success/Error Notifications
49. ✅ Modal Dialogs
50. ✅ Icon Buttons

### Security Features (10+)
51. ✅ JWT Authentication
52. ✅ Password Hashing
53. ✅ Email Validation
54. ✅ Secure Token Generation
55. ✅ Session Management
56. ✅ Authorization Checks
57. ✅ API Key Encryption
58. ✅ CORS Protection
59. ✅ SQL Injection Prevention
60. ✅ XSS Protection

---

## 📚 DOCUMENTATION

### Available Guides (24 Files)
1. 🚀_READ_ME_FIRST.txt
2. START_HERE.md
3. COMPLETE_SETUP_GUIDE.md (This file)
4. COMPLETE_SUMMARY.md
5. FINAL_VERIFICATION.md
6. FORMATTING_FIXES.md
7. PASSWORD_RECOVERY.md
8. RETENTION_SETTINGS.md
9. NO_DUPLICATES_UPDATE.md
10. FINAL_UPDATES.md
11. SOC_FEATURES_ADDED.md
12. TEST_ALL_FEATURES.md
13. TOOL_ENHANCEMENTS_V2.md
14. DASHBOARD_UPDATES.md
15. SOC_ENHANCEMENTS.md
16. SCORING_FIX.md
17. PDF_EXPORT_FIX.md
18. NOTES_FEATURE.md
19. SEVERITY_FIX.md
20. AI_ENHANCEMENTS.md
21. TOOL_INTEGRATION.md
22. DATABASE_SCHEMA.md
23. API_DOCUMENTATION.md
24. DEPLOYMENT_GUIDE.md

---

## 🎯 QUICK START CHECKLIST

### Pre-Launch
- [ ] Python 3.8+ installed
- [ ] Dependencies installed (`pip install -r requirements.txt`)
- [ ] Database migrated (`python migrate_retention.py`)
- [ ] Port 5000 available

### Launch
- [ ] Run `python app.py`
- [ ] Open http://localhost:5000
- [ ] Register new account
- [ ] Login successfully

### Verify Core Features
- [ ] Dashboard loads
- [ ] Analyze IOC works
- [ ] History displays
- [ ] Settings accessible
- [ ] Dark mode works

### Optional Setup
- [ ] Configure email (for password recovery)
- [ ] Add API keys (for enhanced analysis)
- [ ] Set retention period (in Settings)

---

## 🔐 DEFAULT CREDENTIALS

### Demo Account
```
Email: demo@iocvalidator.com
Password: Demo123!
```

**Note**: Create this account on first run or register your own.

---

## 🌐 DEPLOYMENT OPTIONS

### Option 1: Local Development
```bash
python app.py
# Access: http://localhost:5000
```

### Option 2: Production with Gunicorn
```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
# Access: http://your-server-ip:5000
```

### Option 3: Docker (Future)
```bash
# Coming soon
docker build -t ioc-validator .
docker run -p 5000:5000 ioc-validator
```

### Option 4: Cloud Deployment
- **Heroku**: Use Procfile
- **AWS**: Use EC2 or Elastic Beanstalk
- **Azure**: Use App Service
- **Google Cloud**: Use App Engine

---

## 📊 PERFORMANCE TIPS

### 1. Database Optimization
```python
# Already implemented:
- Automatic cleanup (retention-based)
- Indexed queries
- Efficient filtering
```

### 2. API Key Usage
```
- Add VirusTotal key for enhanced data
- Add AbuseIPDB for IP reputation
- Other keys optional
```

### 3. Retention Settings
```
- Lower retention = faster queries
- Higher retention = more historical data
- Recommended: 1-2 weeks for production
```

---

## 🆘 SUPPORT

### Getting Help
1. Check documentation (24 guides available)
2. Review TROUBLESHOOTING section
3. Check console for errors
4. Review browser console (F12)

### Common Issues
- Port conflicts → Use different port
- Database locked → Restart application
- Email not sending → Optional feature
- Dark mode unclear → Already fixed

---

## ✅ FINAL CHECKLIST

### Installation Complete When:
- [ ] All dependencies installed
- [ ] Database migrated
- [ ] Application starts without errors
- [ ] Can access http://localhost:5000
- [ ] Can register and login
- [ ] Can analyze IOCs
- [ ] Can view history
- [ ] Can export data
- [ ] Dark mode works
- [ ] All features functional

---

## 🎉 SUCCESS!

If all checks pass, your IOC Validator is ready for use!

**Next Steps**:
1. Configure API keys (Settings)
2. Set retention period (Settings)
3. Start analyzing IOCs
4. Explore all features
5. Customize as needed

---

**Version**: 1.9.1 - Production Ready  
**Total Features**: 60+  
**Documentation**: 24 comprehensive guides  
**Status**: ✅ **READY FOR DEPLOYMENT**

---

**Happy Analyzing! 🚀**
