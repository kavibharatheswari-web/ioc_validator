# Quick Start Guide - IOC Validator

## 🚀 Get Started in 3 Steps

### Step 1: Install Dependencies
```bash
# Run the setup script
./setup.sh

# OR manually:
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Step 2: Start the Application
```bash
# Run the start script
./run.sh

# OR manually:
source venv/bin/activate
python app.py
```

### Step 3: Access the Web Interface
Open your browser and go to: **http://localhost:5000**

---

## 📋 First Time Setup

### 1. Create an Account
- Click "Register" on the login page
- Fill in your details
- Click "Register"

### 2. Login
- Enter your email and password
- Click "Login"

### 3. (Optional) Add API Keys
Go to **Settings** and add API keys for:

| Service | Free Tier | Get API Key |
|---------|-----------|-------------|
| VirusTotal | ✅ Yes | https://www.virustotal.com/gui/join-us |
| AbuseIPDB | ✅ Yes | https://www.abuseipdb.com/register |
| Hybrid Analysis | ✅ Yes | https://www.hybrid-analysis.com/signup |
| AlienVault OTX | ✅ No key needed | - |
| URLScan.io | ✅ No key needed | - |
| MalwareBazaar | ✅ No key needed | - |

---

## 🔍 Analyze Your First IOC

### Method 1: Text Input
1. Go to **Analyze** section
2. Enter IOCs (one per line):
   ```
   8.8.8.8
   google.com
   https://example.com
   5d41402abc4b2a76b9719d911017c592
   ```
3. Click **Analyze**

### Method 2: File Upload
1. Go to **Analyze** section
2. Click **File Upload** tab
3. Upload `sample_iocs.txt` (included in project)
4. Click **Analyze File**

---

## 📊 Understanding Results

### Threat Scores
- **0-30**: Low risk (Green)
- **30-50**: Medium risk (Blue)
- **50-70**: High risk (Orange)
- **70-100**: Critical (Red)

### Severity Levels
- **Info**: Clean, no threats detected
- **Low**: Minor suspicious activity
- **Medium**: Potentially malicious
- **High**: Likely malicious
- **Critical**: Confirmed malicious

### View Detailed Reports
- Click **View Details** on any result
- See tool-by-tool analysis
- Read AI-generated summary
- Get actionable recommendations

---

## 💾 Export Results

### PDF Export
1. After analyzing IOCs, click **Export PDF**
2. PDF includes:
   - Executive summary
   - Detailed analysis for each IOC
   - Tool results with links
   - AI recommendations
   - Timestamp

---

## 🔧 Troubleshooting

### Application won't start
```bash
# Check if port 5000 is in use
lsof -i :5000

# Use different port
# Edit app.py, change: app.run(port=5001)
```

### Database errors
```bash
# Reset database
rm ioc_validator.db
python -c "from app import app, db; app.app_context().push(); db.create_all()"
```

### AI model not loading
- Don't worry! The app uses rule-based analysis as fallback
- All features work without the AI model
- For GPU acceleration: `pip install torch --index-url https://download.pytorch.org/whl/cu118`

---

## 📚 Supported IOC Types

| Type | Example | Detection |
|------|---------|-----------|
| IPv4 | `192.168.1.1` | ✅ |
| IPv6 | `2001:0db8::1` | ✅ |
| Domain | `example.com` | ✅ |
| URL | `http://example.com` | ✅ |
| MD5 | `5d41402abc4b2a76b9719d911017c592` | ✅ |
| SHA1 | `aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d` | ✅ |
| SHA256 | `2c26b46b68ffc68ff99b453c1d30413413422d706...` | ✅ |
| Email | `test@example.com` | ✅ |
| PowerShell | `Invoke-WebRequest...` | ✅ |

---

## 🎯 Best Practices

### For Accurate Results
1. **Add API Keys**: More tools = better analysis
2. **Batch Analysis**: Analyze 10-20 IOCs at a time
3. **Review History**: Track trends over time
4. **Export Reports**: Keep records for compliance

### Security Tips
1. Never share your API keys
2. Use strong passwords
3. Review AI recommendations carefully
4. Verify critical findings manually

---

## 🆘 Need Help?

### Common Questions

**Q: Do I need API keys?**
A: No, but they improve results. Some tools work without keys.

**Q: Is my data secure?**
A: Yes, all data is stored locally in SQLite database.

**Q: Can I analyze files?**
A: Yes, upload .txt or .csv files with IOCs (one per line).

**Q: How accurate is the AI?**
A: AI provides recommendations; always verify critical findings.

**Q: Can I use this commercially?**
A: Yes, but check API terms of service for each tool.

---

## 🎉 You're Ready!

Start analyzing IOCs and stay ahead of threats!

For detailed documentation, see **README.md**
