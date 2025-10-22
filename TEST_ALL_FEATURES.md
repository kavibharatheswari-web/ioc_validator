# 🧪 IOC Validator - Complete Feature Testing Guide

## ✅ COMPREHENSIVE TEST PLAN

**Version**: 1.6.0  
**Date**: 2025-10-22

---

## 🎯 TEST CATEGORIES

1. Authentication & Authorization
2. Dashboard Features
3. IOC Analysis
4. History & Search
5. Export Functions
6. UI/UX Features
7. Security Tools Integration
8. PDF Generation
9. API Key Management
10. Dark Mode

---

## 1️⃣ AUTHENTICATION & AUTHORIZATION

### Test 1.1: User Registration
```
Steps:
1. Open http://localhost:5000
2. Click "Register"
3. Enter email: test@example.com
4. Enter username: testuser
5. Enter password: Test123!
6. Click Register

Expected:
✓ Success message
✓ Redirected to login
✓ User created in database

Status: [ ]
```

### Test 1.2: User Login
```
Steps:
1. Enter email: demo@iocvalidator.com
2. Enter password: Demo123!
3. Click Login

Expected:
✓ Success message
✓ Redirected to dashboard
✓ Token stored in localStorage

Status: [ ]
```

### Test 1.3: User Logout
```
Steps:
1. Click "Logout" button

Expected:
✓ Redirected to login
✓ Token removed
✓ Cannot access protected pages

Status: [ ]
```

---

## 2️⃣ DASHBOARD FEATURES

### Test 2.1: Stats Display (Last 2 Validations)
```
Steps:
1. Login to application
2. View dashboard

Expected:
✓ 5 stat cards visible (Critical, High, Medium, Low, Clean)
✓ Counts from last 2 analyses
✓ Numbers accurate

Status: [ ]
```

### Test 2.2: Top 20 IOCs Display
```
Steps:
1. View dashboard
2. Check "Top 20 IOCs by Severity" section

Expected:
✓ Up to 20 IOCs displayed
✓ Sorted by severity (Critical first)
✓ Within severity, sorted by score
✓ Threat scores shown
✓ View and Download buttons present

Status: [ ]
```

### Test 2.3: Dashboard IOC Actions
```
Steps:
1. Click "View" on any IOC
2. Verify detailed report opens
3. Close modal
4. Click "Download" on any IOC
5. Verify PDF downloads

Expected:
✓ View opens detailed modal
✓ Download generates PDF
✓ Both actions work correctly

Status: [ ]
```

---

## 3️⃣ IOC ANALYSIS

### Test 3.1: Text Input Analysis
```
Steps:
1. Go to "Analyze" tab
2. Click "Text Input"
3. Enter IOCs:
   8.8.8.8
   google.com
   http://example.com
4. Click "Analyze IOCs"

Expected:
✓ Analysis starts
✓ Progress shown
✓ Results displayed
✓ All 3 IOCs analyzed

Status: [ ]
```

### Test 3.2: File Upload Analysis
```
Steps:
1. Go to "Analyze" tab
2. Click "File Upload"
3. Select sample_iocs.txt
4. Click "Analyze File"

Expected:
✓ File uploaded
✓ Analysis starts
✓ All IOCs from file analyzed
✓ Results displayed

Status: [ ]
```

### Test 3.3: IOC Type Detection
```
Test IOCs:
- 8.8.8.8 → IP
- google.com → Domain
- http://example.com → URL
- 5d41402abc4b2a76b9719d911017c592 → MD5
- aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d → SHA1

Expected:
✓ All types correctly detected
✓ Appropriate tools used
✓ Correct analysis performed

Status: [ ]
```

### Test 3.4: Results Display
```
Steps:
1. After analysis completes
2. Check results table

Expected:
✓ All IOCs listed
✓ Type shown correctly
✓ Threat score displayed
✓ Severity badge shown
✓ View Details button works

Status: [ ]
```

---

## 4️⃣ HISTORY & SEARCH

### Test 4.1: History Display
```
Steps:
1. Go to "History" tab
2. View all analyses

Expected:
✓ All unique IOCs shown
✓ No duplicates
✓ Most recent per IOC
✓ All columns populated

Status: [ ]
```

### Test 4.2: Search Functionality
```
Steps:
1. Go to History
2. Type "google" in search box

Expected:
✓ Results filter instantly
✓ Only matching IOCs shown
✓ Case-insensitive search
✓ Clear search shows all

Status: [ ]
```

### Test 4.3: Severity Filter
```
Steps:
1. Select "Critical" from severity dropdown

Expected:
✓ Only Critical IOCs shown
✓ Other severities hidden
✓ Count updates

Status: [ ]
```

### Test 4.4: Type Filter
```
Steps:
1. Select "IP Address" from type dropdown

Expected:
✓ Only IP addresses shown
✓ Other types hidden
✓ Count updates

Status: [ ]
```

### Test 4.5: Combined Filters
```
Steps:
1. Search: "192"
2. Severity: "High"
3. Type: "IP Address"

Expected:
✓ All filters apply together
✓ Only matching results shown
✓ Accurate filtering

Status: [ ]
```

### Test 4.6: Clear Filters
```
Steps:
1. Apply multiple filters
2. Click "Clear Filters"

Expected:
✓ All filters reset
✓ All data shown
✓ Dropdowns reset to default

Status: [ ]
```

---

## 5️⃣ EXPORT FUNCTIONS

### Test 5.1: Export History to CSV
```
Steps:
1. Go to History
2. Click "📊 Export CSV"

Expected:
✓ CSV file downloads
✓ Filename: ioc_history_[timestamp].csv
✓ All fields included
✓ Opens in Excel

Status: [ ]
```

### Test 5.2: Export Filtered Data
```
Steps:
1. Apply filters (e.g., Critical only)
2. Click "Export CSV"

Expected:
✓ Only filtered data exported
✓ Respects current filters
✓ Correct data in CSV

Status: [ ]
```

### Test 5.3: Download Single IOC PDF
```
Steps:
1. Click download button on any IOC

Expected:
✓ PDF generates
✓ Contains IOC data
✓ Includes all details
✓ Filename includes IOC

Status: [ ]
```

### Test 5.4: Bulk PDF Export
```
Steps:
1. After analysis, click "Download PDF Report"

Expected:
✓ PDF generates for all analyzed IOCs
✓ All data included
✓ Proper formatting

Status: [ ]
```

---

## 6️⃣ UI/UX FEATURES

### Test 6.1: Copy to Clipboard
```
Steps:
1. Go to History
2. Click 📋 button next to any IOC

Expected:
✓ IOC copied to clipboard
✓ Success notification shown
✓ Can paste in other apps

Status: [ ]
```

### Test 6.2: Dark Mode Toggle
```
Steps:
1. Click "🌙 Dark Mode" button

Expected:
✓ Theme switches to dark
✓ All components styled
✓ Readable text
✓ Professional appearance

Status: [ ]
```

### Test 6.3: Dark Mode Persistence
```
Steps:
1. Enable dark mode
2. Refresh page (Ctrl+R)

Expected:
✓ Dark mode still enabled
✓ Preference saved
✓ Consistent across sessions

Status: [ ]
```

### Test 6.4: Navigation
```
Steps:
1. Click each tab: Dashboard, Analyze, History, Settings

Expected:
✓ All tabs work
✓ Correct section shown
✓ Active tab highlighted
✓ No errors

Status: [ ]
```

### Test 6.5: Responsive Design
```
Steps:
1. Resize browser window
2. Test on different screen sizes

Expected:
✓ Layout adapts
✓ No horizontal scroll
✓ All elements accessible
✓ Mobile-friendly

Status: [ ]
```

---

## 7️⃣ SECURITY TOOLS INTEGRATION

### Test 7.1: VirusTotal Integration
```
Test IOC: 8.8.8.8

Expected Data:
✓ Malicious count
✓ Suspicious count
✓ Harmless count
✓ Community score
✓ ISP (Google LLC)
✓ Country (US)
✓ Is CDN: Yes

Status: [ ]
```

### Test 7.2: AbuseIPDB Integration
```
Test IOC: 8.8.8.8

Expected Data:
✓ Abuse confidence score
✓ Total reports
✓ Link to AbuseIPDB

Status: [ ]
```

### Test 7.3: AlienVault OTX Integration
```
Test IOC: Known malicious IP

Expected Data:
✓ Pulse count
✓ Reputation score
✓ Top 3 malware families (if any)
✓ Top 3 campaigns (if any)
✓ Top 5 tags (if any)

Status: [ ]
```

### Test 7.4: Domain Analysis
```
Test IOC: google.com

Expected Data:
✓ VirusTotal: Registrar, age, categories
✓ ViewDNS: Links for reverse IP, WHOIS
✓ Palo Alto: Category check link
✓ AlienVault: Pulse info

Status: [ ]
```

### Test 7.5: Hash Analysis
```
Test IOC: MD5/SHA1/SHA256 hash

Expected Data:
✓ VirusTotal: File name, size, type
✓ MalwareBazaar: Check link
✓ Threat label (if malicious)

Status: [ ]
```

---

## 8️⃣ PDF GENERATION

### Test 8.1: Single IOC PDF
```
Steps:
1. Download PDF for one IOC

Expected Content:
✓ IOC value
✓ Type
✓ Threat score
✓ Severity
✓ Tool results
✓ AI summary
✓ AI recommendation
✓ IOC context (if available)
✓ Campaigns (if available)

Status: [ ]
```

### Test 8.2: Bulk PDF
```
Steps:
1. Analyze multiple IOCs
2. Download PDF report

Expected Content:
✓ All IOCs included
✓ Each IOC on separate section
✓ All data for each IOC
✓ Proper formatting

Status: [ ]
```

---

## 9️⃣ API KEY MANAGEMENT

### Test 9.1: View API Keys
```
Steps:
1. Go to Settings tab
2. View API keys list

Expected:
✓ All configured keys shown
✓ Service names displayed
✓ Creation dates shown

Status: [ ]
```

### Test 9.2: Add API Key
```
Steps:
1. Select service (e.g., VirusTotal)
2. Enter API key
3. Click Add

Expected:
✓ Key added successfully
✓ Appears in list
✓ Can be used for analysis

Status: [ ]
```

### Test 9.3: Delete API Key
```
Steps:
1. Click Delete on any key
2. Confirm deletion

Expected:
✓ Key removed
✓ No longer in list
✓ Not used for analysis

Status: [ ]
```

---

## 🔟 DARK MODE

### Test 10.1: Dark Mode Components
```
Components to Check:
✓ Navbar
✓ Stat cards
✓ Analyze cards
✓ Tables
✓ Input fields
✓ Buttons
✓ Modals
✓ Dropdowns

Expected:
✓ All styled for dark mode
✓ Good contrast
✓ Readable text

Status: [ ]
```

### Test 10.2: Dark Mode Toggle
```
Steps:
1. Toggle dark mode on
2. Toggle dark mode off
3. Repeat multiple times

Expected:
✓ Smooth transition
✓ No flickering
✓ Consistent behavior

Status: [ ]
```

---

## 📊 TEST SUMMARY TEMPLATE

```
Total Tests: 50+
Passed: ___
Failed: ___
Skipped: ___

Critical Issues: ___
Minor Issues: ___

Overall Status: [ ] PASS [ ] FAIL

Notes:
_________________________________
_________________________________
_________________________________
```

---

## 🚀 QUICK TEST SEQUENCE

### 5-Minute Quick Test
```
1. Login ✓
2. View Dashboard ✓
3. Analyze 1 IOC ✓
4. View Details ✓
5. Check History ✓
6. Try Search ✓
7. Export CSV ✓
8. Toggle Dark Mode ✓
9. Download PDF ✓
10. Logout ✓
```

### 15-Minute Full Test
```
1. All Authentication tests
2. Dashboard features
3. Analyze multiple IOCs
4. All History features
5. All Export functions
6. UI/UX features
7. Dark mode
8. API key management
```

### 30-Minute Comprehensive Test
```
Run all 50+ tests above
Document all findings
Test edge cases
Verify all integrations
```

---

## 🐛 BUG REPORT TEMPLATE

```
Bug ID: ___
Severity: [ ] Critical [ ] High [ ] Medium [ ] Low

Description:
_________________________________

Steps to Reproduce:
1. ___
2. ___
3. ___

Expected Behavior:
_________________________________

Actual Behavior:
_________________________________

Screenshots: [ ] Attached

Environment:
- Browser: ___
- OS: ___
- Version: ___
```

---

## ✅ FINAL CHECKLIST

Before marking as complete:

### Functionality
- [ ] All features work
- [ ] No console errors
- [ ] No broken links
- [ ] All buttons functional

### Data Integrity
- [ ] IOCs analyzed correctly
- [ ] Scores calculated properly
- [ ] No data loss
- [ ] Exports accurate

### UI/UX
- [ ] Professional appearance
- [ ] Responsive design
- [ ] Dark mode works
- [ ] Good user experience

### Performance
- [ ] Fast load times
- [ ] No lag
- [ ] Efficient filtering
- [ ] Quick exports

### Security
- [ ] Authentication works
- [ ] Authorization enforced
- [ ] API keys secure
- [ ] No vulnerabilities

---

**Test Completed By**: ___________  
**Date**: ___________  
**Status**: [ ] PASS [ ] FAIL  
**Notes**: ___________
