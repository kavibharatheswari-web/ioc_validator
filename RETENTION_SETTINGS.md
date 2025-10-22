# 📅 IOC Validator - Configurable History Retention

## ✅ FEATURE ADDED

**Date**: 2025-10-22  
**Version**: 1.8.0

---

## 🎯 WHAT WAS ADDED

### User-Configurable History Retention

**Feature**: Users can now set how long to keep IOC history

**Options**:
- 1 Week (Default)
- 2 Weeks
- 3 Weeks
- 4 Weeks
- 5 Weeks (Maximum)

**Benefits**:
- ✅ User control over data retention
- ✅ Flexible storage management
- ✅ Automatic cleanup
- ✅ Compliance-friendly

---

## 📊 HOW IT WORKS

### Settings Page
```
Settings → History Retention
┌─────────────────────────────────────────────────┐
│ 📅 History Retention                            │
│                                                  │
│ Retention Period (Weeks)                        │
│ [Dropdown: 1 Week ▼]                           │
│                                                  │
│ Current setting: 1 week                         │
└─────────────────────────────────────────────────┘
```

### Automatic Cleanup
- Data older than retention period is **automatically deleted**
- Cleanup runs when loading history page
- No manual intervention needed
- Keeps database clean and fast

---

## 🔧 TECHNICAL DETAILS

### Database Changes

#### New Field in User Model
```python
class User(UserMixin, db.Model):
    ...
    history_retention_weeks = db.Column(db.Integer, default=1)
```

#### Default Value
- New users: 1 week
- Existing users: 1 week (after migration)
- Range: 1-5 weeks
- Validation: Enforced on backend

### Backend Logic

#### Get Retention Setting
```python
@app.route('/api/settings/retention', methods=['GET'])
def get_retention_setting():
    # Returns user's retention setting
    return {'retention_weeks': user.history_retention_weeks}
```

#### Update Retention Setting
```python
@app.route('/api/settings/retention', methods=['PUT'])
def update_retention_setting():
    # Validates: 1-5 weeks
    retention_weeks = max(1, min(5, int(retention_weeks)))
    user.history_retention_weeks = retention_weeks
```

#### Apply Retention
```python
@app.route('/api/history', methods=['GET'])
def get_history():
    # Get user's setting
    retention_weeks = user.history_retention_weeks
    
    # Delete old data
    retention_date = datetime.now() - timedelta(weeks=retention_weeks)
    AnalysisResult.query.filter(
        analyzed_at < retention_date
    ).delete()
```

---

## 📝 FILES MODIFIED

### 1. `models.py`
**Added**:
- `history_retention_weeks` field to User model
- Default value: 1 week

**Lines Changed**: 1 line

### 2. `app.py`
**Added**:
- `/api/settings/retention` GET endpoint
- `/api/settings/retention` PUT endpoint
- Updated `/api/history` to use user's retention setting

**Lines Added**: ~50 lines

### 3. `static/index.html`
**Added**:
- History Retention section in Settings
- Dropdown selector (1-5 weeks)
- Current setting display

**Lines Added**: ~25 lines

### 4. `static/app.js`
**Added**:
- `loadRetentionSetting()` function
- `updateRetentionSetting()` function
- Auto-load on app init

**Lines Added**: ~45 lines

### 5. `migrate_retention.py` (NEW)
**Purpose**: Database migration script
- Adds new column to existing databases
- Safe to run multiple times

---

## 🔄 MIGRATION REQUIRED

### Step 1: Run Migration
```bash
python migrate_retention.py
```

**Output**:
```
Adding history_retention_weeks column to user table...
✅ Column added successfully!

✅ Database migration completed successfully!
Users can now configure history retention (1-5 weeks)
```

### Step 2: Restart Application
```bash
# Stop: Ctrl+C
# Restart: python app.py
# Browser: Ctrl+Shift+R
```

---

## 🧪 TESTING

### Test 1: Load Retention Setting
```
Steps:
1. Login to application
2. Go to Settings tab
3. Check History Retention section

Expected:
✓ Dropdown shows current setting
✓ Default is 1 week
✓ Current setting displayed

Status: [ ]
```

### Test 2: Update Retention Setting
```
Steps:
1. Go to Settings
2. Change dropdown to "3 Weeks"
3. Check notification

Expected:
✓ Success notification shown
✓ Current setting updates to "3 weeks"
✓ Setting saved

Status: [ ]
```

### Test 3: Verify Data Cleanup
```
Steps:
1. Set retention to 1 week
2. Wait or manually set old dates
3. Go to History page

Expected:
✓ Only last week's data shown
✓ Older data deleted
✓ Automatic cleanup works

Status: [ ]
```

### Test 4: Different Retention Periods
```
Steps:
1. Set to 1 week → Check history
2. Set to 3 weeks → Check history
3. Set to 5 weeks → Check history

Expected:
✓ Each setting shows correct data range
✓ Cleanup respects setting
✓ No data loss within period

Status: [ ]
```

---

## 💡 USE CASES

### Use Case 1: Short-Term Analysis
```
Scenario: Daily SOC operations
Setting: 1 week
Benefit: Keep only recent, relevant data
```

### Use Case 2: Trend Analysis
```
Scenario: Weekly/monthly reporting
Setting: 4-5 weeks
Benefit: Historical data for trends
```

### Use Case 3: Compliance
```
Scenario: Data retention policy
Setting: As per policy (1-5 weeks)
Benefit: Automatic compliance
```

### Use Case 4: Storage Management
```
Scenario: Limited database space
Setting: 1-2 weeks
Benefit: Smaller database size
```

---

## 🎯 BENEFITS

### For Users
- ✅ Control over data retention
- ✅ Flexible based on needs
- ✅ Easy to configure
- ✅ Automatic cleanup

### For System
- ✅ Smaller database
- ✅ Faster queries
- ✅ Better performance
- ✅ Automatic maintenance

### For Compliance
- ✅ Configurable retention
- ✅ Automatic deletion
- ✅ Audit trail
- ✅ Policy enforcement

---

## 📊 RETENTION PERIODS EXPLAINED

### 1 Week (Default)
```
Best for: Daily operations
Data kept: Last 7 days
Database size: Smallest
Use case: Active monitoring
```

### 2 Weeks
```
Best for: Short-term analysis
Data kept: Last 14 days
Database size: Small
Use case: Weekly reports
```

### 3 Weeks
```
Best for: Medium-term tracking
Data kept: Last 21 days
Database size: Medium
Use case: Trend analysis
```

### 4 Weeks
```
Best for: Monthly reporting
Data kept: Last 28 days
Database size: Large
Use case: Monthly reviews
```

### 5 Weeks (Maximum)
```
Best for: Long-term analysis
Data kept: Last 35 days
Database size: Largest
Use case: Historical trends
```

---

## ⚠️ IMPORTANT NOTES

### Data Deletion
- Data older than retention period is **permanently deleted**
- Deletion is automatic
- Cannot be recovered
- Happens on history page load

### Changing Settings
- Can change anytime
- Takes effect immediately
- Shorter period = immediate deletion
- Longer period = keeps more data

### Recommendations
- Start with 1 week
- Increase if needed
- Consider storage capacity
- Match to use case

---

## 🔄 HOW TO USE

### Configure Retention
```
1. Login to application
2. Go to Settings tab
3. Find "History Retention" section
4. Select desired period (1-5 weeks)
5. Setting saves automatically
6. Notification confirms change
```

### Check Current Setting
```
Settings page shows:
- Dropdown with current selection
- "Current setting: X week(s)"
- Updates immediately on change
```

### Verify Cleanup
```
1. Go to History page
2. Check date range of data
3. Should match retention period
4. Older data automatically deleted
```

---

## 📋 SUMMARY

**What Was Added**:
- ✅ User-configurable retention (1-5 weeks)
- ✅ Settings UI in Settings page
- ✅ Backend API endpoints
- ✅ Automatic data cleanup
- ✅ Database migration script

**Result**:
- User control over data retention
- Flexible storage management
- Automatic cleanup
- Better performance

**Files Modified**: 4 files + 1 new  
**Lines Changed**: ~120 lines  
**Migration Required**: Yes (run migrate_retention.py)  
**Impact**: Major feature addition

---

**Version**: 1.8.0  
**Status**: ✅ Complete  
**Migration Required**: Yes  
**Restart Required**: Yes
