#!/usr/bin/env python3
"""
Test script to verify malicious IOC detection
Tests with known malicious indicators
"""

import requests
import json
import time

# Configuration
API_URL = "http://localhost:5000/api"
TEST_EMAIL = "test@malicious-test.com"
TEST_PASSWORD = "TestPassword123!"

# Known malicious IOCs for testing
MALICIOUS_IOCS = {
    "malicious_ips": [
        "185.220.101.1",  # Known Tor exit node
        "45.142.212.61",  # Known malicious IP
        "89.248.165.2",   # Known C2 server
    ],
    "malicious_domains": [
        "malware-traffic-analysis.net",  # Malware analysis site (safe but flagged)
        "testphp.vulnweb.com",           # Intentionally vulnerable site
    ],
    "malicious_urls": [
        "http://malware.wicar.org/data/eicar.com",  # EICAR test file
    ],
    "malicious_hashes": [
        "44d88612fea8a8f36de82e1278abb02f",  # EICAR MD5
        "3395856ce81f2b7382dee72602f798b642f14140",  # EICAR SHA1
    ]
}

def register_test_user():
    """Register a test user"""
    print("🔐 Registering test user...")
    try:
        response = requests.post(
            f"{API_URL}/register",
            json={
                "email": TEST_EMAIL,
                "username": "TestUser",
                "password": TEST_PASSWORD
            },
            timeout=10
        )
        if response.status_code == 201:
            print("✅ Test user registered successfully")
            return True
        elif response.status_code == 400 and "already registered" in response.text:
            print("ℹ️  Test user already exists")
            return True
        else:
            print(f"❌ Registration failed: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Error registering: {e}")
        return False

def login_test_user():
    """Login and get auth token"""
    print("\n🔑 Logging in...")
    try:
        response = requests.post(
            f"{API_URL}/login",
            json={
                "email": TEST_EMAIL,
                "password": TEST_PASSWORD
            },
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            token = data.get('token')
            print("✅ Login successful")
            return token
        else:
            print(f"❌ Login failed: {response.text}")
            return None
    except Exception as e:
        print(f"❌ Error logging in: {e}")
        return None

def analyze_iocs(token, iocs, category):
    """Analyze a list of IOCs"""
    print(f"\n{'='*60}")
    print(f"🔍 Testing {category}")
    print(f"{'='*60}")
    
    results = []
    
    for ioc in iocs:
        print(f"\n📊 Analyzing: {ioc}")
        try:
            response = requests.post(
                f"{API_URL}/analyze",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                },
                json={"iocs": [ioc]},
                timeout=60
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('results'):
                    result = data['results'][0]
                    
                    print(f"  ✓ Type: {result.get('type')}")
                    print(f"  ✓ Threat Score: {result.get('threat_score')}/100")
                    print(f"  ✓ Severity: {result.get('severity')}")
                    print(f"  ✓ Category: {result.get('threat_category')}")
                    print(f"  ✓ Threat Type: {result.get('threat_type')}")
                    
                    # Check detections
                    details = result.get('details', {})
                    detections = []
                    
                    for tool, data in details.items():
                        if isinstance(data, dict):
                            if data.get('malicious', 0) > 0:
                                detections.append(f"{tool}: {data['malicious']} malicious")
                            if data.get('abuse_confidence_score', 0) > 0:
                                detections.append(f"{tool}: {data['abuse_confidence_score']}% abuse")
                            if data.get('pulse_count', 0) > 0:
                                detections.append(f"{tool}: {data['pulse_count']} pulses")
                    
                    if detections:
                        print(f"  🚨 Detections:")
                        for det in detections[:5]:
                            print(f"     - {det}")
                    else:
                        print(f"  ⚠️  No detections (may be zero-day or clean)")
                    
                    results.append({
                        'ioc': ioc,
                        'threat_score': result.get('threat_score'),
                        'severity': result.get('severity'),
                        'detections': len(detections)
                    })
                else:
                    print(f"  ❌ No results returned")
            else:
                print(f"  ❌ Analysis failed: {response.status_code}")
                print(f"     {response.text[:200]}")
        
        except Exception as e:
            print(f"  ❌ Error: {e}")
        
        # Rate limiting
        time.sleep(2)
    
    return results

def print_summary(all_results):
    """Print test summary"""
    print(f"\n{'='*60}")
    print("📊 TEST SUMMARY")
    print(f"{'='*60}\n")
    
    total_tested = 0
    high_threat = 0
    medium_threat = 0
    low_threat = 0
    clean = 0
    
    for category, results in all_results.items():
        print(f"\n{category}:")
        for result in results:
            total_tested += 1
            severity = result['severity']
            
            if severity in ['Critical', 'High']:
                high_threat += 1
                emoji = "🔴"
            elif severity == 'Medium':
                medium_threat += 1
                emoji = "🟡"
            elif severity == 'Low':
                low_threat += 1
                emoji = "🟠"
            else:
                clean += 1
                emoji = "🟢"
            
            print(f"  {emoji} {result['ioc']}: {result['severity']} "
                  f"(Score: {result['threat_score']}, "
                  f"Detections: {result['detections']})")
    
    print(f"\n{'='*60}")
    print(f"Total IOCs Tested: {total_tested}")
    print(f"High/Critical Threats: {high_threat}")
    print(f"Medium Threats: {medium_threat}")
    print(f"Low Threats: {low_threat}")
    print(f"Clean/Info: {clean}")
    print(f"{'='*60}\n")
    
    # Detection rate
    detected = high_threat + medium_threat + low_threat
    if total_tested > 0:
        detection_rate = (detected / total_tested) * 100
        print(f"Detection Rate: {detection_rate:.1f}%")
        
        if detection_rate >= 80:
            print("✅ EXCELLENT: Detection system working well!")
        elif detection_rate >= 60:
            print("⚠️  GOOD: Most threats detected")
        elif detection_rate >= 40:
            print("⚠️  FAIR: Some threats missed")
        else:
            print("❌ POOR: Many threats not detected")
    
    print()

def main():
    """Main test function"""
    print("="*60)
    print("🧪 IOC VALIDATOR - MALICIOUS IOC DETECTION TEST")
    print("="*60)
    print("\nThis script tests the detection of known malicious IOCs")
    print("to verify that all security tools are working correctly.\n")
    
    # Register and login
    if not register_test_user():
        print("❌ Failed to register test user. Exiting.")
        return
    
    token = login_test_user()
    if not token:
        print("❌ Failed to login. Exiting.")
        return
    
    # Test each category
    all_results = {}
    
    # Test malicious IPs
    if MALICIOUS_IOCS['malicious_ips']:
        results = analyze_iocs(token, MALICIOUS_IOCS['malicious_ips'], 
                              "MALICIOUS IPs")
        all_results['Malicious IPs'] = results
    
    # Test malicious domains
    if MALICIOUS_IOCS['malicious_domains']:
        results = analyze_iocs(token, MALICIOUS_IOCS['malicious_domains'], 
                              "MALICIOUS DOMAINS")
        all_results['Malicious Domains'] = results
    
    # Test malicious URLs
    if MALICIOUS_IOCS['malicious_urls']:
        results = analyze_iocs(token, MALICIOUS_IOCS['malicious_urls'], 
                              "MALICIOUS URLs")
        all_results['Malicious URLs'] = results
    
    # Test malicious hashes
    if MALICIOUS_IOCS['malicious_hashes']:
        results = analyze_iocs(token, MALICIOUS_IOCS['malicious_hashes'], 
                              "MALICIOUS HASHES")
        all_results['Malicious Hashes'] = results
    
    # Print summary
    print_summary(all_results)
    
    print("✅ Testing complete!")
    print("\nNote: Some IOCs may show as 'clean' if:")
    print("  - They are test/research sites (not actually malicious)")
    print("  - API keys are not configured")
    print("  - Rate limits are hit")
    print("  - Tools are temporarily unavailable")

if __name__ == "__main__":
    main()
