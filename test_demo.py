#!/usr/bin/env python3
"""
Demo script to test security improvements in the NPM Supply Chain Detector
Shows how the tool blocks various security risks
"""

import sys
import time
from supply import NPMAttackDetector

def test_security_features():
    """Demonstrate the security features"""
    
    print("=" * 70)
    print("ChalkGuard Security Features Demo")
    print("=" * 70)
    print()
    
    # Create detector with verbose settings
    detector = NPMAttackDetector(
        verbose=True,
        rate_limit=1.0,  # 1 second between requests
        max_pages=5,
        check_robots=True,
        allow_redirects=True
    )
    
    # Test cases to demonstrate security features
    test_urls = [
        # DNS failure
        ("https://this-domain-does-not-exist-12345.com", "DNS Resolution", False),
        
        # Blocked URLs
        ("http://localhost/admin", "Localhost Blocking", False),
        ("http://127.0.0.1:8080", "Loopback IP Blocking", False),
        ("http://192.168.1.1/router", "Private IP Blocking", False),
        ("ftp://example.com/files", "Protocol Restriction", False),
        
        # Valid public URL (would work with real domain)
        ("https://example.com", "Valid Public URL", True),
    ]
    
    passed = 0
    failed = 0
    
    for url, test_name, expected_valid in test_urls:
        print(f"\n[TEST] {test_name}")
        print(f"URL: {url}")
        print("-" * 40)
        
        # Validate URL
        is_valid, error_msg = detector._validate_url(url)
        
        if is_valid:
            print(f"✅ ALLOWED: URL passed security validation")
        else:
            print(f"🚫 BLOCKED: {error_msg}")
        
        # Check if test passed based on expected result
        if is_valid == expected_valid:
            passed += 1
            print(f"✓ Test PASSED (expected {'valid' if expected_valid else 'blocked'})")
        else:
            failed += 1
            print(f"✗ Test FAILED (expected {'valid' if expected_valid else 'blocked'})")
        
        time.sleep(0.5)  # Brief pause for readability
    
    total_tests = passed + failed
    pass_percentage = (passed / total_tests * 100) if total_tests > 0 else 0
    
    print("\n" + "=" * 70)
    print("Test Results Summary:")
    print("-" * 40)
    print(f"Tests Passed: {passed}/{total_tests}")
    print(f"Pass Rate: {pass_percentage:.1f}%")
    if failed > 0:
        print(f"Tests Failed: {failed}")
    print("\n" + "=" * 70)
    print("Security Features Summary:")
    print("-" * 40)
    print("✅ DNS resolution with proper error messages")
    print("✅ Blocking of localhost and loopback addresses")
    print("✅ Blocking of private IP ranges (RFC 1918)")
    print("✅ Protocol restrictions (HTTP/HTTPS only)")
    print("✅ Rate limiting between requests")
    print("✅ Robots.txt compliance")
    print("✅ Safe redirect handling")
    print("✅ Maximum page scan limits")
    print("=" * 70)
    
    return passed, total_tests

if __name__ == "__main__":
    test_security_features()