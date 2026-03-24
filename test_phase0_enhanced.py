#!/usr/bin/env python3
"""
Test Enhanced Phase 0 (Smart Profiler)
Tests WAF/IDS, CDN, Load Balancer, and Rate Limiting detection
"""

from core.profiler import SmartProfiler
from core.logger import setup_logger

def test_enhanced_profiler():
    """Test enhanced profiler features"""
    logger = setup_logger()
    
    print("\n" + "="*60)
    print("Testing Enhanced Phase 0 Features")
    print("="*60)
    
    # Test 1: Cloudflare (WAF + CDN)
    print("\n[TEST 1] Testing Cloudflare detection...")
    profiler1 = SmartProfiler("www.cloudflare.com", logger)
    profile1, strategy1 = profiler1.execute()
    
    print(f"\n✓ WAF Detected: {profile1.get('waf', 'None')}")
    print(f"✓ CDN Detected: {profile1.get('cdn', 'None')}")
    print(f"✓ Load Balancer: {profile1.get('load_balancer', 'None')}")
    print(f"✓ Rate Limiting: {profile1.get('rate_limiting', 'None')}")
    
    # Test 2: Regular site
    print("\n" + "="*60)
    print("[TEST 2] Testing regular site...")
    profiler2 = SmartProfiler("scanme.nmap.org", logger)
    profile2, strategy2 = profiler2.execute()
    
    print(f"\n✓ WAF Detected: {profile2.get('waf', 'None')}")
    print(f"✓ CDN Detected: {profile2.get('cdn', 'None')}")
    print(f"✓ Load Balancer: {profile2.get('load_balancer', 'None')}")
    print(f"✓ Rate Limiting: {profile2.get('rate_limiting', 'None')}")
    
    print("\n" + "="*60)
    print("✅ Enhanced Phase 0 tests complete!")
    print("="*60)

if __name__ == '__main__':
    test_enhanced_profiler()
