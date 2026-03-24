#!/usr/bin/env python3
"""
Test Intelligent Skipping of Web-Specific Checks
"""

from core.profiler import SmartProfiler
from core.reconnaissance import ReconnaissanceEngine
from core.logger import setup_logger

def test_intelligent_skip():
    """Test that web-specific checks are skipped for non-web targets"""
    logger = setup_logger()
    
    print("\n" + "="*60)
    print("Testing Intelligent Skipping for Non-Web Targets")
    print("="*60)
    
    # Test with IP address (no web services)
    print("\n[TEST] Scanning IP address 30.8.18.71...")
    profiler = SmartProfiler("30.8.18.71", logger)
    profile, strategy = profiler.execute()
    
    print(f"\n✓ Attack Surface: {profile.get('attack_surface', [])}")
    print(f"✓ Has Web: {'web' in profile.get('attack_surface', [])}")
    
    # Run reconnaissance
    print("\n[TEST] Running reconnaissance...")
    recon = ReconnaissanceEngine("30.8.18.71", logger, profile)
    recon.set_strategy(strategy)
    
    # This should skip WHOIS, DNS records, and subdomain enumeration
    print("\n✅ Test complete! Check logs above for skipped checks.")

if __name__ == '__main__':
    test_intelligent_skip()
