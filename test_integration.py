#!/usr/bin/env python3
"""
Integration Test: Phase 0 + Phase 1
Tests the complete flow from profiling to reconnaissance
"""
import sys
from core.logger import setup_logger
from core.framework import PentestFramework


def test_integration():
    """Test integrated framework with Phase 0 and Phase 1"""
    
    # Setup logger
    logger = setup_logger(verbose=True)
    
    # Test target
    target = "scanme.nmap.org"
    
    logger.info(f"\n{'='*60}")
    logger.info(f"INTEGRATION TEST: Phase 0 + Phase 1")
    logger.info(f"Target: {target}")
    logger.info(f"{'='*60}\n")
    
    # Initialize framework
    framework = PentestFramework(target=target, logger=logger)
    
    # Execute full pentest (currently Phase 0 + Phase 1)
    results = framework.execute_full_pentest()
    
    # Generate report
    framework.generate_report(results)
    
    # Verification
    logger.info("\n" + "="*60)
    logger.info("VERIFICATION")
    logger.info("="*60)
    
    checks = {
        'Profile Generated': results.get('profile') is not None,
        'Strategy Created': results.get('strategy') is not None,
        'Reconnaissance Complete': results.get('reconnaissance') is not None,
        'IP Resolved': len(results.get('reconnaissance', {}).get('ip_addresses', [])) > 0,
        'Ports Scanned': len(results.get('reconnaissance', {}).get('open_ports', [])) > 0,
        'Attack Surface Identified': len(results.get('profile', {}).get('attack_surface', [])) > 0
    }
    
    for check, passed in checks.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        logger.info(f"{check}: {status}")
    
    all_passed = all(checks.values())
    
    if all_passed:
        logger.info("\n✅ INTEGRATION TEST PASSED - Phase 0 & 1 working together!")
        return 0
    else:
        logger.error("\n❌ INTEGRATION TEST FAILED")
        return 1


if __name__ == '__main__':
    sys.exit(test_integration())
