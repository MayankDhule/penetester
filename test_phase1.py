#!/usr/bin/env python3
"""
Test Phase 1: Reconnaissance
"""
import sys
from core.logger import setup_logger
from core.reconnaissance import ReconnaissanceEngine

def test_reconnaissance():
    """Test reconnaissance module"""
    
    # Setup logger
    logger = setup_logger(verbose=True)
    
    # Test target (use a safe, public test site)
    target = "scanme.nmap.org"
    
    logger.info(f"Testing Phase 1: Reconnaissance on {target}")
    logger.info("="*60)
    
    # Initialize reconnaissance engine
    recon = ReconnaissanceEngine(target=target, logger=logger)
    
    # Execute reconnaissance
    results = recon.execute()
    
    # Print summary
    print(recon.get_summary())
    
    # Verify results
    logger.info("\n" + "="*60)
    logger.info("VERIFICATION")
    logger.info("="*60)
    
    checks = {
        'IP Resolution': len(results['ip_addresses']) > 0,
        'WHOIS Data': len(results['whois_info']) > 0,
        'DNS Records': len(results['dns_records']) > 0,
        'Port Scan': len(results['open_ports']) > 0
    }
    
    for check, passed in checks.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        logger.info(f"{check}: {status}")
    
    all_passed = all(checks.values())
    
    if all_passed:
        logger.info("\n✓ Phase 1 (Reconnaissance) - ALL TESTS PASSED")
        return 0
    else:
        logger.error("\n✗ Phase 1 (Reconnaissance) - SOME TESTS FAILED")
        return 1

if __name__ == '__main__':
    sys.exit(test_reconnaissance())
