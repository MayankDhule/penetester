#!/usr/bin/env python3
"""
Test Phase 0: Smart Profiler
"""
import sys
from core.logger import setup_logger
from core.profiler import SmartProfiler

def test_profiler():
    """Test smart profiler module"""
    
    # Setup logger
    logger = setup_logger(verbose=True)
    
    # Test target
    target = "scanme.nmap.org"
    
    logger.info(f"\nTesting Phase 0: Smart Profiler on {target}\n")
    
    # Initialize profiler
    profiler = SmartProfiler(target=target, logger=logger)
    
    # Execute profiling
    profile, strategy = profiler.execute()
    
    # Verification
    logger.info("\n" + "="*60)
    logger.info("VERIFICATION")
    logger.info("="*60)
    
    checks = {
        'Target Type Identified': profile['target_type'] != 'unknown',
        'Attack Surface Mapped': len(profile['attack_surface']) > 0,
        'Strategy Generated': len(strategy['recommended_phases']) > 0,
        'Tools Recommended': len(strategy['recommended_tools']) > 0,
        'Risk Level Determined': strategy['risk_level'] != 'unknown'
    }
    
    for check, passed in checks.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        logger.info(f"{check}: {status}")
    
    all_passed = all(checks.values())
    
    # Display results
    logger.info("\n" + "="*60)
    logger.info("PROFILER RESULTS")
    logger.info("="*60)
    logger.info(f"Target Type: {profile['target_type']}")
    logger.info(f"Attack Surface: {profile['attack_surface']}")
    logger.info(f"Open Ports: {profile['open_ports']}")
    logger.info(f"Recommended Phases: {len(strategy['recommended_phases'])}")
    logger.info(f"Recommended Tools: {len(strategy['recommended_tools'])}")
    logger.info(f"Estimated Time: {strategy['estimated_time']} minutes")
    logger.info(f"Risk Level: {strategy['risk_level']}")
    
    if all_passed:
        logger.info("\n✓ Phase 0 (Smart Profiler) - ALL TESTS PASSED")
        return 0
    else:
        logger.error("\n✗ Phase 0 (Smart Profiler) - SOME TESTS FAILED")
        return 1

if __name__ == '__main__':
    sys.exit(test_profiler())
