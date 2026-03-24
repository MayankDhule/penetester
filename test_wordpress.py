#!/usr/bin/env python3
"""
Test Smart Profiler on WordPress site
"""
import sys
from core.logger import setup_logger
from core.profiler import SmartProfiler

def test_wordpress():
    """Test profiler on WordPress site"""
    
    logger = setup_logger(verbose=True)
    
    # WordPress test site
    target = "wordpress.org"
    
    logger.info(f"\nTesting Smart Profiler on WordPress site: {target}\n")
    
    profiler = SmartProfiler(target=target, logger=logger)
    profile, strategy = profiler.execute()
    
    logger.info("\n" + "="*60)
    logger.info("WORDPRESS DETECTION TEST")
    logger.info("="*60)
    logger.info(f"CMS Detected: {profile['cms']}")
    logger.info(f"Strategy Type: {'WordPress-specific' if 'wordpress' in str(strategy['recommended_phases']).lower() else 'Generic'}")
    logger.info(f"WPScan Recommended: {'wpscan' in strategy['recommended_tools']}")
    
    return 0

if __name__ == '__main__':
    sys.exit(test_wordpress())
