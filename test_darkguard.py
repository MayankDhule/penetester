#!/usr/bin/env python3
"""
Test Smart Profiler on DarkGuard target
"""
import sys
from core.logger import setup_logger
from core.profiler import SmartProfiler

def test_darkguard():
    """Test profiler on DarkGuard"""
    
    logger = setup_logger(verbose=True)
    
    # Your target
    target = "darkguard.netlify.app"
    
    logger.info(f"\n{'='*60}")
    logger.info(f"Testing Smart Profiler on YOUR TARGET")
    logger.info(f"Target: https://{target}")
    logger.info(f"{'='*60}\n")
    
    # Initialize profiler
    profiler = SmartProfiler(target=target, logger=logger)
    
    # Execute profiling
    profile, strategy = profiler.execute()
    
    # Detailed analysis
    logger.info("\n" + "="*60)
    logger.info("DETAILED ANALYSIS")
    logger.info("="*60)
    
    logger.info(f"\n📊 Profile Details:")
    logger.info(f"   Target Type: {profile['target_type']}")
    logger.info(f"   CMS: {profile['cms'] or 'None detected'}")
    logger.info(f"   Web Server: {profile['web_server'] or 'Unknown'}")
    logger.info(f"   Language: {profile['programming_language'] or 'Unknown'}")
    logger.info(f"   Frameworks: {', '.join(profile['frameworks']) if profile['frameworks'] else 'None detected'}")
    logger.info(f"   SSL Enabled: {profile['ssl_enabled']}")
    logger.info(f"   API Detected: {profile['api_detected']}")
    
    logger.info(f"\n🎯 Attack Surface:")
    for surface in profile['attack_surface']:
        logger.info(f"   • {surface}")
    
    logger.info(f"\n🔓 Login Pages Found:")
    if profile['login_pages']:
        for page in profile['login_pages']:
            logger.info(f"   • {page}")
    else:
        logger.info(f"   • None found")
    
    logger.info(f"\n🛠️  Complete Tool List:")
    for i, tool in enumerate(strategy['recommended_tools'], 1):
        logger.info(f"   {i}. {tool}")
    
    logger.info(f"\n📍 All Recommended Phases:")
    for i, phase in enumerate(strategy['recommended_phases'], 1):
        logger.info(f"   {i}. {phase.replace('_', ' ').title()}")
    
    logger.info(f"\n⚠️  Assessment:")
    logger.info(f"   Risk Level: {strategy['risk_level'].upper()}")
    logger.info(f"   Estimated Scan Time: {strategy['estimated_time']} minutes")
    logger.info(f"   Open Ports: {profile['open_ports']}")
    
    return 0

if __name__ == '__main__':
    sys.exit(test_darkguard())
