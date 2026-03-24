#!/usr/bin/env python3
"""
PentestAI - Intelligent Penetration Testing Framework
Main entry point for the framework
"""

import sys
import argparse
from core.framework import PentestFramework
from core.logger import setup_logger

def main():
    parser = argparse.ArgumentParser(
        description='PentestAI - Intelligent Penetration Testing Framework'
    )
    
    parser.add_argument('target', help='Target IP/domain to test')
    parser.add_argument('--mode', choices=['recon', 'scan', 'exploit', 'full'], 
                       default='full', help='Pentesting mode')
    parser.add_argument('--output', help='Output directory for reports')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logger(verbose=args.verbose)
    
    # Initialize framework
    framework = PentestFramework(target=args.target, logger=logger)
    
    # Execute based on mode
    if args.mode == 'recon':
        results = framework.reconnaissance()
    elif args.mode == 'scan':
        results = framework.scan_and_enumerate()
    elif args.mode == 'exploit':
        results = framework.exploit()
    else:  # full
        results = framework.execute_full_pentest()
    
    # Generate report
    framework.generate_report(results, output_dir=args.output)
    
    logger.info("Pentesting complete!")

if __name__ == '__main__':
    main()
