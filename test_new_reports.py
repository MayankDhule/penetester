#!/usr/bin/env python3
"""
Test Professional PDF Reporting System
"""
from core.logger import setup_logger
from core.framework import PentestFramework

def test_pdf_report():
    """Test the professional PDF reporting system"""
    logger = setup_logger(verbose=True)
    
    # Test on a simple target
    target = "example.com"
    
    logger.info(f"Testing PDF reporting system on: {target}")
    
    # Initialize framework
    framework = PentestFramework(target=target, logger=logger)
    
    # Run full pentest
    results = framework.execute_full_pentest()
    
    # Generate PDF report
    framework.generate_report(results, output_dir='reports')
    
    logger.info("\n✓ Test complete - Check reports/ directory for PDF file")

if __name__ == '__main__':
    test_pdf_report()
