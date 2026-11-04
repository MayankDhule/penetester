#!/usr/bin/env python3
"""
Pentestrr - Penetration Testing Framework
CLI-based security assessment tool
"""

import sys
import argparse
import os
from datetime import datetime
from core.framework import PentestFramework
from core.logger import setup_logger
from core.stdin_handler import StdinHandler
from core.json_output import JSONOutput, StreamingJSONReporter
from core.proxy_handler import ProxyHandler, ProxyConfig
from core import http_config

# Version
VERSION = "1.0.0"

# Banner
BANNER = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██████╗ ███████╗███╗   ██╗████████╗███████╗███████╗████████╗║
║   ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝║
║   ██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗  ███████╗   ██║   ║
║   ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ╚════██║   ██║   ║
║   ██║     ███████╗██║ ╚████║   ██║   ███████╗███████║   ██║   ║
║   ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝   ╚═╝   ║
║                                                               ║
║             Penetration Testing Framework                    ║
║                    Version {version}                            ║
╚═══════════════════════════════════════════════════════════════╝
"""

def print_banner():
    """Print tool banner"""
    print(BANNER.format(version=VERSION))

def validate_target(target):
    """Validate target format"""
    import re
    # Check if it's a valid domain or IP
    domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    
    if re.match(domain_pattern, target) or re.match(ip_pattern, target):
        return True
    
    # Allow URLs (will be cleaned by framework)
    if target.startswith('http://') or target.startswith('https://'):
        return True
    
    return False

def create_parser():
    """Create argument parser with all options"""
    parser = argparse.ArgumentParser(
        prog='pentestrr',
        description='Pentestrr - Penetration Testing Framework',
        epilog='Example: pentestrr scan example.com --output ./reports',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Version
    parser.add_argument('-v', '--version', action='version', 
                       version=f'Pentestrr {VERSION}')
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # === SCAN COMMAND ===
    scan_parser = subparsers.add_parser('scan', 
                                        help='Run full penetration test',
                                        description='Execute complete security assessment')
    scan_parser.add_argument('target', nargs='?', help='Target domain or IP address (or read from stdin)')
    scan_parser.add_argument('-o', '--output', default='reports',
                            help='Output directory for PDF reports (default: reports/)')
    scan_parser.add_argument('-v', '--verbose', action='store_true',
                            help='Enable verbose output')
    scan_parser.add_argument('--no-banner', action='store_true',
                            help='Disable banner display')
    scan_parser.add_argument('--async', dest='use_async', action='store_true',
                            help='Use concurrent scanning for faster enumeration')
    scan_parser.add_argument('--max-concurrent', type=int, default=50,
                            help='Max concurrent requests for async mode (default: 50)')
    scan_parser.add_argument('--dir-wordlist', metavar='FILE',
                            help='Custom directory wordlist file')
    scan_parser.add_argument('--subdomain-wordlist', metavar='FILE',
                            help='Custom subdomain wordlist file')
    scan_parser.add_argument('--file-wordlist', metavar='FILE',
                            help='Custom file wordlist file')
    scan_parser.add_argument('--json', action='store_true',
                            help='Output results as JSON')
    scan_parser.add_argument('--jsonl', action='store_true',
                            help='Output results as JSON Lines (streaming)')
    scan_parser.add_argument('--proxy', metavar='URL',
                            help='HTTP/HTTPS proxy (e.g., http://127.0.0.1:8080 for Burp Suite)')
    scan_parser.add_argument('--oob-domain', metavar='DOMAIN',
                            help='Out-of-band domain for blind vulnerability testing '
                                 '(e.g., abc123.interact.sh or your Burp Collaborator domain)')
    scan_parser.add_argument('--delay', type=float, default=0.0, metavar='SECONDS',
                            help='Throttle: minimum delay between HTTP requests '
                                 '(e.g., 0.5). Reduces load and avoids rate-limit blocks.')
    
    # === PROFILE COMMAND ===
    profile_parser = subparsers.add_parser('profile',
                                          help='Run Phase 0: Smart Profiling only',
                                          description='Analyze target and generate attack strategy')
    profile_parser.add_argument('target', help='Target domain or IP address')
    profile_parser.add_argument('-v', '--verbose', action='store_true',
                               help='Enable verbose output')
    profile_parser.add_argument('--no-banner', action='store_true',
                                help='Disable banner display')
    
    # === RECON COMMAND ===
    recon_parser = subparsers.add_parser('recon',
                                        help='Run Phase 1: Reconnaissance only',
                                        description='Perform information gathering')
    recon_parser.add_argument('target', help='Target domain or IP address')
    recon_parser.add_argument('-v', '--verbose', action='store_true',
                             help='Enable verbose output')
    recon_parser.add_argument('--no-banner', action='store_true',
                              help='Disable banner display')
    
    # === ENUMERATE COMMAND ===
    enum_parser = subparsers.add_parser('enumerate',
                                       help='Run Phase 2: Scanning & Enumeration only',
                                       description='Discover endpoints and resources')
    enum_parser.add_argument('target', help='Target domain or IP address')
    enum_parser.add_argument('-v', '--verbose', action='store_true',
                            help='Enable verbose output')
    enum_parser.add_argument('--no-banner', action='store_true',
                             help='Disable banner display')
    enum_parser.add_argument('--async', dest='use_async', action='store_true',
                            help='Use concurrent scanning for faster enumeration')
    enum_parser.add_argument('--max-concurrent', type=int, default=50,
                            help='Max concurrent requests (default: 50)')
    enum_parser.add_argument('--dir-wordlist', metavar='FILE',
                            help='Custom directory wordlist file')
    
    # === EXPLOIT COMMAND ===
    exploit_parser = subparsers.add_parser('exploit',
                                          help='Run Phase 4: Safe Exploitation only',
                                          description='Test for exploitable vulnerabilities')
    exploit_parser.add_argument('target', help='Target domain or IP address')
    exploit_parser.add_argument('-v', '--verbose', action='store_true',
                               help='Enable verbose output')
    exploit_parser.add_argument('--no-banner', action='store_true',
                                help='Disable banner display')
    
    # === INFO COMMAND ===
    info_parser = subparsers.add_parser('info',
                                       help='Display framework information',
                                       description='Show version and capabilities')
    
    # === LIST COMMAND ===
    list_parser = subparsers.add_parser('list',
                                       help='List available tools and phases',
                                       description='Display framework capabilities')
    list_parser.add_argument('--phases', action='store_true',
                            help='List all phases')
    list_parser.add_argument('--tools', action='store_true',
                            help='List recommended tools')
    
    return parser

def cmd_scan(args, logger):
    """Execute full penetration test"""
    # Get targets from argument or stdin
    targets = StdinHandler.read_target_or_stdin(args.target)
    
    if not targets:
        logger.error("No target specified. Provide target as argument or via stdin.")
        logger.error("Examples:")
        logger.error("  pentestrr scan example.com")
        logger.error("  echo 'example.com' | pentestrr scan")
        logger.error("  cat targets.txt | pentestrr scan")
        return 1
    
    # Validate targets
    targets = StdinHandler.validate_targets(targets)
    if not targets:
        logger.error("No valid targets found")
        return 1
    
    # Setup proxy if specified
    if args.proxy:
        ProxyConfig.set_proxy(args.proxy)
        logger.info(f"Proxy: {args.proxy}")

    # Apply global request throttle if requested
    if getattr(args, 'delay', 0):
        http_config.configure(delay=args.delay)
        logger.info(f"Throttle: >= {args.delay}s between requests")

    # Setup JSON output if requested
    json_mode = args.json or args.jsonl
    
    # Scan each target
    exit_code = 0
    for target in targets:
        if not validate_target(target):
            logger.error(f"Invalid target format: {target}")
            continue
        
        if not json_mode:
            logger.info(f"Target: {target}")
            logger.info(f"Output: {args.output}")
            if args.use_async:
                logger.info(f"Mode: Async (max {args.max_concurrent} concurrent)")
            logger.info("")
        
        try:
            # Setup streaming JSON reporter if using JSON Lines
            if args.jsonl:
                json_reporter = StreamingJSONReporter(target)
                json_reporter.report_start()
            
            framework = PentestFramework(target, logger)
            
            # Pass async settings and wordlists to framework
            if args.use_async:
                framework.use_async = True
                framework.max_concurrent = args.max_concurrent
            if hasattr(args, 'dir_wordlist') and args.dir_wordlist:
                framework.dir_wordlist = args.dir_wordlist
            if hasattr(args, 'subdomain_wordlist') and args.subdomain_wordlist:
                framework.subdomain_wordlist = args.subdomain_wordlist
            if hasattr(args, 'file_wordlist') and args.file_wordlist:
                framework.file_wordlist = args.file_wordlist
            
            # Pass proxy to framework
            if ProxyConfig.is_proxy_enabled():
                framework.proxy_handler = ProxyConfig.get_proxy()
            
            # Pass OOB domain if provided
            if hasattr(args, 'oob_domain') and args.oob_domain:
                framework.oob_domain = args.oob_domain
            
            results = framework.execute_full_pentest()
            
            # Output results
            if args.json:
                # Full JSON output
                json_data = JSONOutput.format_scan_result(results)
                JSONOutput.print_json(json_data, pretty=True)
            elif args.jsonl:
                # JSON Lines - final summary
                json_reporter.report_complete({
                    'vulnerabilities': results['vulnerabilities']['total_count'],
                    'exploits': results['exploits']['exploits_successful'],
                })
            else:
                # Normal output - generate report
                framework.generate_report(results, output_dir=args.output)
                
                logger.info("")
                logger.info("="*60)
                logger.info("SCAN COMPLETE")
                logger.info("="*60)
                logger.info(f"Vulnerabilities found: {results['vulnerabilities']['total_count']}")
                logger.info(f"Exploitable: {results['exploits']['exploits_successful']}")
                logger.info(f"Report saved to: {args.output}/")
        
        except KeyboardInterrupt:
            logger.warning("\nScan interrupted by user")
            exit_code = 130
            break
        except Exception as e:
            logger.error(f"Scan failed for {target}: {e}")
            if args.verbose:
                import traceback
                logger.error(traceback.format_exc())
            exit_code = 1
    
    return exit_code

def cmd_profile(args, logger):
    """Execute Phase 0: Smart Profiling"""
    if not validate_target(args.target):
        logger.error(f"Invalid target format: {args.target}")
        return 1
    
    logger.info(f"Profiling target: {args.target}\n")
    
    try:
        framework = PentestFramework(args.target, logger)
        profile, strategy = framework._run_profiler()
        
        logger.info("\nProfile analysis complete!")
        return 0
    except Exception as e:
        logger.error(f"Profiling failed: {e}")
        return 1

def cmd_recon(args, logger):
    """Execute Phase 1: Reconnaissance"""
    if not validate_target(args.target):
        logger.error(f"Invalid target format: {args.target}")
        return 1
    
    logger.info(f"Reconnaissance on: {args.target}\n")
    
    try:
        framework = PentestFramework(args.target, logger)
        results = framework.reconnaissance()
        
        logger.info("\nReconnaissance complete!")
        return 0
    except Exception as e:
        logger.error(f"Reconnaissance failed: {e}")
        return 1

def cmd_enumerate(args, logger):
    """Execute Phase 2: Scanning & Enumeration"""
    if not validate_target(args.target):
        logger.error(f"Invalid target format: {args.target}")
        return 1
    
    logger.info(f"Enumerating: {args.target}\n")
    
    try:
        framework = PentestFramework(args.target, logger)
        results = framework.scan_and_enumerate()
        
        logger.info("\nEnumeration complete!")
        return 0
    except Exception as e:
        logger.error(f"Enumeration failed: {e}")
        return 1

def cmd_exploit(args, logger):
    """Execute Phase 4: Safe Exploitation"""
    if not validate_target(args.target):
        logger.error(f"Invalid target format: {args.target}")
        return 1
    
    logger.info(f"Testing exploits on: {args.target}\n")
    
    try:
        framework = PentestFramework(args.target, logger)
        results = framework.exploit()
        
        logger.info("\nExploitation testing complete!")
        return 0
    except Exception as e:
        logger.error(f"Exploitation failed: {e}")
        return 1

def cmd_info(args, logger):
    """Display framework information"""
    print(f"\nPentestrr - Penetration Testing Framework")
    print(f"Version: {VERSION}")
    print(f"\nCapabilities:")
    print(f"  - Phase 0: Smart Profiling (Heuristic-based target analysis)")
    print(f"  - Phase 1: Reconnaissance (DNS, WHOIS, port scanning)")
    print(f"  - Phase 2: Scanning & Enumeration (web crawling, directory discovery)")
    print(f"  - Phase 3: Vulnerability Detection (security headers, SSL/TLS)")
    print(f"  - Phase 4: Safe Exploitation (controlled vulnerability testing)")
    print(f"  - Phase 5: Professional PDF Reporting")
    print(f"\nFeatures:")
    print(f"  - WAF/CDN detection")
    print(f"  - Rate limiting detection")
    print(f"  - Tool recommendation")
    print(f"  - Adaptive scanning strategy")
    print(f"  - Professional PDF reports")
    print(f"\nAuthor: Security Research Team")
    print(f"License: MIT")
    print()
    return 0

def cmd_list(args, logger):
    """List framework capabilities"""
    if args.phases:
        print("\nAvailable Phases:")
        print("  0. Smart Profiling - Rule-based target analysis")
        print("  1. Reconnaissance - Information gathering")
        print("  2. Scanning & Enumeration - Resource discovery")
        print("  3. Vulnerability Detection - Security analysis")
        print("  4. Safe Exploitation - Controlled testing")
        print("  5. Professional Reporting - PDF generation")
        print()
    elif args.tools:
        print("\nRecommended Tools (based on target profile):")
        print("  Web Applications:")
        print("    - nikto, dirb, gobuster, sqlmap, xsser")
        print("  WordPress:")
        print("    - wpscan, wp-cli")
        print("  APIs:")
        print("    - postman, burp, ffuf")
        print("  Databases:")
        print("    - sqlmap, hydra, medusa")
        print("  Network:")
        print("    - nmap, masscan, netcat")
        print()
    else:
        print("\nUse --phases to list phases or --tools to list tools")
        print()
    return 0

def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    # Show help if no command
    if not args.command:
        parser.print_help()
        return 0
    
    # Show banner (unless disabled)
    if not getattr(args, 'no_banner', False) and args.command not in ['info', 'list']:
        print_banner()
    
    # Setup logger
    verbose = getattr(args, 'verbose', False)
    logger = setup_logger(verbose=verbose)
    
    # Route to command handler
    commands = {
        'scan': cmd_scan,
        'profile': cmd_profile,
        'recon': cmd_recon,
        'enumerate': cmd_enumerate,
        'exploit': cmd_exploit,
        'info': cmd_info,
        'list': cmd_list
    }
    
    handler = commands.get(args.command)
    if handler:
        return handler(args, logger)
    else:
        parser.print_help()
        return 1

if __name__ == '__main__':
    sys.exit(main())
