"""
Pentestrr Framework - Main Orchestrator
Integrates all pentesting phases with a rule-based strategy
"""
from typing import Dict, Any
from core.profiler import SmartProfiler
from core.reconnaissance import ReconnaissanceEngine
from core.scanner import ScanningEngine
from core.vulnerability_detector import VulnerabilityDetector
from core.exploiter import ExploitationEngine


class PentestFramework:
    """Main framework orchestrator that integrates all pentesting phases"""
    
    def __init__(self, target: str, logger):
        self.target = target
        self.logger = logger
        self.profile = None
        self.strategy = None
        self.use_async = False
        self.max_concurrent = 50
        self.results = {
            'target': target,
            'profile': None,
            'strategy': None,
            'reconnaissance': None,
            'scanning': None,
            'vulnerabilities': None,
            'exploits': []
        }
    
    def execute_full_pentest(self) -> Dict[str, Any]:
        """Execute complete penetration test with all phases"""
        self.logger.info("="*60)
        self.logger.info("🚀 STARTING PENETRATION TEST")
        self.logger.info("="*60)
        
        # Phase 0: Smart Profiling
        self.logger.info("\n[FRAMEWORK] Executing Phase 0: Smart Profiling")
        self.profile, self.strategy = self._run_profiler()
        self.results['profile'] = self.profile
        self.results['strategy'] = self.strategy
        
        # Phase 1: Reconnaissance (guided by strategy)
        self.logger.info("\n[FRAMEWORK] Executing Phase 1: Reconnaissance")
        recon_results = self._run_reconnaissance()
        self.results['reconnaissance'] = recon_results
        
        # Phase 2: Scanning & Enumeration (guided by strategy)
        self.logger.info("\n[FRAMEWORK] Executing Phase 2: Scanning & Enumeration")
        scan_results = self._run_scanning()
        self.results['scanning'] = scan_results
        
        # Phase 3: Vulnerability Detection
        self.logger.info("\n[FRAMEWORK] Executing Phase 3: Vulnerability Detection")
        vuln_results = self._run_vulnerability_detection()
        self.results['vulnerabilities'] = vuln_results
        
        # Phase 4: Exploitation (Safe Testing)
        self.logger.info("\n[FRAMEWORK] Executing Phase 4: Safe Exploitation")
        exploit_results = self._run_exploitation()
        self.results['exploits'] = exploit_results
        
        self.logger.info("\n" + "="*60)
        self.logger.info("✅ PENETRATION TEST COMPLETE")
        self.logger.info("="*60)
        
        return self.results
    
    def reconnaissance(self) -> Dict[str, Any]:
        """Execute only reconnaissance phase"""
        self.logger.info("[FRAMEWORK] Running reconnaissance-only mode")
        
        self.profile, self.strategy = self._run_profiler()
        self.results['profile'] = self.profile
        self.results['strategy'] = self.strategy
        
        recon_results = self._run_reconnaissance()
        self.results['reconnaissance'] = recon_results
        
        return self.results
    
    def scan_and_enumerate(self) -> Dict[str, Any]:
        """Execute scanning and enumeration phase"""
        self.logger.info("[FRAMEWORK] Running scanning and enumeration mode")
        
        self.profile, self.strategy = self._run_profiler()
        self.results['profile'] = self.profile
        self.results['strategy'] = self.strategy
        
        scan_results = self._run_scanning()
        self.results['scanning'] = scan_results
        
        return self.results
    
    def exploit(self) -> Dict[str, Any]:
        """Execute exploitation phase"""
        self.logger.info("[FRAMEWORK] Running exploitation-only mode")
        
        self.profile, self.strategy = self._run_profiler()
        self.results['profile'] = self.profile
        self.results['strategy'] = self.strategy
        
        vuln_results = self._run_vulnerability_detection()
        self.results['vulnerabilities'] = vuln_results
        
        exploit_results = self._run_exploitation()
        self.results['exploits'] = exploit_results
        
        return self.results
    
    def _run_profiler(self) -> tuple:
        """Run Smart Profiler (Phase 0)"""
        profiler = SmartProfiler(target=self.target, logger=self.logger)
        profile, strategy = profiler.execute()
        return profile, strategy
    
    def _run_reconnaissance(self) -> Dict:
        """Run Reconnaissance (Phase 1) — async or sync based on flag"""
        if self.use_async:
            try:
                from core.async_recon import AsyncReconEngine
                import asyncio
                recon = AsyncReconEngine(
                    target=self.target,
                    logger=self.logger,
                    profile=self.profile
                )
                results = asyncio.run(recon.execute())
                return results
            except Exception as e:
                self.logger.warning(f"[FRAMEWORK] Async recon failed, falling back to sync: {e}")

        recon = ReconnaissanceEngine(target=self.target, logger=self.logger, profile=self.profile)
        if self.strategy:
            recon.set_strategy(self.strategy)
        results = recon.execute()
        return results
    
    def _run_scanning(self) -> Dict:
        """Run Scanning & Enumeration (Phase 2) — async or sync based on flag"""
        if self.use_async:
            from core.async_scanner import AsyncScanner
            scanner = AsyncScanner(
                target=self.target,
                logger=self.logger,
                profile=self.profile,
                strategy=self.strategy,
                max_concurrent=self.max_concurrent
            )
            import asyncio
            results = asyncio.run(scanner.execute())
        else:
            scanner = ScanningEngine(
                target=self.target,
                logger=self.logger,
                profile=self.profile,
                strategy=self.strategy
            )
            results = scanner.execute()
        
        return results
    
    def _run_vulnerability_detection(self) -> Dict:
        """Run Vulnerability Detection (Phase 3)"""
        detector = VulnerabilityDetector(
            target=self.target,
            logger=self.logger,
            profile=self.profile,
            scan_results=self.results.get('scanning', {})
        )
        
        results = detector.execute()
        return results
    
    def _run_exploitation(self) -> Dict:
        """Run Safe Exploitation (Phase 4)"""
        exploiter = ExploitationEngine(
            target=self.target,
            logger=self.logger,
            profile=self.profile,
            vulnerabilities=self.results.get('vulnerabilities', {}),
            scan_results=self.results.get('scanning', {})  # Pass forms from Phase 2
        )
        
        results = exploiter.execute()
        return results
    
    def generate_report(self, results: Dict, output_dir: str = None):
        """Generate penetration test report — console summary always, PDF when output_dir is given"""
        self.logger.info("\n" + "="*60)
        self.logger.info("📊 PENETRATION TEST REPORT")
        self.logger.info("="*60)
        
        # Target Information
        self.logger.info(f"\n🎯 Target: {results['target']}")
        
        # Profile Summary
        if results.get('profile'):
            profile = results['profile']
            self.logger.info(f"\n📋 Profile:")
            self.logger.info(f"   Type: {profile.get('target_type', 'unknown')}")
            self.logger.info(f"   CMS: {profile.get('cms', 'None')}")
            self.logger.info(f"   Web Server: {profile.get('web_server', 'None')}")
            self.logger.info(f"   Attack Surface: {', '.join(profile.get('attack_surface', []))}")
            self.logger.info(f"   Open Ports: {', '.join(map(str, profile.get('open_ports', [])))}")
        
        # Strategy Summary
        if results.get('strategy'):
            strategy = results['strategy']
            self.logger.info(f"\n🎯 Strategy:")
            self.logger.info(f"   Risk Level: {strategy.get('risk_level', 'unknown').upper()}")
            self.logger.info(f"   Recommended Phases: {len(strategy.get('recommended_phases', []))}")
            self.logger.info(f"   Recommended Tools: {len(strategy.get('recommended_tools', []))}")
            self.logger.info(f"   Estimated Time: ~{strategy.get('estimated_time', 0)} minutes")
        
        # Reconnaissance Summary
        if results.get('reconnaissance'):
            recon = results['reconnaissance']
            self.logger.info(f"\n🔍 Reconnaissance:")
            self.logger.info(f"   IP Addresses: {', '.join(recon.get('ip_addresses', []))}")
            self.logger.info(f"   Open Ports: {', '.join(map(str, recon.get('open_ports', [])))}")
            self.logger.info(f"   DNS Records: {len(recon.get('dns_records', {}))} types")
            
            if recon.get('whois_info'):
                whois = recon['whois_info']
                self.logger.info(f"   Registrar: {whois.get('registrar', 'N/A')}")
        
        # Scanning Summary
        if results.get('scanning'):
            scan = results['scanning']
            self.logger.info(f"\n🔍 Scanning & Enumeration:")
            self.logger.info(f"   Pages Discovered: {len(scan.get('discovered_urls', []))}")
            self.logger.info(f"   Directories Found: {len(scan.get('directories', []))}")
            self.logger.info(f"   Interesting Files: {len(scan.get('files', []))}")
            self.logger.info(f"   Forms Detected: {len(scan.get('forms', []))}")
            self.logger.info(f"   Email Addresses: {len(scan.get('emails', []))}")
        
        # Vulnerability Summary
        if results.get('vulnerabilities'):
            vulns = results['vulnerabilities']
            self.logger.info(f"\n🔒 Vulnerabilities:")
            self.logger.info(f"   Total Found: {vulns.get('total_count', 0)}")
            if vulns.get('critical', 0) > 0:
                self.logger.info(f"   🔴 CRITICAL: {vulns['critical']}")
            if vulns.get('high', 0) > 0:
                self.logger.info(f"   🟠 HIGH: {vulns['high']}")
            if vulns.get('medium', 0) > 0:
                self.logger.info(f"   🟡 MEDIUM: {vulns['medium']}")
            if vulns.get('low', 0) > 0:
                self.logger.info(f"   🟢 LOW: {vulns['low']}")
            if vulns.get('info', 0) > 0:
                self.logger.info(f"   ℹ️  INFO: {vulns['info']}")
        
        # Exploitation Summary
        if results.get('exploits'):
            exploits = results['exploits']
            self.logger.info(f"\n🎯 Exploitation Results:")
            self.logger.info(f"   Tests Attempted: {exploits.get('exploits_attempted', 0)}")
            self.logger.info(f"   Exploitable Vulnerabilities: {exploits.get('exploits_successful', 0)}")
            
            if exploits.get('exploits_successful', 0) > 0:
                severity = exploits.get('severity_breakdown', {})
                if severity.get('critical', 0) > 0:
                    self.logger.info(f"   🔴 CRITICAL: {severity['critical']}")
                if severity.get('high', 0) > 0:
                    self.logger.info(f"   🟠 HIGH: {severity['high']}")
                if severity.get('medium', 0) > 0:
                    self.logger.info(f"   🟡 MEDIUM: {severity['medium']}")
                if severity.get('low', 0) > 0:
                    self.logger.info(f"   🟢 LOW: {severity['low']}")
                
                if exploits.get('exploits'):
                    self.logger.info(f"\n   Top Exploitable Issues:")
                    for exploit in exploits['exploits'][:3]:
                        self.logger.info(f"   • [{exploit['severity']}] {exploit['type']}")
                        self.logger.info(f"     Impact: {exploit['impact']}")
        
        self.logger.info("\n" + "="*60)
        
        # Generate PDF report if output directory specified
        if output_dir:
            try:
                from core.reporter import ReportGenerator
                reporter = ReportGenerator(results, self.logger)
                reporter.generate_all_reports(output_dir=output_dir)
            except Exception as e:
                self.logger.error(f"[FRAMEWORK] PDF report generation failed: {e}")
