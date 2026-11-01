"""
Phase 0: Smart Profiler
Rule-based target analysis and attack strategy generation
"""
import socket
import requests
import urllib3
import re
from typing import Dict, List, Tuple
from urllib.parse import urlparse
import ssl
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SmartProfiler:
    """Rule-based target profiler that analyzes and creates custom attack strategies"""
    
    def __init__(self, target: str, logger):
        self.target = target
        self.logger = logger
        self.profile = {
            'target': target,
            'target_type': 'unknown',
            'technologies': [],
            'cms': None,
            'web_server': None,
            'programming_language': None,
            'frameworks': [],
            'attack_surface': [],
            'open_ports': [],
            'ssl_enabled': False,
            'api_detected': False,
            'login_pages': [],
            'interesting_paths': [],
            'waf': None,
            'cdn': None,
            'load_balancer': None,
            'rate_limiting': None,
            'http_version': None,
            'tls_version': None,
            'security_txt': False,
            'cookies': {},
            'server_technologies': [],
            'robots_txt': {}
        }
        self.strategy = {
            'recommended_phases': [],
            'recommended_tools': [],
            'skip_tools': [],
            'priority_targets': [],
            'estimated_time': 0,
            'risk_level': 'unknown'
        }
    
    def execute(self) -> Tuple[Dict, Dict]:
        """Execute smart profiling and strategy generation"""
        self.logger.info("="*60)
        self.logger.info("[PROFILER] 🧠 Smart Profiler - Rule-Based Target Analysis")
        self.logger.info("="*60)
        
        # Step 1: Quick fingerprinting
        self.quick_fingerprint()
        
        # Step 2: Technology detection
        self.detect_technologies()
        
        # Step 3: Attack surface mapping
        self.map_attack_surface()
        
        # Step 4: Build custom strategy
        self.build_strategy()
        
        # Step 5: Display strategy
        self.display_strategy()
        
        return self.profile, self.strategy
    
    def quick_fingerprint(self):
        """Quick fingerprinting of target"""
        self.logger.info("\n[PROFILER] Step 1: Quick Fingerprinting")
        self.logger.info("-" * 60)
        
        # Check if target is IP or domain
        if self._is_ip_address(self.target):
            self.profile['target_type'] = 'ip_address'
            self.logger.info(f"[PROFILER] Target type: IP Address")
        else:
            self.profile['target_type'] = 'domain'
            self.logger.info(f"[PROFILER] Target type: Domain")
        
        # Quick port check
        self._quick_port_check()
        
        # If no ports detected, try HTTP/HTTPS directly
        if not self.profile['open_ports']:
            self._try_web_service()
        
        # Check for web services
        if 80 in self.profile['open_ports'] or 443 in self.profile['open_ports']:
            self.profile['attack_surface'].append('web')
            self.logger.info(f"[PROFILER] ✓ Web service detected")
            
            # Check SSL
            if 443 in self.profile['open_ports']:
                self.profile['ssl_enabled'] = True
                self.logger.info(f"[PROFILER] ✓ SSL/TLS enabled")
    
    def _try_web_service(self):
        """Try to connect via HTTP/HTTPS if port scan fails"""
        try:
            # Try HTTPS first
            response = requests.get(self.target if '://' in self.target else f'https://{self.target}', 
                                   timeout=5, verify=False)
            if response.status_code:
                self.profile['open_ports'].append(443)
                self.logger.info(f"[PROFILER] ✓ HTTPS service detected (direct connection)")
                return
        except (requests.exceptions.RequestException, ConnectionError, TimeoutError) as e:
            self.logger.debug(f"[PROFILER] HTTPS connection failed: {e}")
        
        try:
            # Try HTTP
            response = requests.get(self.target if '://' in self.target else f'http://{self.target}', 
                                   timeout=5)
            if response.status_code:
                self.profile['open_ports'].append(80)
                self.logger.info(f"[PROFILER] ✓ HTTP service detected (direct connection)")
                return
        except (requests.exceptions.RequestException, ConnectionError, TimeoutError) as e:
            self.logger.debug(f"[PROFILER] HTTP connection failed: {e}")
        
        # Check for SSH
        if 22 in self.profile['open_ports']:
            self.profile['attack_surface'].append('ssh')
            self.logger.info(f"[PROFILER] ✓ SSH service detected")
        
        # Check for database services
        db_ports = {3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'MSSQL', 27017: 'MongoDB'}
        for port, db_name in db_ports.items():
            if port in self.profile['open_ports']:
                self.profile['attack_surface'].append('database')
                self.logger.info(f"[PROFILER] ✓ Database service detected: {db_name}")
                break
    
    def detect_technologies(self):
        """Detect technologies used by target"""
        self.logger.info("\n[PROFILER] Step 2: Technology Detection")
        self.logger.info("-" * 60)
        
        if 'web' not in self.profile['attack_surface']:
            self.logger.info("[PROFILER] No web service - skipping technology detection")
            return
        
        # Try HTTP first, then HTTPS
        urls_to_try = []
        if 80 in self.profile['open_ports']:
            urls_to_try.append(f"http://{self.target}")
        if 443 in self.profile['open_ports']:
            urls_to_try.append(f"https://{self.target}")
        
        for url in urls_to_try:
            try:
                response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
                
                # Detect web server
                server = response.headers.get('Server', '')
                if server:
                    self.profile['web_server'] = server
                    self.logger.info(f"[PROFILER] ✓ Web Server: {server}")
                
                # Detect WAF/IDS
                waf_detected = self._detect_waf(response)
                if waf_detected:
                    self.profile['waf'] = waf_detected
                    self.logger.info(f"[PROFILER] ⚠️  WAF/IDS Detected: {waf_detected}")
                
                # Detect CDN
                cdn_detected = self._detect_cdn(response)
                if cdn_detected:
                    self.profile['cdn'] = cdn_detected
                    self.logger.info(f"[PROFILER] ✓ CDN Detected: {cdn_detected}")
                
                # Detect Load Balancer
                lb_detected = self._detect_load_balancer(response)
                if lb_detected:
                    self.profile['load_balancer'] = lb_detected
                    self.logger.info(f"[PROFILER] ✓ Load Balancer: {lb_detected}")
                
                # Detect CMS
                cms = self._detect_cms(response)
                if cms:
                    self.profile['cms'] = cms
                    self.logger.info(f"[PROFILER] ✓ CMS Detected: {cms}")
                
                # Detect programming language
                lang = self._detect_language(response)
                if lang:
                    self.profile['programming_language'] = lang
                    self.logger.info(f"[PROFILER] ✓ Language: {lang}")
                
                # Detect frameworks
                frameworks = self._detect_frameworks(response)
                if frameworks:
                    self.profile['frameworks'] = frameworks
                    self.logger.info(f"[PROFILER] ✓ Frameworks: {', '.join(frameworks)}")
                
                # Check for API
                if self._detect_api(response):
                    self.profile['api_detected'] = True
                    self.profile['attack_surface'].append('api')
                    self.logger.info(f"[PROFILER] ✓ API Detected")
                
                # Detect HTTP version
                http_version = self._detect_http_version(response)
                if http_version:
                    self.profile['http_version'] = http_version
                    self.logger.info(f"[PROFILER] ✓ HTTP Version: {http_version}")
                
                # Check for security.txt
                if self._check_security_txt(url):
                    self.profile['security_txt'] = True
                    self.logger.info(f"[PROFILER] ✓ security.txt found (RFC 9116 compliant)")
                
                # Analyze cookies
                cookies_info = self._analyze_cookies(response)
                if cookies_info['total'] > 0:
                    self.profile['cookies'] = cookies_info
                    self.logger.info(f"[PROFILER] ✓ Cookies: {cookies_info['total']} found")
                    if cookies_info['issues']:
                        self.logger.info(f"[PROFILER] ⚠️  Cookie Issues: {len(cookies_info['issues'])}")
                
                # Detect TLS version
                if url.startswith('https'):
                    tls_version = self._detect_tls_version(url)
                    if tls_version != 'Unknown':
                        self.profile['tls_version'] = tls_version
                        self.logger.info(f"[PROFILER] ✓ TLS Version: {tls_version}")
                
                # Advanced server technology detection
                server_techs = self._detect_server_technologies(response)
                if server_techs:
                    self.profile['server_technologies'] = server_techs
                    self.logger.info(f"[PROFILER] ✓ Server Technologies: {', '.join(server_techs)}")
                
                # Check robots.txt
                robots_info = self._check_robots_txt(url)
                if robots_info['exists']:
                    self.profile['robots_txt'] = robots_info
                    self.logger.info(f"[PROFILER] ✓ robots.txt found ({robots_info['total_rules']} rules)")
                    if robots_info['disallowed_paths']:
                        self.logger.info(f"[PROFILER]   Interesting paths: {', '.join(robots_info['disallowed_paths'][:3])}")
                
                # Find login pages
                login_pages = self._find_login_pages(response, url)
                if login_pages:
                    self.profile['login_pages'] = login_pages
                    self.logger.info(f"[PROFILER] ✓ Login pages found: {len(login_pages)}")
                
                # Check rate limiting
                rate_limit = self._detect_rate_limiting(url)
                if rate_limit:
                    self.profile['rate_limiting'] = rate_limit
                    self.logger.info(f"[PROFILER] ✓ Rate Limiting: {rate_limit}")
                
                break  # Success, no need to try other URLs
                
            except requests.exceptions.SSLError:
                self.logger.debug(f"[PROFILER] SSL error on {url}")
                continue
            except requests.exceptions.ConnectionError:
                self.logger.debug(f"[PROFILER] Connection error on {url}")
                continue
            except Exception as e:
                self.logger.debug(f"[PROFILER] Error detecting technologies: {e}")
                continue
    
    def map_attack_surface(self):
        """Map the complete attack surface"""
        self.logger.info("\n[PROFILER] Step 3: Attack Surface Mapping")
        self.logger.info("-" * 60)
        
        attack_surface_summary = {
            'web': 'Web Application',
            'api': 'REST/GraphQL API',
            'ssh': 'SSH Remote Access',
            'database': 'Database Service',
            'ftp': 'File Transfer',
            'smb': 'File Sharing'
        }
        
        if self.profile['attack_surface']:
            self.logger.info("[PROFILER] Attack Surface Components:")
            for surface in self.profile['attack_surface']:
                desc = attack_surface_summary.get(surface, surface)
                self.logger.info(f"[PROFILER]   • {desc}")
        else:
            self.logger.info("[PROFILER] Limited attack surface detected")
    
    def build_strategy(self):
        """Build custom attack strategy based on comprehensive profile analysis"""
        self.logger.info("\n[PROFILER] Step 4: Building Custom Attack Strategy")
        self.logger.info("-" * 60)
        
        # Initialize strategy components
        self.strategy['recommended_phases'] = []
        self.strategy['recommended_tools'] = []
        self.strategy['skip_tools'] = []
        self.strategy['priority_targets'] = []
        self.strategy['attack_vectors'] = []
        
        # Determine primary target type and build strategy
        if self.profile['cms'] == 'WordPress':
            self._strategy_wordpress()
        elif self.profile['cms'] in ['Joomla', 'Drupal', 'Magento']:
            self._strategy_cms()
        elif self.profile['api_detected']:
            self._strategy_api()
        elif 'web' in self.profile['attack_surface']:
            self._strategy_web_app()
        elif 'database' in self.profile['attack_surface']:
            self._strategy_database()
        elif 'ssh' in self.profile['attack_surface']:
            self._strategy_ssh()
        else:
            self._strategy_generic()
        
        # Add security-specific tools based on detections
        self._add_security_tools()
        
        # Add technology-specific tools
        self._add_technology_tools()
        
        # Calculate estimated time
        self._calculate_estimated_time()
        
        # Determine risk level
        self._determine_risk_level()
    
    def _add_security_tools(self):
        """Add tools based on security infrastructure detected"""
        # WAF detected - add WAF bypass tools
        if self.profile.get('waf'):
            self.strategy['recommended_tools'].extend(['wafw00f', 'bypass-waf'])
            self.strategy['attack_vectors'].append('WAF Bypass Techniques')
            self.logger.info(f"[PROFILER] ⚠️  WAF detected - adding bypass tools")
        
        # CDN detected - add CDN-specific tools
        if self.profile.get('cdn'):
            self.strategy['attack_vectors'].append('CDN Origin Discovery')
            self.logger.info(f"[PROFILER] ℹ️  CDN detected - origin discovery recommended")
        
        # Rate limiting detected - adjust strategy
        if self.profile.get('rate_limiting') and 'Active' in str(self.profile.get('rate_limiting')):
            self.strategy['attack_vectors'].append('Rate Limit Evasion')
            self.strategy['skip_tools'].extend(['hydra', 'medusa'])  # Skip brute force
            self.logger.info(f"[PROFILER] ⚠️  Rate limiting active - skipping brute force tools")
        
        # Weak TLS version
        if self.profile.get('tls_version') and 'TLSv1.0' in str(self.profile.get('tls_version')):
            self.strategy['attack_vectors'].append('SSL/TLS Downgrade Attack')
            self.strategy['recommended_tools'].append('sslscan')
        
        # Cookie issues detected
        if self.profile.get('cookies', {}).get('issues'):
            self.strategy['attack_vectors'].append('Session Hijacking')
            self.strategy['recommended_tools'].append('cookie-cadger')
    
    def _add_technology_tools(self):
        """Add tools based on detected technologies"""
        # Programming language specific
        lang = self.profile.get('programming_language')
        if lang == 'PHP':
            self.strategy['recommended_tools'].extend(['phpggc', 'php-reverse-shell'])
            self.strategy['attack_vectors'].append('PHP Deserialization')
        elif lang == 'ASP.NET':
            self.strategy['recommended_tools'].extend(['viewstate-decoder', 'aspx-shell'])
            self.strategy['attack_vectors'].append('ViewState Exploitation')
        elif lang == 'Java':
            self.strategy['recommended_tools'].extend(['ysoserial', 'java-deserialization'])
            self.strategy['attack_vectors'].append('Java Deserialization')
        
        # Framework specific
        frameworks = self.profile.get('frameworks', [])
        if 'React' in frameworks or 'Vue.js' in frameworks or 'Angular' in frameworks:
            self.strategy['recommended_tools'].append('retire.js')
            self.strategy['attack_vectors'].append('Client-Side Vulnerabilities')
        
        # Server technologies
        server_techs = self.profile.get('server_technologies', [])
        if 'Express.js' in server_techs or 'Next.js' in server_techs:
            self.strategy['attack_vectors'].append('Node.js Prototype Pollution')
            self.strategy['recommended_tools'].append('npm-audit')
    
    def _strategy_database(self):
        """Strategy for database services"""
        self.logger.info("[PROFILER] 🎯 Target Profile: Database Service")
        
        self.strategy['recommended_phases'] = [
            'reconnaissance',
            'service_enumeration',
            'authentication_testing',
            'exploitation'
        ]
        
        self.strategy['recommended_tools'] = [
            'nmap-db-scripts',
            'hydra',
            'metasploit',
            'sqlmap'
        ]
        
        self.strategy['attack_vectors'] = [
            'Default Credentials',
            'SQL Injection',
            'Database Exposure'
        ]
    
    def _strategy_wordpress(self):
        """Strategy for WordPress sites"""
        self.logger.info("[PROFILER] 🎯 Target Profile: WordPress Website")
        
        self.strategy['recommended_phases'] = [
            'reconnaissance',
            'wordpress_enumeration',
            'vulnerability_scanning',
            'brute_force',
            'exploitation'
        ]
        
        self.strategy['recommended_tools'] = [
            'wpscan',           # WordPress scanner
            'wp-user-enum',     # User enumeration
            'xmlrpc-scan',      # XML-RPC attacks
            'nikto',            # Web vulnerabilities
            'sqlmap',           # SQL injection
            'hydra'             # Brute force
        ]
        
        self.strategy['skip_tools'] = [
            'ssh-audit',        # Not relevant
            'enum4linux',       # Not relevant
            'snmp-check'        # Not relevant
        ]
        
        self.strategy['priority_targets'] = [
            '/wp-admin/',
            '/wp-login.php',
            '/xmlrpc.php',
            '/wp-json/',
            '/wp-content/plugins/'
        ]
    
    def _strategy_api(self):
        """Strategy for API targets"""
        self.logger.info("[PROFILER] 🎯 Target Profile: API Service")
        
        self.strategy['recommended_phases'] = [
            'reconnaissance',
            'api_enumeration',
            'authentication_testing',
            'injection_testing',
            'authorization_testing'
        ]
        
        self.strategy['recommended_tools'] = [
            'api-fuzzer',
            'jwt-tool',
            'postman',
            'burp-suite',
            'sqlmap'
        ]
        
        self.strategy['priority_targets'] = [
            '/api/',
            '/v1/',
            '/graphql',
            '/swagger',
            '/api-docs'
        ]
    
    def _strategy_web_app(self):
        """Strategy for generic web applications"""
        self.logger.info("[PROFILER] 🎯 Target Profile: Web Application")
        
        self.strategy['recommended_phases'] = [
            'reconnaissance',
            'web_enumeration',
            'vulnerability_scanning',
            'injection_testing',
            'authentication_testing',
            'exploitation'
        ]
        
        self.strategy['recommended_tools'] = [
            'nikto',
            'dirb',
            'gobuster',
            'sqlmap',
            'xsser',
            'burp-suite'
        ]
        
        self.strategy['priority_targets'] = self.profile['login_pages']
    
    def _strategy_ssh(self):
        """Strategy for SSH services"""
        self.logger.info("[PROFILER] 🎯 Target Profile: SSH Service")
        
        self.strategy['recommended_phases'] = [
            'reconnaissance',
            'ssh_enumeration',
            'brute_force',
            'exploitation'
        ]
        
        self.strategy['recommended_tools'] = [
            'ssh-audit',
            'hydra',
            'medusa',
            'nmap-ssh-scripts'
        ]
    
    def _strategy_generic(self):
        """Generic strategy for unknown targets"""
        self.logger.info("[PROFILER] 🎯 Target Profile: Generic Target")
        
        self.strategy['recommended_phases'] = [
            'reconnaissance',
            'port_scanning',
            'service_enumeration',
            'vulnerability_scanning',
            'exploitation'
        ]
        
        self.strategy['recommended_tools'] = [
            'nmap',
            'nikto',
            'metasploit'
        ]
    
    def _strategy_cms(self):
        """Strategy for other CMS platforms"""
        self.logger.info(f"[PROFILER] 🎯 Target Profile: {self.profile['cms']} Website")
        
        self.strategy['recommended_phases'] = [
            'reconnaissance',
            'cms_enumeration',
            'vulnerability_scanning',
            'exploitation'
        ]
        
        self.strategy['recommended_tools'] = [
            'nikto',
            'dirb',
            'sqlmap',
            'metasploit'
        ]
    
    def _calculate_estimated_time(self):
        """Calculate estimated scan time"""
        base_time = 10  # minutes
        
        # Add time based on attack surface
        base_time += len(self.profile['attack_surface']) * 5
        
        # Add time based on tools
        base_time += len(self.strategy['recommended_tools']) * 3
        
        self.strategy['estimated_time'] = base_time
    
    def _determine_risk_level(self):
        """Determine risk level of target"""
        risk_score = 0
        
        # More attack surface = higher risk
        risk_score += len(self.profile['attack_surface']) * 2
        
        # Known CMS = higher risk
        if self.profile['cms']:
            risk_score += 3
        
        # Login pages = higher risk
        risk_score += len(self.profile['login_pages'])
        
        # Determine level
        if risk_score >= 10:
            self.strategy['risk_level'] = 'high'
        elif risk_score >= 5:
            self.strategy['risk_level'] = 'medium'
        else:
            self.strategy['risk_level'] = 'low'
    
    def display_strategy(self):
        """Display the generated strategy"""
        self.logger.info("\n" + "="*60)
        self.logger.info("[PROFILER] 📋 CUSTOM ATTACK STRATEGY GENERATED")
        self.logger.info("="*60)
        
        # Target summary
        self.logger.info(f"\n🎯 Target: {self.target}")
        self.logger.info(f"   Type: {self.profile['target_type']}")
        if self.profile['cms']:
            self.logger.info(f"   CMS: {self.profile['cms']}")
        if self.profile['web_server']:
            self.logger.info(f"   Server: {self.profile['web_server']}")
        if self.profile.get('waf'):
            self.logger.info(f"   WAF: {self.profile['waf']}")
        if self.profile.get('cdn'):
            self.logger.info(f"   CDN: {self.profile['cdn']}")
        
        # Attack surface
        self.logger.info(f"\n🔍 Attack Surface: {', '.join(self.profile['attack_surface']) if self.profile['attack_surface'] else 'Limited'}")
        
        # Attack vectors (NEW)
        if self.strategy.get('attack_vectors'):
            self.logger.info(f"\n⚔️  Attack Vectors ({len(self.strategy['attack_vectors'])}):")
            for vector in self.strategy['attack_vectors'][:5]:
                self.logger.info(f"   • {vector}")
            if len(self.strategy['attack_vectors']) > 5:
                self.logger.info(f"   ... and {len(self.strategy['attack_vectors']) - 5} more")
        
        # Recommended phases
        self.logger.info(f"\n📍 Recommended Phases ({len(self.strategy['recommended_phases'])}):")
        for i, phase in enumerate(self.strategy['recommended_phases'], 1):
            self.logger.info(f"   {i}. {phase.replace('_', ' ').title()}")
        
        # Recommended tools
        self.logger.info(f"\n🛠️  Recommended Tools ({len(self.strategy['recommended_tools'])}):")
        for tool in self.strategy['recommended_tools'][:5]:  # Show first 5
            self.logger.info(f"   • {tool}")
        if len(self.strategy['recommended_tools']) > 5:
            self.logger.info(f"   ... and {len(self.strategy['recommended_tools']) - 5} more")
        
        # Skipped tools (NEW)
        if self.strategy.get('skip_tools'):
            self.logger.info(f"\n🚫 Skipped Tools ({len(self.strategy['skip_tools'])}):")
            for tool in self.strategy['skip_tools'][:3]:
                self.logger.info(f"   • {tool}")
        
        # Priority targets
        if self.strategy['priority_targets']:
            self.logger.info(f"\n🎯 Priority Targets:")
            for target in self.strategy['priority_targets'][:3]:
                self.logger.info(f"   • {target}")
        
        # Estimates
        self.logger.info(f"\n⏱️  Estimated Time: ~{self.strategy['estimated_time']} minutes")
        self.logger.info(f"⚠️  Risk Level: {self.strategy['risk_level'].upper()}")
        
        self.logger.info("\n" + "="*60)
    
    # Helper methods
    def _is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(pattern, target))
    
    def _quick_port_check(self):
        """Quick check of common ports"""
        common_ports = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 8080, 8443]
        
        # Extract hostname from URL if needed
        target_host = self.target
        if '://' in target_host:
            parsed = urlparse(target_host)
            target_host = parsed.netloc or parsed.path
        
        # Try to resolve hostname first
        try:
            target_ip = socket.gethostbyname(target_host)
        except (socket.gaierror, socket.herror) as e:
            self.logger.debug(f"[PROFILER] DNS resolution failed: {e}")
            target_ip = target_host
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)  # Increased timeout for reliability
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    self.profile['open_ports'].append(port)
                sock.close()
            except Exception as e:
                self.logger.debug(f"[PROFILER] Port {port} check failed: {e}")
                pass
    
    def _detect_cms(self, response) -> str:
        """Detect CMS from response"""
        content = response.text.lower()
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        # WordPress
        if 'wp-content' in content or 'wp-includes' in content:
            return 'WordPress'
        
        # Joomla
        if 'joomla' in content or '/components/com_' in content:
            return 'Joomla'
        
        # Drupal
        if 'drupal' in content or 'sites/default' in content:
            return 'Drupal'
        
        # Magento
        if 'magento' in content:
            return 'Magento'
        
        return None
    
    def _detect_language(self, response) -> str:
        """Detect programming language"""
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        # PHP
        if 'x-powered-by' in headers and 'php' in headers['x-powered-by'].lower():
            return 'PHP'
        
        # ASP.NET
        if 'x-aspnet-version' in headers:
            return 'ASP.NET'
        
        # Check URL extensions
        if '.php' in response.url:
            return 'PHP'
        elif '.asp' in response.url or '.aspx' in response.url:
            return 'ASP.NET'
        elif '.jsp' in response.url:
            return 'Java'
        
        return None
    
    def _detect_frameworks(self, response) -> List[str]:
        """Detect web frameworks"""
        frameworks = []
        content = response.text.lower()
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        # React
        if 'react' in content or '__react' in content:
            frameworks.append('React')
        
        # Angular
        if 'ng-' in content or 'angular' in content:
            frameworks.append('Angular')
        
        # Vue.js
        if 'vue' in content or 'v-' in content:
            frameworks.append('Vue.js')
        
        # Laravel
        if 'laravel' in content:
            frameworks.append('Laravel')
        
        # Django
        if 'csrfmiddlewaretoken' in content:
            frameworks.append('Django')
        
        return frameworks
    
    def _detect_api(self, response) -> bool:
        """Detect if target is an API"""
        content_type = response.headers.get('Content-Type', '').lower()
        
        # Check content type
        if 'application/json' in content_type:
            return True
        
        # Check URL patterns
        if any(pattern in response.url.lower() for pattern in ['/api/', '/v1/', '/v2/', '/graphql']):
            return True
        
        return False
    
    def _find_login_pages(self, response, base_url) -> List[str]:
        """Find potential login pages"""
        login_pages = []
        common_paths = [
            '/login', '/admin', '/wp-admin', '/administrator',
            '/signin', '/auth', '/user/login', '/account/login'
        ]
        
        for path in common_paths:
            if path.lower() in response.text.lower():
                login_pages.append(base_url + path)
        
        return login_pages[:5]  # Return max 5

    def _detect_waf(self, response) -> str:
        """Detect Web Application Firewall or IDS"""
        # Check headers for WAF signatures
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        waf_signatures = {
            'cloudflare': ['cf-ray', 'cf-cache-status', '__cfduid'],
            'aws-waf': ['x-amzn-requestid', 'x-amz-cf-id'],
            'akamai': ['akamai-origin-hop', 'x-akamai-transformed'],
            'imperva': ['x-cdn', 'x-iinfo'],
            'f5-bigip': ['bigipserver', 'x-wa-info'],
            'modsecurity': ['mod_security', 'naxsi'],
            'sucuri': ['x-sucuri-id', 'x-sucuri-cache'],
            'wordfence': ['wordfence'],
            'barracuda': ['barra_counter_session'],
            'fortiweb': ['fortigate', 'fortiweb']
        }
        
        for waf_name, signatures in waf_signatures.items():
            for sig in signatures:
                if any(sig in key or sig in str(value).lower() for key, value in headers.items()):
                    return waf_name.upper()
        
        # Check for WAF in Server header
        server = headers.get('server', '').lower()
        if 'cloudflare' in server:
            return 'Cloudflare'
        elif 'akamai' in server:
            return 'Akamai'
        
        # Check response body for WAF signatures
        try:
            body = response.text.lower()
            if 'cloudflare' in body and 'ray id' in body:
                return 'Cloudflare'
            elif 'access denied' in body or 'blocked' in body:
                # Generic WAF detection
                return 'Generic WAF'
        except (requests.exceptions.RequestException, KeyError) as e:
            self.logger.debug(f"[PROFILER] WAF detection failed: {e}")
        
        return None
    
    def _detect_cdn(self, response) -> str:
        """Detect Content Delivery Network"""
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        cdn_signatures = {
            'cloudflare': ['cf-ray', 'cf-cache-status'],
            'akamai': ['akamai-origin-hop', 'x-akamai'],
            'fastly': ['fastly', 'x-fastly'],
            'cloudfront': ['x-amz-cf-id', 'via'],
            'maxcdn': ['x-cdn', 'x-cache'],
            'keycdn': ['x-keycdn'],
            'stackpath': ['x-sp-'],
            'bunnycdn': ['cdn-pullzone'],
            'netlify': ['x-nf-request-id']
        }
        
        for cdn_name, signatures in cdn_signatures.items():
            for sig in signatures:
                if any(sig in key or sig in str(value).lower() for key, value in headers.items()):
                    return cdn_name.capitalize()
        
        # Check Via header
        via = headers.get('via', '').lower()
        if 'cloudfront' in via:
            return 'CloudFront'
        elif 'akamai' in via:
            return 'Akamai'
        elif 'varnish' in via:
            return 'Varnish'
        
        return None
    
    def _detect_load_balancer(self, response) -> str:
        """Detect Load Balancer"""
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        lb_signatures = {
            'f5-bigip': ['bigipserver', 'x-wa-info'],
            'nginx': ['nginx'],
            'haproxy': ['haproxy'],
            'aws-elb': ['awselb', 'x-amzn-requestid'],
            'azure-lb': ['x-azure-ref'],
            'gcp-lb': ['x-goog-'],
            'citrix-netscaler': ['ns_af', 'citrix']
        }
        
        for lb_name, signatures in lb_signatures.items():
            for sig in signatures:
                if any(sig in key or sig in str(value).lower() for key, value in headers.items()):
                    return lb_name.upper()
        
        # Check Server header
        server = headers.get('server', '').lower()
        if 'nginx' in server:
            return 'Nginx'
        elif 'haproxy' in server:
            return 'HAProxy'
        
        return None
    
    def _detect_rate_limiting(self, url: str) -> str:
        """Detect rate limiting mechanisms"""
        try:
            # Make multiple rapid requests
            responses = []
            for i in range(5):
                resp = requests.get(url, timeout=5, verify=False)
                responses.append(resp)
            
            # Check for rate limit headers
            last_response = responses[-1]
            headers = {k.lower(): v for k, v in last_response.headers.items()}
            
            rate_limit_headers = [
                'x-ratelimit-limit',
                'x-rate-limit-limit',
                'ratelimit-limit',
                'x-ratelimit-remaining',
                'retry-after'
            ]
            
            for header in rate_limit_headers:
                if header in headers:
                    return f"Active (Header: {header})"
            
            # Check for 429 status code
            if last_response.status_code == 429:
                return "Active (429 Too Many Requests)"
            
            return "Not Detected"
            
        except Exception as e:
            return "Unknown"

    def _detect_http_version(self, response) -> str:
        """Detect HTTP version (HTTP/1.1, HTTP/2, HTTP/3)"""
        try:
            # Check if HTTP/2 is used
            if hasattr(response.raw, 'version'):
                version = response.raw.version
                if version == 20:
                    return 'HTTP/2'
                elif version == 11:
                    return 'HTTP/1.1'
                elif version == 10:
                    return 'HTTP/1.0'
            
            # Check alt-svc header for HTTP/3
            alt_svc = response.headers.get('alt-svc', '').lower()
            if 'h3' in alt_svc or 'quic' in alt_svc:
                return 'HTTP/3 (QUIC)'
            
            return 'HTTP/1.1'
        except (requests.exceptions.RequestException, AttributeError) as e:
            self.logger.debug(f"[PROFILER] HTTP version detection failed: {e}")
            return 'Unknown'
    
    def _check_security_txt(self, url: str) -> bool:
        """Check for security.txt file (RFC 9116)"""
        try:
            # Check both locations
            locations = [
                f"{url}/.well-known/security.txt",
                f"{url}/security.txt"
            ]
            
            for location in locations:
                try:
                    resp = requests.get(location, timeout=5, verify=False)
                    if resp.status_code == 200 and 'contact' in resp.text.lower():
                        return True
                except requests.exceptions.RequestException:
                    continue
            return False
        except requests.exceptions.RequestException as e:
            self.logger.debug(f"[PROFILER] Security.txt check failed: {e}")
            return False
    
    def _analyze_cookies(self, response) -> Dict:
        """Analyze cookie security"""
        cookies_info = {
            'total': 0,
            'secure': 0,
            'httponly': 0,
            'samesite': 0,
            'issues': []
        }
        
        try:
            cookies = response.cookies
            cookies_info['total'] = len(cookies)
            
            for cookie in cookies:
                if cookie.secure:
                    cookies_info['secure'] += 1
                else:
                    cookies_info['issues'].append(f"{cookie.name}: Missing Secure flag")
                
                if cookie.has_nonstandard_attr('HttpOnly'):
                    cookies_info['httponly'] += 1
                else:
                    cookies_info['issues'].append(f"{cookie.name}: Missing HttpOnly flag")
                
                if cookie.has_nonstandard_attr('SameSite'):
                    cookies_info['samesite'] += 1
                else:
                    cookies_info['issues'].append(f"{cookie.name}: Missing SameSite attribute")
            
            return cookies_info
        except (requests.exceptions.RequestException, AttributeError) as e:
            self.logger.debug(f"[PROFILER] Cookie analysis failed: {e}")
            return cookies_info
    
    def _detect_tls_version(self, target: str) -> str:
        """Detect TLS version"""
        try:
            import ssl
            import socket
            
            # Remove protocol and path
            hostname = target.replace('https://', '').replace('http://', '').split('/')[0]
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    version = ssock.version()
                    return version
        except (ssl.SSLError, socket.error, OSError) as e:
            self.logger.debug(f"[PROFILER] TLS version detection failed: {e}")
            return 'Unknown'
    
    def _detect_server_technologies(self, response) -> List[str]:
        """Advanced server technology detection"""
        technologies = []
        headers = {k.lower(): v for k, v in response.headers.items()}
        body = response.text.lower()
        
        # Check headers for technology signatures
        tech_signatures = {
            'x-powered-by': {
                'php': 'PHP',
                'asp.net': 'ASP.NET',
                'express': 'Express.js',
                'next.js': 'Next.js'
            },
            'x-aspnet-version': {'': 'ASP.NET'},
            'x-aspnetmvc-version': {'': 'ASP.NET MVC'},
            'x-drupal-cache': {'': 'Drupal'},
            'x-generator': {
                'drupal': 'Drupal',
                'wordpress': 'WordPress',
                'joomla': 'Joomla'
            }
        }
        
        for header, sigs in tech_signatures.items():
            if header in headers:
                value = headers[header].lower()
                if sigs:
                    for sig, tech in sigs.items():
                        if sig in value:
                            technologies.append(tech)
                else:
                    technologies.append(list(sigs.values())[0])
        
        # Check body for meta tags and comments
        if 'generator' in body:
            if 'wordpress' in body:
                technologies.append('WordPress')
            if 'drupal' in body:
                technologies.append('Drupal')
            if 'joomla' in body:
                technologies.append('Joomla')
        
        # Check for JavaScript frameworks
        js_frameworks = {
            'react': 'React',
            'vue': 'Vue.js',
            'angular': 'Angular',
            'jquery': 'jQuery',
            'bootstrap': 'Bootstrap',
            'next.js': 'Next.js',
            'nuxt': 'Nuxt.js'
        }
        
        for sig, tech in js_frameworks.items():
            if sig in body:
                technologies.append(tech)
        
        return list(set(technologies))  # Remove duplicates
    
    def _check_robots_txt(self, url: str) -> Dict:
        """Analyze robots.txt for interesting paths"""
        try:
            robots_url = f"{url}/robots.txt"
            resp = requests.get(robots_url, timeout=5, verify=False)
            
            if resp.status_code == 200:
                content = resp.text
                disallowed = []
                
                for line in content.split('\n'):
                    if line.strip().lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            disallowed.append(path)
                
                return {
                    'exists': True,
                    'disallowed_paths': disallowed[:10],  # Top 10
                    'total_rules': len(disallowed)
                }
            return {'exists': False}
        except (requests.exceptions.RequestException, ValueError) as e:
            self.logger.debug(f"[PROFILER] Robots.txt analysis failed: {e}")
            return {'exists': False}
