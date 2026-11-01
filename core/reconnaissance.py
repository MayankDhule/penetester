"""
Phase 1: Reconnaissance Module
Passive and Active information gathering
"""
import socket
import subprocess
import re
import requests
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List
import dns.resolver

class ReconnaissanceEngine:
    """Handles all reconnaissance activities"""
    
    def __init__(self, target: str, logger, profile: Dict = None):
        self.target = target
        self.logger = logger
        self.profile = profile or {}
        self.strategy = None
        self.results = {
            'target': target,
            'ip_addresses': [],
            'subdomains': [],
            'whois_info': {},
            'dns_records': {},
            'open_ports': [],
            'technologies': []
        }
    
    def set_strategy(self, strategy: Dict):
        """Set the reconnaissance strategy from profiler"""
        self.strategy = strategy
        self.logger.info(f"[RECON] Strategy loaded: {len(strategy.get('recommended_phases', []))} phases planned")
    
    def execute(self) -> Dict:
        """Execute full reconnaissance"""
        self.logger.info(f"[RECON] Starting reconnaissance on {self.target}")
        
        # Check if target has web services
        has_web = 'web' in self.profile.get('attack_surface', [])
        
        # Passive reconnaissance (skip web-specific checks for non-web targets)
        self.passive_recon(has_web)
        
        # Active reconnaissance (always run - port scanning is universal)
        self.active_recon()
        
        self.logger.info(f"[RECON] Reconnaissance complete")
        return self.results
    
    def passive_recon(self, has_web: bool = True):
        """Passive information gathering"""
        self.logger.info("[RECON] Phase 1.1: Passive Reconnaissance")
        
        # DNS Resolution (always useful)
        self.resolve_dns()
        
        # Skip web-specific checks for non-web targets
        if not has_web and self._is_ip_address(self.target):
            self.logger.info("[RECON] Non-web target detected - skipping WHOIS, DNS records, and subdomain enumeration")
            return
        
        # WHOIS Lookup (web-specific)
        if has_web or not self._is_ip_address(self.target):
            self.whois_lookup()
        
        # DNS Records (web-specific)
        if has_web or not self._is_ip_address(self.target):
            self.enumerate_dns_records()
        
        # Subdomain Enumeration (web-specific)
        if has_web or not self._is_ip_address(self.target):
            self.enumerate_subdomains()
    
    def active_recon(self):
        """Active information gathering"""
        self.logger.info("[RECON] Phase 1.2: Active Reconnaissance")
        
        # Port scanning (quick scan)
        self.quick_port_scan()
        
        # Service detection
        self.detect_services()
    
    def resolve_dns(self):
        """Resolve target to IP address"""
        try:
            self.logger.info(f"[RECON] Resolving DNS for {self.target}")
            ip = socket.gethostbyname(self.target)
            self.results['ip_addresses'].append(ip)
            self.logger.info(f"[RECON] ✓ Resolved to: {ip}")
        except socket.gaierror as e:
            self.logger.error(f"[RECON] ✗ DNS resolution failed: {e}")
    
    def whois_lookup(self):
        """Perform WHOIS lookup using subprocess"""
        try:
            self.logger.info(f"[RECON] Performing WHOIS lookup")
            
            # Try using system whois command
            try:
                result = subprocess.run(
                    ['whois', self.target],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    whois_data = result.stdout
                    
                    # Parse key information
                    registrar = self._extract_whois_field(whois_data, ['Registrar:', 'registrar:'])
                    creation_date = self._extract_whois_field(whois_data, ['Creation Date:', 'created:'])
                    expiration_date = self._extract_whois_field(whois_data, ['Expiration Date:', 'expires:'])
                    name_servers = self._extract_whois_nameservers(whois_data)
                    
                    self.results['whois_info'] = {
                        'registrar': registrar or 'N/A',
                        'creation_date': creation_date or 'N/A',
                        'expiration_date': expiration_date or 'N/A',
                        'name_servers': name_servers,
                        'raw_data': whois_data[:500]  # Store first 500 chars
                    }
                    
                    self.logger.info(f"[RECON] ✓ WHOIS data retrieved")
                    if registrar:
                        self.logger.info(f"[RECON]   Registrar: {registrar}")
                    
                else:
                    raise Exception("WHOIS command failed")
                    
            except FileNotFoundError:
                # WHOIS command not available, use online API
                self.logger.info(f"[RECON] System WHOIS not available, using online lookup")
                self._whois_online_lookup()
                
        except Exception as e:
            self.logger.warning(f"[RECON] ✗ WHOIS lookup failed: {e}")
    
    def _extract_whois_field(self, whois_data: str, field_names: List[str]) -> str:
        """Extract a field from WHOIS data"""
        for field_name in field_names:
            pattern = rf'{field_name}\s*(.+)'
            match = re.search(pattern, whois_data, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None
    
    def _extract_whois_nameservers(self, whois_data: str) -> List[str]:
        """Extract nameservers from WHOIS data"""
        nameservers = []
        patterns = [r'Name Server:\s*(.+)', r'nserver:\s*(.+)', r'Nameserver:\s*(.+)']
        
        for pattern in patterns:
            matches = re.findall(pattern, whois_data, re.IGNORECASE)
            if matches:
                nameservers.extend([ns.strip() for ns in matches])
        
        return list(set(nameservers))[:5]  # Return unique, max 5
    
    def _whois_online_lookup(self):
        """Fallback: Use online WHOIS API"""
        try:
            # Use a simple WHOIS API
            url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=at_free&domainName={self.target}&outputFormat=json"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                whois_record = data.get('WhoisRecord', {})
                
                self.results['whois_info'] = {
                    'registrar': whois_record.get('registrarName', 'N/A'),
                    'creation_date': whois_record.get('createdDate', 'N/A'),
                    'expiration_date': whois_record.get('expiresDate', 'N/A'),
                    'name_servers': whois_record.get('nameServers', {}).get('hostNames', [])
                }
                
                self.logger.info(f"[RECON] ✓ WHOIS data retrieved (online)")
            else:
                # Minimal fallback
                self.results['whois_info'] = {
                    'registrar': 'N/A',
                    'creation_date': 'N/A',
                    'expiration_date': 'N/A',
                    'name_servers': []
                }
                self.logger.info(f"[RECON] ⚠ WHOIS data limited (online API unavailable)")
                
        except Exception as e:
            self.logger.debug(f"[RECON] Online WHOIS lookup failed: {e}")
            # Set minimal data
            self.results['whois_info'] = {
                'registrar': 'N/A',
                'creation_date': 'N/A',
                'expiration_date': 'N/A',
                'name_servers': []
            }
    
    def enumerate_dns_records(self):
        """Enumerate DNS records"""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
        
        self.logger.info(f"[RECON] Enumerating DNS records")
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                records = [str(rdata) for rdata in answers]
                
                if records:
                    self.results['dns_records'][record_type] = records
                    self.logger.info(f"[RECON] ✓ {record_type} records: {len(records)} found")
                    
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                pass
            except Exception as e:
                self.logger.debug(f"[RECON] Error querying {record_type}: {e}")
    
    def enumerate_subdomains(self):
        """Enumerate subdomains using common wordlist"""
        self.logger.info(f"[RECON] Enumerating subdomains")
        
        # Common subdomain wordlist (top 50)
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mx', 'email', 'api',
            'dev', 'staging', 'test', 'admin', 'portal', 'blog', 'shop', 'store', 'mobile',
            'app', 'cdn', 'static', 'media', 'images', 'img', 'assets', 'files', 'download',
            'vpn', 'remote', 'secure', 'login', 'dashboard', 'panel', 'control', 'manage',
            'support', 'help', 'docs', 'wiki', 'forum', 'community', 'chat'
        ]
        
        found_subdomains = []
        
        for subdomain in common_subdomains[:20]:  # Limit to 20 for speed
            full_domain = f"{subdomain}.{self.target}"
            
            try:
                # Try to resolve the subdomain
                ip = socket.gethostbyname(full_domain)
                found_subdomains.append({
                    'subdomain': full_domain,
                    'ip': ip
                })
                self.logger.info(f"[RECON] ✓ Found subdomain: {full_domain} ({ip})")
                
            except socket.gaierror:
                # Subdomain doesn't exist
                pass
            except Exception as e:
                self.logger.debug(f"[RECON] Error checking {full_domain}: {e}")
        
        self.results['subdomains'] = found_subdomains
        
        if found_subdomains:
            self.logger.info(f"[RECON] ✓ Discovered {len(found_subdomains)} subdomains")
        else:
            self.logger.info(f"[RECON] No subdomains found")
    
    def quick_port_scan(self):
        """Quick scan of common ports"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]
        
        self.logger.info(f"[RECON] Scanning common ports")
        
        if not self.results['ip_addresses']:
            self.logger.warning("[RECON] No IP address to scan")
            return
        
        target_ip = self.results['ip_addresses'][0]

        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_ip, port))
                sock.close()
                return port if result == 0 else None
            except Exception as e:
                self.logger.debug(f"[RECON] Error scanning port {port}: {e}")
                return None

        # Scan ports concurrently so the sweep takes ~one timeout instead of
        # the sum of all per-port timeouts.
        with ThreadPoolExecutor(max_workers=len(common_ports)) as pool:
            open_ports = sorted(p for p in pool.map(check_port, common_ports) if p is not None)

        for port in open_ports:
            self.logger.info(f"[RECON] ✓ Port {port} is OPEN")

        self.results['open_ports'] = open_ports
        self.logger.info(f"[RECON] Found {len(open_ports)} open ports")
    
    def detect_services(self):
        """Detect services on open ports"""
        if not self.results['open_ports']:
            return
        
        self.logger.info(f"[RECON] Detecting services")
        
        service_map = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt'
        }
        
        for port in self.results['open_ports']:
            service = service_map.get(port, 'Unknown')
            self.logger.info(f"[RECON]   Port {port}: {service}")
    
    def get_summary(self) -> str:
        """Get reconnaissance summary"""
        summary = f"\n{'='*60}\n"
        summary += f"RECONNAISSANCE SUMMARY - {self.target}\n"
        summary += f"{'='*60}\n\n"
        
        summary += f"IP Addresses: {', '.join(self.results['ip_addresses']) if self.results['ip_addresses'] else 'None'}\n"
        summary += f"Open Ports: {', '.join(map(str, self.results['open_ports'])) if self.results['open_ports'] else 'None'}\n"
        summary += f"DNS Records: {len(self.results['dns_records'])} types found\n"
        summary += f"WHOIS: {'Available' if self.results['whois_info'] else 'Not available'}\n"
        
        summary += f"\n{'='*60}\n"
        
        return summary

    def _is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address"""
        import re
        # Remove protocol if present
        target = target.replace('http://', '').replace('https://', '').split('/')[0]
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(pattern, target))
