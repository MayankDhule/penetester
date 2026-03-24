"""
Phase 2: Scanning & Enumeration Module
Web crawling, directory discovery, and service enumeration
"""
import requests
import re
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup


class ScanningEngine:
    """Handles scanning and enumeration activities"""
    
    def __init__(self, target: str, logger, profile: Dict = None, strategy: Dict = None):
        self.target = target
        self.logger = logger
        self.profile = profile or {}
        self.strategy = strategy or {}
        self.results = {
            'target': target,
            'discovered_urls': [],
            'directories': [],
            'files': [],
            'forms': [],
            'endpoints': [],
            'technologies': [],
            'comments': [],
            'emails': [],
            'subdomains': []
        }
        self.visited_urls = set()
        self.max_depth = 2
        
    def execute(self) -> Dict:
        """Execute full scanning and enumeration"""
        self.logger.info("="*60)
        self.logger.info("[SCANNER] 🔍 Phase 2: Scanning & Enumeration")
        self.logger.info("="*60)
        
        # Determine base URL
        base_url = self._get_base_url()
        
        # Check if we should scan web (from profile OR if we have web ports)
        should_scan_web = (
            'web' in self.profile.get('attack_surface', []) or
            80 in self.profile.get('open_ports', []) or
            443 in self.profile.get('open_ports', [])
        )
        
        # Web crawling
        if should_scan_web:
            self.web_crawl(base_url)
            self.discover_directories(base_url)
            self.enumerate_endpoints(base_url)
            self.check_backup_files(base_url)  # NEW
            self.check_git_svn_exposure(base_url)  # NEW
            self.discover_api_endpoints(base_url)  # NEW
            self.extract_metadata(base_url)
        else:
            self.logger.info("[SCANNER] No web service detected - skipping web scanning")
        
        # Display results
        self.display_results()
        
        return self.results
    
    def _get_base_url(self) -> str:
        """Determine base URL from target"""
        if self.target.startswith('http'):
            return self.target
        
        # Check if SSL is enabled
        if self.profile.get('ssl_enabled'):
            return f"https://{self.target}"
        else:
            return f"http://{self.target}"
    
    def web_crawl(self, base_url: str, depth: int = 0):
        """Crawl website to discover pages"""
        if depth > self.max_depth:
            return
        
        if depth == 0:
            self.logger.info("\n[SCANNER] Step 1: Web Crawling")
            self.logger.info("-" * 60)
        
        try:
            response = requests.get(base_url, timeout=10, verify=False, allow_redirects=True)
            
            if base_url not in self.visited_urls:
                self.visited_urls.add(base_url)
                self.results['discovered_urls'].append(base_url)
                
                if depth == 0:
                    self.logger.info(f"[SCANNER] ✓ Crawling: {base_url}")
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all links
            links = soup.find_all('a', href=True)
            internal_links = []
            
            for link in links:
                href = link['href']
                full_url = urljoin(base_url, href)
                
                # Only follow internal links
                if urlparse(full_url).netloc == urlparse(base_url).netloc:
                    if full_url not in self.visited_urls:
                        internal_links.append(full_url)
            
            # Recursively crawl (limited depth)
            if depth < self.max_depth:
                for url in internal_links[:5]:  # Limit to 5 links per page
                    self.web_crawl(url, depth + 1)
            
            if depth == 0:
                self.logger.info(f"[SCANNER] ✓ Discovered {len(self.visited_urls)} pages")
                
        except Exception as e:
            self.logger.debug(f"[SCANNER] Error crawling {base_url}: {e}")
    
    def discover_directories(self, base_url: str):
        """Discover common directories"""
        self.logger.info("\n[SCANNER] Step 2: Directory Discovery")
        self.logger.info("-" * 60)
        
        # Common directories to check
        common_dirs = [
            'admin', 'api', 'assets', 'backup', 'config', 'css', 'data',
            'db', 'docs', 'downloads', 'files', 'images', 'img', 'js',
            'login', 'logs', 'media', 'scripts', 'static', 'temp', 'test',
            'uploads', 'user', 'users', 'vendor'
        ]
        
        # Add CMS-specific directories
        if self.profile.get('cms') == 'WordPress':
            common_dirs.extend(['wp-admin', 'wp-content', 'wp-includes'])
        
        found_count = 0
        
        for directory in common_dirs[:10]:  # Check first 10 to keep it fast
            url = urljoin(base_url, f"/{directory}/")
            
            try:
                response = requests.head(url, timeout=5, verify=False, allow_redirects=False)
                
                if response.status_code in [200, 301, 302, 403]:
                    self.results['directories'].append(url)
                    found_count += 1
                    self.logger.info(f"[SCANNER] ✓ Found: /{directory}/ [{response.status_code}]")
                    
            except:
                pass
        
        if found_count == 0:
            self.logger.info("[SCANNER] No common directories found")
        else:
            self.logger.info(f"[SCANNER] ✓ Discovered {found_count} directories")
    
    def enumerate_endpoints(self, base_url: str):
        """Enumerate API endpoints and interesting files"""
        self.logger.info("\n[SCANNER] Step 3: Endpoint Enumeration")
        self.logger.info("-" * 60)
        
        # Common files to check
        interesting_files = [
            'robots.txt', 'sitemap.xml', '.htaccess', 'web.config',
            'package.json', 'composer.json', 'README.md', '.env',
            'config.json', 'swagger.json', 'api-docs'
        ]
        
        found_count = 0
        
        for filename in interesting_files:
            url = urljoin(base_url, f"/{filename}")
            
            try:
                response = requests.get(url, timeout=5, verify=False)
                
                if response.status_code == 200:
                    self.results['files'].append({
                        'url': url,
                        'filename': filename,
                        'size': len(response.content)
                    })
                    found_count += 1
                    self.logger.info(f"[SCANNER] ✓ Found: {filename} ({len(response.content)} bytes)")
                    
                    # Parse robots.txt for additional paths
                    if filename == 'robots.txt':
                        self._parse_robots(response.text, base_url)
                    
            except:
                pass
        
        if found_count == 0:
            self.logger.info("[SCANNER] No interesting files found")
        else:
            self.logger.info(f"[SCANNER] ✓ Found {found_count} interesting files")
    
    def extract_metadata(self, base_url: str):
        """Extract metadata from pages"""
        self.logger.info("\n[SCANNER] Step 4: Metadata Extraction")
        self.logger.info("-" * 60)
        
        try:
            response = requests.get(base_url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find forms
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()
                inputs = [inp.get('name') for inp in form.find_all('input') if inp.get('name')]
                
                self.results['forms'].append({
                    'action': urljoin(base_url, action),
                    'method': method,
                    'inputs': inputs
                })
            
            if forms:
                self.logger.info(f"[SCANNER] ✓ Found {len(forms)} forms")
            
            # Extract emails
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', response.text)
            self.results['emails'] = list(set(emails))
            
            if emails:
                self.logger.info(f"[SCANNER] ✓ Found {len(set(emails))} email addresses")
            
            # Extract comments
            comments = soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--'))
            self.results['comments'] = [c.strip() for c in comments[:5]]  # First 5 comments
            
            if comments:
                self.logger.info(f"[SCANNER] ✓ Found {len(comments)} HTML comments")
            
            if not forms and not emails and not comments:
                self.logger.info("[SCANNER] No significant metadata found")
                
        except Exception as e:
            self.logger.debug(f"[SCANNER] Error extracting metadata: {e}")
    
    def _parse_robots(self, robots_content: str, base_url: str):
        """Parse robots.txt for interesting paths"""
        disallowed = re.findall(r'Disallow:\s*(.+)', robots_content)
        
        for path in disallowed[:5]:  # First 5 paths
            path = path.strip()
            if path and path != '/':
                full_url = urljoin(base_url, path)
                if full_url not in self.results['directories']:
                    self.results['directories'].append(full_url)
    
    def display_results(self):
        """Display scanning results summary"""
        self.logger.info("\n" + "="*60)
        self.logger.info("[SCANNER] 📊 SCANNING RESULTS SUMMARY")
        self.logger.info("="*60)
        
        self.logger.info(f"\n📄 Pages Discovered: {len(self.results['discovered_urls'])}")
        self.logger.info(f"📁 Directories Found: {len(self.results['directories'])}")
        self.logger.info(f"📋 Interesting Files: {len(self.results['files'])}")
        self.logger.info(f"📝 Forms Detected: {len(self.results['forms'])}")
        self.logger.info(f"📧 Email Addresses: {len(self.results['emails'])}")
        self.logger.info(f"💬 HTML Comments: {len(self.results['comments'])}")
        
        # Show some examples
        if self.results['directories']:
            self.logger.info(f"\n📁 Sample Directories:")
            for directory in self.results['directories'][:3]:
                self.logger.info(f"   • {directory}")
        
        if self.results['files']:
            self.logger.info(f"\n📋 Interesting Files:")
            for file_info in self.results['files'][:3]:
                self.logger.info(f"   • {file_info['filename']}")
        
        if self.results['forms']:
            self.logger.info(f"\n📝 Forms Found:")
            for form in self.results['forms'][:3]:
                self.logger.info(f"   • {form['method']} {form['action']}")
        
        self.logger.info("\n" + "="*60)

    def check_backup_files(self, base_url: str):
        """Check for common backup files"""
        self.logger.info("\n[SCANNER] Step 4: Backup File Detection")
        self.logger.info("-" * 60)
        
        # Common backup file extensions and patterns
        backup_patterns = [
            '.bak', '.old', '.backup', '.zip', '.tar.gz', '.sql', '.db',
            '~', '.swp', '.swo', '.orig', '.save', '.copy'
        ]
        
        # Common filenames to check
        common_files = [
            'backup', 'database', 'db', 'dump', 'site', 'www', 'web',
            'config', 'settings', 'data', 'export'
        ]
        
        found_backups = []
        
        # Check combinations
        for filename in common_files[:5]:  # Limit for speed
            for ext in backup_patterns[:6]:
                test_url = urljoin(base_url, f"/{filename}{ext}")
                
                try:
                    response = requests.head(test_url, timeout=3, verify=False, allow_redirects=False)
                    
                    if response.status_code == 200:
                        self.logger.info(f"[SCANNER] ⚠️  Found backup file: {filename}{ext}")
                        found_backups.append({
                            'filename': f"{filename}{ext}",
                            'url': test_url,
                            'size': response.headers.get('Content-Length', 'Unknown')
                        })
                        
                        # Add to files list
                        self.results['files'].append({
                            'filename': f"{filename}{ext}",
                            'url': test_url,
                            'size': response.headers.get('Content-Length', 'Unknown'),
                            'type': 'backup'
                        })
                        
                except requests.RequestException:
                    pass
        
        if found_backups:
            self.logger.info(f"[SCANNER] ✓ Found {len(found_backups)} backup files")
        else:
            self.logger.info(f"[SCANNER] No backup files found")
    
    def check_git_svn_exposure(self, base_url: str):
        """Check for exposed .git and .svn directories"""
        self.logger.info("\n[SCANNER] Step 5: Version Control Exposure Check")
        self.logger.info("-" * 60)
        
        vcs_paths = [
            '.git/config',
            '.git/HEAD',
            '.svn/entries',
            '.svn/wc.db',
            '.hg/requires',
            '.bzr/branch-format'
        ]
        
        found_vcs = []
        
        for vcs_path in vcs_paths:
            test_url = urljoin(base_url, f"/{vcs_path}")
            
            try:
                response = requests.get(test_url, timeout=3, verify=False, allow_redirects=False)
                
                if response.status_code == 200 and len(response.content) > 0:
                    vcs_type = vcs_path.split('/')[0]
                    self.logger.info(f"[SCANNER] ⚠️  CRITICAL: {vcs_type} repository exposed!")
                    
                    found_vcs.append({
                        'type': vcs_type,
                        'url': test_url,
                        'severity': 'CRITICAL'
                    })
                    
                    # Add to files list
                    self.results['files'].append({
                        'filename': vcs_path,
                        'url': test_url,
                        'size': len(response.content),
                        'type': 'vcs_exposure'
                    })
                    
            except requests.RequestException:
                pass
        
        if found_vcs:
            self.logger.info(f"[SCANNER] ⚠️  Found {len(found_vcs)} VCS exposures (CRITICAL!)")
        else:
            self.logger.info(f"[SCANNER] ✓ No VCS exposures found")
    
    def discover_api_endpoints(self, base_url: str):
        """Discover API endpoints"""
        self.logger.info("\n[SCANNER] Step 6: API Endpoint Discovery")
        self.logger.info("-" * 60)
        
        # Common API paths
        api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/rest/v1', '/rest/v2',
            '/graphql', '/gql',
            '/v1', '/v2', '/v3',
            '/api/users', '/api/auth', '/api/login',
            '/api/data', '/api/config', '/api/status',
            '/swagger', '/swagger.json', '/swagger-ui',
            '/openapi.json', '/api-docs',
            '/api/swagger.json', '/api/openapi.json'
        ]
        
        found_apis = []
        
        for api_path in api_paths:
            test_url = urljoin(base_url, api_path)
            
            try:
                response = requests.get(test_url, timeout=3, verify=False, allow_redirects=False)
                
                # Check for API indicators
                if response.status_code in [200, 401, 403]:
                    content_type = response.headers.get('Content-Type', '').lower()
                    
                    # Check if it's likely an API
                    is_api = (
                        'json' in content_type or
                        'xml' in content_type or
                        response.status_code == 401 or  # Auth required
                        'api' in response.text.lower()[:500] or
                        'swagger' in response.text.lower()[:500] or
                        'openapi' in response.text.lower()[:500]
                    )
                    
                    if is_api:
                        self.logger.info(f"[SCANNER] ✓ Found API endpoint: {api_path} [{response.status_code}]")
                        
                        found_apis.append({
                            'path': api_path,
                            'url': test_url,
                            'status': response.status_code,
                            'content_type': content_type
                        })
                        
                        self.results['endpoints'].append({
                            'path': api_path,
                            'url': test_url,
                            'type': 'api',
                            'status': response.status_code
                        })
                        
            except requests.RequestException:
                pass
        
        if found_apis:
            self.logger.info(f"[SCANNER] ✓ Discovered {len(found_apis)} API endpoints")
        else:
            self.logger.info(f"[SCANNER] No API endpoints found")
