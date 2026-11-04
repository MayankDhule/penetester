"""
Phase 2: Scanning & Enumeration Module
Web crawling, directory discovery, and service enumeration
"""
import requests
import urllib3
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
        
        # For detecting false positives (SPA redirects)
        self.base_page_hash = None
        self.base_page_size = None
        
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
            # Learn base page characteristics first (for SPA detection)
            self._learn_base_page(base_url)
            
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
    
    def _learn_base_page(self, base_url: str):
        """Learn the base page characteristics to detect SPA redirects"""
        try:
            response = requests.get(base_url, timeout=10, verify=False)
            self.base_page_size = len(response.content)
            self.base_page_hash = hash(response.content)
            self.logger.debug(f"[SCANNER] Base page: {self.base_page_size} bytes, hash: {self.base_page_hash}")
        except (requests.exceptions.RequestException, AttributeError) as e:
            self.logger.debug(f"[SCANNER] Failed to learn base page: {e}")
    
    def _is_real_file(self, response, expected_type: str = None) -> bool:
        """
        Detect if response is a real file or SPA redirect
        Returns True if it's a real file, False if it's a false positive
        """
        # Check if response is empty
        if len(response.content) == 0:
            return False
        
        # Check if it's the same as base page (SPA redirect)
        if self.base_page_hash and hash(response.content) == self.base_page_hash:
            return False
        
        # Check if size matches base page (likely SPA redirect)
        if self.base_page_size and len(response.content) == self.base_page_size:
            return False
        
        # Check if response is HTML when we expect a specific file type
        content_type = response.headers.get('Content-Type', '').lower()
        is_html = 'text/html' in content_type or response.content.startswith(b'<!DOCTYPE') or response.content.startswith(b'<html')
        
        # If we're looking for specific file types and got HTML, it's likely a false positive
        if expected_type:
            if expected_type in ['backup', 'config', 'vcs']:
                if is_html:
                    return False
        
        # Check for common SPA indicators in content
        if is_html:
            content_str = response.content.decode('utf-8', errors='ignore').lower()
            spa_indicators = [
                'id="root"',
                'id="app"',
                'react',
                'vue',
                'angular',
                'single page application',
                'spa'
            ]
            if any(indicator in content_str for indicator in spa_indicators):
                return False
        
        return True
    
    def _probe(self, urls, method: str = 'get', timeout: int = 5,
               allow_redirects: bool = False, max_workers: int = 12) -> Dict:
        """Fetch many URLs concurrently; return {url: Response or None}.

        Enumeration steps (directories, files, backups, VCS, API paths) are
        independent probes, so running them in parallel turns the sum of all
        per-request timeouts into roughly a single timeout.
        """
        results: Dict[str, object] = {}
        if not urls:
            return results

        def fetch(u):
            try:
                fn = requests.head if method == 'head' else requests.get
                return u, fn(u, timeout=timeout, verify=False, allow_redirects=allow_redirects)
            except requests.RequestException:
                return u, None

        with ThreadPoolExecutor(max_workers=min(max_workers, len(urls))) as pool:
            for u, r in pool.map(fetch, urls):
                results[u] = r
        return results

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
        dir_urls = {d: urljoin(base_url, f"/{d}/") for d in common_dirs[:10]}
        responses = self._probe(list(dir_urls.values()), method='head')

        for directory, url in dir_urls.items():
            response = responses.get(url)
            if response is not None and response.status_code in [200, 301, 302, 403]:
                self.results['directories'].append(url)
                found_count += 1
                self.logger.info(f"[SCANNER] ✓ Found: /{directory}/ [{response.status_code}]")
        
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
        file_urls = {f: urljoin(base_url, f"/{f}") for f in interesting_files}
        responses = self._probe(list(file_urls.values()), method='get', allow_redirects=True)

        for filename, url in file_urls.items():
            response = responses.get(url)
            if response is None or response.status_code != 200:
                continue
            try:
                # Verify it's a real file, not SPA redirect
                if self._is_real_file(response, expected_type='config'):
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
            except ValueError as e:
                self.logger.debug(f"[SCANNER] Robots.txt parsing failed: {e}")
        
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
        combo_urls = {}
        for filename in common_files[:5]:  # Limit for speed
            for ext in backup_patterns[:6]:
                name = f"{filename}{ext}"
                combo_urls[name] = urljoin(base_url, f"/{name}")

        responses = self._probe(list(combo_urls.values()), method='get', timeout=3)
        for name, test_url in combo_urls.items():
            response = responses.get(test_url)
            if response is not None and response.status_code == 200 \
                    and self._is_real_file(response, expected_type='backup'):
                self.logger.info(f"[SCANNER] ⚠️  Found backup file: {name}")
                found_backups.append({
                    'filename': name,
                    'url': test_url,
                    'size': len(response.content)
                })
                self.results['files'].append({
                    'filename': name,
                    'url': test_url,
                    'size': len(response.content),
                    'type': 'backup'
                })
        
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
        vcs_urls = {p: urljoin(base_url, f"/{p}") for p in vcs_paths}
        responses = self._probe(list(vcs_urls.values()), method='get', timeout=3)

        for vcs_path, test_url in vcs_urls.items():
            response = responses.get(test_url)
            if response is not None and response.status_code == 200 and len(response.content) > 0 \
                    and self._is_real_file(response, expected_type='vcs'):
                vcs_type = vcs_path.split('/')[0]
                self.logger.info(f"[SCANNER] ⚠️  CRITICAL: {vcs_type} repository exposed!")
                found_vcs.append({
                    'type': vcs_type,
                    'url': test_url,
                    'severity': 'CRITICAL'
                })
                self.results['files'].append({
                    'filename': vcs_path,
                    'url': test_url,
                    'size': len(response.content),
                    'type': 'vcs_exposure'
                })
        
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
        api_urls = {p: urljoin(base_url, p) for p in api_paths}
        responses = self._probe(list(api_urls.values()), method='get', timeout=3)

        for api_path, test_url in api_urls.items():
            response = responses.get(test_url)
            if response is None:
                continue
            try:
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
