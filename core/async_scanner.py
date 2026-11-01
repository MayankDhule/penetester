"""
Async Scanner Module - Concurrent Scanning
Uses async/await to run requests concurrently for faster enumeration
"""
import asyncio
import aiohttp
import re
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup


class AsyncScanner:
    """High-performance asynchronous web scanner"""
    
    def __init__(self, target: str, logger, profile: Dict = None, strategy: Dict = None, 
                 max_concurrent: int = 50, timeout: int = 10):
        self.target = target if '://' in target else f'http://{target}'
        self.logger = logger
        self.profile = profile or {}
        self.strategy = strategy or {}
        self.max_concurrent = max_concurrent
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        
        # Results storage
        self.discovered_urls = set()
        self.directories = []
        self.files = []
        self.forms = []
        self.emails = set()
        self.comments = []
        
        # Base page learning for SPA detection
        self.base_page_size = 0
        self.base_page_hash = 0
        
        # Semaphore for rate limiting
        self.semaphore = asyncio.Semaphore(max_concurrent)
    
    async def execute(self) -> Dict:
        """Execute async scanning"""
        self.logger.info(f"[ASYNC-SCANNER] 🚀 Starting high-performance scan (max {self.max_concurrent} concurrent)")
        
        # ssl=False bypasses certificate verification, same as requests' verify=False.
        # Required for self-signed certs; without it HTTPS scans silently fail.
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector, timeout=self.timeout) as session:
            # Learn base page first
            await self._learn_base_page(session)
            
            # Run all scanning tasks concurrently
            tasks = [
                self._crawl_site(session),
                self._discover_directories(session),
                self._find_interesting_files(session),
            ]
            
            await asyncio.gather(*tasks, return_exceptions=True)
        
        results = {
            'discovered_urls': list(self.discovered_urls),
            'directories': self.directories,
            'files': self.files,
            'forms': self.forms,
            'emails': list(self.emails),
            'comments': self.comments,
            'total_urls': len(self.discovered_urls),
            'total_directories': len(self.directories),
            'total_files': len(self.files)
        }
        
        self.logger.info(f"[ASYNC-SCANNER] ✅ Scan complete: {len(self.discovered_urls)} URLs, "
                        f"{len(self.directories)} directories, {len(self.files)} files")
        
        return results
    
    async def _learn_base_page(self, session: aiohttp.ClientSession):
        """Learn base page characteristics for SPA detection"""
        try:
            async with session.get(self.target) as response:
                content = await response.read()
                self.base_page_size = len(content)
                self.base_page_hash = hash(content)
                self.logger.debug(f"[ASYNC-SCANNER] Base page: {self.base_page_size} bytes, hash: {self.base_page_hash}")
        except Exception as e:
            self.logger.debug(f"[ASYNC-SCANNER] Failed to learn base page: {e}")
    
    async def _fetch_url(self, session: aiohttp.ClientSession, url: str) -> tuple:
        """Fetch URL with rate limiting"""
        async with self.semaphore:
            try:
                async with session.get(url, allow_redirects=True) as response:
                    content = await response.text()
                    return url, response.status, content, None
            except asyncio.TimeoutError:
                return url, 0, None, "Timeout"
            except Exception as e:
                return url, 0, None, str(e)
    
    async def _crawl_site(self, session: aiohttp.ClientSession, max_depth: int = 2):
        """Crawl website to discover URLs"""
        self.logger.info("[ASYNC-SCANNER] Step 1: Web Crawling")
        
        visited = set()
        to_visit = [(self.target, 0)]
        
        while to_visit:
            current_url, depth = to_visit.pop(0)
            
            if current_url in visited or depth > max_depth:
                continue
            
            visited.add(current_url)
            
            try:
                async with session.get(current_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        self.discovered_urls.add(current_url)
                        
                        # Parse HTML
                        soup = BeautifulSoup(content, 'html.parser')
                        
                        # Extract links
                        for link in soup.find_all('a', href=True):
                            href = link['href']
                            full_url = urljoin(current_url, href)
                            
                            # Only follow same-domain links
                            if urlparse(full_url).netloc == urlparse(self.target).netloc:
                                if full_url not in visited and depth < max_depth:
                                    to_visit.append((full_url, depth + 1))
                        
                        # Extract forms
                        for form in soup.find_all('form'):
                            self.forms.append({
                                'action': form.get('action', ''),
                                'method': form.get('method', 'get').upper(),
                                'url': current_url
                            })
                        
                        # Extract emails
                        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content)
                        self.emails.update(emails)
                        
                        # Extract comments
                        comments = re.findall(r'<!--(.*?)-->', content, re.DOTALL)
                        self.comments.extend([c.strip() for c in comments if c.strip()])
            
            except Exception as e:
                self.logger.debug(f"[ASYNC-SCANNER] Crawl error for {current_url}: {e}")
        
        self.logger.info(f"[ASYNC-SCANNER] ✓ Crawled {len(visited)} pages, found {len(self.discovered_urls)} URLs")
    
    async def _discover_directories(self, session: aiohttp.ClientSession):
        """Discover directories using concurrent requests"""
        self.logger.info("[ASYNC-SCANNER] Step 2: Directory Discovery")
        
        # Common directories to check
        common_dirs = [
            'admin', 'api', 'backup', 'config', 'dashboard', 'dev', 'docs',
            'images', 'js', 'css', 'uploads', 'files', 'assets', 'static',
            'test', 'tmp', 'temp', 'old', 'new', 'v1', 'v2', 'beta',
            'staging', 'prod', 'login', 'logout', 'register', 'user', 'users'
        ]
        
        # Create tasks for all directories
        tasks = []
        for directory in common_dirs:
            url = urljoin(self.target, f'/{directory}/')
            tasks.append(self._check_directory(session, url, directory))
        
        # Execute all tasks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for result in results:
            if isinstance(result, dict) and result.get('found'):
                self.directories.append(result)
        
        self.logger.info(f"[ASYNC-SCANNER] ✓ Found {len(self.directories)} directories")
    
    async def _check_directory(self, session: aiohttp.ClientSession, url: str, directory: str) -> Dict:
        """Check if directory exists"""
        async with self.semaphore:
            try:
                async with session.get(url) as response:
                    # Check if it's a real directory (not SPA redirect)
                    content = await response.read()
                    content_size = len(content)
                    content_hash = hash(content)
                    
                    # If size/hash matches base page, it's likely SPA redirect
                    if abs(content_size - self.base_page_size) < 100 and content_hash == self.base_page_hash:
                        return {'found': False}
                    
                    if response.status in [200, 301, 302, 403]:
                        self.logger.info(f"[ASYNC-SCANNER] ✓ Found: /{directory}/ [{response.status}]")
                        return {
                            'found': True,
                            'directory': directory,
                            'url': url,
                            'status': response.status
                        }
            except Exception as e:
                self.logger.debug(f"[ASYNC-SCANNER] Directory check failed for /{directory}/: {e}")
        
        return {'found': False}
    
    async def _find_interesting_files(self, session: aiohttp.ClientSession):
        """Find interesting files using concurrent requests"""
        self.logger.info("[ASYNC-SCANNER] Step 3: Interesting Files Discovery")
        
        # Common interesting files
        interesting_files = [
            'robots.txt', 'sitemap.xml', '.git/config', '.env', 'config.php',
            'wp-config.php', 'web.config', '.htaccess', 'package.json',
            'composer.json', 'README.md', 'CHANGELOG.md', 'backup.sql',
            'database.sql', 'dump.sql', '.DS_Store', 'phpinfo.php'
        ]
        
        # Create tasks for all files
        tasks = []
        for filename in interesting_files:
            url = urljoin(self.target, f'/{filename}')
            tasks.append(self._check_file(session, url, filename))
        
        # Execute all tasks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for result in results:
            if isinstance(result, dict) and result.get('found'):
                self.files.append(result)
        
        self.logger.info(f"[ASYNC-SCANNER] ✓ Found {len(self.files)} interesting files")
    
    async def _check_file(self, session: aiohttp.ClientSession, url: str, filename: str) -> Dict:
        """Check if file exists"""
        async with self.semaphore:
            try:
                async with session.get(url) as response:
                    if response.status == 200:
                        content = await response.read()
                        content_size = len(content)
                        content_hash = hash(content)
                        
                        # Verify it's a real file (not SPA redirect)
                        if abs(content_size - self.base_page_size) < 100 and content_hash == self.base_page_hash:
                            return {'found': False}
                        
                        # Additional verification for specific files
                        if filename == 'robots.txt':
                            text = content.decode('utf-8', errors='ignore')
                            if 'User-agent' not in text and 'Disallow' not in text:
                                return {'found': False}
                        
                        self.logger.info(f"[ASYNC-SCANNER] ✓ Found: {filename} [{response.status}]")
                        return {
                            'found': True,
                            'filename': filename,
                            'url': url,
                            'status': response.status,
                            'size': content_size
                        }
            except Exception as e:
                self.logger.debug(f"[ASYNC-SCANNER] File check failed for {filename}: {e}")
        
        return {'found': False}


class AsyncSubdomainScanner:
    """High-performance asynchronous subdomain scanner"""
    
    def __init__(self, domain: str, logger, max_concurrent: int = 100):
        self.domain = domain
        self.logger = logger
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.found_subdomains = []
    
    async def scan(self, wordlist: List[str] = None) -> List[str]:
        """Scan for subdomains concurrently"""
        if not wordlist:
            # Default common subdomains
            wordlist = [
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
                'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mx', 'email', 'api',
                'dev', 'staging', 'test', 'admin', 'blog', 'shop', 'store', 'portal'
            ]
        
        self.logger.info(f"[ASYNC-SUBDOMAIN] 🚀 Scanning {len(wordlist)} subdomains (max {self.max_concurrent} concurrent)")
        
        # Create tasks for all subdomains
        tasks = [self._check_subdomain(subdomain) for subdomain in wordlist]
        
        # Execute all tasks concurrently
        await asyncio.gather(*tasks, return_exceptions=True)
        
        self.logger.info(f"[ASYNC-SUBDOMAIN] ✅ Found {len(self.found_subdomains)} subdomains")
        
        return self.found_subdomains
    
    async def _check_subdomain(self, subdomain: str):
        """Check if subdomain exists"""
        async with self.semaphore:
            full_domain = f"{subdomain}.{self.domain}"
            try:
                # Use aiodns for async DNS resolution
                import aiodns
                resolver = aiodns.DNSResolver()
                result = await resolver.query(full_domain, 'A')
                
                if result:
                    ip = result[0].host
                    self.found_subdomains.append({
                        'subdomain': full_domain,
                        'ip': ip
                    })
                    self.logger.info(f"[ASYNC-SUBDOMAIN] ✓ Found: {full_domain} → {ip}")
            
            except aiodns.error.DNSError:
                pass  # Subdomain doesn't exist
            except Exception as e:
                self.logger.debug(f"[ASYNC-SUBDOMAIN] Error checking {full_domain}: {e}")
