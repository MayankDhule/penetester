"""
Wordlist Manager - External Wordlist Support
Allows users to provide custom wordlists for directory/subdomain scanning
"""
import os
from typing import List


class WordlistManager:
    """Manages wordlists for scanning"""
    
    # Default built-in wordlists (small, for quick scans)
    DEFAULT_DIRECTORIES = [
        'admin', 'api', 'backup', 'config', 'dashboard', 'dev', 'docs',
        'images', 'js', 'css', 'uploads', 'files', 'assets', 'static',
        'test', 'tmp', 'temp', 'old', 'new', 'v1', 'v2', 'beta',
        'staging', 'prod', 'login', 'logout', 'register', 'user', 'users',
        'app', 'application', 'auth', 'authentication', 'authorization',
        'cache', 'cdn', 'content', 'data', 'database', 'db', 'download',
        'downloads', 'error', 'errors', 'export', 'feed', 'feeds', 'file',
        'forum', 'forums', 'help', 'home', 'img', 'include', 'includes',
        'index', 'info', 'install', 'installation', 'lib', 'library',
        'libs', 'log', 'logs', 'mail', 'media', 'member', 'members',
        'mobile', 'news', 'old', 'page', 'pages', 'panel', 'password',
        'php', 'private', 'public', 'root', 'rss', 'script', 'scripts',
        'search', 'secure', 'security', 'server', 'service', 'services',
        'setup', 'site', 'sites', 'sql', 'src', 'storage', 'style',
        'styles', 'support', 'system', 'template', 'templates', 'theme',
        'themes', 'tools', 'upload', 'vendor', 'web', 'webmail', 'wp',
        'wp-admin', 'wp-content', 'wp-includes', 'www', 'xml'
    ]
    
    DEFAULT_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1',
        'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig',
        'mx', 'email', 'api', 'dev', 'staging', 'test', 'admin', 'blog',
        'shop', 'store', 'portal', 'app', 'mobile', 'secure', 'vpn',
        'remote', 'cloud', 'backup', 'git', 'svn', 'jenkins', 'ci', 'cd',
        'beta', 'alpha', 'demo', 'sandbox', 'lab', 'labs', 'internal',
        'intranet', 'extranet', 'partner', 'partners', 'client', 'clients',
        'customer', 'customers', 'support', 'help', 'docs', 'documentation',
        'wiki', 'forum', 'forums', 'community', 'status', 'monitor',
        'monitoring', 'metrics', 'analytics', 'stats', 'dashboard'
    ]
    
    DEFAULT_FILES = [
        'robots.txt', 'sitemap.xml', '.git/config', '.env', 'config.php',
        'wp-config.php', 'web.config', '.htaccess', 'package.json',
        'composer.json', 'README.md', 'CHANGELOG.md', 'backup.sql',
        'database.sql', 'dump.sql', '.DS_Store', 'phpinfo.php',
        'info.php', 'test.php', 'admin.php', 'login.php', 'config.json',
        'settings.json', 'app.json', '.env.local', '.env.production',
        '.env.development', 'docker-compose.yml', 'Dockerfile', 'Makefile',
        '.gitignore', '.dockerignore', 'yarn.lock', 'package-lock.json',
        'Gemfile', 'Gemfile.lock', 'requirements.txt', 'setup.py',
        'pom.xml', 'build.gradle', 'build.xml', 'webpack.config.js',
        'tsconfig.json', 'babel.config.js', '.babelrc', '.eslintrc',
        'nginx.conf', 'apache.conf', 'httpd.conf', '.htpasswd'
    ]
    
    @staticmethod
    def load_wordlist(filepath: str) -> List[str]:
        """Load wordlist from file"""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Wordlist not found: {filepath}")
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            # Read lines, strip whitespace, remove empty lines and comments
            words = [
                line.strip() 
                for line in f 
                if line.strip() and not line.strip().startswith('#')
            ]
        
        return words
    
    @staticmethod
    def get_directories(custom_wordlist: str = None) -> List[str]:
        """Get directory wordlist (custom or default)"""
        if custom_wordlist:
            return WordlistManager.load_wordlist(custom_wordlist)
        return WordlistManager.DEFAULT_DIRECTORIES
    
    @staticmethod
    def get_subdomains(custom_wordlist: str = None) -> List[str]:
        """Get subdomain wordlist (custom or default)"""
        if custom_wordlist:
            return WordlistManager.load_wordlist(custom_wordlist)
        return WordlistManager.DEFAULT_SUBDOMAINS
    
    @staticmethod
    def get_files(custom_wordlist: str = None) -> List[str]:
        """Get files wordlist (custom or default)"""
        if custom_wordlist:
            return WordlistManager.load_wordlist(custom_wordlist)
        return WordlistManager.DEFAULT_FILES
    
    @staticmethod
    def merge_wordlists(*wordlists: List[str]) -> List[str]:
        """Merge multiple wordlists and remove duplicates"""
        merged = set()
        for wordlist in wordlists:
            merged.update(wordlist)
        return sorted(list(merged))
    
    @staticmethod
    def filter_by_extension(wordlist: List[str], extensions: List[str]) -> List[str]:
        """Filter wordlist by file extensions"""
        return [
            word for word in wordlist 
            if any(word.endswith(ext) for ext in extensions)
        ]
    
    @staticmethod
    def filter_by_pattern(wordlist: List[str], pattern: str) -> List[str]:
        """Filter wordlist by regex pattern"""
        import re
        regex = re.compile(pattern)
        return [word for word in wordlist if regex.search(word)]



