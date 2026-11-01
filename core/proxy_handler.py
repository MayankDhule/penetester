"""
Proxy Handler - HTTP/HTTPS Proxy Support
Enables traffic inspection through Burp Suite, OWASP ZAP, etc.
"""
import os
from typing import Dict, Optional
from urllib.parse import urlparse


class ProxyHandler:
    """Handles proxy configuration for HTTP/HTTPS requests"""
    
    def __init__(self, proxy_url: str = None):
        self.proxy_url = proxy_url
        self.proxies = None
        
        if proxy_url:
            self.proxies = self._parse_proxy(proxy_url)
    
    def _parse_proxy(self, proxy_url: str) -> Dict[str, str]:
        """Parse proxy URL and create proxy dict"""
        # Handle common formats:
        # http://127.0.0.1:8080
        # https://127.0.0.1:8080
        # 127.0.0.1:8080 (assume http)
        
        if not proxy_url.startswith('http'):
            proxy_url = f'http://{proxy_url}'
        
        return {
            'http': proxy_url,
            'https': proxy_url,
        }
    
    def get_proxies(self) -> Optional[Dict[str, str]]:
        """Get proxy configuration for requests"""
        return self.proxies
    
    def get_aiohttp_proxy(self) -> Optional[str]:
        """Get proxy URL for aiohttp"""
        if self.proxies:
            return self.proxies.get('http')
        return None
    
    @staticmethod
    def from_env() -> 'ProxyHandler':
        """Create proxy handler from environment variables"""
        # Check standard proxy environment variables
        proxy_url = (
            os.environ.get('HTTPS_PROXY') or
            os.environ.get('HTTP_PROXY') or
            os.environ.get('https_proxy') or
            os.environ.get('http_proxy')
        )
        
        if proxy_url:
            return ProxyHandler(proxy_url)
        
        return ProxyHandler()
    
    @staticmethod
    def burp_suite(port: int = 8080) -> 'ProxyHandler':
        """Create proxy handler for Burp Suite"""
        return ProxyHandler(f'http://127.0.0.1:{port}')
    
    @staticmethod
    def owasp_zap(port: int = 8080) -> 'ProxyHandler':
        """Create proxy handler for OWASP ZAP"""
        return ProxyHandler(f'http://127.0.0.1:{port}')
    
    @staticmethod
    def mitmproxy(port: int = 8080) -> 'ProxyHandler':
        """Create proxy handler for mitmproxy"""
        return ProxyHandler(f'http://127.0.0.1:{port}')
    
    def __repr__(self) -> str:
        if self.proxies:
            return f"ProxyHandler(proxy={self.proxies['http']})"
        return "ProxyHandler(no proxy)"


class ProxyConfig:
    """Global proxy configuration"""
    
    _proxy_handler = None
    
    @classmethod
    def set_proxy(cls, proxy_url: str):
        """Set global proxy"""
        cls._proxy_handler = ProxyHandler(proxy_url)
    
    @classmethod
    def get_proxy(cls) -> Optional[ProxyHandler]:
        """Get global proxy handler"""
        return cls._proxy_handler
    
    @classmethod
    def clear_proxy(cls):
        """Clear global proxy"""
        cls._proxy_handler = None
    
    @classmethod
    def is_proxy_enabled(cls) -> bool:
        """Check if proxy is enabled"""
        return cls._proxy_handler is not None


def apply_proxy_to_requests(session, proxy_handler: ProxyHandler):
    """Apply proxy to requests session"""
    if proxy_handler and proxy_handler.get_proxies():
        session.proxies.update(proxy_handler.get_proxies())
        # Disable SSL verification when using proxy (common for Burp/ZAP)
        session.verify = False


