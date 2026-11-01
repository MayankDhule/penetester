"""
Async Reconnaissance Module - High-Performance Concurrent Recon
Replaces synchronous port scanning and DNS queries with async operations
"""
import asyncio
import socket
from typing import Dict, List
import aiodns


class AsyncRecon:
    """High-performance asynchronous reconnaissance"""
    
    def __init__(self, target: str, logger, profile: Dict = None, max_concurrent: int = 100):
        self.target = target
        self.logger = logger
        self.profile = profile or {}
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        
        # Results
        self.ip_addresses = []
        self.open_ports = []
        self.dns_records = {}
        self.subdomains = []
    
    async def execute(self) -> Dict:
        """Execute async reconnaissance"""
        self.logger.info(f"[ASYNC-RECON] 🚀 Starting high-performance reconnaissance")
        
        # Run all recon tasks concurrently
        tasks = [
            self._resolve_dns(),
            self._scan_ports(),
            self._enumerate_dns_records(),
        ]
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        results = {
            'ip_addresses': self.ip_addresses,
            'open_ports': self.open_ports,
            'dns_records': self.dns_records,
            'subdomains': self.subdomains,
            'whois_info': {}  # Placeholder for WHOIS (still sync)
        }
        
        self.logger.info(f"[ASYNC-RECON] ✅ Recon complete: {len(self.ip_addresses)} IPs, "
                        f"{len(self.open_ports)} open ports")
        
        return results
    
    async def _resolve_dns(self):
        """Resolve target to IP addresses"""
        self.logger.info("[ASYNC-RECON] Step 1: DNS Resolution")
        
        try:
            # Extract hostname
            target_host = self.target.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
            
            # Async DNS resolution
            resolver = aiodns.DNSResolver()
            
            try:
                # Try A records
                result = await resolver.query(target_host, 'A')
                for record in result:
                    self.ip_addresses.append(record.host)
                    self.logger.info(f"[ASYNC-RECON] ✓ Resolved: {target_host} → {record.host}")
            except aiodns.error.DNSError:
                pass
            
            try:
                # Try AAAA records (IPv6)
                result = await resolver.query(target_host, 'AAAA')
                for record in result:
                    self.ip_addresses.append(record.host)
                    self.logger.info(f"[ASYNC-RECON] ✓ Resolved (IPv6): {target_host} → {record.host}")
            except aiodns.error.DNSError:
                pass
        
        except Exception as e:
            self.logger.debug(f"[ASYNC-RECON] DNS resolution failed: {e}")
    
    async def _scan_ports(self):
        """Scan common ports concurrently"""
        self.logger.info("[ASYNC-RECON] Step 2: Port Scanning")
        
        if not self.ip_addresses:
            self.logger.debug("[ASYNC-RECON] No IP addresses to scan")
            return
        
        target_ip = self.ip_addresses[0]
        
        # Common ports to scan
        common_ports = [
            21,    # FTP
            22,    # SSH
            23,    # Telnet
            25,    # SMTP
            53,    # DNS
            80,    # HTTP
            110,   # POP3
            143,   # IMAP
            443,   # HTTPS
            445,   # SMB
            3306,  # MySQL
            3389,  # RDP
            5432,  # PostgreSQL
            5900,  # VNC
            6379,  # Redis
            8080,  # HTTP Alt
            8443,  # HTTPS Alt
            27017, # MongoDB
        ]
        
        # Create tasks for all ports
        tasks = [self._check_port(target_ip, port) for port in common_ports]
        
        # Execute all tasks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect open ports
        self.open_ports = [port for port in results if port is not None]
        
        self.logger.info(f"[ASYNC-RECON] ✓ Found {len(self.open_ports)} open ports")
    
    async def _check_port(self, ip: str, port: int) -> int:
        """Check if port is open"""
        async with self.semaphore:
            try:
                # Create connection with timeout
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=2.0)
                
                writer.close()
                await writer.wait_closed()
                
                self.logger.info(f"[ASYNC-RECON] ✓ Port {port} open")
                return port
            
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
            except Exception as e:
                self.logger.debug(f"[ASYNC-RECON] Port {port} check failed: {e}")
                return None
    
    async def _enumerate_dns_records(self):
        """Enumerate DNS records"""
        self.logger.info("[ASYNC-RECON] Step 3: DNS Record Enumeration")
        
        try:
            target_host = self.target.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
            resolver = aiodns.DNSResolver()
            
            # Record types to query
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
            
            # Create tasks for all record types
            tasks = []
            for record_type in record_types:
                tasks.append(self._query_dns_record(resolver, target_host, record_type))
            
            # Execute all tasks concurrently
            await asyncio.gather(*tasks, return_exceptions=True)
            
            self.logger.info(f"[ASYNC-RECON] ✓ Enumerated {len(self.dns_records)} DNS record types")
        
        except Exception as e:
            self.logger.debug(f"[ASYNC-RECON] DNS enumeration failed: {e}")
    
    async def _query_dns_record(self, resolver, hostname: str, record_type: str):
        """Query specific DNS record type"""
        try:
            result = await resolver.query(hostname, record_type)
            
            records = []
            for record in result:
                if record_type == 'A' or record_type == 'AAAA':
                    records.append(record.host)
                elif record_type == 'MX':
                    records.append(f"{record.host} (priority: {record.priority})")
                elif record_type == 'NS':
                    records.append(record.host)
                elif record_type == 'TXT':
                    records.append(record.text)
                elif record_type == 'SOA':
                    records.append(f"{record.nsname} (serial: {record.serial})")
                elif record_type == 'CNAME':
                    records.append(record.cname)
            
            if records:
                self.dns_records[record_type] = records
                self.logger.info(f"[ASYNC-RECON] ✓ {record_type} records: {len(records)}")
        
        except aiodns.error.DNSError:
            pass  # Record type not found
        except Exception as e:
            self.logger.debug(f"[ASYNC-RECON] {record_type} query failed: {e}")


class AsyncPortScanner:
    """Standalone async port scanner"""
    
    def __init__(self, target: str, logger, max_concurrent: int = 100):
        self.target = target
        self.logger = logger
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
    
    async def scan_range(self, start_port: int = 1, end_port: int = 1024) -> List[int]:
        """Scan port range concurrently"""
        self.logger.info(f"[ASYNC-PORT] 🚀 Scanning ports {start_port}-{end_port} (max {self.max_concurrent} concurrent)")
        
        # Create tasks for all ports
        tasks = [self._check_port(port) for port in range(start_port, end_port + 1)]
        
        # Execute all tasks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect open ports
        open_ports = [port for port in results if port is not None]
        
        self.logger.info(f"[ASYNC-PORT] ✅ Found {len(open_ports)} open ports")
        
        return open_ports
    
    async def _check_port(self, port: int) -> int:
        """Check if port is open"""
        async with self.semaphore:
            try:
                conn = asyncio.open_connection(self.target, port)
                reader, writer = await asyncio.wait_for(conn, timeout=1.0)
                
                writer.close()
                await writer.wait_closed()
                
                return port
            
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
            except Exception:
                return None
