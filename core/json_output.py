"""
JSON Output Module - Machine-Readable Output
Enables piping Pentestrr output to other tools (jq, grep, etc.)
"""
import json
import sys
from datetime import datetime
from typing import Dict, Any


class JSONOutput:
    """Handles JSON and JSON Lines output for tool chaining"""
    
    @staticmethod
    def print_json(data: Dict[str, Any], pretty: bool = False):
        """Print JSON to stdout"""
        if pretty:
            print(json.dumps(data, indent=2, default=str))
        else:
            print(json.dumps(data, default=str))
        sys.stdout.flush()
    
    @staticmethod
    def print_jsonl(data: Dict[str, Any]):
        """Print JSON Lines (one JSON object per line)"""
        print(json.dumps(data, default=str))
        sys.stdout.flush()
    
    @staticmethod
    def format_scan_result(results: Dict[str, Any]) -> Dict[str, Any]:
        """Format scan results for JSON output"""
        return {
            'timestamp': datetime.now().isoformat(),
            'target': results.get('target'),
            'profile': {
                'target_type': results.get('profile', {}).get('target_type'),
                'cms': results.get('profile', {}).get('cms'),
                'web_server': results.get('profile', {}).get('web_server'),
                'technologies': results.get('profile', {}).get('technologies', []),
                'attack_surface': results.get('profile', {}).get('attack_surface', []),
                'open_ports': results.get('profile', {}).get('open_ports', []),
            },
            'reconnaissance': {
                'ip_addresses': results.get('reconnaissance', {}).get('ip_addresses', []),
                'open_ports': results.get('reconnaissance', {}).get('open_ports', []),
                'dns_records': results.get('reconnaissance', {}).get('dns_records', {}),
                'subdomains': results.get('reconnaissance', {}).get('subdomains', []),
            },
            'scanning': {
                'discovered_urls': results.get('scanning', {}).get('discovered_urls', []),
                'directories': results.get('scanning', {}).get('directories', []),
                'files': results.get('scanning', {}).get('files', []),
                'forms': results.get('scanning', {}).get('forms', []),
                'emails': results.get('scanning', {}).get('emails', []),
            },
            'vulnerabilities': {
                'total': results.get('vulnerabilities', {}).get('total_count', 0),
                'critical': results.get('vulnerabilities', {}).get('critical', 0),
                'high': results.get('vulnerabilities', {}).get('high', 0),
                'medium': results.get('vulnerabilities', {}).get('medium', 0),
                'low': results.get('vulnerabilities', {}).get('low', 0),
                'info': results.get('vulnerabilities', {}).get('info', 0),
                'findings': results.get('vulnerabilities', {}).get('vulnerabilities', []),
            },
            'exploits': {
                'attempted': results.get('exploits', {}).get('exploits_attempted', 0),
                'successful': results.get('exploits', {}).get('exploits_successful', 0),
                'findings': results.get('exploits', {}).get('exploits', []),
            }
        }
    
    @staticmethod
    def format_vulnerability(vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Format single vulnerability for JSON Lines output"""
        return {
            'timestamp': datetime.now().isoformat(),
            'type': 'vulnerability',
            'title': vuln.get('title'),
            'severity': vuln.get('severity'),
            'category': vuln.get('category'),
            'url': vuln.get('url'),
            'description': vuln.get('description'),
            'cvss_score': vuln.get('cvss_score'),
            'cwe': vuln.get('cwe'),
        }
    
    @staticmethod
    def format_exploit(exploit: Dict[str, Any]) -> Dict[str, Any]:
        """Format single exploit for JSON Lines output"""
        return {
            'timestamp': datetime.now().isoformat(),
            'type': 'exploit',
            'exploit_type': exploit.get('type'),
            'severity': exploit.get('severity'),
            'target': exploit.get('target'),
            'method': exploit.get('method'),
            'payload': exploit.get('payload'),
            'impact': exploit.get('impact'),
            'evidence': exploit.get('evidence'),
        }
    
    @staticmethod
    def format_discovery(item_type: str, item: Any, target: str) -> Dict[str, Any]:
        """Format discovery item (URL, directory, file, etc.) for JSON Lines"""
        return {
            'timestamp': datetime.now().isoformat(),
            'type': 'discovery',
            'item_type': item_type,
            'target': target,
            'value': item,
        }
    
    @staticmethod
    def stream_vulnerabilities(vulnerabilities: list, target: str):
        """Stream vulnerabilities as JSON Lines (for real-time output)"""
        for vuln in vulnerabilities:
            vuln_data = JSONOutput.format_vulnerability(vuln)
            vuln_data['target'] = target
            JSONOutput.print_jsonl(vuln_data)
    
    @staticmethod
    def stream_exploits(exploits: list, target: str):
        """Stream exploits as JSON Lines (for real-time output)"""
        for exploit in exploits:
            exploit_data = JSONOutput.format_exploit(exploit)
            exploit_data['target'] = target
            JSONOutput.print_jsonl(exploit_data)


class StreamingJSONReporter:
    """Real-time JSON Lines reporter for live output"""
    
    def __init__(self, target: str):
        self.target = target
        self.start_time = datetime.now()
    
    def report_start(self):
        """Report scan start"""
        JSONOutput.print_jsonl({
            'timestamp': datetime.now().isoformat(),
            'type': 'scan_start',
            'target': self.target,
        })
    
    def report_phase(self, phase: str, status: str = 'started'):
        """Report phase change"""
        JSONOutput.print_jsonl({
            'timestamp': datetime.now().isoformat(),
            'type': 'phase',
            'phase': phase,
            'status': status,
            'target': self.target,
        })
    
    def report_discovery(self, item_type: str, item: Any):
        """Report discovered item"""
        JSONOutput.print_jsonl(
            JSONOutput.format_discovery(item_type, item, self.target)
        )
    
    def report_vulnerability(self, vuln: Dict[str, Any]):
        """Report vulnerability"""
        vuln_data = JSONOutput.format_vulnerability(vuln)
        vuln_data['target'] = self.target
        JSONOutput.print_jsonl(vuln_data)
    
    def report_exploit(self, exploit: Dict[str, Any]):
        """Report exploit"""
        exploit_data = JSONOutput.format_exploit(exploit)
        exploit_data['target'] = self.target
        JSONOutput.print_jsonl(exploit_data)
    
    def report_complete(self, summary: Dict[str, Any]):
        """Report scan completion"""
        JSONOutput.print_jsonl({
            'timestamp': datetime.now().isoformat(),
            'type': 'scan_complete',
            'target': self.target,
            'duration': (datetime.now() - self.start_time).total_seconds(),
            'summary': summary,
        })



