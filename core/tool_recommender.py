"""
Tool Recommendation System
Suggests specialized tools for further testing based on detected vulnerabilities
"""
from typing import Dict, List


class ToolRecommender:
    """Recommends specialized pentesting tools based on vulnerability findings"""
    
    def __init__(self):
        self.tool_database = self._build_tool_database()
    
    def _build_tool_database(self) -> Dict:
        """Build comprehensive tool recommendation database"""
        return {
            # SQL Injection
            'sql_injection': {
                'category': 'SQL Injection',
                'tools': [
                    {
                        'name': 'SQLMap',
                        'type': 'Automated',
                        'description': 'Most popular automated SQL injection tool',
                        'command': 'sqlmap -u "URL" --batch --risk=3 --level=5',
                        'platform': 'Python',
                        'priority': 'HIGH'
                    },
                    {
                        'name': 'jSQL Injection',
                        'type': 'GUI',
                        'description': 'Java-based SQL injection tool with GUI',
                        'command': 'java -jar jsql-injection.jar',
                        'platform': 'Java',
                        'priority': 'MEDIUM'
                    },
                    {
                        'name': 'NoSQLMap',
                        'type': 'Automated',
                        'description': 'NoSQL injection tool (MongoDB, CouchDB)',
                        'command': 'python nosqlmap.py -u "URL"',
                        'platform': 'Python',
                        'priority': 'MEDIUM'
                    }
                ]
            },
            
            # XSS
            'xss': {
                'category': 'Cross-Site Scripting (XSS)',
                'tools': [
                    {
                        'name': 'XSStrike',
                        'type': 'Automated',
                        'description': 'Advanced XSS detection suite with DOM analysis',
                        'command': 'python xsstrike.py -u "URL"',
                        'platform': 'Python',
                        'priority': 'HIGH'
                    },
                    {
                        'name': 'Dalfox',
                        'type': 'Automated',
                        'description': 'Fast XSS scanner with powerful analysis',
                        'command': 'dalfox url "URL"',
                        'platform': 'Go',
                        'priority': 'HIGH'
                    },
                    {
                        'name': 'XSS Hunter',
                        'type': 'Service',
                        'description': 'Blind XSS detection platform',
                        'command': 'Visit: https://xsshunter.com',
                        'platform': 'SaaS',
                        'priority': 'MEDIUM'
                    },
                    {
                        'name': 'BeEF',
                        'type': 'Framework',
                        'description': 'Browser Exploitation Framework',
                        'command': 'beef-xss',
                        'platform': 'Ruby',
                        'priority': 'HIGH'
                    }
                ]
            },
            
            # Clickjacking
            'clickjacking': {
                'category': 'Clickjacking',
                'tools': [
                    {
                        'name': 'Burp Suite',
                        'type': 'Manual',
                        'description': 'Test iframe embedding manually',
                        'command': 'Use Burp Repeater to test X-Frame-Options',
                        'platform': 'Java',
                        'priority': 'HIGH'
                    },
                    {
                        'name': 'ClickjackPoc',
                        'type': 'Generator',
                        'description': 'Generate clickjacking PoC HTML',
                        'command': 'Visit: https://clickjackpoc.com',
                        'platform': 'Web',
                        'priority': 'MEDIUM'
                    }
                ]
            },
            
            # CORS
            'cors': {
                'category': 'CORS Misconfiguration',
                'tools': [
                    {
                        'name': 'CORScanner',
                        'type': 'Automated',
                        'description': 'CORS misconfiguration scanner',
                        'command': 'python cors_scan.py -u "URL"',
                        'platform': 'Python',
                        'priority': 'HIGH'
                    },
                    {
                        'name': 'CORStest',
                        'type': 'Automated',
                        'description': 'CORS vulnerability scanner',
                        'command': 'corstest "URL"',
                        'platform': 'Python',
                        'priority': 'MEDIUM'
                    }
                ]
            },
            
            # SSL/TLS
            'ssl_tls': {
                'category': 'SSL/TLS Vulnerabilities',
                'tools': [
                    {
                        'name': 'testssl.sh',
                        'type': 'Automated',
                        'description': 'Comprehensive SSL/TLS testing tool',
                        'command': 'testssl.sh "URL"',
                        'platform': 'Bash',
                        'priority': 'HIGH'
                    },
                    {
                        'name': 'SSLyze',
                        'type': 'Automated',
                        'description': 'Fast SSL/TLS scanner',
                        'command': 'sslyze --regular "DOMAIN"',
                        'platform': 'Python',
                        'priority': 'HIGH'
                    },
                    {
                        'name': 'SSL Labs',
                        'type': 'Online',
                        'description': 'Comprehensive online SSL testing',
                        'command': 'Visit: https://www.ssllabs.com/ssltest/',
                        'platform': 'Web',
                        'priority': 'MEDIUM'
                    }
                ]
            },
            
            # Security Headers
            'security_headers': {
                'category': 'Security Headers',
                'tools': [
                    {
                        'name': 'SecurityHeaders.com',
                        'type': 'Online',
                        'description': 'Online security header checker',
                        'command': 'Visit: https://securityheaders.com',
                        'platform': 'Web',
                        'priority': 'HIGH'
                    },
                    {
                        'name': 'Mozilla Observatory',
                        'type': 'Online',
                        'description': 'Security analysis tool',
                        'command': 'Visit: https://observatory.mozilla.org',
                        'platform': 'Web',
                        'priority': 'MEDIUM'
                    }
                ]
            },
            
            # Authentication
            'authentication': {
                'category': 'Authentication & Authorization',
                'tools': [
                    {
                        'name': 'Hydra',
                        'type': 'Brute Force',
                        'description': 'Fast network logon cracker',
                        'command': 'hydra -L users.txt -P pass.txt "URL" http-post-form',
                        'platform': 'C',
                        'priority': 'HIGH'
                    },
                    {
                        'name': 'Burp Intruder',
                        'type': 'Manual',
                        'description': 'Custom authentication attacks',
                        'command': 'Use Burp Suite Intruder',
                        'platform': 'Java',
                        'priority': 'HIGH'
                    },
                    {
                        'name': 'jwt_tool',
                        'type': 'JWT Testing',
                        'description': 'JWT manipulation and testing',
                        'command': 'python jwt_tool.py "TOKEN"',
                        'platform': 'Python',
                        'priority': 'MEDIUM'
                    }
                ]
            },
            
            # API Security
            'api_security': {
                'category': 'API Security',
                'tools': [
                    {
                        'name': 'Postman',
                        'type': 'Manual',
                        'description': 'API testing platform',
                        'command': 'Use Postman GUI',
                        'platform': 'Electron',
                        'priority': 'HIGH'
                    },
                    {
                        'name': 'Arjun',
                        'type': 'Discovery',
                        'description': 'HTTP parameter discovery',
                        'command': 'arjun -u "URL"',
                        'platform': 'Python',
                        'priority': 'MEDIUM'
                    },
                    {
                        'name': 'Kiterunner',
                        'type': 'Discovery',
                        'description': 'API endpoint discovery',
                        'command': 'kr scan "URL" -w routes.txt',
                        'platform': 'Go',
                        'priority': 'HIGH'
                    },
                    {
                        'name': 'GraphQLmap',
                        'type': 'GraphQL',
                        'description': 'GraphQL security testing',
                        'command': 'python graphqlmap.py -u "URL/graphql"',
                        'platform': 'Python',
                        'priority': 'MEDIUM'
                    }
                ]
            },
            
            # Directory Traversal
            'directory_traversal': {
                'category': 'Directory Traversal',
                'tools': [
                    {
                        'name': 'DotDotPwn',
                        'type': 'Fuzzer',
                        'description': 'Directory traversal fuzzer',
                        'command': 'dotdotpwn.pl -m http -h "HOST"',
                        'platform': 'Perl',
                        'priority': 'HIGH'
                    },
                    {
                        'name': 'Wfuzz',
                        'type': 'Fuzzer',
                        'description': 'Web application fuzzer',
                        'command': 'wfuzz -w traversal.txt "URL/FUZZ"',
                        'platform': 'Python',
                        'priority': 'MEDIUM'
                    }
                ]
            },
            
            # Command Injection
            'command_injection': {
                'category': 'Command Injection',
                'tools': [
                    {
                        'name': 'Commix',
                        'type': 'Automated',
                        'description': 'Automated command injection tool',
                        'command': 'python commix.py --url="URL"',
                        'platform': 'Python',
                        'priority': 'HIGH'
                    }
                ]
            },
            
            # File Upload
            'file_upload': {
                'category': 'File Upload Vulnerabilities',
                'tools': [
                    {
                        'name': 'Fuxploider',
                        'type': 'Scanner',
                        'description': 'File upload vulnerability scanner',
                        'command': 'python fuxploider.py --url "URL"',
                        'platform': 'Python',
                        'priority': 'HIGH'
                    },
                    {
                        'name': 'Upload Scanner',
                        'type': 'Burp Extension',
                        'description': 'Burp extension for upload testing',
                        'command': 'Install via Burp BApp Store',
                        'platform': 'Java',
                        'priority': 'MEDIUM'
                    }
                ]
            },
            
            # SSRF
            'ssrf': {
                'category': 'Server-Side Request Forgery',
                'tools': [
                    {
                        'name': 'SSRFmap',
                        'type': 'Automated',
                        'description': 'Automatic SSRF detection and exploitation',
                        'command': 'python ssrfmap.py -r request.txt',
                        'platform': 'Python',
                        'priority': 'HIGH'
                    },
                    {
                        'name': 'Gopherus',
                        'type': 'Payload Generator',
                        'description': 'Generate SSRF payloads',
                        'command': 'python gopherus.py --exploit mysql',
                        'platform': 'Python',
                        'priority': 'MEDIUM'
                    },
                    {
                        'name': 'Burp Collaborator',
                        'type': 'OOB Service',
                        'description': 'Out-of-band SSRF detection',
                        'command': 'Use Burp Collaborator client',
                        'platform': 'Java',
                        'priority': 'HIGH'
                    }
                ]
            },
            
            # Information Disclosure
            'information_disclosure': {
                'category': 'Information Disclosure',
                'tools': [
                    {
                        'name': 'GitLeaks',
                        'type': 'Secret Scanner',
                        'description': 'Find secrets in git repositories',
                        'command': 'gitleaks detect --source . -v',
                        'platform': 'Go',
                        'priority': 'HIGH'
                    },
                    {
                        'name': 'TruffleHog',
                        'type': 'Secret Scanner',
                        'description': 'Search for secrets in git history',
                        'command': 'trufflehog git "REPO_URL"',
                        'platform': 'Python',
                        'priority': 'HIGH'
                    },
                    {
                        'name': 'SecretFinder',
                        'type': 'JS Scanner',
                        'description': 'Discover secrets in JavaScript',
                        'command': 'python SecretFinder.py -i "URL"',
                        'platform': 'Python',
                        'priority': 'MEDIUM'
                    },
                    {
                        'name': 'LinkFinder',
                        'type': 'Endpoint Discovery',
                        'description': 'Discover endpoints in JavaScript',
                        'command': 'python linkfinder.py -i "URL" -o results.html',
                        'platform': 'Python',
                        'priority': 'MEDIUM'
                    }
                ]
            },
            
            # General Web Scanning
            'web_scanning': {
                'category': 'Web Application Scanning',
                'tools': [
                    {
                        'name': 'Burp Suite Pro',
                        'type': 'Commercial',
                        'description': 'Industry-standard web scanner',
                        'command': 'Use Burp Scanner',
                        'platform': 'Java',
                        'priority': 'HIGH'
                    },
                    {
                        'name': 'OWASP ZAP',
                        'type': 'Free',
                        'description': 'Open-source web scanner',
                        'command': 'zap.sh -quickurl "URL"',
                        'platform': 'Java',
                        'priority': 'HIGH'
                    },
                    {
                        'name': 'Nikto',
                        'type': 'Scanner',
                        'description': 'Web server vulnerability scanner',
                        'command': 'nikto -h "URL"',
                        'platform': 'Perl',
                        'priority': 'MEDIUM'
                    }
                ]
            },
            
            # Network Scanning
            'network_scanning': {
                'category': 'Network Reconnaissance',
                'tools': [
                    {
                        'name': 'Nmap',
                        'type': 'Port Scanner',
                        'description': 'Network scanner (industry standard)',
                        'command': 'nmap -sV -sC -p- "TARGET"',
                        'platform': 'C',
                        'priority': 'HIGH'
                    },
                    {
                        'name': 'Masscan',
                        'type': 'Fast Scanner',
                        'description': 'Very fast port scanner',
                        'command': 'masscan -p1-65535 "TARGET" --rate=1000',
                        'platform': 'C',
                        'priority': 'MEDIUM'
                    }
                ]
            }
        }
    
    def get_recommendations(self, vulnerability: Dict) -> List[Dict]:
        """Get tool recommendations for a specific vulnerability"""
        category = vulnerability.get('category', '').lower()
        title = vulnerability.get('title', '').lower()
        
        # Map vulnerability to tool category
        tool_category = self._map_vulnerability_to_category(category, title)
        
        if tool_category and tool_category in self.tool_database:
            return self.tool_database[tool_category]['tools']
        
        # Default to general web scanning tools
        return self.tool_database.get('web_scanning', {}).get('tools', [])
    
    def _map_vulnerability_to_category(self, category: str, title: str) -> str:
        """Map vulnerability category/title to tool database key"""
        
        # Direct category mappings
        category_map = {
            'sql injection': 'sql_injection',
            'xss': 'xss',
            'cross-site scripting': 'xss',
            'clickjacking': 'clickjacking',
            'cors': 'cors',
            'ssl/tls': 'ssl_tls',
            'security headers': 'security_headers',
            'authentication': 'authentication',
            'authorization': 'authentication',
            'api security': 'api_security',
            'directory traversal': 'directory_traversal',
            'path traversal': 'directory_traversal',
            'command injection': 'command_injection',
            'file upload': 'file_upload',
            'ssrf': 'ssrf',
            'information disclosure': 'information_disclosure',
            'configuration': 'security_headers'
        }
        
        # Check category first
        for key, value in category_map.items():
            if key in category:
                return value
        
        # Check title for keywords
        if 'sql' in title or 'injection' in title:
            return 'sql_injection'
        elif 'xss' in title or 'script' in title:
            return 'xss'
        elif 'clickjack' in title or 'frame' in title:
            return 'clickjacking'
        elif 'cors' in title:
            return 'cors'
        elif 'ssl' in title or 'tls' in title or 'certificate' in title:
            return 'ssl_tls'
        elif 'header' in title:
            return 'security_headers'
        elif 'auth' in title or 'login' in title or 'session' in title:
            return 'authentication'
        elif 'api' in title:
            return 'api_security'
        elif 'traversal' in title or 'path' in title:
            return 'directory_traversal'
        elif 'command' in title:
            return 'command_injection'
        elif 'upload' in title:
            return 'file_upload'
        elif 'ssrf' in title or 'request forgery' in title:
            return 'ssrf'
        elif 'disclosure' in title or 'exposed' in title or 'leak' in title:
            return 'information_disclosure'
        
        # Default to web scanning
        return 'web_scanning'
    
    def format_recommendations(self, tools: List[Dict], max_tools: int = 3) -> str:
        """Format tool recommendations as a readable string"""
        if not tools:
            return "No specific tool recommendations available."
        
        # Sort by priority
        priority_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
        sorted_tools = sorted(tools, key=lambda x: priority_order.get(x.get('priority', 'LOW'), 3))
        
        # Take top N tools
        top_tools = sorted_tools[:max_tools]
        
        output = []
        for i, tool in enumerate(top_tools, 1):
            output.append(f"{i}. {tool['name']} ({tool['type']})")
            output.append(f"   {tool['description']}")
            output.append(f"   Command: {tool['command']}")
            if i < len(top_tools):
                output.append("")
        
        return "\n".join(output)
    
    def get_all_recommendations_for_vulnerabilities(self, vulnerabilities: List[Dict]) -> Dict:
        """Get recommendations for all vulnerabilities, grouped by category"""
        recommendations = {}
        
        for vuln in vulnerabilities:
            tools = self.get_recommendations(vuln)
            category = vuln.get('category', 'Unknown')
            
            if category not in recommendations:
                recommendations[category] = {
                    'vulnerabilities': [],
                    'tools': tools
                }
            
            recommendations[category]['vulnerabilities'].append(vuln['title'])
        
        return recommendations
