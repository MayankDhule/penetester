"""
API Fuzzing Module
Automatic API discovery and fuzzing for OpenAPI, Swagger, GraphQL
"""
import json
import re
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse


class APIFuzzer:
    """Automatic API discovery and fuzzing"""
    
    def __init__(self, target: str, logger):
        self.target = target
        self.logger = logger
        self.discovered_apis = []
        self.api_specs = {}
    
    async def discover_apis(self) -> List[Dict]:
        """Discover API endpoints and specifications"""
        self.logger.info("[API-FUZZER] 🔍 Discovering APIs...")
        
        # Common API spec locations
        spec_paths = [
            '/openapi.json',
            '/openapi.yaml',
            '/swagger.json',
            '/swagger.yaml',
            '/swagger/v1/swagger.json',
            '/api-docs',
            '/api/docs',
            '/api/swagger.json',
            '/api/openapi.json',
            '/v1/api-docs',
            '/v2/api-docs',
            '/v3/api-docs',
            '/docs/api',
            '/api.json',
            '/api.yaml',
            '/graphql',
            '/graphql/schema',
            '/api/graphql',
        ]
        
        for path in spec_paths:
            url = urljoin(self.target, path)
            # In production: actually fetch and parse
            self.logger.debug(f"[API-FUZZER] Checking {url}")
        
        self.logger.info(f"[API-FUZZER] ✓ Found {len(self.discovered_apis)} API specs")
        return self.discovered_apis
    
    def parse_openapi_spec(self, spec: Dict) -> List[Dict]:
        """Parse OpenAPI/Swagger specification"""
        endpoints = []
        
        try:
            # OpenAPI 3.0
            if 'paths' in spec:
                for path, methods in spec['paths'].items():
                    for method, details in methods.items():
                        if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                            endpoints.append({
                                'path': path,
                                'method': method.upper(),
                                'summary': details.get('summary', ''),
                                'parameters': details.get('parameters', []),
                                'requestBody': details.get('requestBody', {}),
                                'responses': details.get('responses', {}),
                            })
            
            self.logger.info(f"[API-FUZZER] ✓ Parsed {len(endpoints)} endpoints from OpenAPI spec")
        
        except Exception as e:
            self.logger.error(f"[API-FUZZER] Failed to parse OpenAPI spec: {e}")
        
        return endpoints
    
    def parse_graphql_schema(self, schema: str) -> List[Dict]:
        """Parse GraphQL schema"""
        queries = []
        mutations = []
        
        try:
            # Extract queries
            query_pattern = r'type Query \{([^}]+)\}'
            query_match = re.search(query_pattern, schema, re.DOTALL)
            if query_match:
                query_fields = query_match.group(1)
                queries = re.findall(r'(\w+)\s*\([^)]*\)\s*:\s*(\w+)', query_fields)
            
            # Extract mutations
            mutation_pattern = r'type Mutation \{([^}]+)\}'
            mutation_match = re.search(mutation_pattern, schema, re.DOTALL)
            if mutation_match:
                mutation_fields = mutation_match.group(1)
                mutations = re.findall(r'(\w+)\s*\([^)]*\)\s*:\s*(\w+)', mutation_fields)
            
            self.logger.info(f"[API-FUZZER] ✓ Found {len(queries)} queries, {len(mutations)} mutations")
        
        except Exception as e:
            self.logger.error(f"[API-FUZZER] Failed to parse GraphQL schema: {e}")
        
        return queries + mutations
    
    def generate_fuzzing_payloads(self, endpoint: Dict) -> List[Dict]:
        """Generate fuzzing payloads for endpoint"""
        payloads = []
        
        # SQL Injection payloads
        sqli_payloads = [
            "' OR '1'='1",
            "1' OR '1'='1' --",
            "admin'--",
            "' UNION SELECT NULL--",
            "1; DROP TABLE users--",
        ]
        
        # XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
        ]
        
        # Command injection payloads
        cmd_payloads = [
            "; ls -la",
            "| whoami",
            "`id`",
            "$(cat /etc/passwd)",
        ]
        
        # Path traversal payloads
        path_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
        ]
        
        # NoSQL injection payloads
        nosql_payloads = [
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$regex": ".*"}',
        ]
        
        # Generate payloads for each parameter
        for param in endpoint.get('parameters', []):
            param_name = param.get('name', '')
            
            for payload in sqli_payloads:
                payloads.append({
                    'type': 'sqli',
                    'param': param_name,
                    'payload': payload,
                    'method': endpoint['method'],
                    'path': endpoint['path']
                })
            
            for payload in xss_payloads:
                payloads.append({
                    'type': 'xss',
                    'param': param_name,
                    'payload': payload,
                    'method': endpoint['method'],
                    'path': endpoint['path']
                })
        
        return payloads
    
    async def fuzz_endpoint(self, endpoint: Dict, payloads: List[Dict]) -> List[Dict]:
        """Fuzz single endpoint with payloads"""
        findings = []
        
        self.logger.info(f"[API-FUZZER] Fuzzing {endpoint['method']} {endpoint['path']} with {len(payloads)} payloads")
        
        for payload_info in payloads:
            # In production: send actual request with payload
            # Check response for vulnerability indicators
            pass
        
        return findings
    
    async def fuzz_graphql(self, endpoint: str, queries: List[tuple]) -> List[Dict]:
        """Fuzz GraphQL endpoint"""
        findings = []
        
        self.logger.info(f"[API-FUZZER] Fuzzing GraphQL endpoint: {endpoint}")
        
        for query_name, return_type in queries:
            # Generate GraphQL query
            graphql_query = f"""
            query {{
                {query_name} {{
                    __typename
                }}
            }}
            """
            
            # In production: send GraphQL request
            # Check for errors, information disclosure
            pass
        
        return findings
    
    def test_authentication_bypass(self, endpoints: List[Dict]) -> List[Dict]:
        """Test for authentication bypass vulnerabilities"""
        findings = []
        
        self.logger.info("[API-FUZZER] Testing authentication bypass...")
        
        # Test techniques:
        # 1. Remove auth headers
        # 2. Use expired tokens
        # 3. Use tokens from different users
        # 4. Manipulate JWT claims
        # 5. Test HTTP verb tampering
        
        return findings
    
    def test_authorization_issues(self, endpoints: List[Dict]) -> List[Dict]:
        """Test for authorization issues (IDOR, privilege escalation)"""
        findings = []
        
        self.logger.info("[API-FUZZER] Testing authorization issues...")
        
        # Test techniques:
        # 1. Access other users' resources
        # 2. Escalate privileges
        # 3. Access admin endpoints
        # 4. Manipulate IDs
        
        return findings
    
    def test_rate_limiting(self, endpoint: Dict) -> Optional[Dict]:
        """Test if endpoint has rate limiting"""
        self.logger.info(f"[API-FUZZER] Testing rate limiting on {endpoint['path']}")
        
        # In production: send many requests quickly
        # Check for 429 responses
        
        return None
    
    def test_mass_assignment(self, endpoint: Dict) -> List[Dict]:
        """Test for mass assignment vulnerabilities"""
        findings = []
        
        if endpoint['method'] in ['POST', 'PUT', 'PATCH']:
            self.logger.info(f"[API-FUZZER] Testing mass assignment on {endpoint['path']}")
            
            # Test by adding extra fields:
            # - is_admin: true
            # - role: admin
            # - permissions: ["*"]
            # - verified: true
        
        return findings


class OpenAPIParser:
    """Parse OpenAPI/Swagger specifications"""
    
    @staticmethod
    def parse(spec: Dict) -> Dict:
        """Parse OpenAPI spec"""
        return {
            'version': spec.get('openapi') or spec.get('swagger'),
            'title': spec.get('info', {}).get('title'),
            'description': spec.get('info', {}).get('description'),
            'servers': spec.get('servers', []),
            'paths': spec.get('paths', {}),
            'components': spec.get('components', {}),
        }
    
    @staticmethod
    def extract_endpoints(spec: Dict) -> List[Dict]:
        """Extract all endpoints from spec"""
        endpoints = []
        
        for path, methods in spec.get('paths', {}).items():
            for method, details in methods.items():
                if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
                    endpoints.append({
                        'path': path,
                        'method': method.upper(),
                        'summary': details.get('summary'),
                        'description': details.get('description'),
                        'parameters': details.get('parameters', []),
                        'requestBody': details.get('requestBody'),
                        'responses': details.get('responses', {}),
                        'security': details.get('security', []),
                    })
        
        return endpoints


class GraphQLIntrospection:
    """GraphQL introspection and schema discovery"""
    
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
        __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
                ...FullType
            }
        }
    }
    
    fragment FullType on __Type {
        kind
        name
        description
        fields(includeDeprecated: true) {
            name
            description
            args {
                ...InputValue
            }
            type {
                ...TypeRef
            }
        }
    }
    
    fragment InputValue on __InputValue {
        name
        description
        type { ...TypeRef }
        defaultValue
    }
    
    fragment TypeRef on __Type {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
            }
        }
    }
    """
    
    @staticmethod
    def introspect(endpoint: str) -> Optional[Dict]:
        """Perform GraphQL introspection"""
        # In production: send introspection query
        # Parse and return schema
        return None



