"""
Test script for tool recommendation feature
"""
from core.tool_recommender import ToolRecommender

def test_recommendations():
    """Test tool recommendations for different vulnerability types"""
    recommender = ToolRecommender()
    
    # Test vulnerabilities
    test_vulns = [
        {
            'title': 'Missing Security Header: X-Frame-Options',
            'severity': 'MEDIUM',
            'category': 'Security Headers',
            'description': 'X-Frame-Options header not set',
            'url': 'https://example.com'
        },
        {
            'title': 'CORS Wildcard Misconfiguration',
            'severity': 'MEDIUM',
            'category': 'CORS',
            'description': 'Access-Control-Allow-Origin is set to wildcard (*)',
            'url': 'https://example.com'
        },
        {
            'title': 'SQL Injection Vulnerability',
            'severity': 'CRITICAL',
            'category': 'SQL Injection',
            'description': 'SQL injection found in parameter',
            'url': 'https://example.com/page?id=1'
        },
        {
            'title': 'Cross-Site Scripting (XSS)',
            'severity': 'HIGH',
            'category': 'XSS',
            'description': 'Reflected XSS vulnerability',
            'url': 'https://example.com/search?q=test'
        }
    ]
    
    print("="*80)
    print("TOOL RECOMMENDATION SYSTEM TEST")
    print("="*80)
    
    for vuln in test_vulns:
        print(f"\n{'='*80}")
        print(f"Vulnerability: {vuln['title']}")
        print(f"Severity: {vuln['severity']}")
        print(f"Category: {vuln['category']}")
        print(f"{'='*80}")
        
        # Get recommendations
        tools = recommender.get_recommendations(vuln)
        
        if tools:
            print(f"\n🛠️  Recommended Tools ({len(tools)} found):\n")
            for i, tool in enumerate(tools[:3], 1):  # Show top 3
                print(f"{i}. {tool['name']} ({tool['type']}) - Priority: {tool['priority']}")
                print(f"   Description: {tool['description']}")
                print(f"   Command: {tool['command']}")
                print(f"   Platform: {tool['platform']}")
                if i < len(tools[:3]):
                    print()
        else:
            print("\n❌ No specific tools recommended")
    
    print(f"\n{'='*80}")
    print("TEST COMPLETE")
    print(f"{'='*80}\n")

if __name__ == '__main__':
    test_recommendations()
