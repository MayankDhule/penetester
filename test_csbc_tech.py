#!/usr/bin/env python3
"""
Check what technologies csbc.sanjivaniuniversity.com actually uses
"""
import requests
import re

def check_technologies(url):
    """Check what technologies the site uses"""
    print(f"[*] Analyzing {url}")
    print("="*60)
    
    try:
        response = requests.get(url, timeout=10, verify=False)
        html = response.text
        headers = response.headers
        
        print(f"\n[*] Server Headers:")
        print(f"    Server: {headers.get('Server', 'Not disclosed')}")
        print(f"    X-Powered-By: {headers.get('X-Powered-By', 'Not disclosed')}")
        
        print(f"\n[*] Checking for Firebase...")
        firebase_indicators = [
            'firebase',
            'firebaseapp.com',
            'firebaseio.com',
            'googleapis.com',
            '__FIREBASE_DEFAULTS__'
        ]
        
        firebase_found = []
        for indicator in firebase_indicators:
            if indicator.lower() in html.lower():
                firebase_found.append(indicator)
        
        if firebase_found:
            print(f"    ✓ Firebase detected!")
            print(f"    Found indicators: {', '.join(firebase_found)}")
        else:
            print(f"    ✗ No Firebase indicators found")
        
        print(f"\n[*] Checking for MySQL/Database references...")
        db_indicators = ['mysql', 'mysqli', 'pdo', 'database', 'db_']
        db_found = []
        for indicator in db_indicators:
            if indicator.lower() in html.lower():
                db_found.append(indicator)
        
        if db_found:
            print(f"    ✓ Database references found: {', '.join(set(db_found))}")
        else:
            print(f"    ✗ No obvious database references in HTML")
        
        print(f"\n[*] Checking for JavaScript frameworks...")
        frameworks = {
            'React': ['react', 'react-dom'],
            'Vue.js': ['vue.js', 'vue.min.js', '__vue__'],
            'Angular': ['angular', 'ng-app'],
            'jQuery': ['jquery'],
        }
        
        for framework, indicators in frameworks.items():
            for indicator in indicators:
                if indicator.lower() in html.lower():
                    print(f"    ✓ {framework} detected")
                    break
        
        print(f"\n[*] Checking page content...")
        print(f"    HTML size: {len(html)} bytes")
        print(f"    Title: ", end='')
        title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
        if title_match:
            print(title_match.group(1))
        else:
            print("Not found")
        
        # Check for API endpoints
        print(f"\n[*] Looking for API endpoints...")
        api_patterns = [
            r'api[./]',
            r'/api/',
            r'\.php',
            r'\.asp',
            r'\.jsp'
        ]
        
        apis_found = set()
        for pattern in api_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                apis_found.add(pattern)
        
        if apis_found:
            print(f"    ✓ API patterns found: {', '.join(apis_found)}")
        else:
            print(f"    ✗ No obvious API endpoints")
        
        print(f"\n[*] Sample HTML (first 500 chars):")
        print(f"    {html[:500]}")
        
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    url = "https://csbc.sanjivaniuniversity.com"
    check_technologies(url)
    print("\n" + "="*60)
