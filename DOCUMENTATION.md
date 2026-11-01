# Pentestrr - Intelligent Penetration Testing Framework

## 1. Overview and Summary

**Pentestrr v1.0.0** is an automated, end-to-end security assessment framework designed to map, scan, and safely exploit vulnerabilities in web applications. Unlike simplistic single-purpose scanners, Pentestrr acts as an orchestrator that intelligently profiles a target, customizes its scanning strategy based on the technologies it discovers, and seamlessly chains reconnaissance, vulnerability detection, and controlled exploitation.

The framework is highly concurrent (utilizing `aiohttp` for speed), integrates cleanly with local proxies (like Burp Suite or OWASP ZAP) for manual verification, and outputs professional, executive-ready PDF reports via `ReportLab`. 

## 2. Usage and CLI

Pentestrr operates via a simple Command Line Interface (CLI).

### Basic Full Assessment
To run all phases (Profiling -> Recon -> Scanning -> Detection -> Exploitation -> Reporting) concurrently:
```bash
python main.py scan example.com --async --verbose --output reports/
```

### Advanced Usage
```bash
# Route traffic through Burp Suite for manual inspection
python main.py scan example.com --proxy http://127.0.0.1:8080

# Provide custom wordlists for directory and subdomain brute-forcing
python main.py scan example.com --dir-wordlist custom_dirs.txt

# Stream JSON Lines output to other tools (like jq)
python main.py scan example.com --jsonl | jq .
```

---

## 3. Architecture and Phase Logic

Pentestrr operates in a strict, sequential pipeline. Each phase relies on the data collected by the previous phases, ensuring that attacks are contextual and highly targeted.

### Phase 0: Smart Profiling (`core/profiler.py`)
**Logic:** Before launching any aggressive scans, Pentestrr silently analyzes the target's footprint. It fetches the root page and analyzes HTTP headers, cookies, and HTML signatures to determine the underlying technology stack.
*   **Signatures:** It uses predefined regex and header matching to identify Content Management Systems (e.g., WordPress, Drupal), Web Servers (e.g., Nginx, Apache), Programming Languages (e.g., PHP, Python), and WAF/CDNs (e.g., Cloudflare, AWS).
*   **Strategy Generation:** Based on the identified stack, it generates an "Attack Strategy", dictating the risk level and which subsequent checks to prioritize (e.g., if WordPress is detected, it flags CMS-specific attack vectors).

### Phase 1: Reconnaissance (`core/reconnaissance.py` / `async_recon.py`)
**Logic:** This phase focuses on mapping the infrastructure and network surface.
*   **DNS & WHOIS:** Uses `dnspython` to extract A, AAAA, MX, NS, and TXT records. It pulls domain registration details to check for registrar information.
*   **Port Scanning:** Uses Python's `socket` library to probe a list of common ports (e.g., 21, 22, 80, 443, 3306). It relies on socket timeouts to identify open, filtered, or closed ports.

### Phase 2: Scanning & Enumeration (`core/scanner.py` / `async_scanner.py`)
**Logic:** This phase builds a map of the web application's internal structure and attack surface.
*   **Web Crawling:** Fetches the base URL and extracts all `href` and `src` links to build a list of discovered endpoints. 
*   **Form Extraction:** Parses HTML to locate `<form>` tags, extracting action URLs, methods (GET/POST), and input fields (types and names). This data is critically passed to Phase 4 for targeted injection testing.
*   **Directory/File Brute-forcing:** Iterates through built-in (or user-provided) wordlists to discover hidden files (like `.env`, `config.php`, `robots.txt`) and administrative directories.

### Phase 3: Vulnerability Detection (`core/vulnerability_detector.py`)
**Logic:** A comprehensive, passive, and active rule-based detection engine that analyzes the responses gathered in earlier phases without launching destructive attacks.
*   **Security Headers:** Checks for missing security boundaries (HSTS, CSP, X-Frame-Options).
*   **CORS:** Sends requests with arbitrary and `null` Origin headers to see if the server dangerously reflects them with credentials allowed.
*   **Authentication & Session Management:** Inspects raw `Set-Cookie` headers for missing `Secure` and `HttpOnly` flags. Flags forms without CSRF tokens.
*   **Information Disclosure & Serialization:** Analyzes `robots.txt` for disallowed paths. Inspects cookies for known serialization signatures (like `rO0` for Java, `gA` for Pickle, or PHP object serialization patterns).
*   **Heuristics for XXE/SSRF:** Scans discovered endpoints and forms for XML processing endpoints (`/api`, `/soap`) and URL-fetching parameters (`?url=`, `?redirect=`) to flag potential attack surfaces for manual OOB (Out-of-Band) testing.

### Phase 4: Safe Exploitation (`core/exploiter.py`)
**Logic:** Takes the vulnerabilities and forms discovered in Phases 2 and 3 and attempts controlled, non-destructive exploits to confirm if a vulnerability is truly exploitable (eliminating false positives).
*   **Cross-Site Scripting (XSS):** Injects benign `<script>` or HTML payloads into discovered form inputs and checks if the exact payload is reflected unescaped in the HTTP response.
*   **SQL Injection (SQLi):** Injects boolean and error-based SQL payloads (e.g., `' OR '1'='1`) and checks the response text for common database error signatures (MySQL, PostgreSQL, etc.).
*   **Command Injection:** Sends safe command execution triggers (e.g., `echo VULNERABLE`) and checks if the specific string is echoed back by the server.
*   **Service Exposures:** Attempts anonymous logins to FTP servers on port 21 and attempts to read the database banner of exposed MySQL services on port 3306.

### Phase 5: Professional PDF Reporting (`core/reporter.py`)
**Logic:** Aggregates all context (Target Profile, Strategy, Vulnerability Counts, and Exploitation Results) into an executive-ready PDF using `ReportLab`. Findings are sorted by severity, decorated with specific recommendations, and explicitly flag any vulnerability that was confirmed as "Exploitable" during Phase 4.
