# SecureIntel Pro - Intelligent Penetration Testing Framework

An enterprise-grade AI-powered security intelligence platform that demonstrates advanced engineering through intelligent pre-assessment, adaptive scanning, and custom attack strategies.

## 🎯 What Makes This Different

Unlike traditional pentesting tools that blindly run the same scans on every target, SecureIntel Pro:

1. **Intelligently Profiles** targets before testing (Phase 0: Smart Profiler)
2. **Adapts Strategy** based on what it discovers (CMS detection, tech stack analysis)
3. **Optimizes Execution** by only running relevant tools for each target
4. **Provides Context** with risk scoring and custom attack strategies

## 🚀 Current Implementation Status

### ✅ Phase 0: Smart Profiler (Complete) - **ENHANCED**
Intelligent target analysis with **accurate tool recommendations**:
- Detects target type (IP vs domain)
- Identifies web servers, CMS platforms (WordPress, Joomla, Drupal)
- Maps attack surface (web, SSH, databases, APIs)
- Detects technologies (React, Vue.js, Angular, PHP, ASP.NET, Node.js)
- **NEW**: Detects security infrastructure (WAF, CDN, Load Balancers)
- **NEW**: Detects rate limiting and adapts strategy
- **NEW**: Analyzes HTTP/TLS versions and cookie security
- **NEW**: Detects server technologies (Express.js, Next.js, etc.)
- **NEW**: Analyzes robots.txt for interesting paths
- Finds login pages and API endpoints
- **NEW**: Generates attack vectors based on detections
- **NEW**: Recommends tools based on security infrastructure
- **NEW**: Recommends tools based on technology stack
- **NEW**: Skips irrelevant tools automatically
- Calculates risk levels and estimated scan times

### ✅ Phase 1: Reconnaissance (Complete)
Comprehensive information gathering:
- DNS resolution and enumeration (A, AAAA, MX, NS, TXT, SOA records)
- WHOIS lookup with fallback mechanisms
- Subdomain enumeration (20 common subdomains)
- Port scanning (common ports)
- Service detection
- Strategy-guided execution

### ✅ Phase 2: Scanning & Enumeration (Complete)
Web application scanning:
- Web crawling (depth-limited)
- Directory discovery
- Endpoint enumeration
- Metadata extraction (emails, comments, forms)
- Backup file detection (.bak, .old, .zip, .sql)
- Git/SVN exposure check
- API endpoint discovery (REST, GraphQL, Swagger)

### ✅ Phase 3: Vulnerability Detection (Complete)
Security analysis:
- Security header analysis (HSTS, CSP, X-Frame-Options, etc.)
- SSL/TLS configuration checks
- CORS misconfiguration detection
- Information disclosure detection
- Sensitive file analysis
- Severity-based classification (CRITICAL, HIGH, MEDIUM, LOW, INFO)

### ✅ Phase 4: Exploitation (Complete)
Safe vulnerability validation:
- SQL injection testing
- XSS detection
- Directory traversal testing
- Command injection detection
- Open redirect detection
- Clickjacking verification
- Protocol downgrade testing
- MySQL database exposure testing
- FTP anonymous access testing

### ✅ Phase 5: Professional Reporting (Complete)
Professional PDF report generation:
- **PDF Reports**: Professional penetration testing reports with cover page, executive summary, methodology, detailed findings, and technical appendix
- LaTeX-based generation with fallback to ReportLab
- Unique filenames with timestamp: `pentest_{target}_{timestamp}.pdf`
- Color-coded severity levels
- Exploitable vulnerability highlighting

### 🔄 Phase 6-10: In Development
Following the complete 10-phase pentesting methodology (see roadmap below)

## 📋 Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    PentestFramework                      │
│              (Main Orchestrator)                         │
└─────────────────────────────────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│   Phase 0    │  │   Phase 1    │  │  Phase 2-10  │
│Smart Profiler│→ │Reconnaissance│  │  (Planned)   │
└──────────────┘  └──────────────┘  └──────────────┘
```

## 🛠️ Installation

```bash
# Clone the repository
git clone <repo-url>
cd project

# Install dependencies
pip install -r requirements.txt
```

## 💻 Usage

### Basic Usage
```bash
# Full intelligent pentest with PDF report
python main.py scanme.nmap.org --output reports

# Without report (console output only)
python main.py scanme.nmap.org

# Reconnaissance only
python main.py scanme.nmap.org --mode recon

# Verbose output
python main.py scanme.nmap.org --verbose --output reports
```

### Generated Report
When using `--output` flag, a professional PDF report is generated with unique filename:
- Format: `pentest_{target}_{timestamp}.pdf`
- Example: `pentest_scanme_nmap_org_20240203_145030.pdf`

### Example Output
```
🚀 STARTING INTELLIGENT PENETRATION TEST
============================================================

[PROFILER] 🧠 Smart Profiler - Intelligent Target Analysis
[PROFILER] Target type: Domain
[PROFILER] ✓ Web service detected
[PROFILER] ✓ Web Server: Apache/2.4.7 (Ubuntu)
[PROFILER] ⚠️  WAF/IDS Detected: Cloudflare
[PROFILER] ✓ CDN Detected: Cloudflare

📋 CUSTOM ATTACK STRATEGY GENERATED
🎯 Target: scanme.nmap.org
   Type: domain
   Server: Apache/2.4.7 (Ubuntu)
   WAF: Cloudflare
   CDN: Cloudflare
🔍 Attack Surface: web, ssh

⚔️  Attack Vectors (5):
   • WAF Bypass Techniques
   • CDN Origin Discovery
   • Rate Limit Evasion
   • PHP Deserialization
   • Client-Side Vulnerabilities

📍 Recommended Phases (6):
   1. Reconnaissance
   2. Web Enumeration
   3. Vulnerability Scanning
   ...

🛠️  Recommended Tools (10):
   • nikto
   • dirb
   • gobuster
   • sqlmap
   • xsser
   ... and 5 more

🚫 Skipped Tools (2):
   • hydra (Rate limiting active)
   • medusa (Rate limiting active)

⏱️  Estimated Time: ~38 minutes
⚠️  Risk Level: MEDIUM
```

## 🧪 Testing

```bash
# Test Phase 0 (Smart Profiler)
python test_phase0.py

# Test Phase 1 (Reconnaissance)
python test_phase1.py

# Test Integration (All Phases)
python test_integration.py

# Test MySQL Exploitation
python test_mysql_exploit.py

# Test FTP Exploitation
python test_ftp_exploit.py

# Test PDF Report Generation
python test_pdf_report.py

# Test specific targets
python test_wordpress.py
python test_darkguard.py
python test_csbc_tech.py
```

## 📊 Smart Profiler Capabilities

The Smart Profiler (Phase 0) analyzes targets and generates **intelligent, context-aware strategies**:

### Target Detection
- **CMS Detection**: WordPress, Joomla, Drupal, Magento
- **Web Servers**: Apache, Nginx, IIS, LiteSpeed
- **Frameworks**: React, Vue.js, Angular, Laravel, Django
- **Languages**: PHP, ASP.NET, Java, Python, Node.js
- **APIs**: REST, GraphQL detection
- **Security Infrastructure**: WAF (Cloudflare, AWS WAF, Akamai, etc.), CDN, Load Balancers
- **Rate Limiting**: Detects active rate limiting mechanisms
- **HTTP/TLS**: HTTP version (HTTP/1.1, HTTP/2, HTTP/3), TLS version
- **Cookie Security**: Analyzes Secure, HttpOnly, SameSite flags
- **Server Technologies**: Express.js, Next.js, PHP, ASP.NET MVC, etc.

### Intelligent Strategy Generation
Based on target profile, generates:
- **Custom Phase List**: Only relevant pentesting phases
- **Context-Aware Tools**: Tools selected based on actual detections
- **Attack Vectors**: Specific attack techniques for the target
- **Skipped Tools**: Shows which tools are skipped and why
- **Priority Targets**: High-value endpoints to focus on
- **Risk Assessment**: LOW/MEDIUM/HIGH based on attack surface
- **Time Estimation**: Realistic scan duration

### Example Strategies

**WordPress Site with Cloudflare WAF**:
- Attack Vectors: WAF Bypass, CDN Origin Discovery, Rate Limit Evasion, PHP Deserialization
- Tools: wpscan, wp-user-enum, xmlrpc-scan, nikto, sqlmap, **wafw00f, bypass-waf, phpggc, php-reverse-shell**
- Skipped: hydra, medusa (rate limiting detected)
- Priority: /wp-admin/, /wp-login.php, /xmlrpc.php

**React SPA with Express.js Backend**:
- Attack Vectors: Client-Side Vulnerabilities, Node.js Prototype Pollution, API Injection
- Tools: nikto, dirb, gobuster, sqlmap, **retire.js, npm-audit, api-fuzzer**
- Priority: /api/, /graphql

**ASP.NET App with Weak TLS**:
- Attack Vectors: ViewState Exploitation, SSL/TLS Downgrade Attack, Session Hijacking
- Tools: nikto, dirb, sqlmap, **viewstate-decoder, aspx-shell, sslscan, cookie-cadger**
- Priority: Login pages, API endpoints

**Database Server (MySQL)**:
- Attack Vectors: Default Credentials, SQL Injection, Database Exposure
- Tools: nmap-db-scripts, hydra, metasploit, sqlmap
- Skipped: nikto, dirb, gobuster (not relevant for database)

### Key Features

✅ **Security-Based Recommendations**:
- WAF detected → Adds WAF bypass tools
- CDN detected → Adds origin discovery techniques
- Rate limiting → Skips brute force tools
- Weak TLS → Adds SSL/TLS testing tools
- Cookie issues → Adds session hijacking tools

✅ **Technology-Based Recommendations**:
- PHP → phpggc, php-reverse-shell (deserialization)
- ASP.NET → viewstate-decoder, aspx-shell (ViewState)
- Java → ysoserial, java-deserialization
- React/Vue/Angular → retire.js (client-side vulns)
- Express.js/Next.js → npm-audit (prototype pollution)

✅ **Intelligent Skipping**:
- Database targets → Skip web-specific tools (WHOIS, DNS, subdomain enum)
- Rate limiting active → Skip brute force tools
- No web service → Skip web scanners

See **PHASE0_ENHANCEMENTS.md** and **STRATEGY_COMPARISON.md** for detailed examples.

## 🗺️ Roadmap

### Completed ✅
- [x] Phase 0: Smart Profiler with intelligent target analysis
- [x] Phase 1: Reconnaissance with DNS, WHOIS, port scanning, subdomain enumeration
- [x] Phase 2: Scanning & Enumeration with web crawling, directory discovery, API detection
- [x] Phase 3: Vulnerability Detection with security headers, CORS, SSL/TLS checks
- [x] Phase 4: Exploitation with SQL injection, XSS, database exposure testing
- [x] Phase 5: Professional Reporting with PDF/HTML/JSON generation
- [x] Framework integration and orchestration
- [x] Strategy-guided execution
- [x] Real exploit verification (MySQL exposure proven)

### Next Steps 🔄
- [ ] Phase 6: Post-Exploitation (privilege escalation, lateral movement)
- [ ] Phase 7: Advanced Reporting (compliance mapping, risk scoring)
- [ ] Phase 8: Cleanup & Verification

### Future Enhancements 🚀
- [ ] Custom ML models for vulnerability classification
- [ ] Attack path discovery using graph algorithms
- [ ] Distributed scanning with Celery workers
- [ ] Compliance mapping (OWASP Top 10, CWE, PCI-DSS)
- [ ] Remediation workflow integration (Jira, GitHub)
- [ ] Real-time dashboards and visualizations

## 📁 Project Structure

```
project/
├── core/
│   ├── __init__.py
│   ├── framework.py         # Main orchestrator
│   ├── profiler.py          # Phase 0: Smart Profiler
│   ├── reconnaissance.py    # Phase 1: Reconnaissance
│   ├── scanner.py           # Phase 2: Scanning & Enumeration
│   ├── vulnerability_detector.py  # Phase 3: Vulnerability Detection
│   ├── exploiter.py         # Phase 4: Exploitation
│   ├── reporter.py          # Phase 5: Report Generation
│   └── logger.py            # Logging utilities
├── reports/                 # Generated reports directory
│   └── pentest_{target}_{timestamp}.pdf  # Professional PDF report
├── main.py                  # CLI entry point
├── test_phase0.py           # Phase 0 tests
├── test_phase1.py           # Phase 1 tests
├── test_integration.py      # Integration tests
├── test_mysql_exploit.py    # MySQL exploitation tests
├── test_ftp_exploit.py      # FTP exploitation tests
├── test_pdf_report.py       # PDF report tests
├── requirements.txt         # Dependencies
├── PROGRESS.md             # Development progress tracker
├── PHASE_AUDIT.md          # Phase completeness audit
├── PHASE0_ENHANCEMENTS.md  # Phase 0 enhancement details
├── STRATEGY_COMPARISON.md  # Before/after strategy comparison
└── README.md               # This file
```

## 🔧 Dependencies

- **colorama**: Terminal colors and formatting
- **dnspython**: DNS resolution and enumeration
- **requests**: HTTP requests for web analysis
- **urllib3**: HTTP client (disable SSL warnings)
- **reportlab**: Professional PDF report generation
- **PyPDF2**: PDF validation and testing

## 🎓 Learning Resources

This project demonstrates:
- **Software Architecture**: Modular design with clear separation of concerns
- **Intelligent Automation**: Decision-making based on reconnaissance
- **Security Engineering**: Real-world pentesting methodology
- **Python Best Practices**: Type hints, documentation, testing

## ⚠️ Legal Disclaimer

This tool is for **authorized security testing only**. Always obtain written permission before testing any systems you don't own. Unauthorized access to computer systems is illegal.

## 📝 License

MIT License - See LICENSE file for details

## 🤝 Contributing

Contributions welcome! Please read CONTRIBUTING.md first.

## 📧 Contact

For questions or feedback, please open an issue on GitHub.
