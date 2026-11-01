# Pentestrr - Penetration Testing Framework

**Target Profiling + Tool Recommendations for Rapid Security Assessments**

A CLI-based penetration testing framework that profiles targets before testing and recommends specialized tools for deeper analysis. Aimed at rapid first-pass security assessments and bug bounty reconnaissance.

## 🎯 What It Does

Pentestrr focuses on **automated first-pass checks + tool guidance**:

1. **Target Profiling** - Analyzes the target first and adapts the strategy to the detected tech stack
2. **Tool Recommendations** - Suggests 40 tools across 15 categories with ready-to-use commands
3. **Async Scanning** - Optional async/concurrent scanning for faster enumeration
4. **Confidence-Rated Findings** - Each exploitation finding is tagged `confirmed` or `probable` so you know what still needs manual checking
5. **Clean Output** - Readable CLI output plus JSON/JSON Lines for tooling

**Best For:** Bug bounty hunters, security auditors, and DevSecOps teams who want a fast first-pass pass over a target, with pointers to the specialized tools to use next.

**Not For:** Deep exploitation, advanced manual testing, or replacing tools like Burp Suite Pro or Nuclei. Pentestrr finds low-hanging fruit and tells you which specialized tools to use for deeper testing. Injection checks are lightweight heuristics, not a substitute for sqlmap/Burp.

## 🚀 Quick Start

### Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Install as CLI tool (recommended)
pip install -e .

# Verify installation
pentestrr --version
```

### Basic Usage

```bash
# Full security assessment
pentestrr scan example.com

# Async scanning for faster enumeration
pentestrr scan example.com --async --max-concurrent 50

# With out-of-band callback testing (interact.sh)
pentestrr scan example.com --oob-domain abc123.interact.sh

# Professional workflow with Burp Suite
pentestrr scan example.com --proxy http://127.0.0.1:8080 --async

# Tool chaining with JSON output
cat targets.txt | pentestrr scan --jsonl | jq 'select(.severity == "CRITICAL")'

# Get help
pentestrr --help
```

## 📖 CLI Commands

### Main Commands

| Command | Description | Example |
|---------|-------------|---------|
| `scan` | Run full penetration test | `pentestrr scan example.com` |
| `profile` | Phase 0: Smart profiling | `pentestrr profile example.com` |
| `recon` | Phase 1: Reconnaissance | `pentestrr recon example.com` |
| `enumerate` | Phase 2: Enumeration | `pentestrr enumerate example.com` |
| `exploit` | Phase 4: Exploitation | `pentestrr exploit example.com` |
| `info` | Show framework info | `pentestrr info` |
| `list` | List phases/tools | `pentestrr list --phases` |

### Common Options

```bash
# Performance
--async                 Use async/concurrent scanning
--max-concurrent N      Max concurrent requests (default: 50)

# Wordlists
--dir-wordlist FILE     Custom directory wordlist
--subdomain-wordlist    Custom subdomain wordlist
--file-wordlist FILE    Custom file wordlist

# Integration
--proxy URL             HTTP/HTTPS proxy (e.g., http://127.0.0.1:8080)
--json                  Output as JSON
--jsonl                 Output as JSON Lines (streaming)

# General
-v, --verbose           Enable verbose output
--no-banner             Disable banner display
--version               Show version
```

## 💻 Framework Phases

### ✅ Phase 0: Smart Profiler
- Detects target type, web server, CMS, frameworks
- Identifies WAF/CDN, rate limiting
- Maps attack surface
- Generates custom attack strategy

### ✅ Phase 1: Reconnaissance
- DNS resolution and enumeration
- Subdomain discovery (20 common)
- Port scanning (common ports)
- Service detection

### ✅ Phase 2: Scanning & Enumeration
- Web crawling
- Directory discovery
- Endpoint enumeration
- Backup file detection
- Form discovery

### ✅ Phase 3: Vulnerability Detection
- Security header analysis (HSTS, CSP, X-Frame-Options, etc.)
- SSL/TLS configuration
- CORS misconfiguration
- Information disclosure
- Cookie security

### ✅ Phase 4: Safe Exploitation
- Clickjacking testing
- Protocol downgrade testing
- Basic SQL injection detection (error-based)
- Basic XSS detection (reflection-based)
- Tests discovered forms from Phase 2

### ✅ Tool Recommendations
- Suggests specialized tools for each vulnerability
- 40-tool database across 15 categories with commands
- Priority-ranked recommendations

## 📁 Project Structure

```
project/
├── core/
│   ├── __init__.py
│   ├── framework.py              # Main orchestrator
│   ├── profiler.py               # Phase 0: Smart Profiler
│   ├── reconnaissance.py         # Phase 1: Reconnaissance
│   ├── async_recon.py            # Async reconnaissance (100+ concurrent)
│   ├── scanner.py                # Phase 2: Scanning & Enumeration
│   ├── async_scanner.py          # Async scanner (50+ concurrent)
│   ├── wordlists.py              # External wordlist management
│   ├── vulnerability_detector.py # Phase 3: Vulnerability Detection
│   ├── exploiter.py              # Phase 4: Exploitation
│   ├── oob_testing.py            # Out-of-Band callback testing (interact.sh client)
│   ├── api_fuzzer.py             # API fuzzing (OpenAPI/GraphQL)
│   ├── smart_retry.py            # Retry logic with circuit breaker
│   ├── reporter.py               # Phase 5: Report Generation
│   ├── json_output.py            # JSON/JSON Lines output
│   ├── stdin_handler.py          # Stdin target reading
│   ├── proxy_handler.py          # Burp/ZAP proxy integration
│   └── logger.py                 # Logging utilities
├── reports/                      # Generated reports directory
├── main.py                       # CLI entry point
├── requirements.txt              # Dependencies (12 packages)
├── setup.py                      # Package setup
├── .gitignore                    # Git ignore rules
└── README.md                     # This file
```

## 🔧 Dependencies

**Minimal & focused (12 packages)**

### Core HTTP & Networking
- **requests**: Synchronous HTTP requests
- **urllib3**: HTTP client library
- **dnspython**: DNS resolution and enumeration

### Async Performance (Phase 2)
- **aiohttp**: Async HTTP client
- **aiodns**: Async DNS resolution

### Web Parsing
- **beautifulsoup4**: HTML/XML parsing

### Terminal Output
- **colorama**: Cross-platform colored terminal output

### Professional Reporting
- **reportlab**: Professional PDF generation
- **PyPDF2**: PDF manipulation

### Out-of-Band Testing
- **cryptography**: RSA/AES for the interact.sh callback client

**No ML libraries. No unused dependencies.**

## 🚀 Advanced Features

### ⚡ Performance
- **Async/Concurrent Scanning**: Concurrent requests speed up enumeration
- **Configurable Concurrency**: Tune the concurrent request limit
- **External Wordlists**: Bring your own SecLists wordlists
- **Connection Pooling**: Reuses connections automatically

### 🛠️ Tool Recommendations
- **Suggestions**: Recommends specialized tools for each vulnerability
- **40 Tools / 15 Categories**: Curated tool recommendations
- **Priority-Based**: Tools ranked by effectiveness
- **Ready-to-Use Commands**: Copy-paste commands for immediate testing
- **Integrated in Reports**: Tool recommendations in CLI output

**Example Output:**
```
[VULN] ✗ Missing: X-Frame-Options [MEDIUM]

🛠️  Recommended Tools for Further Testing:
   1. Burp Suite (Manual)
      Test iframe embedding manually
      💻 Use Burp Repeater to test X-Frame-Options
   
   2. SecurityHeaders.com (Online)
      Online security header checker
      💻 Visit: https://securityheaders.com
```

### 🔗 Professional Integration
- **Burp Suite / OWASP ZAP**: Proxy all traffic for manual review
- **JSON Output**: Machine-readable results
- **JSON Lines**: Streaming output for real-time processing
- **Stdin Support**: Read targets from pipes
- **Tool Chaining**: `cat targets.txt | pentestrr scan --jsonl | jq`

### 📊 Testing Notes
- **Tried against**: testfire.net, demo.testfire.net, testphp.vulnweb.com
- **Typical runtime**: roughly 40 seconds per site (varies with target and options)
- **Error handling**: Graceful handling of timeouts and unreachable services

## 🏆 Competitive Position

| Feature | Pentestrr | Nuclei | Burp Suite | OWASP ZAP |
|---------|-----------|--------|-----------|-----------|
| Smart Profiling | ✅ | ❌ | ⚠️ | ❌ |
| Async Scanning | ✅ | ✅ | ✅ | ⚠️ |
| Tool Recommendations | ✅ | ❌ | ❌ | ❌ |
| Easy Setup | ✅ | ✅ | ⚠️ | ✅ |
| Templates/Rules | ❌ | ✅ 9000+ | ✅ | ✅ |
| Manual Testing | ❌ | ❌ | ✅ | ✅ |
| Price | Free | Free | $449/yr | Free |

**Pentestrr's niche:** Smart profiling + tool recommendations for rapid first-pass assessments

## 💡 Usage Examples

### Example 1: Async Scan
```bash
# Concurrent scanning for faster enumeration
pentestrr scan example.com --async --max-concurrent 50
```

### Example 2: Out-of-Band (OOB) Callback Testing
```bash
# Option A: use the built-in interact.sh client (needs the 'cryptography' package)
#           it self-registers a domain and polls for callbacks

# Option B: use a domain you control (e.g. Burp Collaborator); you check that
#           platform yourself for callbacks
pentestrr scan example.com --oob-domain abc123.interact.sh
```

> OOB testing confirms a blind vulnerability only when a DNS/HTTP callback is
> received for the unique subdomain. No callback is not, by itself, proof the
> target is safe.

### Example 3: JSON Output for Tooling
```bash
# Full machine-readable results
pentestrr scan example.com --json > results.json
```

> Note: an API fuzzer exists in `core/api_fuzzer.py` but is not yet wired to a
> CLI flag, so there is no `--fuzz-apis` option today.

### Example 4: Professional Workflow with Burp Suite
```bash
# Route all traffic through Burp for manual review
pentestrr scan example.com --proxy http://127.0.0.1:8080 --async
```

### Example 5: Tool Chaining
```bash
# Scan multiple targets and filter critical vulnerabilities
cat targets.txt | pentestrr scan --jsonl | jq 'select(.severity == "CRITICAL")'
```

### Example 6: Custom Wordlists
```bash
# Use SecLists wordlists
pentestrr scan example.com \\
  --async \\
  --dir-wordlist ~/SecLists/Discovery/Web-Content/common.txt \\
  --subdomain-wordlist ~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

### Example 7: Full Scan with Available Options
```bash
# Combine the options that actually exist today
pentestrr scan example.com \\
  --async \\
  --max-concurrent 50 \\
  --oob-domain xyz.interact.sh \\
  --proxy http://127.0.0.1:8080 \\
  --dir-wordlist ~/SecLists/directories.txt \\
  --jsonl | tee results.jsonl
```

## 🎓 Learning Resources

This project demonstrates:
- **Software Architecture**: Modular design with clear separation of concerns
- **Automation**: Decision-making based on reconnaissance
- **Security Engineering**: Real-world pentesting methodology
- **Python Best Practices**: Type hints, documentation, testing

## ⚠️ Legal Disclaimer

This tool is for **authorized security testing only**. Always obtain written permission before testing any systems you don't own. Unauthorized access to computer systems is illegal.

## 📝 License

MIT License - See LICENSE file for details

## 🤝 Contributing

Contributions welcome! Please open an issue or pull request on GitHub.

## 📧 Contact

For questions or feedback, please open an issue on GitHub.
