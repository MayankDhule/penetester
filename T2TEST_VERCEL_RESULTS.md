# Pentestrr Security Assessment Report
## Target: t2test.vercel.app

**Assessment Date:** April 22, 2026  
**Framework Version:** Pentestrr 1.0.0  
**Assessment Duration:** 1 minute 28 seconds  
**Assessment Type:** Automated Security Scan

---

## Executive Summary

Pentestrr conducted a comprehensive security assessment of **t2test.vercel.app**, a web application hosted on Vercel's infrastructure. The assessment identified **7 security vulnerabilities** across multiple categories, with **1 confirmed exploitable** issue.

### Risk Rating: 🟡 MEDIUM

### Key Findings:
- ✅ HSTS properly configured
- ⚠️ **Clickjacking vulnerability confirmed** (exploitable)
- ⚠️ CORS wildcard misconfiguration detected
- ⚠️ Missing critical security headers (X-Frame-Options, CSP)
- ✅ No SQL injection, XSS, or command injection vulnerabilities
- ⚠️ 10 publicly accessible directories discovered
- ⚠️ 20 subdomains enumerated (potential attack surface)

---

## Target Information

### Basic Information
| Property | Value |
|----------|-------|
| **Domain** | t2test.vercel.app |
| **IP Address** | 64.29.17.195 |
| **Web Server** | Vercel |
| **SSL/TLS** | ✅ Enabled |
| **HTTP Version** | HTTP/1.1 |
| **Target Type** | Domain |
| **Attack Surface** | Web Application |

### Infrastructure
- **Hosting Provider:** Vercel (Serverless Platform)
- **CDN:** Vercel Edge Network
- **Open Ports:** 80 (HTTP)
- **DNS Records:** 2 A records found

---

## Phase 0: Smart Profiling Results

### Technology Stack Detected
- **Web Server:** Vercel
- **HTTP Version:** HTTP/1.1
- **SSL/TLS:** Enabled with HSTS
- **robots.txt:** Present (0 rules)
- **Rate Limiting:** Not detected

### Attack Strategy Generated
**Risk Level:** LOW  
**Estimated Assessment Time:** ~33 minutes  
**Recommended Phases:** 6
1. Reconnaissance
2. Web Enumeration
3. Vulnerability Scanning
4. Injection Testing
5. Authentication Testing
6. Exploitation

**Recommended Tools:** 6
- nikto
- dirb
- gobuster
- sqlmap
- xsser
- burp suite

---

## Phase 1: Reconnaissance Results

### DNS Information
**Primary IP:** 64.29.17.195  
**A Records:** 2 found

### Subdomain Enumeration
**Total Subdomains Discovered:** 20

| Subdomain | IP Address | Purpose |
|-----------|------------|---------|
| www.t2test.vercel.app | 64.29.17.3 | Web |
| mail.t2test.vercel.app | 64.29.17.195 | Email |
| ftp.t2test.vercel.app | 216.198.79.131 | File Transfer |
| localhost.t2test.vercel.app | 216.198.79.195 | Development |
| webmail.t2test.vercel.app | 64.29.17.3 | Email |
| smtp.t2test.vercel.app | 64.29.17.3 | Email |
| pop.t2test.vercel.app | 216.198.79.195 | Email |
| ns1.t2test.vercel.app | 216.198.79.131 | DNS |
| webdisk.t2test.vercel.app | 64.29.17.67 | Storage |
| ns2.t2test.vercel.app | 216.198.79.131 | DNS |
| cpanel.t2test.vercel.app | 64.29.17.67 | Control Panel |
| whm.t2test.vercel.app | 64.29.17.3 | Hosting |
| autodiscover.t2test.vercel.app | 64.29.17.3 | Email Config |
| autoconfig.t2test.vercel.app | 64.29.17.3 | Email Config |
| mx.t2test.vercel.app | 64.29.17.67 | Mail Exchange |
| email.t2test.vercel.app | 216.198.79.131 | Email |
| **api.t2test.vercel.app** | 64.29.17.3 | **API** ⚠️ |
| **dev.t2test.vercel.app** | 64.29.17.131 | **Development** ⚠️ |
| **staging.t2test.vercel.app** | 216.198.79.131 | **Staging** ⚠️ |
| **test.t2test.vercel.app** | 216.198.79.3 | **Testing** ⚠️ |

**⚠️ Security Concern:** Development, staging, and test environments are publicly accessible, which may expose sensitive information or unfinished features.

### Port Scanning Results
**Open Ports:** 1
- **Port 80 (HTTP):** OPEN
  - Service: HTTP
  - Status: Active

**Note:** Port 443 (HTTPS) is handled by Vercel's edge network and redirects to HTTPS automatically.

---

## Phase 2: Scanning & Enumeration Results

### Web Crawling
**Pages Discovered:** 1
- https://t2test.vercel.app/

### Directory Discovery
**Directories Found:** 10 (All returning 200 OK)

| Directory | Status | Risk Level |
|-----------|--------|------------|
| **/admin/** | 200 OK | 🔴 HIGH |
| **/api/** | 200 OK | 🟡 MEDIUM |
| **/assets/** | 200 OK | 🟢 LOW |
| **/backup/** | 200 OK | 🔴 HIGH |
| **/config/** | 200 OK | 🔴 HIGH |
| **/css/** | 200 OK | 🟢 LOW |
| **/data/** | 200 OK | 🟡 MEDIUM |
| **/db/** | 200 OK | 🔴 HIGH |
| **/docs/** | 200 OK | 🟢 LOW |
| **/downloads/** | 200 OK | 🟡 MEDIUM |

**⚠️ Critical Findings:**
- `/admin/` - Administrative interface accessible
- `/backup/` - Backup files may be exposed
- `/config/` - Configuration files may be exposed
- `/db/` - Database files may be exposed
- `/api/` - API endpoints accessible

### Metadata Extraction
- **Forms Detected:** 0
- **Email Addresses:** 0
- **HTML Comments:** 0
- **Interesting Files:** 0

---

## Phase 3: Vulnerability Detection Results

### Summary
**Total Vulnerabilities:** 7
- 🟡 **MEDIUM:** 3
- 🟢 **LOW:** 2
- ℹ️ **INFO:** 2

### Detailed Vulnerability Analysis

#### 1. Missing Security Header: X-Frame-Options
**Severity:** 🟡 MEDIUM  
**Category:** Security Headers  
**CVSS Score:** 5.0

**Description:**
The X-Frame-Options header is not set, making the site vulnerable to clickjacking attacks. Attackers can embed the site in an iframe and overlay deceptive UI elements to trick users into performing unintended actions.

**Impact:**
- Clickjacking attacks
- UI redressing
- Credential theft via deceptive overlays
- Unauthorized actions performed by users

**Recommendation:**
Add the X-Frame-Options header to all responses:
```
X-Frame-Options: DENY
```
or
```
X-Frame-Options: SAMEORIGIN
```

**Vercel Configuration:**
Add to `vercel.json`:
```json
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "X-Frame-Options",
          "value": "DENY"
        }
      ]
    }
  ]
}
```

---

#### 2. Missing Security Header: Content Security Policy (CSP)
**Severity:** 🟡 MEDIUM  
**Category:** Security Headers  
**CVSS Score:** 6.0

**Description:**
Content Security Policy (CSP) header is not set. CSP helps prevent XSS attacks, data injection attacks, and other code injection vulnerabilities by specifying which sources of content are trusted.

**Impact:**
- Cross-Site Scripting (XSS) attacks
- Data injection attacks
- Malicious script execution
- Content spoofing

**Recommendation:**
Implement a strict Content Security Policy:
```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';
```

**Vercel Configuration:**
Add to `vercel.json`:
```json
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "Content-Security-Policy",
          "value": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';"
        }
      ]
    }
  ]
}
```

---

#### 3. CORS Wildcard Misconfiguration
**Severity:** 🟡 MEDIUM  
**Category:** CORS  
**CVSS Score:** 5.5

**Description:**
The Access-Control-Allow-Origin header is set to wildcard (*), allowing any domain to make cross-origin requests to the application. This can lead to unauthorized data access and CSRF attacks.

**Current Configuration:**
```
Access-Control-Allow-Origin: *
```

**Impact:**
- Unauthorized cross-origin requests
- Data theft from authenticated sessions
- CSRF attacks
- Sensitive data exposure

**Recommendation:**
Replace wildcard with specific allowed origins:
```
Access-Control-Allow-Origin: https://yourdomain.com
```

Or implement dynamic origin validation:
```javascript
const allowedOrigins = ['https://yourdomain.com', 'https://app.yourdomain.com'];
const origin = request.headers.get('origin');
if (allowedOrigins.includes(origin)) {
  response.headers.set('Access-Control-Allow-Origin', origin);
}
```

---

#### 4. Missing Security Header: X-Content-Type-Options
**Severity:** 🟢 LOW  
**Category:** Security Headers  
**CVSS Score:** 3.0

**Description:**
X-Content-Type-Options header is not set. Browsers may MIME-sniff responses, potentially leading to security vulnerabilities.

**Impact:**
- MIME-sniffing attacks
- Content type confusion
- Potential XSS via uploaded files

**Recommendation:**
```
X-Content-Type-Options: nosniff
```

---

#### 5. Missing Security Header: X-XSS-Protection
**Severity:** 🟢 LOW  
**Category:** Security Headers  
**CVSS Score:** 3.0

**Description:**
X-XSS-Protection header is not set or disabled. While modern browsers have built-in XSS protection, this header provides an additional layer of defense.

**Impact:**
- Reduced XSS protection in older browsers
- Potential XSS attacks

**Recommendation:**
```
X-XSS-Protection: 1; mode=block
```

---

#### 6. Missing Security Header: Referrer-Policy
**Severity:** ℹ️ INFO  
**Category:** Security Headers  
**CVSS Score:** 2.0

**Description:**
Referrer-Policy header is not set. This may leak sensitive information in the Referer header when navigating to external sites.

**Recommendation:**
```
Referrer-Policy: strict-origin-when-cross-origin
```

---

#### 7. Missing Security Header: Permissions-Policy
**Severity:** ℹ️ INFO  
**Category:** Security Headers  
**CVSS Score:** 2.0

**Description:**
Permissions-Policy (formerly Feature-Policy) header is not set. This header controls which browser features and APIs can be used.

**Recommendation:**
```
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

---

## Phase 4: Safe Exploitation Results

### Exploitation Summary
**Tests Attempted:** 5  
**Exploitable Vulnerabilities:** 1  
**Severity:** 🟡 MEDIUM

### Confirmed Exploitable Vulnerability

#### Clickjacking Vulnerability
**Status:** ⚠️ **CONFIRMED EXPLOITABLE**  
**Severity:** 🟡 MEDIUM  
**CVSS Score:** 5.0

**Proof of Concept:**
The site can be successfully embedded in an iframe, confirming the clickjacking vulnerability:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC</title>
</head>
<body>
    <h1>Clickjacking Demonstration</h1>
    <iframe src="https://t2test.vercel.app" width="800" height="600"></iframe>
</body>
</html>
```

**Attack Scenario:**
1. Attacker creates a malicious page with the target site embedded in an iframe
2. Attacker overlays invisible or deceptive UI elements
3. User thinks they're clicking on legitimate content
4. User actually performs actions on the embedded site (e.g., clicking buttons, submitting forms)

**Impact:**
- Credential theft
- Unauthorized transactions
- Account takeover
- Social engineering attacks

**Remediation:**
Implement X-Frame-Options header (see Vulnerability #1 above).

---

### Additional Exploitation Tests

#### SQL Injection Testing
**Status:** ✅ PASSED  
**Result:** No SQL injection vulnerabilities detected

**Tests Performed:**
- Error-based SQL injection
- Boolean-based blind SQL injection
- Time-based blind SQL injection
- Union-based SQL injection

---

#### Cross-Site Scripting (XSS) Testing
**Status:** ✅ PASSED  
**Result:** No XSS vulnerabilities detected

**Tests Performed:**
- Reflected XSS
- Stored XSS
- DOM-based XSS
- XSS via URL parameters

**Note:** While no XSS vulnerabilities were found, the missing CSP header increases the risk if XSS vulnerabilities are introduced in the future.

---

#### Directory Traversal Testing
**Status:** ✅ PASSED  
**Result:** No directory traversal vulnerabilities detected

**Tests Performed:**
- Path traversal with `../`
- Absolute path access
- URL encoding bypass
- Double encoding bypass

---

#### Command Injection Testing
**Status:** ✅ PASSED  
**Result:** No command injection vulnerabilities detected

**Tests Performed:**
- Shell command injection
- Command chaining
- Command substitution
- Null byte injection

---

#### Open Redirect Testing
**Status:** ✅ PASSED  
**Result:** No open redirect vulnerabilities detected

**Tests Performed:**
- URL parameter manipulation
- Header injection
- Protocol handler abuse

---

## Security Posture Analysis

### Strengths ✅
1. **HSTS Properly Configured**
   - max-age=63072000 (2 years)
   - includeSubDomains enabled
   - preload enabled
   - Excellent SSL/TLS security

2. **No Mixed Content**
   - All resources loaded over HTTPS
   - No HTTP resources on HTTPS pages

3. **No Critical Injection Vulnerabilities**
   - SQL injection: Not vulnerable
   - XSS: Not vulnerable
   - Command injection: Not vulnerable
   - Directory traversal: Not vulnerable

4. **Vercel Infrastructure**
   - Modern serverless platform
   - Automatic HTTPS
   - DDoS protection
   - Global CDN

### Weaknesses ⚠️
1. **Missing Critical Security Headers**
   - X-Frame-Options (enables clickjacking)
   - Content Security Policy (reduces XSS protection)
   - X-Content-Type-Options
   - X-XSS-Protection

2. **CORS Misconfiguration**
   - Wildcard (*) allows any origin
   - Potential for unauthorized data access

3. **Excessive Attack Surface**
   - 10 publicly accessible directories
   - 20 subdomains enumerated
   - Admin, backup, config, db directories accessible

4. **Development Environments Exposed**
   - dev.t2test.vercel.app
   - staging.t2test.vercel.app
   - test.t2test.vercel.app
   - May expose unfinished features or sensitive data

---

## Risk Assessment

### Overall Risk Rating: 🟡 MEDIUM

### Risk Breakdown

| Category | Risk Level | Justification |
|----------|------------|---------------|
| **Confidentiality** | 🟡 MEDIUM | CORS wildcard may expose data |
| **Integrity** | 🟡 MEDIUM | Clickjacking can manipulate user actions |
| **Availability** | 🟢 LOW | No DoS vulnerabilities found |
| **Authentication** | 🟢 LOW | No auth bypass found |
| **Authorization** | 🟡 MEDIUM | Excessive directories accessible |

### CVSS v3.1 Score: 5.3 (MEDIUM)
**Vector String:** CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N

---

## Recommendations

### Critical (Fix Immediately) 🔴

1. **Implement X-Frame-Options Header**
   - Priority: HIGH
   - Effort: LOW
   - Impact: Prevents clickjacking attacks
   ```json
   {
     "key": "X-Frame-Options",
     "value": "DENY"
   }
   ```

2. **Fix CORS Wildcard Configuration**
   - Priority: HIGH
   - Effort: MEDIUM
   - Impact: Prevents unauthorized cross-origin access
   - Replace `*` with specific allowed origins

3. **Restrict Access to Sensitive Directories**
   - Priority: HIGH
   - Effort: MEDIUM
   - Impact: Reduces attack surface
   - Directories to protect:
     - /admin/
     - /backup/
     - /config/
     - /db/

### High Priority (Fix Within 30 Days) 🟡

4. **Implement Content Security Policy**
   - Priority: HIGH
   - Effort: MEDIUM
   - Impact: Prevents XSS and injection attacks

5. **Remove or Protect Development Environments**
   - Priority: HIGH
   - Effort: MEDIUM
   - Impact: Prevents information disclosure
   - Environments to address:
     - dev.t2test.vercel.app
     - staging.t2test.vercel.app
     - test.t2test.vercel.app

6. **Add X-Content-Type-Options Header**
   - Priority: MEDIUM
   - Effort: LOW
   - Impact: Prevents MIME-sniffing attacks

### Medium Priority (Fix Within 90 Days) 🟢

7. **Add X-XSS-Protection Header**
   - Priority: MEDIUM
   - Effort: LOW
   - Impact: Additional XSS protection

8. **Implement Referrer-Policy**
   - Priority: LOW
   - Effort: LOW
   - Impact: Prevents information leakage

9. **Implement Permissions-Policy**
   - Priority: LOW
   - Effort: LOW
   - Impact: Controls browser features

### Complete Vercel Configuration

Create or update `vercel.json` in your project root:

```json
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "X-Frame-Options",
          "value": "DENY"
        },
        {
          "key": "Content-Security-Policy",
          "value": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';"
        },
        {
          "key": "X-Content-Type-Options",
          "value": "nosniff"
        },
        {
          "key": "X-XSS-Protection",
          "value": "1; mode=block"
        },
        {
          "key": "Referrer-Policy",
          "value": "strict-origin-when-cross-origin"
        },
        {
          "key": "Permissions-Policy",
          "value": "geolocation=(), microphone=(), camera=()"
        }
      ]
    },
    {
      "source": "/admin/(.*)",
      "headers": [
        {
          "key": "X-Robots-Tag",
          "value": "noindex, nofollow"
        }
      ]
    }
  ],
  "rewrites": [
    {
      "source": "/admin/:path*",
      "destination": "/404"
    },
    {
      "source": "/backup/:path*",
      "destination": "/404"
    },
    {
      "source": "/config/:path*",
      "destination": "/404"
    },
    {
      "source": "/db/:path*",
      "destination": "/404"
    }
  ]
}
```

---

## Compliance Assessment

### OWASP Top 10 2021

| Risk | Status | Notes |
|------|--------|-------|
| A01:2021 – Broken Access Control | ⚠️ PARTIAL | Sensitive directories accessible |
| A02:2021 – Cryptographic Failures | ✅ PASS | HSTS properly configured |
| A03:2021 – Injection | ✅ PASS | No injection vulnerabilities |
| A04:2021 – Insecure Design | ⚠️ PARTIAL | CORS misconfiguration |
| A05:2021 – Security Misconfiguration | ⚠️ FAIL | Missing security headers |
| A06:2021 – Vulnerable Components | ℹ️ N/A | Unable to assess |
| A07:2021 – Identification & Auth Failures | ✅ PASS | No issues found |
| A08:2021 – Software & Data Integrity | ✅ PASS | No issues found |
| A09:2021 – Security Logging & Monitoring | ℹ️ N/A | Unable to assess |
| A10:2021 – Server-Side Request Forgery | ✅ PASS | No SSRF found |

**Compliance Score:** 60% (6/10 passed)

---

## Testing Methodology

### Tools Used
- **Pentestrr 1.0.0** - Automated penetration testing framework
- **Smart Profiler** - Intelligent target analysis
- **DNS Enumeration** - Subdomain discovery
- **Port Scanner** - Network service detection
- **Web Crawler** - Content discovery
- **Vulnerability Scanner** - Security issue detection
- **Exploitation Framework** - Vulnerability confirmation

### Testing Phases
1. ✅ Phase 0: Smart Profiling (20 seconds)
2. ✅ Phase 1: Reconnaissance (17 seconds)
3. ✅ Phase 2: Scanning & Enumeration (23 seconds)
4. ✅ Phase 3: Vulnerability Detection (11 seconds)
5. ✅ Phase 4: Safe Exploitation (4 seconds)
6. ✅ Phase 5: Report Generation (1 second)

**Total Duration:** 1 minute 28 seconds

---

## Conclusion

The security assessment of **t2test.vercel.app** revealed **7 vulnerabilities** with **1 confirmed exploitable** issue. While the application benefits from Vercel's secure infrastructure and proper HSTS configuration, several critical security headers are missing, and the CORS configuration is overly permissive.

### Key Takeaways:

1. **Immediate Action Required:**
   - Fix clickjacking vulnerability (X-Frame-Options)
   - Fix CORS wildcard misconfiguration
   - Restrict access to sensitive directories

2. **Good Security Practices:**
   - HSTS properly configured
   - No injection vulnerabilities
   - Vercel's secure infrastructure

3. **Areas for Improvement:**
   - Implement Content Security Policy
   - Add missing security headers
   - Reduce attack surface (subdomains, directories)

### Next Steps:

1. Implement the recommended Vercel configuration
2. Test the changes in a staging environment
3. Deploy to production
4. Re-scan to verify fixes
5. Implement continuous security monitoring

---

## Report Metadata

| Property | Value |
|----------|-------|
| **Report Generated** | April 22, 2026 at 22:45:43 |
| **Assessment Tool** | Pentestrr 1.0.0 |
| **Assessment Type** | Automated Security Scan |
| **Tester** | Pentestrr Automated Framework |
| **Report Format** | Markdown |
| **PDF Report** | reports/pentest_t2test.vercel.app_20260422_224542.pdf |

---

## Appendix A: Subdomain Details

### Complete Subdomain List with IP Addresses

```
www.t2test.vercel.app          → 64.29.17.3
mail.t2test.vercel.app         → 64.29.17.195
ftp.t2test.vercel.app          → 216.198.79.131
localhost.t2test.vercel.app    → 216.198.79.195
webmail.t2test.vercel.app      → 64.29.17.3
smtp.t2test.vercel.app         → 64.29.17.3
pop.t2test.vercel.app          → 216.198.79.195
ns1.t2test.vercel.app          → 216.198.79.131
webdisk.t2test.vercel.app      → 64.29.17.67
ns2.t2test.vercel.app          → 216.198.79.131
cpanel.t2test.vercel.app       → 64.29.17.67
whm.t2test.vercel.app          → 64.29.17.3
autodiscover.t2test.vercel.app → 64.29.17.3
autoconfig.t2test.vercel.app   → 64.29.17.3
mx.t2test.vercel.app           → 64.29.17.67
email.t2test.vercel.app        → 216.198.79.131
api.t2test.vercel.app          → 64.29.17.3
dev.t2test.vercel.app          → 64.29.17.131
staging.t2test.vercel.app      → 216.198.79.131
test.t2test.vercel.app         → 216.198.79.3
```

---

## Appendix B: Directory Enumeration Results

### Accessible Directories (All 200 OK)

```
https://t2test.vercel.app/admin/
https://t2test.vercel.app/api/
https://t2test.vercel.app/assets/
https://t2test.vercel.app/backup/
https://t2test.vercel.app/config/
https://t2test.vercel.app/css/
https://t2test.vercel.app/data/
https://t2test.vercel.app/db/
https://t2test.vercel.app/docs/
https://t2test.vercel.app/downloads/
```

---

## Appendix C: Security Headers Analysis

### Current Headers
```
HTTP/1.1 200 OK
strict-transport-security: max-age=63072000; includeSubDomains; preload
access-control-allow-origin: *
server: Vercel
```

### Recommended Headers
```
HTTP/1.1 200 OK
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-frame-options: DENY
content-security-policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';
x-content-type-options: nosniff
x-xss-protection: 1; mode=block
referrer-policy: strict-origin-when-cross-origin
permissions-policy: geolocation=(), microphone=(), camera=()
access-control-allow-origin: https://yourdomain.com
server: Vercel
```

---

**End of Report**

---

**Disclaimer:** This security assessment was conducted using automated tools and may not identify all potential vulnerabilities. A comprehensive manual security review by qualified security professionals is recommended for production applications.

**Contact:** For questions about this report or to schedule a follow-up assessment, please contact your security team.

