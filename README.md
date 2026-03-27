<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=32&pause=1000&color=FF0000&center=true&vCenter=true&width=700&lines=BugScanner+%F0%9F%94%8D;Professional+Web+Security+Scanner;OWASP+Top+10+%7C+Zero-Day+AI+%7C+CVE+Scanner" alt="Typing SVG" />

<br/>

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-000000?style=for-the-badge&logo=owasp&logoColor=white)](https://owasp.org/)
[![NVD](https://img.shields.io/badge/NVD-CVE%20Database-red?style=for-the-badge)](https://nvd.nist.gov/)
[![AI](https://img.shields.io/badge/AI-GPT4%20%7C%20Claude%20%7C%20Ollama-blueviolet?style=for-the-badge)](/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![EC-Council](https://img.shields.io/badge/EC--Council-Bug%20Bounty-red?style=for-the-badge)](https://www.eccouncil.org/)
[![Modules](https://img.shields.io/badge/Modules-16%20Scanners-blueviolet?style=for-the-badge)](/)
[![Reports](https://img.shields.io/badge/Reports-PDF%20%2B%20Markdown-orange?style=for-the-badge)](/)

<br/>

```
 ██████╗ ██╗   ██╗ ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
 ██╔══██╗██║   ██║██╔════╝ ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
 ██████╔╝██║   ██║██║  ███╗███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
 ██╔══██╗██║   ██║██║   ██║╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
 ██████╔╝╚██████╔╝╚██████╔╝███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
 ╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
```

### *The Ultimate Web Security Scanner — OWASP Top 10 · Zero-Day AI · CVE Intelligence · Port Scanner*

<br/>

> ⚠️ **For authorized security testing only. Use responsibly on targets you own or have written permission to test.**

</div>

---

## 🚀 What's New in v2.0

BugScanner now has a full **Phase-0 Intelligence Pipeline** that runs automatically before any vulnerability testing. Just give it a URL — it does everything:

| Phase | Module | What It Finds |
|-------|--------|---------------|
| 0-A | **Reconnaissance** | IP, DNS records, Whois, Geolocation, HTTP headers, WAF detection |
| 0-B | **Port Scanner** | 70+ TCP ports, service banners, dangerous exposure detection |
| 0-C | **Tech Detector** | CMS, web frameworks, server software, JS libraries, CDNs (80+ signatures) |
| 0-D | **CVE Scanner** | NVD CVE database lookup + active exploit tests for detected systems |
| 1   | **Vuln Modules** | OWASP Top 10: SQLi, XSS, LFI, SSRF, XXE, IDOR, RCE, JWT, Headers… |
| 2   | **AI Zero-Day** | GPT-4 / Claude / Ollama — novel payload generation & behavior analysis |

---

## ✨ Features

### 🔍 Phase-0: Auto Intelligence Gathering
- **IP resolution** + reverse DNS + ASN/ISP geolocation (ip-api.com, free)
- **DNS records**: A, AAAA, MX, NS, TXT, CNAME, SOA via dnspython
- **Whois** registration data (registrar, expiry, nameservers, org)
- **SSL/TLS** certificate analysis (subject, issuer, SANs, expiry warnings)
- **WAF detection**: Cloudflare, Akamai, AWS WAF, ModSecurity, Sucuri, F5 BIG-IP, Imperva, Wordfence, Barracuda

### 🔌 TCP Port Scanner
- Scans 70+ common ports concurrently (50 threads by default)
- Service banner grabbing (FTP, SSH, HTTP, Redis, MySQL, etc.)
- Flags **CRITICAL** for internet-exposed datastores (MongoDB, Redis, Elasticsearch, etc.)
- Flags **HIGH** for dangerous services (RDP, SMB, MySQL, MSSQL, VNC, etc.)

### 🧬 Technology Detector (80+ signatures)
- **CMS**: WordPress, Joomla, Drupal, Magento, Shopify, Ghost, OpenCart, PrestaShop…
- **Frameworks**: Laravel, Django, Rails, ASP.NET, Spring Boot, Next.js, React, Vue, Flask…
- **Servers**: Nginx, Apache, IIS, LiteSpeed, Tomcat, WebLogic, JBoss, Caddy
- **Languages**: PHP (version), Python, Node.js, Java
- **JS Libraries**: jQuery, Bootstrap, Lodash, Chart.js, D3.js, Three.js…
- **CDN**: Cloudflare, Fastly, AWS CloudFront
- **Analytics**: Google Analytics/GTM, Hotjar, Mixpanel, Facebook Pixel
- Version extraction from headers, meta tags, and script URLs

### 🔥 CVE Scanner
- Queries **NIST NVD API v2.0** (free, no key required)
- Maps detected software + versions → CVEs sorted by CVSS score
- **Active exploit tests** for critical known vulnerabilities:
  - CVE-2018-7600 (Drupalgeddon2 RCE)
  - CVE-2021-3129 (Laravel Ignition RCE)
  - CVE-2022-22965 (Spring4Shell RCE)
  - CVE-2021-44228 (Log4Shell)
  - CVE-2015-8562 (Joomla RCE)
  - WordPress XML-RPC abuse + user enumeration
  - Exposed phpMyAdmin, Elasticsearch, MongoDB panels

### 🤖 AI Zero-Day Engine
- **OpenAI GPT-4o/GPT-4-turbo** — requires API key
- **Anthropic Claude Opus/Sonnet** — requires API key
- **Ollama (100% free, local)** — llama3.2, deepseek-r1, mistral, qwen2.5-coder, phi3, gemma2, codellama
- 7-phase analysis: crawl → response audit → payload gen → source audit → behavior diff → business logic → exploit chain

### 🛡 OWASP Top 10 Vulnerability Modules
| Module | Covers |
|--------|--------|
| `sqli` | SQL Injection (OWASP A03) |
| `xss` | Cross-Site Scripting (OWASP A03) |
| `ssrf` | Server-Side Request Forgery (OWASP A10) |
| `lfi` | Local File Inclusion / Path Traversal (OWASP A05) |
| `xxe` | XXE Injection (OWASP A04) |
| `cmdi` | Command Injection (OWASP A03) |
| `idor` | Insecure Direct Object Reference (OWASP A01) |
| `jwt` | JWT Attacks / Broken Authentication (OWASP A02) |
| `headers` | Security Headers / Misconfigurations (OWASP A05) |
| `open_redirect` | Open Redirect (OWASP A10) |
| `payment` | Payment / Balance Bypass (OWASP A01) |
| `php` | PHP Arsenal: DB dumps, webshell upload, file access (OWASP A05) |

---

## 📦 Installation

### Quick Install (Linux/Mac)
```bash
git clone https://github.com/faizzyhon/bugscanner
cd bugscanner
pip install -r requirements.txt
python main.py --help
```

### Linux Installer (auto-installs, adds to PATH)
```bash
chmod +x install.sh
./install.sh
# Then use from anywhere:
bugscanner scan --target https://target.com --i-have-permission
```

### Windows Installer
```batch
install.bat
# Creates desktop shortcuts for CLI and Web GUI
```

### Docker (quick test environment)
```bash
docker run -it python:3.11 bash
pip install requests beautifulsoup4 click rich flask dnspython python-whois
python main.py scan --target https://example.com --i-have-permission
```

---

## 🖥 Usage

### Web GUI (Recommended)
```bash
python web_gui.py
# Opens http://localhost:5000 in your browser automatically
```

The Web GUI includes a dedicated **🔍 Intel tab** showing:
- Live IP / Geo / DNS / Whois / SSL / WAF data
- Open ports table with risk levels
- Detected technology stack
- CVE findings from NVD database

### CLI — Full Auto-Scan (just a URL)
```bash
python main.py scan \
  --target https://target.com \
  --i-have-permission
```
This automatically runs: Recon → Port Scan → Tech Detection → CVE Lookup → All Vulnerability Modules

### CLI — Quick Recon Only
```bash
python main.py scan \
  --target https://target.com \
  --modules headers \
  --i-have-permission
# Full Phase-0 runs regardless; use --skip-recon to disable
```

### CLI — Specific Modules
```bash
python main.py scan \
  --target https://target.com \
  --modules sqli,xss,lfi,cmdi \
  --i-have-permission
```

### CLI — With AI Zero-Day (Ollama, free)
```bash
python main.py scan \
  --target https://target.com \
  --ai-provider ollama \
  --ai-model deepseek-r1 \
  --i-have-permission
```

### CLI — With AI Zero-Day (OpenAI)
```bash
python main.py scan \
  --target https://target.com \
  --ai-key sk-YOUR_OPENAI_KEY \
  --ai-provider openai \
  --ai-model gpt-4o \
  --i-have-permission
```

### CLI — With Authentication
```bash
python main.py scan \
  --target https://target.com \
  --username admin \
  --password secret \
  --auth-type form \
  --i-have-permission
```

### CLI — Skip Intelligence Phase (faster)
```bash
python main.py scan \
  --target https://target.com \
  --skip-recon \
  --modules sqli,xss \
  --i-have-permission
```

### CLI — Port Scan Only (skip vuln modules)
```bash
python main.py scan \
  --target https://target.com \
  --modules headers \
  --skip-ports \
  --i-have-permission
```

---

## 📊 Output & Reports

All reports are saved to `./reports/` (or custom `--output` path):
- **PDF report** — Full professional report with findings, CVSS scores, remediation
- **Markdown report** — Machine-readable, suitable for GitHub issues

```bash
# Custom output directory
python main.py scan --target https://target.com --output /tmp/pentest/ --i-have-permission

# Skip PDF (faster, markdown only)
python main.py scan --target https://target.com --no-pdf --i-have-permission
```

---

## 🔧 All CLI Options

```
python main.py scan [OPTIONS]

Required:
  --target / -t TEXT          Target URL
  --i-have-permission         Confirm authorization (required)

Intelligence:
  --skip-recon                Skip Phase-0 (recon/ports/tech/CVE)
  --skip-ports                Skip port scan only
  --nvd-key TEXT              NIST NVD API key (optional, increases rate limits)

Modules:
  --modules / -m TEXT         Comma-separated modules or 'all' (default: all)
                              Values: recon,ports,tech,cve,sqli,xss,lfi,xxe,
                                      ssrf,cmdi,idor,jwt,headers,open_redirect,
                                      payment,php

AI Zero-Day:
  --ai-key TEXT               OpenAI (sk-...) or Anthropic (sk-ant-...) API key
  --ai-provider               auto|openai|anthropic|ollama
  --ai-model TEXT             Model name (gpt-4o, claude-opus-4-5, deepseek-r1...)
  --ollama-host TEXT          Ollama URL (default: http://localhost:11434)
  --ai-only                   Run only AI engine (skip standard modules)

Authentication:
  --username / -u TEXT        Login username
  --password / -p TEXT        Login password
  --login-url TEXT            Explicit login page URL
  --auth-type                 auto|form|json|basic

Output:
  --output / -o TEXT          Reports directory (default: ./reports)
  --no-pdf                    Skip PDF generation
  --format                    pdf|markdown|both (default: both)

Advanced:
  --timeout INT               HTTP timeout in seconds (default: 10)
  --threads INT               Concurrent threads (default: 5)
  --depth INT                 Crawl depth (default: 2)
  --cookies TEXT              Cookie string 'name=val; name2=val2'
  --headers-extra TEXT        JSON headers string
  --verbose / -v              Verbose output
```

---

## 🏗 Architecture

```
bugscanner/
├── main.py                    # CLI entry point + phased scan pipeline
├── web_gui.py                 # Flask web GUI with SSE streaming
├── scanners/
│   ├── base.py                # BaseScanner + Finding dataclass
│   ├── recon.py               # Phase-0A: IP/DNS/Whois/Geo/WAF          ← NEW
│   ├── port_scanner.py        # Phase-0B: TCP port scan + banners        ← NEW
│   ├── tech_detector.py       # Phase-0C: 80+ tech signatures            ← NEW
│   ├── cve_scanner.py         # Phase-0D: NVD CVE + exploit tests        ← NEW
│   ├── sqli.py                # SQL Injection
│   ├── xss.py                 # Cross-Site Scripting
│   ├── ssrf.py                # SSRF
│   ├── lfi.py                 # LFI / Path Traversal
│   ├── xxe.py                 # XXE Injection
│   ├── cmdi.py                # Command Injection
│   ├── idor.py                # IDOR
│   ├── jwt_check.py           # JWT Attacks
│   ├── headers.py             # Security Headers
│   ├── open_redirect.py       # Open Redirect
│   ├── payment_bypass.py      # Payment Bypass
│   ├── php_specific.py        # PHP Arsenal
│   └── ai_scanner.py          # AI Zero-Day Engine
├── utils/
│   ├── http_client.py         # HTTP client with retry + cookie handling
│   ├── auth.py                # Authentication manager (form/JSON/Basic)
│   ├── scope.py               # Scope validator
│   └── logger.py              # Logger setup
├── reporter/
│   └── generator.py           # PDF + Markdown report generation
├── requirements.txt
├── install.sh                 # Linux/Mac installer
├── install.bat                # Windows installer
├── run_web.sh                 # Linux quick-launch web GUI
└── run_web.bat                # Windows quick-launch web GUI
```

---

## 🔍 Phase-0 Intelligence Pipeline Detail

When you give BugScanner any URL, it automatically:

1. **Resolves IP** — `socket.gethostbyname()`, reverse DNS, geolocates via ip-api.com
2. **Pulls DNS** — A, AAAA, MX, NS, TXT, CNAME, SOA records via dnspython
3. **Whois lookup** — Registrar, creation/expiry dates, nameservers, org via python-whois
4. **HTTP headers** — Server, X-Powered-By, security headers audit
5. **SSL/TLS** — Certificate subject, issuer, SANs, expiry check
6. **WAF detection** — Probes with `<script>alert(1)</script>` and checks 10 WAF signatures
7. **Port scan** — 70 common ports, 50 concurrent threads, 2.5s timeout per port
8. **Banner grab** — HTTP HEAD, Redis PING, FTP/SSH greeting banners
9. **Tech fingerprint** — 80+ patterns across headers, body, cookies, meta tags, script URLs
10. **CVE lookup** — NVD API v2.0 for each detected technology, sorted by CVSS
11. **Exploit test** — Active PoC tests for: Drupalgeddon2, Laravel Ignition, Spring4Shell, Log4Shell, Joomla RCE, WordPress XMLRPC, phpMyAdmin exposure, Elasticsearch/MongoDB no-auth

All data is saved to the report AND streamed live to the Web GUI Intel tab.

---

## 🤖 AI Providers

| Provider | Cost | Setup | Best For |
|----------|------|-------|---------|
| Ollama (local) | **FREE** | `ollama pull deepseek-r1` | Privacy, no limits |
| OpenAI GPT-4o | ~$0.01/scan | API key | Best accuracy |
| Anthropic Claude | ~$0.01/scan | API key | Long context |

### Install Ollama (Linux)
```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull deepseek-r1       # best for security reasoning
ollama pull qwen2.5-coder:7b  # best for source code audit
ollama pull llama3.2          # fastest general purpose
```

---

## 🧑‍💻 Author

**Muhammad Faizan** — Bug Bounty Researcher & Security Engineer
GitHub: [@faizzyhon](https://github.com/faizzyhon)
Email: faizzyhon@gmail.com
EC-Council Certified Ethical Hacker

---

## ⚖️ Legal Disclaimer

This tool is provided for **authorized security testing only**.

- Only use on targets you own or have **explicit written permission** to test
- Unauthorized scanning is **illegal** under CFAA, Computer Misuse Act, and similar laws
- The author accepts no responsibility for misuse

**You must use `--i-have-permission` flag to acknowledge authorization before any scan.**
