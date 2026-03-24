<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=32&pause=1000&color=FF0000&center=true&vCenter=true&width=600&lines=BugScanner+%F0%9F%94%8D;Professional+Web+Security+Scanner;OWASP+Top+10+%7C+Bug+Bounty+%7C+PHP+Exploitation" alt="Typing SVG" />

<br/>

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-000000?style=for-the-badge&logo=owasp&logoColor=white)](https://owasp.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![EC-Council](https://img.shields.io/badge/EC--Council-Bug%20Bounty-red?style=for-the-badge)](https://www.eccouncil.org/)
[![Modules](https://img.shields.io/badge/Modules-12%20Scanners-blueviolet?style=for-the-badge)](/)
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

### *The Ultimate PHP Web Security Scanner for Bug Bounty & Penetration Testing*

<br/>

> ⚠️ **For authorized security testing only.** Use responsibly.

</div>

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Scanner Modules](#-scanner-modules)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Usage](#-usage)
- [Authentication](#-authentication)
- [PHP Exploitation Module](#-php-exploitation-module)
- [Payment Bypass Module](#-payment-bypass-module)
- [Report Generation](#-report-generation)
- [Target Analysis](#-target-analysis)
- [OWASP Coverage](#-owasp-coverage)
- [Legal Disclaimer](#-legal-disclaimer)
- [Author](#-author)

---

## 🔍 Overview

**BugScanner** is a professional-grade, modular Python web vulnerability scanner engineered for **bug bounty hunters**, **penetration testers**, and **security researchers**. Built specifically around the **OWASP Top 10 (2021)** framework, it combines automated detection with deep PHP-specific exploitation capabilities.

Unlike generic scanners, BugScanner is **source-intelligence driven** — it can parse target JavaScript and HTML source files to extract exact API endpoints, response codes, and parameter names, then surgically craft tests against the real attack surface instead of guessing blindly.

```
Target JS/HTML Analysis → API Surface Map → Surgical Exploitation → HackerOne-Grade Report
```

**Designed for:**
- EC-Council Bug Bounty Course assignments
- HackerOne / Bugcrowd submissions
- CTF Lab environments
- Authorized penetration testing engagements

---

## ✨ Key Features

| Feature | Description |
|--------|-------------|
| 🧠 **Source Intelligence** | Parse JS/HTML to extract real API endpoints and response codes |
| 🔐 **Auto Authentication** | Auto-detects login forms, CSRF tokens, handles PHP response codes |
| 📋 **12 Scan Modules** | Full OWASP Top 10 coverage + PHP-specific + Payment Bypass |
| 📄 **Dual Reports** | Professional PDF + Markdown in HackerOne/Bugcrowd format |
| 🎯 **CVSS 3.1 Scoring** | Every finding gets a CVSS vector and numerical score |
| 🏃 **Race Condition Engine** | Multi-threaded parallel request firing for timing attacks |
| 💾 **DB Dump Module** | UNION SQLi, LOAD_FILE, INTO OUTFILE, phpMyAdmin brute force |
| 🐚 **Webshell Detection** | Probes 20+ shell paths + upload bypass attempts |
| 🪙 **Crypto Payment Bypass** | Business logic tests sourced directly from site JS |
| 🔑 **JWT Attacks** | alg:none, 23 weak secrets, kid path traversal |
| 📡 **SSRF Probing** | AWS/GCP/Azure metadata, internal network |
| 🔒 **Scope Validation** | Blocks RFC-1918 IPs, validates target domain |

---

## 🧩 Scanner Modules

<details>
<summary><b>Click to expand full module details</b></summary>

### Core OWASP Modules

| Module Key | Name | OWASP | CWE | Techniques |
|-----------|------|-------|-----|------------|
| `xxe` | XML External Entity | A4:2021 | CWE-611 | Classic, OOB, SVG, SOAP, blind |
| `sqli` | SQL Injection | A3:2021 | CWE-89 | Error-based, time-based, boolean-blind, UNION (5 DB signatures) |
| `xss` | Cross-Site Scripting | A3:2021 | CWE-79 | 18 reflected payloads, stored, header, DOM sinks |
| `ssrf` | Server-Side Request Forgery | A10:2021 | CWE-918 | AWS/GCP/Azure metadata, internal network, webhooks |
| `idor` | Insecure Direct Object Reference | A1:2021 | CWE-639 | ID enumeration, mass assignment, API enumeration |
| `cmdi` | OS Command Injection | A3:2021 | CWE-78 | Shell metacharacters, time-based blind |
| `lfi` | Local File Inclusion | A5:2021 | CWE-22 | Traversal 2-6 deep, null bytes, double-encoding, PHP wrappers |
| `open_redirect` | Open Redirect | A10:2021 | CWE-601 | 10 bypass variants, form fields, JS DOM sinks |
| `headers` | Security Headers | A5:2021 | CWE-16 | 6 headers, CORS, cookies, 22 sensitive file paths |
| `jwt` | JWT / Broken Auth | A2:2021 | CWE-287 | alg:none, 23 weak secrets, claim manipulation, kid traversal |

### Specialized Modules

| Module Key | Name | OWASP | Key Tests |
|-----------|------|-------|-----------|
| `payment` | Crypto Payment / Balance Bypass | A1:2021 | 15 business-logic tests sourced from allinone.js |
| `php` | PHP-Specific Exploitation | A5:2021 | 13 PHP attack categories (see below) |

</details>

---

## 🏗️ Architecture

```
bugscanner/
│
├── main.py                     # CLI entrypoint (Click + Rich)
│
├── scanners/
│   ├── base.py                 # BaseScanner + Finding dataclass
│   ├── xxe.py                  # XML External Entity
│   ├── sqli.py                 # SQL Injection
│   ├── xss.py                  # Cross-Site Scripting
│   ├── ssrf.py                 # Server-Side Request Forgery
│   ├── idor.py                 # Insecure Direct Object Reference
│   ├── cmdi.py                 # OS Command Injection
│   ├── lfi.py                  # Local File Inclusion
│   ├── open_redirect.py        # Open Redirect
│   ├── headers.py              # Security Headers & Misconfig
│   ├── jwt_check.py            # JWT / Broken Authentication
│   ├── payment_bypass.py       # Crypto Payment Bypass (site-tuned)
│   └── php_specific.py         # PHP Exploitation Suite
│
├── utils/
│   ├── auth.py                 # AuthManager: form/JSON/basic/CSRF
│   ├── http_client.py          # Shared requests.Session wrapper
│   ├── scope.py                # Target scope & IP validation
│   └── logger.py               # Rich logging setup
│
├── reporter/
│   ├── generator.py            # PDF (ReportLab) + Markdown generator
│   └── templates/
│       ├── report.md.j2        # Jinja2 Markdown template
│       └── report.html.j2      # Jinja2 HTML→PDF template
│
├── Target/                     # Drop target JS/HTML here for analysis
│   ├── allinone.js
│   └── ...
│
├── reports/                    # Generated reports land here
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation

### Prerequisites

- Python **3.10+**
- pip

### Quick Setup

```bash
# 1. Clone or download the tool
git clone https://github.com/yourusername/bugscanner.git
cd bugscanner

# 2. Install dependencies
pip install -r requirements.txt

# 3. Verify installation
python main.py list-modules
```

### Dependencies

```
requests>=2.31.0
beautifulsoup4>=4.12.0
lxml>=4.9.0
click>=8.1.0
rich>=13.0.0
Jinja2>=3.1.0
reportlab>=4.0.0
weasyprint>=60.0
```

---

## 🚀 Usage

### Basic Scan

```bash
python main.py scan \
  -t https://target.com \
  --i-have-permission
```

### Full Authenticated Scan

```bash
python main.py scan \
  -t https://target.com \
  --i-have-permission \
  -u your_username \
  -p your_password \
  --verbose
```

### Run Specific Modules

```bash
# PHP exploitation only
python main.py scan -t https://target.com --i-have-permission --modules php

# Payment bypass only
python main.py scan -t https://target.com --i-have-permission -u USER -p PASS --modules payment

# Combined high-value modules
python main.py scan -t https://target.com --i-have-permission -u USER -p PASS \
  --modules php payment sqli lfi --verbose
```

### Test Authentication First

```bash
python main.py test-login \
  -t https://target.com \
  -u your_username \
  -p your_password
```

### List All Modules

```bash
python main.py list-modules
```

### All CLI Options

```
Options:
  -t, --target TEXT           Target URL (required)
  --i-have-permission         Confirm authorization (required)
  -m, --modules CHOICE        Modules to run (default: all)
  -u, --username TEXT         Login username
  -p, --password TEXT         Login password
  --login-url TEXT            Explicit login URL (auto-detected if omitted)
  --auth-type CHOICE          auto|form|json|basic (default: auto)
  -o, --output TEXT           Report output directory (default: ./reports)
  --timeout INTEGER           HTTP timeout in seconds (default: 10)
  --threads INTEGER           Concurrent threads (default: 5)
  --cookies TEXT              Manual cookie string (e.g. 'PHPSESSID=abc')
  --headers-extra TEXT        Extra headers as JSON string
  --depth INTEGER             Crawl depth (default: 2)
  --no-pdf                    Skip PDF generation
  --format CHOICE             pdf|markdown|both (default: both)
  -v, --verbose               Verbose output
```

---

## 🔐 Authentication

BugScanner includes a fully automatic authentication pipeline:

```
1. Auto-detect login URL (scans common paths + LOGIN_URL_PATTERNS)
2. Parse login form → extract field names + CSRF tokens
3. Submit credentials via form POST / JSON / Basic Auth
4. Evaluate response (body text, status code, redirect, JSON token)
5. Apply session cookies + auth headers to ALL subsequent scanner requests
```

### PHP Site-Specific Authentication

For PHP sites returning single-character response codes (e.g., `'5'` = success):

```bash
python main.py scan \
  -t https://php-target.com \
  --i-have-permission \
  --auth-type form \
  --login-url /login.php?login \
  -u YOUR_USERNAME \
  -p YOUR_PASSWORD
```

The auth engine recognizes these response codes automatically:

| Code | Meaning |
|------|---------|
| `5` | Login success |
| `3` | No such account |
| `0` | IP rate-limited |
| `1` | Username rate-limited |

---

## 🐘 PHP Exploitation Module

The `php` module targets 13 attack categories specific to PHP applications:

```bash
python main.py scan -t https://target.com --i-have-permission --modules php --verbose
```

### What It Tests

| # | Test | Severity | Description |
|---|------|----------|-------------|
| 1 | **PHPInfo Exposure** | HIGH | Probes 6 phpinfo paths, extracts PHP version |
| 2 | **Version Header Disclosure** | LOW | X-Powered-By / Server header leak |
| 3 | **Sensitive File Exposure** | CRITICAL | 50+ paths: `.env`, `config.php`, `database.sql`, `.git`, backups |
| 4 | **DB Admin Panel Discovery** | CRITICAL | phpMyAdmin, Adminer, SQLiteManager (15 paths) |
| 5 | **Pre-existing Web Shells** | CRITICAL | 20+ known shell signatures (c99, r57, WSO, b374k) |
| 6 | **PHP Error Mode** | MEDIUM | Triggers errors to expose file paths and stack traces |
| 7 | **PHP Object Injection** | CRITICAL | Unserialize gadget chain detection |
| 8 | **Remote File Inclusion** | CRITICAL | data:// wrapper RFI with execution verification |
| 9 | **LFI + PHP Filter Wrappers** | CRITICAL | `php://filter/base64-encode` to read PHP source files |
| 10 | **SQL Injection → DB Dump** | CRITICAL | UNION, error-based, `LOAD_FILE()`, `INTO OUTFILE` |
| 11 | **phpMyAdmin Default Creds** | CRITICAL | Tests 9 default credential pairs |
| 12 | **Server-Side Template Injection** | CRITICAL | Twig, Smarty, ERB expression evaluation |
| 13 | **Webshell Upload** | CRITICAL | Extension bypass, Content-Type spoofing, null byte, .htaccess |

### PHP Filter Wrapper — Read Source Code

```
GET /index.php?page=php://filter/convert.base64-encode/resource=config.php
              → Base64 blob → decoded PHP source with DB credentials
```

### MySQL File Operations via SQLi

```sql
-- Read server files (requires FILE privilege)
' UNION SELECT LOAD_FILE('/etc/passwd'),2,3-- -
' UNION SELECT LOAD_FILE('/var/www/html/config.php'),2,3-- -

-- Write webshell (requires write permission on webroot)
' UNION SELECT '<?php system($_GET[cmd]); ?>' INTO OUTFILE '/var/www/html/x.php'-- -
```

---

## 💰 Payment Bypass Module

The `payment` module was purpose-built for PHP e-commerce / crypto deposit sites, with tests reverse-engineered directly from real JavaScript source analysis.

```bash
python main.py scan -t https://target.com --i-have-permission -u USER -p PASS \
  --modules payment --verbose
```

### 15 Business Logic Tests

| # | Test | Priority | Vector |
|---|------|----------|--------|
| 1 | **Payment Type Enumeration** | HIGH | `GET /money_add.php?type=0/-1/999` |
| 2 | **Force-Confirm Order (IDOR)** | 🔴 CRITICAL | `GET /money_view.php?check_order=<id>` |
| 3 | **Cross-User Order Takeover** | 🔴 CRITICAL | Sequential order ID enumeration |
| 4 | **Fake Transaction Hash** | CRITICAL | Submit fake LTC/BTC hash to deposit endpoint |
| 5 | **Amount Parameter Injection** | MEDIUM | `amount=9999` alongside payment type |
| 6 | **Direct Balance Manipulation** | CRITICAL | `/info.php?set_balance=9999` |
| 7 | **Quick Buy with Zero Balance** | CRITICAL | `POST /cc_buy.php?buy_one` |
| 8 | **Basket Buy with Low Balance** | CRITICAL | `GET /cc_basket.php?buy` |
| 9 | **Bulk Cart Duplicate IDs** | MEDIUM | Send same `id[]` 20× in one request |
| 10 | **Transaction History IDOR** | HIGH | `get_history=0/all/'` |
| 11 | **Purchased Card IDOR** | CRITICAL | `get_card=<other_user_id>` |
| 12 | **Card Data IDOR** | CRITICAL | `get_card_data=<id>` without purchase |
| 13 | **Password Change No-Auth** | CRITICAL | `POST /ch_password.php` with empty/wrong password |
| 14 | **Race Condition** | CRITICAL | 10 parallel `check_order` requests |
| 15 | **Session Cookie Flags** | MEDIUM | PHPSESSID HttpOnly/Secure/SameSite audit |

---

## 📄 Report Generation

Every scan automatically produces two professional reports:

```
reports/
└── bugscanner_target.com_20240324_143052/
    ├── report.pdf          ← Professional PDF with cover page
    └── report.md           ← Markdown for Bugcrowd/HackerOne submission
```

Each finding includes:
- **Title** and **Severity** (CRITICAL / HIGH / MEDIUM / LOW / INFO)
- **CVSS 3.1 Score** and **Vector String**
- **OWASP Category** and **CWE Reference**
- **Proof of Concept** — exact URL, parameter, payload
- **Evidence** — response excerpts confirming the vulnerability
- **Impact** — real-world exploitation scenario
- **Remediation** — specific fix with code examples

---

## 🔬 Target Analysis

Drop the target website's JS/HTML files into the `Target/` folder to enable **source intelligence mode**. BugScanner extracts:

- All AJAX endpoint URLs and HTTP methods
- POST field names and expected response codes
- Client-side validation logic (to bypass server-side)
- DOM XSS sinks (`.html()`, `.append()` with server data)

**Endpoints extracted from EC-Council CVV HUB training target:**

```
POST /login.php?login              response: '5'=ok, '3'=no-acct, '0'=ip-ban
GET  /info.php?get_balance         returns: "0,91" comma-decimal format
GET  /money_add.php?type=<1-5>     type 5 = USDT min $50
GET  /money_view.php?check_order=  HIGH VALUE: returns '1' = payment confirmed
POST /cc_buy.php?buy_one           response: 3=bought, 2=low-bal, 0=err
GET  /cc_basket.php?buy            response: '3'=bought
POST /ch_password.php              returns new auto-generated password!
```

---

## 📊 OWASP Coverage

```
OWASP Top 10 (2021) — 10/10 ████████████████████ 100%

A1  Broken Access Control      ████████████████████ IDOR, Payment Bypass, PHP Auth
A2  Cryptographic Failures     ████████████████████ JWT Attacks, Session Flags
A3  Injection                  ████████████████████ SQLi, XSS, CMDi, XXE, RFI, SSTI
A4  Insecure Design            ████████████████████ Payment Business Logic Testing
A5  Security Misconfiguration  ████████████████████ Headers, PHPInfo, DB Admin Panels
A6  Vulnerable Components      ████████████████████ PHP Version Detection, CVE Mapping
A7  Auth Failures              ████████████████████ JWT, Default Creds, PW Bypass
A8  Data Integrity Failures    ████████████████████ PHP Object Injection / Unserialize
A9  Logging & Monitoring       ████████████████████ Error Mode & Debug Exposure
A10 SSRF                       ████████████████████ Cloud Metadata, Internal Network
```

---

## 💡 Advanced Tips

```bash
# Use manually grabbed browser cookies
python main.py scan -t https://target.com --i-have-permission \
  --cookies "PHPSESSID=abc123def456"

# Add custom headers (e.g. bypass WAF, internal routing)
python main.py scan -t https://target.com --i-have-permission \
  --headers-extra '{"X-Forwarded-For": "127.0.0.1"}'

# Maximum coverage attack
python main.py scan -t https://target.com --i-have-permission \
  -u admin -p password \
  --modules php payment sqli lfi idor headers jwt \
  --verbose --format both --output ./my_reports
```

---

## ⚖️ Legal Disclaimer

```
╔═══════════════════════════════════════════════════════╗
║              ⚠  AUTHORIZED USE ONLY ⚠               ║
╠═══════════════════════════════════════════════════════╣
║                                                       ║
║  ✓ Bug bounty programs with explicit written scope    ║
║  ✓ CTF (Capture The Flag) lab environments            ║
║  ✓ Systems you own or have written permission to test ║
║  ✓ EC-Council course lab environments                 ║
║                                                       ║
║  ✗ Unauthorized scanning of third-party systems       ║
║  ✗ Any use violating computer fraud laws (CFAA/CMA)   ║
║  ✗ Malicious exploitation of discovered vulns         ║
║                                                       ║
║  The author assumes NO LIABILITY for misuse.          ║
║  Unauthorized use is a criminal offense worldwide.    ║
╚═══════════════════════════════════════════════════════╝
```

---

<div align="center">

---

## 👨‍💻 Author & Signature

<br/>

```
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║    ███╗   ███╗██╗   ██╗██╗  ██╗ █████╗ ███╗   ███╗███╗   ███╗      ║
║    ████╗ ████║██║   ██║██║  ██║██╔══██╗████╗ ████║████╗ ████║      ║
║    ██╔████╔██║██║   ██║███████║███████║██╔████╔██║██╔████╔██║      ║
║    ██║╚██╔╝██║██║   ██║██╔══██║██╔══██║██║╚██╔╝██║██║╚██╔╝██║      ║
║    ██║ ╚═╝ ██║╚██████╔╝██║  ██║██║  ██║██║ ╚═╝ ██║██║ ╚═╝ ██║      ║
║    ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝     ╚═╝      ║
║                                                                      ║
║    ███████╗ █████╗ ██╗███████╗ █████╗ ███╗   ██╗                   ║
║    ██╔════╝██╔══██╗██║╚════██║██╔══██╗████╗  ██║                   ║
║    █████╗  ███████║██║    ██╔╝███████║██╔██╗ ██║                   ║
║    ██╔══╝  ██╔══██║██║   ██╔╝ ██╔══██║██║╚██╗██║                   ║
║    ██║     ██║  ██║██║   ██║  ██║  ██║██║ ╚████║                   ║
║    ╚═╝     ╚═╝  ╚═╝╚═╝   ╚═╝  ╚═╝  ╚═╝╚═╝  ╚═══╝                   ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║                  Muhammad Faizan                                     ║
║                  ─────────────────────────────                       ║
║                  Cybersecurity Researcher                            ║
║                  Bug Bounty Hunter                                   ║
║                  EC-Council Bug Bounty Student                       ║
║                                                                      ║
║                  📧  faizzyhon@gmail.com                             ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
```

<br/>

[![Email](https://img.shields.io/badge/Email-faizzyhon%40gmail.com-red?style=for-the-badge&logo=gmail&logoColor=white)](mailto:faizzyhon@gmail.com)
[![EC-Council](https://img.shields.io/badge/EC--Council-Bug%20Bounty%20Student-blue?style=for-the-badge)](https://www.eccouncil.org/)
[![Bug Bounty](https://img.shields.io/badge/Status-Active%20Researcher-brightgreen?style=for-the-badge&logo=hackerone)](/)

<br/>

---

```
  ██████╗ ██╗ ██████╗     ███████╗ ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗
  ██╔══██╗██║██╔════╝     ██╔════╝██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝
  ██████╔╝██║██║  ███╗    █████╗  ██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝
  ██╔══██╗██║██║   ██║    ██╔══╝  ██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝
  ██████╔╝██║╚██████╔╝    ██║     ╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║
  ╚═════╝ ╚═╝ ╚═════╝     ╚═╝      ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝

        "The quieter you become, the more you can hear."
                     — hack the planet 🌍 —
```

<br/>

---

*Engineered with 🔥 passion for cybersecurity*
*EC-Council Bug Bounty Course — 2024*

**© 2024 Muhammad Faizan — All Rights Reserved**

*⭐ If this tool helped you find a bug, drop a star!*

</div>
