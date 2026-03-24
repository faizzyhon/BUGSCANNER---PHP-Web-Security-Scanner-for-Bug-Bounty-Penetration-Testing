"""
Security Headers & Misconfiguration Scanner
OWASP A05:2021 — Security Misconfiguration
CWE-16: Configuration / CWE-693: Protection Mechanism Failure

Tests for:
  - Missing/weak security headers (CSP, HSTS, X-Frame-Options, etc.)
  - Information disclosure headers (Server, X-Powered-By, etc.)
  - CORS misconfiguration (wildcard, reflect-origin)
  - Cookie security flags (Secure, HttpOnly, SameSite)
  - Exposed admin/debug endpoints
  - Directory listing
  - Sensitive file exposure (.env, .git, backup files)
  - HTTP methods (TRACE, OPTIONS)
"""

import re
from .base import BaseScanner, Finding


# ── Security header checks ────────────────────────────────────────────────────

REQUIRED_HEADERS = {
    "Strict-Transport-Security": {
        "description": "HTTP Strict Transport Security (HSTS) forces HTTPS connections.",
        "severity": "HIGH",
        "cvss": 7.5,
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "cwe": "CWE-319",
    },
    "Content-Security-Policy": {
        "description": "CSP prevents XSS and data injection by whitelisting content sources.",
        "severity": "HIGH",
        "cvss": 7.1,
        "remediation": "Implement a restrictive CSP: Content-Security-Policy: default-src 'self'; ...",
        "cwe": "CWE-693",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing attacks.",
        "severity": "LOW",
        "cvss": 4.3,
        "remediation": "Add: X-Content-Type-Options: nosniff",
        "cwe": "CWE-16",
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking by controlling iframe embedding.",
        "severity": "MEDIUM",
        "cvss": 6.1,
        "remediation": "Add: X-Frame-Options: DENY or SAMEORIGIN (or use CSP frame-ancestors)",
        "cwe": "CWE-1021",
    },
    "Referrer-Policy": {
        "description": "Controls what information is sent in the Referer header.",
        "severity": "LOW",
        "cvss": 3.7,
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "cwe": "CWE-16",
    },
    "Permissions-Policy": {
        "description": "Restricts access to browser features (camera, microphone, geolocation).",
        "severity": "LOW",
        "cvss": 3.1,
        "remediation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
        "cwe": "CWE-16",
    },
}

WEAK_CSP_PATTERNS = [
    (r"unsafe-inline", "CSP allows 'unsafe-inline' — XSS protection bypassed"),
    (r"unsafe-eval", "CSP allows 'unsafe-eval' — JS code execution possible"),
    (r"\*", "CSP uses wildcard (*) — all origins permitted"),
    (r"data:", "CSP allows data: URIs — XSS bypass possible"),
]

# ── Information disclosure ────────────────────────────────────────────────────

INFO_DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Backend-Server",
    "X-Runtime",
    "X-Version",
]

# ── Sensitive files ───────────────────────────────────────────────────────────

SENSITIVE_FILES = [
    ("/.env", ["DB_PASSWORD", "APP_SECRET", "API_KEY", "SECRET_KEY", "DATABASE_URL"]),
    ("/.git/HEAD", ["ref:", "HEAD"]),
    ("/.git/config", ["[core]", "[remote"]),
    ("/web.config", ["<configuration>", "connectionString"]),
    ("/config.php", ["$db", "mysql_connect", "password"]),
    ("/wp-config.php", ["DB_PASSWORD", "DB_USER", "table_prefix"]),
    ("/database.yml", ["adapter:", "username:", "password:"]),
    ("/.htpasswd", [":"]),
    ("/backup.sql", ["INSERT INTO", "CREATE TABLE"]),
    ("/dump.sql", ["INSERT INTO", "CREATE TABLE"]),
    ("/.DS_Store", ["\x00\x00\x00\x01\x00\x00\x00"]),
    ("/phpinfo.php", ["PHP Version", "php.ini"]),
    ("/server-status", ["Apache Server Status", "Total Requests"]),
    ("/server-info", ["Apache Server Information"]),
    ("/actuator/env", ["activeProfiles", "propertySources"]),
    ("/actuator/health", ["status", "UP"]),
    ("/actuator/dump", ["threads"]),
    ("/.travis.yml", ["language:", "script:"]),
    ("/docker-compose.yml", ["services:", "version:"]),
    ("/Dockerfile", ["FROM ", "RUN "]),
    ("/package.json", ["dependencies", "scripts"]),
    ("/swagger.json", ["swagger", "paths"]),
    ("/openapi.json", ["openapi", "paths"]),
    ("/graphql", ["__schema", "types"]),
]


class HeadersScanner(BaseScanner):
    """Scans for security header misconfigurations and sensitive file exposure."""

    SCANNER_NAME = "Security Headers & Misconfiguration"
    OWASP_CATEGORY = "A05:2021"
    CWE = "CWE-16"

    def run(self) -> list[Finding]:
        self.logger.info(f"Starting Headers/Misconfiguration scan against {self.target}")

        # Fetch the target page
        resp, evidence = self.http.get(self.target)
        if resp:
            self._check_security_headers(resp, evidence)
            self._check_csp_quality(resp, evidence)
            self._check_info_disclosure(resp, evidence)
            self._check_cors(resp)
            self._check_cookies(resp, evidence)

        # Check HTTP methods
        self._check_http_methods()

        # Scan for sensitive files
        self._scan_sensitive_files()

        # Check for directory listing
        self._check_directory_listing()

        return self.findings

    def _check_security_headers(self, resp, evidence):
        """Check for missing security headers."""
        for header, info in REQUIRED_HEADERS.items():
            if header.lower() not in {k.lower() for k in resp.headers.keys()}:
                self.add_finding(Finding(
                    title=f"Missing Security Header: {header}",
                    severity=info["severity"],
                    owasp="A05:2021",
                    cwe=info["cwe"],
                    cvss_score=info["cvss"],
                    cvss_vector=f"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                    url=self.target,
                    parameter=header,
                    payload="(header absent)",
                    description=f"The response is missing the `{header}` security header. {info['description']}",
                    impact=f"Without this header, the application is vulnerable to specific client-side attacks.",
                    remediation=info["remediation"],
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                        "https://securityheaders.com/",
                    ],
                    evidence=evidence,
                    confirmed=True,
                    vuln_type="headers",
                ))

    def _check_csp_quality(self, resp, evidence):
        """Validate Content-Security-Policy quality if present."""
        csp = resp.headers.get("Content-Security-Policy", "")
        if not csp:
            return  # Already reported as missing
        for pattern, desc in WEAK_CSP_PATTERNS:
            if re.search(pattern, csp, re.IGNORECASE):
                self.add_finding(Finding(
                    title=f"Weak Content-Security-Policy: {desc}",
                    severity="MEDIUM",
                    owasp="A05:2021",
                    cwe="CWE-693",
                    cvss_score=6.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    url=self.target,
                    parameter="Content-Security-Policy",
                    payload=csp[:200],
                    description=f"CSP is present but contains a weak directive: {desc}. Current CSP: `{csp[:200]}`",
                    impact="XSS protection may be bypassed despite CSP being present.",
                    remediation="Harden CSP: remove 'unsafe-inline', 'unsafe-eval', wildcards, and data: URIs. Use nonces or hashes.",
                    references=["https://content-security-policy.com/", "https://csp-evaluator.withgoogle.com/"],
                    evidence=evidence,
                    confirmed=True,
                    vuln_type="headers",
                ))

    def _check_info_disclosure(self, resp, evidence):
        """Check for server technology disclosure headers."""
        for header in INFO_DISCLOSURE_HEADERS:
            value = resp.headers.get(header, "")
            if value:
                self.add_finding(Finding(
                    title=f"Information Disclosure via HTTP Header: {header}",
                    severity="LOW",
                    owasp="A05:2021",
                    cwe="CWE-200",
                    cvss_score=3.7,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    url=self.target,
                    parameter=header,
                    payload=value,
                    description=(
                        f"The server discloses technology information in the `{header}` header: `{value}`. "
                        "Attackers can use this to identify known CVEs for the specific version."
                    ),
                    impact="Reconnaissance — narrows attack surface by revealing exact technology stack.",
                    remediation=f"Remove or suppress the `{header}` header in your web server configuration.",
                    references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"],
                    evidence=evidence,
                    confirmed=True,
                    vuln_type="headers",
                ))

    def _check_cors(self, resp):
        """Check for CORS misconfiguration."""
        # Test with a cross-origin header
        origin = "https://evil-attacker.example.com"
        resp2, evidence2 = self.http.get(self.target, headers={"Origin": origin})
        if resp2 is None:
            return

        acao = resp2.headers.get("Access-Control-Allow-Origin", "")
        acac = resp2.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*":
            self.add_finding(Finding(
                title="CORS Misconfiguration — Wildcard Origin",
                severity="MEDIUM",
                owasp="A05:2021",
                cwe="CWE-942",
                cvss_score=6.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                url=self.target,
                parameter="Access-Control-Allow-Origin",
                payload=f"Origin: {origin}",
                description="Server responds with `Access-Control-Allow-Origin: *`, allowing any origin to read responses.",
                impact="Any website can make cross-origin requests and read the response data.",
                remediation="Set ACAO to specific trusted domains only. Never use wildcard with credentials.",
                references=["https://portswigger.net/web-security/cors"],
                evidence=evidence2,
                confirmed=True,
                vuln_type="headers",
            ))
        elif acao == origin and acac.lower() == "true":
            self.add_finding(Finding(
                title="CORS Misconfiguration — Reflects Origin with Credentials",
                severity="HIGH",
                owasp="A05:2021",
                cwe="CWE-942",
                cvss_score=8.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                url=self.target,
                parameter="Access-Control-Allow-Origin",
                payload=f"Origin: {origin}",
                description=(
                    f"Server reflects the supplied Origin (`{origin}`) in ACAO and sets "
                    "`Access-Control-Allow-Credentials: true`. "
                    "This allows any website to make authenticated cross-origin requests."
                ),
                impact="Full authenticated CORS attack — steal session tokens, perform actions as victim.",
                remediation=(
                    "Validate Origin against an explicit allowlist. "
                    "Never reflect arbitrary origins when credentials are enabled."
                ),
                references=["https://portswigger.net/web-security/cors/access-control-allow-origin"],
                evidence=evidence2,
                confirmed=True,
                vuln_type="headers",
            ))

    def _check_cookies(self, resp, evidence):
        """Check cookie security flags."""
        set_cookies = resp.headers.get("Set-Cookie", "")
        # requests merges multiple Set-Cookie into one; iterate raw headers
        all_cookies = [v for k, v in resp.headers.items() if k.lower() == "set-cookie"]
        if not all_cookies and set_cookies:
            all_cookies = [set_cookies]

        for cookie_str in all_cookies:
            cookie_name = cookie_str.split("=")[0].strip()
            is_session = any(s in cookie_name.lower() for s in ["session", "token", "auth", "jwt", "sid"])
            missing = []

            if "httponly" not in cookie_str.lower():
                missing.append("HttpOnly")
            if "secure" not in cookie_str.lower():
                missing.append("Secure")
            if "samesite" not in cookie_str.lower():
                missing.append("SameSite")

            if missing:
                sev = "HIGH" if is_session else "MEDIUM"
                cvss = 7.5 if is_session else 5.3
                self.add_finding(Finding(
                    title=f"Insecure Cookie Flags Missing — {cookie_name}",
                    severity=sev,
                    owasp="A05:2021",
                    cwe="CWE-614",
                    cvss_score=cvss,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                    url=self.target,
                    parameter=f"Set-Cookie: {cookie_name}",
                    payload=cookie_str[:150],
                    description=(
                        f"Cookie `{cookie_name}` is missing security flags: {', '.join(missing)}. "
                        + ("This appears to be a session/auth cookie." if is_session else "")
                    ),
                    impact=(
                        "Without HttpOnly: XSS can steal the cookie. "
                        "Without Secure: cookie transmitted over HTTP. "
                        "Without SameSite: CSRF attacks possible."
                    ),
                    remediation=(
                        f"Set-Cookie: {cookie_name}=...; Secure; HttpOnly; SameSite=Strict"
                    ),
                    references=[
                        "https://owasp.org/www-community/controls/SecureCookieAttribute",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
                    ],
                    evidence=evidence,
                    confirmed=True,
                    vuln_type="headers",
                ))

    def _check_http_methods(self):
        """Check for dangerous HTTP methods enabled."""
        resp, evidence = self.http.request("OPTIONS", self.target)
        if resp is None:
            return
        allow = resp.headers.get("Allow", "") + resp.headers.get("Public", "")
        if "TRACE" in allow:
            self.add_finding(Finding(
                title="Dangerous HTTP Method Enabled — TRACE",
                severity="LOW",
                owasp="A05:2021",
                cwe="CWE-16",
                cvss_score=4.3,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                url=self.target,
                parameter="Allow",
                payload="OPTIONS",
                description="Server allows HTTP TRACE method, enabling Cross-Site Tracing (XST) attacks.",
                impact="XST can be used to steal cookies and bypass HttpOnly flag in older browsers.",
                remediation="Disable TRACE method in web server config: `TraceEnable Off` (Apache).",
                references=["https://owasp.org/www-community/attacks/Cross_Site_Tracing"],
                evidence=evidence,
                confirmed=True,
                vuln_type="headers",
            ))

    def _scan_sensitive_files(self):
        """Probe for commonly exposed sensitive files."""
        for path, indicators in SENSITIVE_FILES:
            url = f"{self.target}{path}"
            resp, evidence = self.http.get(url)
            if resp is None or resp.status_code not in (200, 403):
                continue
            if resp.status_code == 200 and self.contains_any(resp.text, indicators):
                self.add_finding(Finding(
                    title=f"Sensitive File Exposed — {path}",
                    severity="HIGH" if path in ("/.env", "/.git/config", "/wp-config.php") else "MEDIUM",
                    owasp="A05:2021",
                    cwe="CWE-538",
                    cvss_score=8.6 if "password" in "".join(indicators).lower() else 6.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    url=url,
                    parameter="URL path",
                    payload=path,
                    description=f"The file `{path}` is publicly accessible and contains sensitive content.",
                    impact="Credential/secret exposure, source code disclosure, server enumeration.",
                    remediation=(
                        f"Remove `{path}` from the web root or block access via web server rules. "
                        "Rotate any exposed credentials immediately."
                    ),
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/",
                    ],
                    evidence=evidence,
                    confirmed=True,
                    vuln_type="headers",
                ))
            elif resp.status_code == 403 and path in ("/.env", "/.git/HEAD"):
                self.add_finding(Finding(
                    title=f"Sensitive File Detected (Access Restricted) — {path}",
                    severity="INFO",
                    owasp="A05:2021",
                    cwe="CWE-538",
                    cvss_score=2.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    url=url,
                    parameter="URL path",
                    payload=path,
                    description=f"Server returned 403 for `{path}` — file exists but is restricted. May be bypassable.",
                    impact="Confirm with bypass techniques (e.g., case change, .htaccess override).",
                    remediation="Ensure the file is completely inaccessible from the web root.",
                    references=[],
                    evidence=evidence,
                    confirmed=False,
                    vuln_type="headers",
                ))

    def _check_directory_listing(self):
        """Check for directory listing on common paths."""
        dirs = ["/uploads/", "/images/", "/static/", "/assets/", "/backup/", "/files/", "/logs/"]
        for path in dirs:
            url = f"{self.target}{path}"
            resp, evidence = self.http.get(url)
            if resp is None or resp.status_code != 200:
                continue
            if re.search(r"Index of|Parent Directory|<a href=.*\.\./|Directory listing", resp.text, re.IGNORECASE):
                self.add_finding(Finding(
                    title=f"Directory Listing Enabled — {path}",
                    severity="MEDIUM",
                    owasp="A05:2021",
                    cwe="CWE-548",
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    url=url,
                    parameter="URL path",
                    payload=path,
                    description=f"Directory listing is enabled at `{url}`, exposing file tree contents.",
                    impact="Reconnaissance — attacker can enumerate all files in the directory.",
                    remediation="Disable directory listing: `Options -Indexes` (Apache), `autoindex off` (nginx).",
                    references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"],
                    evidence=evidence,
                    confirmed=True,
                    vuln_type="headers",
                ))
