"""
Open Redirect Scanner
OWASP A10:2021 — Unvalidated Redirects and Forwards
CWE-601: URL Redirection to Untrusted Site ('Open Redirect')

Tests for:
  - Open redirect via GET parameters
  - Redirect via HTTP headers (Location, Refresh)
  - Bypass techniques (//evil.com, \/evil.com, https:evil.com)
  - Meta refresh redirects
  - JavaScript-based redirects (window.location)
"""

import re
from urllib.parse import urlparse
from .base import BaseScanner, Finding


# External domain to test redirect to
CANARY_DOMAIN = "https://evil-canary.example.com"
CANARY_VARIATIONS = [
    "https://evil-canary.example.com",
    "//evil-canary.example.com",
    "\\/\\/evil-canary.example.com",
    "https:evil-canary.example.com",
    "///evil-canary.example.com",
    "https://\nevil-canary.example.com",
    "%2F%2Fevil-canary.example.com",
    "https%3A%2F%2Fevil-canary.example.com",
    "/%09/evil-canary.example.com",
    "//https://evil-canary.example.com",
]

REDIRECT_PARAMS = [
    "redirect", "redirect_url", "redirect_uri", "redirectUrl", "redirectUri",
    "next", "next_url", "nextUrl", "return", "returnUrl", "return_url",
    "url", "target", "dest", "destination", "goto", "continue",
    "forward", "redir", "to", "back", "returnTo", "return_to",
    "ref", "referer", "referrer", "site", "host", "callback",
    "out", "view", "logout_redirect", "success_url", "cancel_url",
    "error_uri", "fallback",
]

REDIRECT_INDICATORS = [
    "evil-canary.example.com",
]

# JavaScript redirect patterns
JS_REDIRECT_PATTERNS = [
    r"window\.location\s*=\s*['\"]([^'\"]+)['\"]",
    r"window\.location\.href\s*=\s*['\"]([^'\"]+)['\"]",
    r"window\.location\.replace\s*\(\s*['\"]([^'\"]+)['\"]",
    r"document\.location\s*=\s*['\"]([^'\"]+)['\"]",
]


class OpenRedirectScanner(BaseScanner):
    """Scans for Open Redirect vulnerabilities."""

    SCANNER_NAME = "Open Redirect"
    OWASP_CATEGORY = "A01:2021"
    CWE = "CWE-601"

    def run(self) -> list[Finding]:
        self.logger.info(f"Starting Open Redirect scan against {self.target}")

        # Test URL parameters on target
        params = self.get_query_params(self.target)
        for param in params:
            if param.lower() in REDIRECT_PARAMS or any(r in param.lower() for r in ["url", "redir", "next", "return"]):
                self._test_redirect_param(self.target, param)

        # Test common redirect endpoints
        self._test_common_redirect_endpoints()

        # Test forms with redirect-like fields
        forms = self.get_forms(self.target)
        for form in forms:
            self._test_form_redirects(form)

        # Detect JS-based redirects
        self._detect_js_redirects()

        return self.findings

    def _test_redirect_param(self, url: str, param: str):
        """Test a URL parameter for open redirect."""
        for payload in CANARY_VARIATIONS:
            test_url = self.inject_param(url, param, payload)
            resp, evidence = self.http.get(test_url, allow_redirects=False)
            if resp is None:
                continue

            # Check for redirect to our canary domain
            if self._is_open_redirect(resp, payload):
                self.add_finding(Finding(
                    title="Open Redirect",
                    severity="MEDIUM",
                    owasp="A01:2021",
                    cwe="CWE-601",
                    cvss_score=6.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    url=url,
                    parameter=param,
                    payload=payload,
                    description=(
                        f"Parameter `{param}` controls a redirect without proper validation. "
                        f"Setting `{param}={payload}` causes the server to issue a redirect "
                        f"to `{payload}` (an external/attacker-controlled domain)."
                    ),
                    impact=(
                        "Phishing: victims trust the original domain name in the URL. "
                        "Used to steal OAuth tokens when combined with authentication flows. "
                        "Account takeover via redirect_uri manipulation."
                    ),
                    remediation=(
                        "Validate redirect destinations against an allowlist of permitted domains/paths. "
                        "Only allow relative paths for internal redirects. "
                        "Never use user input as a direct redirect target. "
                        "For OAuth: validate redirect_uri exactly against registered values."
                    ),
                    references=[
                        "https://cwe.mitre.org/data/definitions/601.html",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                        "https://portswigger.net/web-security/dom-based/open-redirection",
                    ],
                    evidence=evidence,
                    confirmed=True,
                    vuln_type="open_redirect",
                ))
                return

    def _is_open_redirect(self, resp, payload: str) -> bool:
        """Return True if the response redirects to the canary domain."""
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            if "evil-canary.example.com" in location:
                return True
            # Check the payload itself is in Location
            if payload.replace("%2F", "/").replace("%3A", ":") in location:
                return True
        # Check meta refresh
        if "evil-canary.example.com" in resp.text:
            return True
        return False

    def _test_common_redirect_endpoints(self):
        """Test common endpoints that perform redirects."""
        endpoints = [
            f"{self.target}/logout?next=",
            f"{self.target}/redirect?url=",
            f"{self.target}/out?url=",
            f"{self.target}/go?url=",
            f"{self.target}/link?url=",
            f"{self.target}/leave?target=",
            f"{self.target}/?redirect=",
            f"{self.target}/login?next=",
            f"{self.target}/sso/callback?redirect_uri=",
            f"{self.target}/oauth/callback?redirect_uri=",
            f"{self.target}/auth/callback?return_url=",
        ]
        for ep_base in endpoints:
            for payload in CANARY_VARIATIONS[:4]:
                full_url = ep_base + payload
                resp, evidence = self.http.get(full_url, allow_redirects=False)
                if resp is None:
                    continue
                if self._is_open_redirect(resp, payload):
                    param = ep_base.split("?")[-1].rstrip("=") if "?" in ep_base else "url"
                    self.add_finding(Finding(
                        title="Open Redirect via Common Endpoint",
                        severity="MEDIUM",
                        owasp="A01:2021",
                        cwe="CWE-601",
                        cvss_score=6.1,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        url=ep_base.rstrip("=").split("?")[0],
                        parameter=param,
                        payload=payload,
                        description=f"Endpoint `{ep_base.rstrip('=')}` redirects to attacker-controlled URLs.",
                        impact="Phishing, OAuth token theft, account takeover.",
                        remediation="Validate redirect targets against an allowlist.",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
                        evidence=evidence,
                        confirmed=True,
                        vuln_type="open_redirect",
                    ))
                    return

    def _test_form_redirects(self, form: dict):
        """Test form hidden fields for redirect manipulation."""
        action = form.get("action", self.target)
        method = form.get("method", "get")
        inputs = form.get("inputs", [])

        for inp in inputs:
            name = inp.get("name", "")
            if name.lower() not in REDIRECT_PARAMS:
                continue
            for payload in CANARY_VARIATIONS[:3]:
                data = {i.get("name", ""): i.get("value", "test") for i in inputs if i.get("name")}
                data[name] = payload
                if method == "post":
                    resp, evidence = self.http.post(action, data=data, allow_redirects=False)
                else:
                    from urllib.parse import urlencode
                    resp, evidence = self.http.get(f"{action}?{urlencode(data)}", allow_redirects=False)
                if resp is None:
                    continue
                if self._is_open_redirect(resp, payload):
                    self.add_finding(Finding(
                        title="Open Redirect via Form Field",
                        severity="MEDIUM",
                        owasp="A01:2021",
                        cwe="CWE-601",
                        cvss_score=6.1,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        url=action,
                        parameter=name,
                        payload=payload,
                        description=f"Form field `{name}` at `{action}` allows redirect to arbitrary URLs.",
                        impact="Phishing and token theft via crafted form submissions.",
                        remediation="Validate all redirect destinations server-side.",
                        references=["https://cwe.mitre.org/data/definitions/601.html"],
                        evidence=evidence,
                        confirmed=True,
                        vuln_type="open_redirect",
                    ))
                    return

    def _detect_js_redirects(self):
        """Detect JavaScript-based redirect sinks that may be exploitable."""
        resp, _ = self.http.get(self.target)
        if resp is None:
            return
        sinks_found = []
        for pattern in JS_REDIRECT_PATTERNS:
            matches = re.findall(pattern, resp.text)
            for m in matches:
                if any(p in m for p in ["location.hash", "location.search", "document.URL", "document.referrer"]):
                    sinks_found.append(m)

        if sinks_found:
            self.add_finding(Finding(
                title="DOM-Based Open Redirect — JavaScript Redirect Sink",
                severity="MEDIUM",
                owasp="A01:2021",
                cwe="CWE-601",
                cvss_score=5.4,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
                url=self.target,
                parameter="JavaScript DOM",
                payload="(static analysis)",
                description=(
                    f"Found JavaScript redirect sinks driven by URL fragments or query params: "
                    f"{', '.join(sinks_found[:3])}. "
                    "These may enable DOM-based open redirect."
                ),
                impact="Phishing, token exfiltration via crafted URL fragments.",
                remediation="Validate and sanitize URL sources before using them in window.location assignments.",
                references=["https://portswigger.net/web-security/dom-based/open-redirection"],
                confirmed=False,
                vuln_type="open_redirect",
            ))
