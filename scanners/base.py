"""
Base scanner class — all vulnerability scanners inherit from this.
Provides shared helpers for finding creation and reporting.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from utils.http_client import HttpClient, HttpEvidence
    from utils.scope import ScopeValidator

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """
    Represents a single vulnerability finding.
    Structured for HackerOne / Bugcrowd report format.
    """
    title: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    owasp: str             # e.g. "A3:2021"
    cwe: str               # e.g. "CWE-89"
    cvss_score: float      # 0.0 – 10.0
    cvss_vector: str       # CVSS v3.1 vector string
    url: str
    parameter: str = ""
    payload: str = ""
    description: str = ""
    impact: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    evidence: Optional[object] = None   # HttpEvidence instance
    confirmed: bool = False             # True = definitely vulnerable
    vuln_type: str = ""                 # e.g. "sqli"

    def to_dict(self) -> dict:
        d = {
            "title": self.title,
            "severity": self.severity,
            "owasp": self.owasp,
            "cwe": self.cwe,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "references": self.references,
            "confirmed": self.confirmed,
            "vuln_type": self.vuln_type,
        }
        if self.evidence:
            d["evidence"] = self.evidence.to_dict()
        return d


class BaseScanner:
    """
    Abstract base scanner.

    Subclasses must implement:
        run(self) -> list[Finding]
    """

    # Override these in subclasses
    SCANNER_NAME = "Base Scanner"
    OWASP_CATEGORY = ""
    CWE = ""

    def __init__(
        self,
        target: str,
        http_client: "HttpClient",
        scope: "ScopeValidator",
        verbose: bool = False,
    ):
        self.target = target.rstrip("/")
        self.http = http_client
        self.scope = scope
        self.verbose = verbose
        self.findings: list[Finding] = []
        self.logger = logging.getLogger(self.__class__.__name__)

    def run(self) -> list[Finding]:
        """
        Execute the scanner.
        Must return a list of Finding objects.
        """
        raise NotImplementedError("Subclasses must implement run()")

    # ── Helper methods ─────────────────────────────────────────────────────────

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.logger.debug(f"Finding: [{finding.severity}] {finding.title} @ {finding.url}")

    def make_finding(self, **kwargs) -> Finding:
        return Finding(**kwargs)

    def inject_param(self, url: str, param: str, payload: str) -> str:
        """Replace a query parameter value with a payload."""
        from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if param in params:
            params[param] = [payload]
            new_query = urlencode(params, doseq=True)
            return urlunparse(parsed._replace(query=new_query))
        # Append if not found
        sep = "&" if parsed.query else ""
        return f"{url}{sep}?{param}={payload}" if not parsed.query else f"{url}&{param}={payload}"

    def get_forms(self, url: str) -> list[dict]:
        """
        Fetch a page and extract all HTML forms with their inputs.
        Returns a list of form dicts.
        """
        from bs4 import BeautifulSoup
        from urllib.parse import urljoin

        resp, _ = self.http.get(url)
        if resp is None:
            return []

        soup = BeautifulSoup(resp.text, "html.parser")
        forms = []
        for form in soup.find_all("form"):
            form_data = {
                "action": urljoin(url, form.get("action", url)),
                "method": form.get("method", "get").lower(),
                "inputs": [],
            }
            for inp in form.find_all(["input", "textarea", "select"]):
                form_data["inputs"].append({
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", ""),
                })
            forms.append(form_data)

        return forms

    def get_query_params(self, url: str) -> list[str]:
        """Return a list of query parameter names from a URL."""
        from urllib.parse import urlparse, parse_qs
        return list(parse_qs(urlparse(url).query).keys())

    def contains_any(self, text: str, indicators: list[str]) -> bool:
        """Return True if any indicator string is found in text (case-insensitive)."""
        text_lower = text.lower()
        return any(ind.lower() in text_lower for ind in indicators)
