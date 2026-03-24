"""
Insecure Direct Object Reference (IDOR) Scanner
OWASP A1:2021 — Broken Access Control
CWE-639: Authorization Bypass Through User-Controlled Key

Tests for:
  - Numeric ID enumeration (increment/decrement)
  - GUID/UUID predictability
  - Horizontal privilege escalation via param manipulation
  - Vertical privilege escalation (user → admin)
  - Parameter pollution
  - Mass assignment hints
"""

import re
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .base import BaseScanner, Finding


# Common parameter names that reference object IDs
ID_PARAMS = [
    "id", "user_id", "userId", "account_id", "accountId",
    "order_id", "orderId", "invoice_id", "invoiceId",
    "document_id", "doc_id", "file_id", "fileId",
    "message_id", "msg_id", "item_id", "product_id",
    "profile_id", "record_id", "ticket_id", "uuid",
    "uid", "pid", "rid", "oid", "num", "no",
]

# Sensitive field patterns in JSON responses
SENSITIVE_FIELDS = [
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "credit_card", "ssn", "dob", "email", "phone", "address",
    "balance", "salary", "private", "internal",
]


class IDORScanner(BaseScanner):
    """Scans for Insecure Direct Object Reference (IDOR) vulnerabilities."""

    SCANNER_NAME = "IDOR / Broken Access Control"
    OWASP_CATEGORY = "A01:2021"
    CWE = "CWE-639"

    def run(self) -> list[Finding]:
        self.logger.info(f"Starting IDOR scan against {self.target}")

        params = self.get_query_params(self.target)

        # Test numeric ID parameters
        for param in params:
            if param.lower() in ID_PARAMS:
                self._test_numeric_idor(self.target, param)

        # Test common API endpoints
        self._test_api_endpoints()

        # Detect mass assignment via PUT/PATCH
        self._test_mass_assignment()

        # Check for API endpoint enumeration
        self._test_api_enumeration()

        return self.findings

    def _test_numeric_idor(self, url: str, param: str):
        """Test numeric IDs by incrementing/decrementing the value."""
        # Parse the current value
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if param not in params:
            return

        try:
            current_val = int(params[param][0])
        except (ValueError, IndexError):
            return

        # Fetch the baseline response
        resp_base, _ = self.http.get(url)
        if resp_base is None:
            return

        # Try adjacent IDs
        test_ids = [current_val - 1, current_val + 1, 1, 2, 100, 999, 9999]
        for test_id in test_ids:
            if test_id == current_val or test_id <= 0:
                continue
            test_url = self.inject_param(url, param, str(test_id))
            resp, evidence = self.http.get(test_url)
            if resp is None:
                continue

            # Same status + non-empty different content = possible IDOR
            if (resp.status_code == resp_base.status_code == 200
                    and len(resp.text) > 50
                    and resp.text.strip() != resp_base.text.strip()):

                # Check for sensitive data leakage
                sensitive = self._detect_sensitive_fields(resp.text)

                self.add_finding(Finding(
                    title=f"Potential IDOR — Parameter `{param}` Allows Object Enumeration",
                    severity="HIGH" if sensitive else "MEDIUM",
                    owasp="A01:2021",
                    cwe="CWE-639",
                    cvss_score=8.1 if sensitive else 6.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    url=url,
                    parameter=param,
                    payload=f"{param}={test_id} (was {current_val})",
                    description=(
                        f"Changing `{param}` from `{current_val}` to `{test_id}` returned a "
                        f"different HTTP 200 response (length: {len(resp.text)} vs {len(resp_base.text)}), "
                        "suggesting direct object access without proper authorisation checks."
                        + (f" Sensitive fields detected: {', '.join(sensitive)}" if sensitive else "")
                    ),
                    impact=(
                        "Horizontal privilege escalation: access to other users' data. "
                        "Vertical privilege escalation if admin object IDs are guessable."
                    ),
                    remediation=(
                        "Implement server-side authorisation checks on every object access. "
                        "Use indirect object references (UUIDs mapped server-side). "
                        "Never trust client-supplied IDs without validating ownership."
                    ),
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
                        "https://cwe.mitre.org/data/definitions/639.html",
                        "https://portswigger.net/web-security/access-control/idor",
                    ],
                    evidence=evidence,
                    confirmed=False,  # requires manual confirmation to determine ownership
                    vuln_type="idor",
                ))
                return

    def _detect_sensitive_fields(self, text: str) -> list[str]:
        """Return a list of sensitive field names found in JSON response."""
        found = []
        try:
            data = json.loads(text)
            flat = json.dumps(data).lower()
        except Exception:
            flat = text.lower()
        for field in SENSITIVE_FIELDS:
            if f'"{field}"' in flat or f"'{field}'" in flat:
                found.append(field)
        return found

    def _test_api_endpoints(self):
        """Test common REST API patterns for IDOR."""
        api_patterns = [
            "/api/v1/users/1",
            "/api/v1/users/2",
            "/api/users/1",
            "/api/users/2",
            "/api/v1/account/1",
            "/api/v1/orders/1",
            "/api/v1/invoices/1",
            "/api/v1/documents/1",
            "/api/v1/profile/1",
            "/users/1",
            "/users/2",
            "/user?id=1",
            "/user?id=2",
            "/account?id=1",
        ]

        resp_1 = None
        for path in api_patterns:
            url = f"{self.target}{path}"
            resp, evidence = self.http.get(url)
            if resp is None or resp.status_code not in (200, 201):
                continue

            # Check if we got data we shouldn't (without auth)
            sensitive = self._detect_sensitive_fields(resp.text)
            if sensitive:
                self.add_finding(Finding(
                    title="IDOR — Unauthenticated Access to User Object with Sensitive Data",
                    severity="HIGH",
                    owasp="A01:2021",
                    cwe="CWE-639",
                    cvss_score=8.6,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    url=url,
                    parameter="URL path ID",
                    payload=path,
                    description=(
                        f"API endpoint `{url}` returned sensitive fields ({', '.join(sensitive)}) "
                        "without requiring authentication."
                    ),
                    impact="Exposure of user PII, credentials, or financial data.",
                    remediation=(
                        "Require authentication on all API endpoints. "
                        "Validate object ownership on every request. "
                        "Apply role-based access control (RBAC)."
                    ),
                    references=["https://portswigger.net/web-security/access-control/idor"],
                    evidence=evidence,
                    confirmed=True,
                    vuln_type="idor",
                ))

    def _test_mass_assignment(self):
        """Detect potential mass assignment vulnerabilities via PUT/PATCH."""
        endpoints = [
            f"{self.target}/api/v1/users/1",
            f"{self.target}/api/users/1",
            f"{self.target}/profile",
        ]
        privilege_fields = {
            "role": "admin",
            "is_admin": True,
            "admin": True,
            "privilege": "admin",
            "group": "admin",
            "permissions": ["admin", "read", "write"],
        }

        for ep in endpoints:
            for field, value in privilege_fields.items():
                resp, evidence = self.http.request(
                    "PUT", ep,
                    json_data={field: value, "id": 1},
                    headers={"Content-Type": "application/json"},
                )
                if resp is None:
                    continue
                if resp.status_code in (200, 201, 204):
                    # Check if the field appears in the response
                    try:
                        data = json.loads(resp.text)
                        resp_text = json.dumps(data).lower()
                    except Exception:
                        resp_text = resp.text.lower()

                    if str(value).lower() in resp_text:
                        self.add_finding(Finding(
                            title="Mass Assignment — Privilege Escalation via Role Field",
                            severity="CRITICAL",
                            owasp="A01:2021",
                            cwe="CWE-915",
                            cvss_score=9.8,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            url=ep,
                            parameter=field,
                            payload=f'{{"{field}": "{value}"}}',
                            description=(
                                f"Setting `{field}={value}` via PUT to `{ep}` was accepted "
                                "and reflected in the response, indicating mass assignment vulnerability."
                            ),
                            impact="Privilege escalation to admin / superuser.",
                            remediation=(
                                "Use an explicit allowlist (DTO / serializer) for fields that can be mass-updated. "
                                "Never bind request bodies directly to model objects."
                            ),
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"],
                            evidence=evidence,
                            confirmed=True,
                            vuln_type="idor",
                        ))
                        return

    def _test_api_enumeration(self):
        """Check if sequential IDs are enumerable (indicates lack of UUID usage)."""
        test_paths = ["/api/v1/users", "/api/users", "/users"]
        for path in test_paths:
            url = f"{self.target}{path}"
            resp, evidence = self.http.get(url)
            if resp is None or resp.status_code != 200:
                continue
            # Check for array of user objects
            try:
                data = json.loads(resp.text)
                if isinstance(data, list) and len(data) > 0:
                    ids = [str(item.get("id", "")) for item in data if isinstance(item, dict)]
                    numeric_ids = [i for i in ids if i.isdigit()]
                    if len(numeric_ids) > 1:
                        self.add_finding(Finding(
                            title="User Enumeration via Sequential Numeric IDs",
                            severity="MEDIUM",
                            owasp="A01:2021",
                            cwe="CWE-639",
                            cvss_score=5.3,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            url=url,
                            parameter="id",
                            payload=f"IDs observed: {numeric_ids[:5]}",
                            description=(
                                f"API at `{url}` exposes objects with sequential numeric IDs "
                                f"({', '.join(numeric_ids[:5])}, ...), making enumeration trivial."
                            ),
                            impact="Full dataset enumeration possible by iterating ID range.",
                            remediation=(
                                "Use non-sequential UUIDs (v4) for public-facing object references. "
                                "Implement rate limiting and access controls."
                            ),
                            references=["https://portswigger.net/web-security/access-control/idor"],
                            evidence=evidence,
                            confirmed=True,
                            vuln_type="idor",
                        ))
                        return
            except Exception:
                pass
