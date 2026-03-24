"""
Authentication Manager for BugScanner.
Handles automatic login to target websites before scanning.

Supports:
  - HTML form-based login (auto-detects login form fields)
  - HTTP Basic Authentication
  - Bearer token / API key (via --headers-extra)
  - Manual cookie injection (via --cookies)
  - CSRF token extraction and replay
"""

import re
import logging
from urllib.parse import urljoin, urlparse
from typing import Optional
from dataclasses import dataclass, field

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Common field name patterns for username and password inputs
USERNAME_FIELD_NAMES = [
    "username", "user", "email", "login", "user_name", "userName",
    "user_email", "account", "identifier", "name", "uname", "uid",
    "loginid", "login_id", "userid", "user_id",
]

PASSWORD_FIELD_NAMES = [
    "password", "passwd", "pass", "pwd", "secret", "credential",
    "user_password", "userpassword", "login_password",
]

# Common login page URL patterns
LOGIN_URL_PATTERNS = [
    "/login", "/signin", "/sign-in", "/auth/login", "/auth/signin",
    "/user/login", "/account/login", "/admin/login", "/api/login",
    "/api/auth/login", "/api/v1/login", "/api/v1/auth",
    "/session/new", "/sessions", "/access",
    # EC-Council CVV HUB training target (discovered from allinone.js)
    "/login.php",
]

# Indicators that login SUCCEEDED
LOGIN_SUCCESS_INDICATORS = [
    "dashboard", "logout", "sign out", "log out", "welcome",
    "profile", "account", "my account", "settings", "home",
    "authenticated", "token", "access_token", "bearer",
]

# Indicators that login FAILED
LOGIN_FAILURE_INDICATORS = [
    "invalid password", "wrong password", "incorrect password",
    "invalid credentials", "authentication failed", "login failed",
    "invalid username", "user not found", "account not found",
    "bad credentials", "unauthorized", "invalid email",
]

# ── EC-Council CVV HUB site-specific login config (from allinone.js) ──────────
# POST /login.php?login
#   fields: username, password, mcaptcha__token, mcaptcha_token
#   response codes: '5'=success, '3'=no such account, '0'=IP rate-limit, '1'=user rate-limit
CVVHUB_LOGIN_URL    = "/login.php?login"
CVVHUB_SUCCESS_CODE = "5"
CVVHUB_FAIL_CODES   = {"3": "no such account", "0": "IP rate-limited", "1": "username rate-limited"}


@dataclass
class AuthResult:
    """Result of an authentication attempt."""
    success: bool
    method: str = ""          # "form", "basic", "token", "cookie"
    username: str = ""
    login_url: str = ""
    session_cookies: dict = field(default_factory=dict)
    auth_headers: dict = field(default_factory=dict)
    csrf_token: str = ""
    message: str = ""
    response_status: int = 0

    def __str__(self):
        if self.success:
            return f"✅ Authenticated as '{self.username}' via {self.method} @ {self.login_url}"
        return f"❌ Authentication failed: {self.message}"


class AuthManager:
    """
    Handles pre-scan authentication against the target website.

    Usage:
        auth = AuthManager(session, target_url)
        result = auth.login(username="admin", password="secret")
        if result.success:
            # session now carries auth cookies
            ...
    """

    def __init__(self, session: requests.Session, target_url: str):
        self.session = session
        self.target = target_url.rstrip("/")
        self._base = self._get_base_url(target_url)

    @staticmethod
    def _get_base_url(url: str) -> str:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    # ── Public entry point ─────────────────────────────────────────────────────

    def login(
        self,
        username: str,
        password: str,
        login_url: Optional[str] = None,
        auth_type: str = "auto",
    ) -> AuthResult:
        """
        Attempt to authenticate against the target.

        Args:
            username:   The login username or email address
            password:   The login password
            login_url:  Explicit login URL (optional — auto-detected if not provided)
            auth_type:  'auto' | 'form' | 'basic' | 'json'

        Returns:
            AuthResult with success status, cookies, and headers
        """
        logger.info(f"Attempting authentication as '{username}' on {self.target}")

        if auth_type == "basic":
            return self._try_basic_auth(username, password, login_url or self.target)

        # Resolve login URL
        resolved_login_url = login_url or self._find_login_url()
        if not resolved_login_url:
            return AuthResult(
                success=False,
                message="Could not find a login page. Use --login-url to specify it manually.",
            )

        # Try JSON login first (common in APIs), then form-based
        if auth_type == "json" or auth_type == "auto":
            result = self._try_json_login(username, password, resolved_login_url)
            if result.success:
                return result

        if auth_type == "form" or auth_type == "auto":
            result = self._try_form_login(username, password, resolved_login_url)
            if result.success:
                return result

        return AuthResult(
            success=False,
            username=username,
            login_url=resolved_login_url,
            message=(
                f"Login failed with username='{username}'. "
                "Check credentials and try --login-url to specify the exact login endpoint."
            ),
        )

    # ── Login URL detection ────────────────────────────────────────────────────

    def _find_login_url(self) -> Optional[str]:
        """Auto-detect the login URL by probing common paths."""
        # Check if the target itself is a login page
        resp = self._get(self.target)
        if resp and self._page_has_login_form(resp.text):
            return self.target

        # Probe common login paths
        for path in LOGIN_URL_PATTERNS:
            url = self._base + path
            resp = self._get(url)
            if resp and resp.status_code == 200 and self._page_has_login_form(resp.text):
                logger.debug(f"Found login form at: {url}")
                return url

        # Try to find login link in the main page HTML
        resp = self._get(self.target)
        if resp:
            soup = BeautifulSoup(resp.text, "html.parser")
            for link in soup.find_all("a", href=True):
                href = link["href"].lower()
                if any(p.strip("/") in href for p in ["login", "signin", "sign-in"]):
                    return urljoin(self.target + "/", link["href"])

        return None

    def _page_has_login_form(self, html: str) -> bool:
        """Return True if the page contains a login form with password field."""
        soup = BeautifulSoup(html, "html.parser")
        for form in soup.find_all("form"):
            inputs = form.find_all("input")
            has_password = any(
                i.get("type", "").lower() == "password" or
                i.get("name", "").lower() in PASSWORD_FIELD_NAMES
                for i in inputs
            )
            if has_password:
                return True
        return False

    # ── Form-based login ───────────────────────────────────────────────────────

    def _try_form_login(self, username: str, password: str, login_url: str) -> AuthResult:
        """Submit the HTML login form with provided credentials."""
        resp = self._get(login_url)
        if resp is None:
            return AuthResult(success=False, message=f"Could not reach {login_url}")

        soup = BeautifulSoup(resp.text, "html.parser")
        login_form = self._find_login_form(soup)

        if not login_form:
            return AuthResult(
                success=False,
                message=f"No login form found at {login_url}",
            )

        # Build the form submission data
        form_data = self._build_form_data(login_form, soup, username, password)
        action = login_form.get("action", "")
        if not action:
            submit_url = login_url
        elif action.startswith("http"):
            submit_url = action
        else:
            submit_url = urljoin(login_url + "/", action)

        method = login_form.get("method", "post").lower()
        logger.debug(f"Submitting login form: {method.upper()} {submit_url}")
        logger.debug(f"Form fields: {list(form_data.keys())}")

        # Submit the form
        if method == "post":
            resp2 = self._post(submit_url, data=form_data)
        else:
            resp2 = self._get(submit_url, params=form_data)

        if resp2 is None:
            return AuthResult(success=False, message="No response from login form submission")

        return self._evaluate_login_response(resp2, username, submit_url, "form")

    def _find_login_form(self, soup: BeautifulSoup):
        """Find the best matching login form in the page."""
        forms = soup.find_all("form")
        # Prefer form containing a password field
        for form in forms:
            inputs = form.find_all("input")
            if any(i.get("type", "").lower() == "password" for i in inputs):
                return form
        return forms[0] if forms else None

    def _build_form_data(self, form, soup: BeautifulSoup, username: str, password: str) -> dict:
        """Build the POST data dict from a form element, injecting credentials."""
        data = {}
        username_field = None
        password_field = None

        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name", "")
            if not name:
                continue
            itype = inp.get("type", "text").lower()
            value = inp.get("value", "")

            if itype == "password" or name.lower() in PASSWORD_FIELD_NAMES:
                password_field = name
                data[name] = password
            elif itype in ("text", "email") and name.lower() in USERNAME_FIELD_NAMES:
                username_field = name
                data[name] = username
            elif itype == "hidden":
                data[name] = value  # preserve CSRF tokens and hidden fields
            elif itype in ("checkbox", "radio"):
                if inp.get("checked"):
                    data[name] = value or "on"
            elif itype == "submit":
                pass  # skip submit buttons
            else:
                data[name] = value or "test"

        # Fallback: if no username field matched by name, use first text/email
        if username_field is None:
            for inp in form.find_all("input"):
                name = inp.get("name", "")
                itype = inp.get("type", "text").lower()
                if itype in ("text", "email") and name and name not in data:
                    data[name] = username
                    username_field = name
                    break

        logger.debug(f"Detected username field: {username_field}, password field: {password_field}")
        return data

    # ── JSON / API login ───────────────────────────────────────────────────────

    def _try_json_login(self, username: str, password: str, login_url: str) -> AuthResult:
        """Try logging in via JSON POST (REST API style)."""
        payloads = [
            {"username": username, "password": password},
            {"email": username, "password": password},
            {"user": username, "pass": password},
            {"login": username, "password": password},
            {"username": username, "passwd": password},
        ]
        for payload in payloads:
            resp = self._post_json(login_url, json_data=payload)
            if resp is None:
                continue
            result = self._evaluate_login_response(resp, username, login_url, "json")
            if result.success:
                # Extract Bearer token from response body if present
                token = self._extract_token(resp)
                if token:
                    result.auth_headers["Authorization"] = f"Bearer {token}"
                    self.session.headers["Authorization"] = f"Bearer {token}"
                    logger.info(f"Bearer token extracted and applied to session")
                return result

        return AuthResult(success=False, message="JSON login unsuccessful")

    def _extract_token(self, resp: requests.Response) -> Optional[str]:
        """Extract a JWT or access token from a JSON response."""
        try:
            data = resp.json()
        except Exception:
            return None
        for key in ["token", "access_token", "accessToken", "jwt", "auth_token", "id_token"]:
            if isinstance(data, dict) and key in data:
                val = data[key]
                if isinstance(val, str) and len(val) > 10:
                    return val
            # nested: {"data": {"token": "..."}}
            if isinstance(data, dict) and "data" in data and isinstance(data["data"], dict):
                if key in data["data"]:
                    return data["data"][key]
        return None

    # ── HTTP Basic Auth ────────────────────────────────────────────────────────

    def _try_basic_auth(self, username: str, password: str, url: str) -> AuthResult:
        """Apply HTTP Basic Authentication to the session."""
        self.session.auth = (username, password)
        resp = self._get(url)
        if resp and resp.status_code not in (401, 403):
            logger.info(f"HTTP Basic Auth succeeded for '{username}'")
            return AuthResult(
                success=True,
                method="basic",
                username=username,
                login_url=url,
                session_cookies=dict(self.session.cookies),
                message="HTTP Basic Auth applied to session",
                response_status=resp.status_code,
            )
        self.session.auth = None
        return AuthResult(
            success=False,
            message=f"HTTP Basic Auth rejected (HTTP {resp.status_code if resp else 'no response'})",
        )

    # ── Response evaluation ────────────────────────────────────────────────────

    def _evaluate_login_response(
        self, resp: requests.Response, username: str, login_url: str, method: str
    ) -> AuthResult:
        """Determine if the login response indicates success or failure."""
        body_stripped = resp.text.strip()
        body_lower = body_stripped.lower()

        # ── EC-Council CVV HUB site-specific check ─────────────────────────────
        # POST /login.php?login returns a bare single-character response code:
        #   '5' = success (JS then does window.location = '/index.php')
        #   '3' = no such account
        #   '0' = IP rate-limited
        #   '1' = username rate-limited
        if body_stripped == CVVHUB_SUCCESS_CODE and resp.status_code == 200:
            cookies = dict(self.session.cookies)
            return AuthResult(
                success=True,
                method=method,
                username=username,
                login_url=login_url,
                session_cookies=cookies,
                message="CVV HUB login: response '5' (success)",
                response_status=resp.status_code,
            )
        if body_stripped in CVVHUB_FAIL_CODES:
            return AuthResult(
                success=False,
                username=username,
                login_url=login_url,
                message=f"CVV HUB login failed: code '{body_stripped}' = {CVVHUB_FAIL_CODES[body_stripped]}",
                response_status=resp.status_code,
            )
        # ───────────────────────────────────────────────────────────────────────

        # Explicit failure indicators
        if any(ind in body_lower for ind in LOGIN_FAILURE_INDICATORS):
            return AuthResult(
                success=False,
                username=username,
                login_url=login_url,
                message=f"Server returned a failure message (HTTP {resp.status_code})",
                response_status=resp.status_code,
            )

        # JSON response: check for token or error key
        try:
            json_data = resp.json()
            if isinstance(json_data, dict):
                if any(k in json_data for k in ["token", "access_token", "accessToken", "jwt"]):
                    cookies = dict(self.session.cookies)
                    return AuthResult(
                        success=True,
                        method=method,
                        username=username,
                        login_url=login_url,
                        session_cookies=cookies,
                        message=f"Token received (HTTP {resp.status_code})",
                        response_status=resp.status_code,
                    )
                if json_data.get("error") or json_data.get("message", "").lower() in LOGIN_FAILURE_INDICATORS:
                    return AuthResult(
                        success=False,
                        message=str(json_data.get("error") or json_data.get("message", "Unknown error")),
                    )
        except Exception:
            pass

        # Redirect after POST (classic web login pattern) = success
        if resp.status_code in (301, 302, 303) and resp.history:
            location = resp.headers.get("Location", "")
            if any(s in location.lower() for s in ["dashboard", "home", "account", "profile", "welcome"]):
                cookies = dict(self.session.cookies)
                return AuthResult(
                    success=True,
                    method=method,
                    username=username,
                    login_url=login_url,
                    session_cookies=cookies,
                    message=f"Redirected to {location} after login",
                    response_status=resp.status_code,
                )

        # Look for success indicators in the final response body
        if resp.status_code == 200 and any(ind in body_lower for ind in LOGIN_SUCCESS_INDICATORS):
            cookies = dict(self.session.cookies)
            return AuthResult(
                success=True,
                method=method,
                username=username,
                login_url=login_url,
                session_cookies=cookies,
                message=f"Login page indicators suggest success (HTTP {resp.status_code})",
                response_status=resp.status_code,
            )

        # HTTP 200 with cookies set = likely success
        if resp.status_code == 200 and len(self.session.cookies) > 0:
            cookies = dict(self.session.cookies)
            return AuthResult(
                success=True,
                method=method,
                username=username,
                login_url=login_url,
                session_cookies=cookies,
                message=f"Session cookies set after login (HTTP {resp.status_code})",
                response_status=resp.status_code,
            )

        return AuthResult(
            success=False,
            username=username,
            login_url=login_url,
            message=f"Could not confirm login success (HTTP {resp.status_code})",
            response_status=resp.status_code,
        )

    # ── Session cookie display ─────────────────────────────────────────────────

    def get_session_cookies_str(self) -> str:
        """Return current session cookies as a formatted string."""
        return "; ".join(f"{k}={v}" for k, v in self.session.cookies.items())

    # ── Internal HTTP helpers ──────────────────────────────────────────────────

    def _get(self, url: str, params: dict = None) -> Optional[requests.Response]:
        try:
            return self.session.get(
                url, params=params, timeout=10, verify=False,
                allow_redirects=True,
            )
        except Exception as e:
            logger.debug(f"GET {url} failed: {e}")
            return None

    def _post(self, url: str, data: dict) -> Optional[requests.Response]:
        try:
            return self.session.post(
                url, data=data, timeout=10, verify=False,
                allow_redirects=True,
            )
        except Exception as e:
            logger.debug(f"POST {url} failed: {e}")
            return None

    def _post_json(self, url: str, json_data: dict) -> Optional[requests.Response]:
        try:
            return self.session.post(
                url, json=json_data, timeout=10, verify=False,
                allow_redirects=True,
            )
        except Exception as e:
            logger.debug(f"POST JSON {url} failed: {e}")
            return None
