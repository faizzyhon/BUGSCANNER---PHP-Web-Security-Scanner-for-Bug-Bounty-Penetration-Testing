"""
Scope validation utility for BugScanner.
Ensures the tool only targets URLs that are structurally valid and in-scope.
"""

import re
from urllib.parse import urlparse, urljoin
from typing import Optional


class ScopeValidator:
    """
    Validates and manages the scan scope.

    Usage:
        scope = ScopeValidator("https://target.example.com")
        if scope.is_valid_url():
            if scope.in_scope("https://target.example.com/login"):
                ...
    """

    # Blocked IP ranges — never scan these (loopback, RFC-1918, link-local, etc.)
    BLOCKED_NETWORKS = [
        r"^127\.",
        r"^10\.",
        r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",
        r"^192\.168\.",
        r"^169\.254\.",
        r"^::1$",
        r"^fc00:",
        r"^fe80:",
        r"^0\.0\.0\.0",
        r"^localhost$",
        r"^metadata\.google\.internal",  # GCP metadata
        r"^169\.254\.169\.254",          # AWS/Azure metadata
    ]

    VALID_SCHEMES = {"http", "https"}

    def __init__(self, target_url: str, extra_scope: Optional[list[str]] = None):
        """
        Args:
            target_url: Primary target URL (e.g. https://app.example.com)
            extra_scope: Additional in-scope base URLs
        """
        self.target_url = target_url.rstrip("/")
        self._parsed = urlparse(self.target_url)
        self.scheme = self._parsed.scheme.lower()
        self.host = self._parsed.hostname or ""
        self.port = self._parsed.port
        self.base_path = self._parsed.path

        self._scope_bases: list[str] = [self.target_url]
        if extra_scope:
            self._scope_bases.extend(extra_scope)

    # ── Validation ────────────────────────────────────────────────────────────

    def is_valid_url(self) -> bool:
        """Return True if the target URL is structurally valid and allowed."""
        if self.scheme not in self.VALID_SCHEMES:
            return False
        if not self.host:
            return False
        if self._is_blocked_host(self.host):
            return False
        return True

    def _is_blocked_host(self, host: str) -> bool:
        """Return True if the host resolves to a blocked/private range."""
        for pattern in self.BLOCKED_NETWORKS:
            if re.match(pattern, host, re.IGNORECASE):
                return True
        return False

    def in_scope(self, url: str) -> bool:
        """
        Return True if `url` is within the defined scan scope.
        Uses host-based matching (subpath overlap acceptable).
        """
        parsed = urlparse(url)
        target_host = parsed.hostname or ""

        if self._is_blocked_host(target_host):
            return False

        for base in self._scope_bases:
            base_parsed = urlparse(base)
            base_host = base_parsed.hostname or ""
            # Exact host or sub-domain match
            if target_host == base_host or target_host.endswith("." + base_host):
                return True

        return False

    def normalize_url(self, path: str) -> str:
        """Build an absolute URL from a relative path against the target base."""
        return urljoin(self.target_url + "/", path.lstrip("/"))

    def get_host(self) -> str:
        return self.host

    def get_base_url(self) -> str:
        """Return scheme + host (no path)."""
        port_str = f":{self.port}" if self.port else ""
        return f"{self.scheme}://{self.host}{port_str}"

    # ── Common endpoint helpers ───────────────────────────────────────────────

    def get_common_paths(self) -> list[str]:
        """Return a list of interesting paths to probe during scanning."""
        return [
            "/",
            "/login",
            "/admin",
            "/api",
            "/api/v1",
            "/api/v2",
            "/graphql",
            "/search",
            "/upload",
            "/download",
            "/redirect",
            "/profile",
            "/user",
            "/account",
            "/register",
            "/reset",
            "/forgot-password",
            "/dashboard",
            "/debug",
            "/test",
            "/backup",
            "/config",
            "/.git/HEAD",
            "/.env",
            "/robots.txt",
            "/sitemap.xml",
            "/swagger.json",
            "/openapi.json",
            "/phpinfo.php",
            "/server-status",
            "/server-info",
        ]
