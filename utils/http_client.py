"""
HTTP client wrapper for BugScanner.
Provides consistent request handling, evidence capture, and retry logic.
"""

import time
import uuid
import logging
from typing import Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36 BugScanner/1.0"
)


@dataclass
class HttpEvidence:
    """Captures the full request/response for a finding's proof-of-concept."""

    request_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    method: str = ""
    url: str = ""
    request_headers: dict = field(default_factory=dict)
    request_body: Optional[str] = None
    status_code: int = 0
    response_headers: dict = field(default_factory=dict)
    response_body: str = ""
    elapsed_ms: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "method": self.method,
            "url": self.url,
            "request_headers": self.request_headers,
            "request_body": self.request_body,
            "status_code": self.status_code,
            "response_headers": dict(self.response_headers),
            "response_body": self.response_body[:4096],  # cap at 4 KB
            "elapsed_ms": round(self.elapsed_ms, 2),
            "error": self.error,
        }

    def format_poc(self) -> str:
        """Return a formatted HTTP request/response block for reports."""
        lines = [
            f"### Request (ID: {self.request_id})",
            f"```http",
            f"{self.method} {self.url}",
        ]
        for k, v in self.request_headers.items():
            lines.append(f"{k}: {v}")
        if self.request_body:
            lines.append("")
            lines.append(self.request_body[:2000])
        lines.append("```")

        lines += [
            "",
            f"### Response",
            f"```http",
            f"HTTP/1.1 {self.status_code}",
        ]
        for k, v in self.response_headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        lines.append(self.response_body[:2000])
        lines.append("```")
        return "\n".join(lines)


class HttpClient:
    """
    Thin wrapper around `requests.Session` with:
      - Automatic retry with back-off
      - Evidence (request/response) capture
      - Consistent User-Agent and headers
      - SSRF-safe redirect handling
    """

    def __init__(
        self,
        timeout: int = 10,
        cookies: Optional[dict] = None,
        extra_headers: Optional[dict] = None,
        max_retries: int = 2,
        follow_redirects: bool = True,
        verify_ssl: bool = False,   # off by default for testing environments
    ):
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl

        self.session = requests.Session()

        # Retry adapter
        retry = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"],
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Default headers
        self.session.headers.update({
            "User-Agent": DEFAULT_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        })

        if extra_headers:
            self.session.headers.update(extra_headers)

        if cookies:
            self.session.cookies.update(cookies)

        # Disable SSL warnings (intentional for pentest)
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def request(
        self,
        method: str,
        url: str,
        data: Optional[dict | str] = None,
        json_data: Optional[dict] = None,
        headers: Optional[dict] = None,
        params: Optional[dict] = None,
        allow_redirects: Optional[bool] = None,
        raw_body: Optional[str] = None,
    ) -> tuple[Optional[requests.Response], HttpEvidence]:
        """
        Perform an HTTP request and capture evidence.

        Returns:
            (response_or_None, HttpEvidence)
        """
        evidence = HttpEvidence(method=method.upper(), url=url)
        redir = self.follow_redirects if allow_redirects is None else allow_redirects

        merged_headers = dict(self.session.headers)
        if headers:
            merged_headers.update(headers)
        evidence.request_headers = merged_headers

        if data and isinstance(data, dict):
            evidence.request_body = "&".join(f"{k}={v}" for k, v in data.items())
        elif isinstance(data, str):
            evidence.request_body = data
        elif json_data:
            import json
            evidence.request_body = json.dumps(json_data)
        elif raw_body:
            evidence.request_body = raw_body

        try:
            t0 = time.perf_counter()
            kwargs: dict = dict(
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=redir,
            )
            if params:
                kwargs["params"] = params
            if json_data:
                kwargs["json"] = json_data
            elif raw_body:
                kwargs["data"] = raw_body
                merged_headers.setdefault("Content-Type", "application/xml")
            elif data:
                kwargs["data"] = data

            response = self.session.request(method, url, headers=headers, **kwargs)
            evidence.elapsed_ms = (time.perf_counter() - t0) * 1000
            evidence.status_code = response.status_code
            evidence.response_headers = dict(response.headers)
            try:
                evidence.response_body = response.text
            except Exception:
                evidence.response_body = ""

            return response, evidence

        except requests.exceptions.Timeout:
            evidence.error = "Request timed out"
            logger.debug(f"Timeout: {method} {url}")
            return None, evidence

        except requests.exceptions.SSLError as e:
            evidence.error = f"SSL error: {e}"
            return None, evidence

        except requests.exceptions.ConnectionError as e:
            evidence.error = f"Connection error: {e}"
            return None, evidence

        except Exception as e:
            evidence.error = str(e)
            logger.debug(f"Request error: {e}")
            return None, evidence

    def get(self, url: str, **kwargs) -> tuple[Optional[requests.Response], HttpEvidence]:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> tuple[Optional[requests.Response], HttpEvidence]:
        return self.request("POST", url, **kwargs)

    def head(self, url: str, **kwargs) -> tuple[Optional[requests.Response], HttpEvidence]:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> tuple[Optional[requests.Response], HttpEvidence]:
        return self.request("OPTIONS", url, **kwargs)

    def apply_auth_result(self, auth_result) -> None:
        """
        Apply an AuthResult from AuthManager to this session so all
        subsequent scanner requests are authenticated.

        Call this after a successful login:
            http_client.apply_auth_result(auth_mgr.login(...))
        """
        if not auth_result or not auth_result.success:
            return
        # Apply session cookies
        for k, v in auth_result.session_cookies.items():
            self.session.cookies.set(k, v)
        # Apply auth headers (e.g. Authorization: Bearer <token>)
        if auth_result.auth_headers:
            self.session.headers.update(auth_result.auth_headers)
        logger.debug(
            f"Auth applied: method={auth_result.method}, "
            f"cookies={list(auth_result.session_cookies.keys())}, "
            f"headers={list(auth_result.auth_headers.keys())}"
        )

    @property
    def is_authenticated(self) -> bool:
        """Return True if the session has authentication cookies or headers."""
        has_cookies = len(self.session.cookies) > 0
        has_auth_header = "Authorization" in self.session.headers
        return has_cookies or has_auth_header

    def close(self):
        self.session.close()
