"""
╔══════════════════════════════════════════════════════════════════════════╗
║  BugScanner — Technology Detector Module                                 ║
║  Author : Muhammad Faizan (faizzyhon@gmail.com)                          ║
║  Covers : CMS, web frameworks, server software, JS libraries,            ║
║           CDN, email providers, analytics, version extraction            ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

import json
import re
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from .base import BaseScanner, Finding

console = Console(stderr=True)

# ── Technology fingerprint database ──────────────────────────────────────────
#
# Each entry: "Category:Name" → {
#   "headers"  : {header_name: regex_pattern},
#   "body"     : [regex_pattern, ...],
#   "cookies"  : [cookie_name, ...],
#   "url"      : [regex_pattern, ...],
#   "meta"     : {meta_name: regex_pattern},
#   "script"   : [regex_pattern, ...],    ← JS src patterns
#   "version"  : regex with capture group ← extract version string
# }

TECH_DB: dict[str, dict] = {

    # ── CMS ────────────────────────────────────────────────────────────────────
    "CMS:WordPress": {
        "body":    [r"wp-content/", r"wp-includes/", r"/wp-json/", r"WordPress"],
        "meta":    {"generator": r"WordPress\s*([\d.]+)?"},
        "cookies": ["wordpress_", "wordpress_logged_in", "wp-settings"],
        "url":     [r"/wp-admin", r"/wp-login"],
        "version": r"WordPress\s*([\d.]+)",
    },
    "CMS:Joomla": {
        "body":    [r"/components/com_", r"/media/jui/", r"Joomla!"],
        "meta":    {"generator": r"Joomla"},
        "cookies": ["joomla_session"],
        "version": r"Joomla!\s*([\d.]+)",
    },
    "CMS:Drupal": {
        "body":    [r"/sites/default/files/", r"Drupal", r"drupal\.js"],
        "meta":    {"generator": r"Drupal\s*([\d.]+)?"},
        "headers": {"X-Generator": r"Drupal"},
        "cookies": ["SESS[a-f0-9]+"],
        "version": r"Drupal\s*([\d.]+)",
    },
    "CMS:Magento": {
        "body":    [r"Mage\.Cookies", r"/skin/frontend/", r"magento"],
        "cookies": ["frontend"],
        "version": r"Magento/([\d.]+)",
    },
    "CMS:Shopify": {
        "body":    [r"cdn\.shopify\.com", r"Shopify\.theme"],
        "headers": {"X-ShopId": r".*"},
    },
    "CMS:Wix": {
        "body":    [r"wix\.com", r"wixstatic\.com"],
    },
    "CMS:Ghost": {
        "body":    [r"ghost-sdk", r"/ghost/api/"],
        "meta":    {"generator": r"Ghost\s*([\d.]+)?"},
    },
    "CMS:TYPO3": {
        "body":    [r"typo3/", r"TYPO3 CMS"],
        "meta":    {"generator": r"TYPO3"},
    },
    "CMS:OpenCart": {
        "body":    [r"route=common/home", r"OpenCart"],
        "cookies": ["OCSESSID"],
    },
    "CMS:PrestaShop": {
        "body":    [r"prestashop", r"/themes/default-bootstrap/"],
        "cookies": ["PrestaShop"],
    },
    "CMS:phpBB": {
        "body":    [r"phpbb", r"Powered by phpBB"],
    },
    "CMS:vBulletin": {
        "body":    [r"vBulletin", r"vb_","vBSEO"],
        "version": r"vBulletin\s*([\d.]+)",
    },

    # ── Web Frameworks ─────────────────────────────────────────────────────────
    "Framework:Laravel": {
        "cookies": ["laravel_session", "XSRF-TOKEN"],
        "body":    [r"laravel", r"csrf-token"],
    },
    "Framework:Django": {
        "cookies": ["csrftoken", "sessionid"],
        "body":    [r"csrfmiddlewaretoken", r"__admin_media_prefix__"],
        "headers": {"X-Frame-Options": r"SAMEORIGIN"},
    },
    "Framework:Ruby on Rails": {
        "headers": {"X-XSS-Protection": r"1", "X-Runtime": r"[\d.]+"},
        "cookies": ["_session_id", "_rails_session"],
        "body":    [r"authenticity_token"],
    },
    "Framework:ASP.NET": {
        "headers": {"X-Powered-By": r"ASP\.NET", "X-AspNet-Version": r"[\d.]+"},
        "cookies": ["ASP\.NET_SessionId", "ASPXAUTH"],
        "body":    [r"__VIEWSTATE", r"__EVENTVALIDATION"],
        "version": r"ASP\.NET\s*([\d.]+)",
    },
    "Framework:Spring Boot": {
        "headers": {"X-Application-Context": r".*"},
        "body":    [r"Whitelabel Error Page", r"Spring Framework"],
    },
    "Framework:Express.js": {
        "headers": {"X-Powered-By": r"Express"},
    },
    "Framework:Next.js": {
        "headers": {"X-Powered-By": r"Next\.js"},
        "body":    [r"__NEXT_DATA__", r"/_next/static/"],
        "version": r"Next\.js\s*([\d.]+)",
    },
    "Framework:Nuxt.js": {
        "body":    [r"__NUXT__", r"/_nuxt/"],
    },
    "Framework:Angular": {
        "body":    [r"ng-version=", r"angular\.min\.js"],
        "version": r"ng-version=\"([\d.]+)\"",
    },
    "Framework:React": {
        "body":    [r"react\.development\.js", r"react\.production\.min\.js", r"__reactFiber"],
        "script":  [r"react[.-][\d.]+\.js"],
    },
    "Framework:Vue.js": {
        "body":    [r"vue\.runtime\.", r"__vue__", r"v-bind:", r"v-on:"],
        "script":  [r"vue[.-][\d.]+\.js"],
        "version": r"vue@([\d.]+)",
    },
    "Framework:Flask": {
        "cookies": ["session"],
        "body":    [r"Werkzeug", r"Flask"],
    },
    "Framework:FastAPI": {
        "body":    [r"FastAPI", r"openapi\.json"],
        "headers": {"server": r"uvicorn"},
    },
    "Framework:Symfony": {
        "cookies": ["PHPSESSID", "sf_redirect"],
        "body":    [r"symfony"],
    },
    "Framework:CodeIgniter": {
        "cookies": ["ci_session"],
        "body":    [r"CodeIgniter"],
    },

    # ── Server Software ────────────────────────────────────────────────────────
    "Server:Nginx": {
        "headers": {"server": r"nginx(?:/([\d.]+))?"},
        "body":    [r"nginx"],
        "version": r"nginx/([\d.]+)",
    },
    "Server:Apache": {
        "headers": {"server": r"Apache(?:/([\d.]+))?"},
        "body":    [r"Apache"],
        "version": r"Apache/([\d.]+)",
    },
    "Server:IIS": {
        "headers": {"server": r"Microsoft-IIS(?:/([\d.]+))?"},
        "version": r"Microsoft-IIS/([\d.]+)",
    },
    "Server:LiteSpeed": {
        "headers": {"server": r"LiteSpeed"},
    },
    "Server:Caddy": {
        "headers": {"server": r"Caddy"},
    },
    "Server:Tomcat": {
        "headers": {"server": r"Apache-Coyote"},
        "body":    [r"Apache Tomcat"],
        "version": r"Apache Tomcat/([\d.]+)",
    },
    "Server:WebLogic": {
        "headers": {"server": r"WebLogic"},
        "body":    [r"WebLogic Server"],
        "version": r"WebLogic Server ([\d.]+)",
    },
    "Server:JBoss": {
        "body":    [r"JBoss", r"WildFly"],
    },

    # ── Programming Languages / Runtimes ──────────────────────────────────────
    "Lang:PHP": {
        "headers": {"X-Powered-By": r"PHP(?:/([\d.]+))?"},
        "body":    [r"\.php"],
        "version": r"PHP/([\d.]+)",
    },
    "Lang:Python": {
        "headers": {"X-Powered-By": r"Python", "server": r"Python"},
    },
    "Lang:Node.js": {
        "headers": {"X-Powered-By": r"Express|Node\.js"},
    },
    "Lang:Java": {
        "cookies": ["JSESSIONID"],
        "headers": {"X-Powered-By": r"JSP", "server": r"Java"},
    },

    # ── JS Libraries ──────────────────────────────────────────────────────────
    "JS:jQuery": {
        "body":    [r"jquery[.-][\d.]+\.(?:min\.)?js", r"jquery\.min\.js"],
        "script":  [r"jquery[.-][\d]+"],
        "version": r"jquery[.-]([\d.]+)",
    },
    "JS:Bootstrap": {
        "body":    [r"bootstrap[.-][\d.]+\.(?:min\.)?js", r"bootstrap\.min\.css"],
        "script":  [r"bootstrap[.-][\d]+"],
        "version": r"bootstrap[.-]([\d.]+)",
    },
    "JS:Lodash": {
        "script":  [r"lodash[.-][\d]+"],
    },
    "JS:Moment.js": {
        "script":  [r"moment[.-][\d]+"],
    },
    "JS:Chart.js": {
        "script":  [r"chart[.-][\d]+"],
    },
    "JS:Three.js": {
        "script":  [r"three[.-][\d]+"],
    },
    "JS:D3.js": {
        "script":  [r"d3[.-][\d]+"],
    },

    # ── CDN / Cloud ────────────────────────────────────────────────────────────
    "CDN:Cloudflare": {
        "headers": {"cf-ray": r".*", "cf-cache-status": r".*"},
    },
    "CDN:Fastly": {
        "headers": {"x-served-by": r"cache", "fastly-restarts": r".*"},
    },
    "CDN:AWS CloudFront": {
        "headers": {"x-amz-cf-id": r".*", "via": r"CloudFront"},
    },
    "CDN:jsDelivr": {
        "body":    [r"cdn\.jsdelivr\.net"],
    },
    "CDN:unpkg": {
        "body":    [r"unpkg\.com"],
    },

    # ── Analytics / Marketing ─────────────────────────────────────────────────
    "Analytics:Google Analytics": {
        "body":    [r"google-analytics\.com/analytics\.js", r"gtag\(", r"UA-\d+-\d+", r"G-[A-Z0-9]+"],
    },
    "Analytics:Google Tag Manager": {
        "body":    [r"googletagmanager\.com/gtm\.js", r"GTM-[A-Z0-9]+"],
    },
    "Analytics:Hotjar": {
        "body":    [r"hotjar\.com", r"hjSiteSettings"],
    },
    "Analytics:Mixpanel": {
        "body":    [r"mixpanel\.com"],
    },
    "Analytics:Segment": {
        "body":    [r"segment\.com/analytics\.js"],
    },
    "Analytics:Facebook Pixel": {
        "body":    [r"connect\.facebook\.net/.*fbevents\.js"],
    },

    # ── Payment ───────────────────────────────────────────────────────────────
    "Payment:Stripe": {
        "body":    [r"js\.stripe\.com"],
        "script":  [r"stripe[.-]"],
    },
    "Payment:PayPal": {
        "body":    [r"paypal\.com/sdk/js"],
    },
    "Payment:Square": {
        "body":    [r"js\.squareup\.com"],
    },

    # ── Search / Infra ────────────────────────────────────────────────────────
    "Search:Algolia": {
        "body":    [r"algoliasearch", r"algolia\.com"],
    },
    "Search:Elasticsearch": {
        "body":    [r"elasticsearch", r"elastic\.co"],
    },

    # ── Security ──────────────────────────────────────────────────────────────
    "Security:reCAPTCHA": {
        "body":    [r"google\.com/recaptcha"],
    },
    "Security:hCaptcha": {
        "body":    [r"hcaptcha\.com"],
    },
    "Security:Cloudflare Turnstile": {
        "body":    [r"challenges\.cloudflare\.com/turnstile"],
    },
}

# ── Technologies that are high-value targets (map to CVE scanning) ────────────

CVE_TARGET_TECH = {
    "CMS:WordPress",
    "CMS:Joomla",
    "CMS:Drupal",
    "CMS:Magento",
    "Framework:Laravel",
    "Framework:ASP.NET",
    "Framework:Spring Boot",
    "Framework:Django",
    "Server:Nginx",
    "Server:Apache",
    "Server:IIS",
    "Server:Tomcat",
    "Server:WebLogic",
    "Server:JBoss",
    "Lang:PHP",
}


class TechDetector(BaseScanner):
    """
    Technology detector — fingerprints CMS, server software, frameworks,
    JS libraries, CDNs, and analytics tools from HTTP responses.

    Outputs a TECH_JSON: line consumed by web_gui's recon panel.
    """

    SCANNER_NAME   = "Technology Detector"
    OWASP_CATEGORY = "A05:2021"
    CWE            = "CWE-200"

    def run(self) -> list[Finding]:
        console.print(f"[bold cyan]🧬 TECH:[/bold cyan] Fingerprinting technologies at [green]{self.target}[/green]")

        detected: dict[str, dict] = {}   # tech_key → {version, category, name}

        # Fetch home page
        try:
            resp = requests.get(
                self.target, timeout=12, verify=False,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 BugScanner/1.0"},
            )
            body     = resp.text
            headers  = {k.lower(): v for k, v in resp.headers.items()}
            cookies  = {c.name: c.value for c in resp.cookies}
            soup     = BeautifulSoup(body, "html.parser")
            scripts  = [s.get("src", "") for s in soup.find_all("script") if s.get("src")]
            meta_gen = soup.find("meta", {"name": re.compile(r"generator", re.I)})
            meta_gen_content = meta_gen.get("content", "") if meta_gen else ""
        except Exception as e:
            console.print(f"  [yellow]![/yellow] Fetch failed: {e}")
            return []

        # Fetch robots.txt / sitemap for extra hints
        extra_body = ""
        for path in ["/robots.txt", "/sitemap.xml", "/feed", "/readme.html"]:
            try:
                r2 = requests.get(
                    self.target.rstrip("/") + path, timeout=6, verify=False
                )
                if r2.status_code == 200:
                    extra_body += r2.text[:2000]
            except Exception:
                pass

        body_all = body + extra_body

        # Run fingerprint checks
        for tech_key, sigs in TECH_DB.items():
            version   = ""
            category, name = tech_key.split(":", 1)
            matched   = False

            # Check HTTP headers
            for hname, pattern in sigs.get("headers", {}).items():
                hval = headers.get(hname.lower(), "")
                if hval and re.search(pattern, hval, re.I):
                    matched = True
                    m = re.search(pattern, hval, re.I)
                    if m and m.lastindex:
                        version = m.group(1)
                    break

            # Check body patterns
            if not matched:
                for pattern in sigs.get("body", []):
                    if re.search(pattern, body_all, re.I):
                        matched = True
                        break

            # Check cookies
            if not matched:
                for cname in sigs.get("cookies", []):
                    for actual_cookie in cookies:
                        if re.search(cname, actual_cookie, re.I):
                            matched = True
                            break
                    if matched:
                        break

            # Check script sources
            if not matched:
                for pattern in sigs.get("script", []):
                    for src in scripts:
                        if re.search(pattern, src, re.I):
                            matched = True
                            # Try to extract version from src URL
                            m2 = re.search(r"([\d]+\.[\d]+(?:\.[\d]+)?)", src)
                            if m2:
                                version = m2.group(1)
                            break
                    if matched:
                        break

            # Check meta tags
            if not matched:
                for meta_name, pattern in sigs.get("meta", {}).items():
                    if re.search(pattern, meta_gen_content, re.I):
                        matched = True
                        m = re.search(pattern, meta_gen_content, re.I)
                        if m and m.lastindex:
                            version = m.group(1)
                        break

            # Version extraction (separate pass on full body)
            if matched and not version and "version" in sigs:
                m = re.search(sigs["version"], body_all, re.I)
                if m and m.lastindex:
                    version = m.group(1)

            if matched:
                detected[tech_key] = {
                    "category": category,
                    "name":     name,
                    "version":  version or "unknown",
                    "cve_target": tech_key in CVE_TARGET_TECH,
                }
                console.print(
                    f"  [green]✓[/green] [{category}] [cyan]{name}[/cyan]"
                    + (f"  [dim]v{version}[/dim]" if version and version != "unknown" else "")
                )

        if not detected:
            console.print("  [dim]No definitive technology signatures matched[/dim]")

        # Store for cross-module access (CVEScanner reads this)
        self.technologies = detected

        # Emit for web GUI
        self._emit_tech_json(detected, headers)
        self._make_findings(detected, headers)

        return [f.to_dict() if hasattr(f, "to_dict") else f for f in self.findings]

    # ─── Output ───────────────────────────────────────────────────────────────

    def _emit_tech_json(self, detected: dict, headers: dict):
        print(f"TECH_JSON:{json.dumps({'technologies': detected, 'headers': headers})}", flush=True)

    # ─── Findings ─────────────────────────────────────────────────────────────

    def _make_findings(self, detected: dict, headers: dict):
        # Technology disclosure finding
        if detected:
            tech_list = [
                f"{v['name']}" + (f" v{v['version']}" if v['version'] != "unknown" else "")
                for v in detected.values()
            ]
            self.add_finding(Finding(
                title=f"Technology Stack Detected ({len(detected)} components)",
                severity="INFO",
                owasp="A05:2021",
                cwe="CWE-200",
                cvss_score=0.0,
                cvss_vector="",
                url=self.target,
                description=(
                    "The following technologies were identified via HTTP response fingerprinting:\n\n"
                    + "\n".join(f"• {t}" for t in sorted(tech_list))
                ),
                impact="Enables targeted CVE and exploit research by attackers.",
                remediation=(
                    "Remove version disclosure from headers (Server, X-Powered-By, X-Generator). "
                    "Use generic error pages. Suppress framework-specific response headers."
                ),
                confirmed=True,
                vuln_type="info_disclosure",
            ))

        # Check for outdated/risky CMS
        outdated = {
            "WordPress": ("6.4", "5.9"),
            "Joomla":    ("5.0", "3.x"),
            "Drupal":    ("10.0", "7.x"),
            "Magento":   ("2.4", "2.3"),
        }
        for tech_key, info in detected.items():
            name    = info["name"]
            version = info["version"]
            if name in outdated and version not in ("unknown", ""):
                latest, eol = outdated[name]
                if any(eol_part in version for eol_part in eol.split(",")):
                    self.add_finding(Finding(
                        title=f"Outdated CMS Detected: {name} {version}",
                        severity="HIGH",
                        owasp="A06:2021",
                        cwe="CWE-1104",
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        url=self.target,
                        description=(
                            f"**{name} {version}** is detected and may be end-of-life. "
                            f"Latest stable version is {latest}. "
                            "Outdated CMS installations often have known, publicly exploited CVEs."
                        ),
                        impact="Critical unpatched vulnerabilities may be exploitable without authentication.",
                        remediation=f"Upgrade {name} to the latest stable release ({latest}+). Apply all security patches.",
                        confirmed=True,
                        vuln_type="outdated_software",
                    ))

        # Missing security headers
        security_headers = {
            "strict-transport-security": ("HSTS Missing", "MEDIUM", 5.9,
                "Enforce HTTPS by adding: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
            "content-security-policy": ("CSP Missing", "MEDIUM", 5.4,
                "Add a Content-Security-Policy header to prevent XSS/injection attacks."),
            "x-frame-options": ("Clickjacking (X-Frame-Options Missing)", "MEDIUM", 4.3,
                "Add X-Frame-Options: SAMEORIGIN or DENY to prevent clickjacking."),
            "x-content-type-options": ("MIME-Sniffing (X-Content-Type-Options Missing)", "LOW", 3.1,
                "Add X-Content-Type-Options: nosniff"),
            "referrer-policy": ("Referrer-Policy Missing", "LOW", 2.5,
                "Add Referrer-Policy: no-referrer or strict-origin-when-cross-origin"),
            "permissions-policy": ("Permissions-Policy Missing", "LOW", 2.0,
                "Add Permissions-Policy to restrict browser features."),
        }
        for hname, (title, sev, cvss, remediation) in security_headers.items():
            if hname not in headers:
                self.add_finding(Finding(
                    title=title,
                    severity=sev,
                    owasp="A05:2021",
                    cwe="CWE-693",
                    cvss_score=cvss,
                    cvss_vector="",
                    url=self.target,
                    description=f"The `{hname}` security header is not present in the HTTP response.",
                    impact=f"Increases exposure to browser-based attacks.",
                    remediation=remediation,
                    confirmed=True,
                    vuln_type="missing_header",
                ))
