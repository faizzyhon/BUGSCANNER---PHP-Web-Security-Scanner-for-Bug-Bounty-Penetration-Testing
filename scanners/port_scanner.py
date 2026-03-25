"""
╔══════════════════════════════════════════════════════════════════════════╗
║  BugScanner — Port Scanner Module                                        ║
║  Author : Muhammad Faizan (faizzyhon@gmail.com)                          ║
║  Covers : Fast TCP connect scan, service banner grabbing,                ║
║           dangerous service detection, SSL on non-standard ports         ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

import json
import socket
import ssl
import concurrent.futures
from datetime import datetime
from urllib.parse import urlparse

from rich.console import Console
from .base import BaseScanner, Finding

console = Console(stderr=True)

# ── Port definitions ──────────────────────────────────────────────────────────

COMMON_PORTS = {
    # Web
    21:   ("FTP",           "ftp"),
    22:   ("SSH",           "ssh"),
    23:   ("Telnet",        "telnet"),
    25:   ("SMTP",          "smtp"),
    53:   ("DNS",           "dns"),
    80:   ("HTTP",          "http"),
    110:  ("POP3",          "pop3"),
    111:  ("RPCBind",       "rpc"),
    135:  ("MSRPC",         "rpc"),
    139:  ("NetBIOS",       "smb"),
    143:  ("IMAP",          "imap"),
    161:  ("SNMP",          "snmp"),
    389:  ("LDAP",          "ldap"),
    443:  ("HTTPS",         "https"),
    445:  ("SMB",           "smb"),
    465:  ("SMTPS",         "smtp"),
    587:  ("SMTP Sub",      "smtp"),
    631:  ("IPP/CUPS",      "ipp"),
    993:  ("IMAPS",         "imap"),
    995:  ("POP3S",         "pop3"),
    1080: ("SOCKS Proxy",   "proxy"),
    1433: ("MSSQL",         "mssql"),
    1521: ("Oracle DB",     "oracle"),
    2049: ("NFS",           "nfs"),
    2375: ("Docker API",    "docker"),
    2376: ("Docker TLS",    "docker"),
    3000: ("Dev Server",    "http"),
    3306: ("MySQL",         "mysql"),
    3389: ("RDP",           "rdp"),
    4000: ("Dev Server",    "http"),
    4443: ("Alt HTTPS",     "https"),
    5000: ("Dev Server",    "http"),
    5432: ("PostgreSQL",    "postgresql"),
    5601: ("Kibana",        "http"),
    5900: ("VNC",           "vnc"),
    5984: ("CouchDB",       "http"),
    6379: ("Redis",         "redis"),
    6443: ("K8s API",       "https"),
    7001: ("WebLogic",      "http"),
    7443: ("WebLogic TLS",  "https"),
    8000: ("Dev HTTP",      "http"),
    8080: ("Alt HTTP",      "http"),
    8081: ("Alt HTTP",      "http"),
    8082: ("Alt HTTP",      "http"),
    8443: ("Alt HTTPS",     "https"),
    8888: ("Jupyter/HTTP",  "http"),
    9000: ("PHP-FPM/HTTP",  "http"),
    9200: ("Elasticsearch", "http"),
    9300: ("Elasticsearch", "tcp"),
    9418: ("Git",           "git"),
    11211:("Memcached",     "memcached"),
    15672:("RabbitMQ Mgmt", "http"),
    27017:("MongoDB",       "mongodb"),
    27018:("MongoDB",       "mongodb"),
    50000:("SAP",           "http"),
}

# Ports that are HIGH risk if exposed
DANGEROUS_PORTS = {
    21, 23, 135, 139, 445, 1433, 1521, 2049, 2375, 2376,
    3306, 3389, 5432, 5900, 5984, 6379, 7001, 9200, 9300,
    11211, 27017, 27018, 50000,
}

# Ports that should only be on localhost
INTERNAL_ONLY = {2375, 2376, 5984, 6379, 9200, 9300, 11211, 27017, 27018}

# ── Banner grabs ──────────────────────────────────────────────────────────────

BANNER_PROBES = {
    "ftp":       b"",
    "ssh":       b"",
    "smtp":      b"",
    "http":      b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    "https":     b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    "mysql":     b"",
    "redis":     b"PING\r\n",
    "memcached": b"stats\r\n",
    "mongodb":   b"",
}


def _grab_banner(host: str, port: int, proto: str, timeout: float = 3.0) -> str:
    """Attempt to grab a service banner from the given port."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)

        probe = BANNER_PROBES.get(proto, b"")
        if probe:
            sock.send(probe.replace(b"{host}", host.encode()))

        banner = sock.recv(256).decode("utf-8", errors="replace").strip()
        sock.close()
        return banner[:120]
    except Exception:
        # Try TLS wrap for HTTPS-like ports
        if proto in ("https",):
            try:
                ctx  = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                conn = ctx.wrap_socket(
                    socket.create_connection((host, port), timeout=timeout),
                    server_hostname=host,
                )
                conn.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                banner = conn.recv(256).decode("utf-8", errors="replace").strip()
                conn.close()
                return banner[:120]
            except Exception:
                pass
        return ""


def _check_port(host: str, port: int, timeout: float = 2.5) -> bool:
    """Return True if port is open (TCP connect)."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


class PortScanner(BaseScanner):
    """
    Fast TCP connect port scanner.

    Scans ~70 common ports concurrently, grabs service banners,
    and flags dangerous/exposed services as findings.
    """

    SCANNER_NAME   = "Port Scanner"
    OWASP_CATEGORY = "A05:2021"
    CWE            = "CWE-200"

    # Override via constructor if you want a different set
    TARGET_PORTS: list[int] = list(COMMON_PORTS.keys())
    MAX_WORKERS:  int       = 50
    TIMEOUT:      float     = 2.5

    def run(self) -> list[Finding]:
        parsed   = urlparse(self.target)
        self.host = parsed.hostname or ""

        # Resolve IP first
        try:
            self.ip = socket.gethostbyname(self.host)
        except socket.gaierror:
            self.ip = self.host

        console.print(
            f"[bold cyan]🔌 PORTS:[/bold cyan] Scanning [green]{self.host}[/green] "
            f"({len(self.TARGET_PORTS)} ports, {self.MAX_WORKERS} threads)"
        )

        open_ports: list[dict] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as pool:
            future_map = {
                pool.submit(_check_port, self.host, port, self.TIMEOUT): port
                for port in self.TARGET_PORTS
            }
            for future in concurrent.futures.as_completed(future_map):
                port = future_map[future]
                try:
                    if future.result():
                        service, proto = COMMON_PORTS.get(port, ("Unknown", "tcp"))
                        banner = _grab_banner(self.host, port, proto)
                        entry = {
                            "port":    port,
                            "service": service,
                            "proto":   proto,
                            "banner":  banner,
                            "state":   "open",
                        }
                        open_ports.append(entry)
                        console.print(
                            f"  [green]✓ OPEN[/green] {port:>5}/tcp  "
                            f"[cyan]{service:<18}[/cyan]"
                            + (f"  [dim]{banner[:60]}[/dim]" if banner else "")
                        )
                except Exception:
                    pass

        open_ports.sort(key=lambda x: x["port"])
        console.print(f"  [bold]Found {len(open_ports)} open port(s)[/bold]")

        # Emit structured JSON for web GUI
        self._emit_port_json(open_ports)

        # Generate findings
        for entry in open_ports:
            self._make_finding(entry)

        return [f.to_dict() if hasattr(f, "to_dict") else f for f in self.findings]

    # ─── Structured output ────────────────────────────────────────────────────

    def _emit_port_json(self, open_ports: list[dict]):
        print(f"PORT_JSON:{json.dumps({'open_ports': open_ports})}", flush=True)

    # ─── Finding generation ───────────────────────────────────────────────────

    def _make_finding(self, entry: dict):
        port    = entry["port"]
        service = entry["service"]
        banner  = entry["banner"]

        # Determine severity
        if port in INTERNAL_ONLY:
            severity   = "CRITICAL"
            cvss       = 9.8
            impact_txt = (
                f"**{service}** (port {port}) is a datastore that must NEVER be internet-exposed. "
                "Unauthenticated access typically leads to full data breach."
            )
            remediation = (
                f"Immediately bind {service} to 127.0.0.1 / firewall port {port} from all external IPs. "
                "Enable authentication and TLS."
            )
        elif port in DANGEROUS_PORTS:
            severity   = "HIGH"
            cvss       = 7.5
            impact_txt = (
                f"**{service}** on port {port} is exposed to the internet. "
                "This service is a high-value target for brute-force, exploitation, or data exfiltration."
            )
            remediation = (
                f"Restrict access to port {port} via firewall rules. "
                "Allow only trusted IP ranges. Enable strong authentication."
            )
        elif port in (80, 443, 8080, 8443, 3000, 4000, 5000, 8000):
            severity   = "INFO"
            cvss       = 0.0
            impact_txt = f"Web service running on port {port}."
            remediation = "Ensure only expected web services are exposed."
        else:
            severity   = "LOW"
            cvss       = 2.5
            impact_txt = f"Service {service} is accessible on port {port}."
            remediation = (
                f"Verify that port {port} ({service}) should be publicly accessible. "
                "Close or firewall if not required."
            )

        desc = f"Open port detected: **{port}/tcp** ({service})"
        if banner:
            desc += f"\n\nBanner: `{banner}`"

        self.add_finding(Finding(
            title=f"Open Port: {port}/tcp ({service})",
            severity=severity,
            owasp="A05:2021",
            cwe="CWE-200",
            cvss_score=cvss,
            cvss_vector=f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" if cvss > 5 else "",
            url=f"{self.target}",
            parameter=f"port:{port}",
            description=desc,
            impact=impact_txt,
            remediation=remediation,
            confirmed=True,
            vuln_type="open_port",
        ))
