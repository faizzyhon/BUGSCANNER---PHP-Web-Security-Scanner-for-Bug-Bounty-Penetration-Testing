#!/usr/bin/env python3
"""
BugScanner - Professional Web Security Scanner
EC-Council Bug Bounty Course Assignment Tool

⚠️  ETHICAL USE DISCLAIMER ⚠️
This tool is intended ONLY for:
  - Authorized bug bounty targets (within defined scope)
  - CTF lab environments
  - Systems you own or have explicit written permission to test

Unauthorized use against systems you do not have permission to test
is ILLEGAL and violates computer fraud laws (CFAA, Computer Misuse Act, etc.)
The authors assume no liability for misuse of this tool.
"""

import sys
import time
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.text import Text
from rich import box

# Internal imports
from utils.logger import setup_logger, get_logger
from utils.scope import ScopeValidator
from utils.http_client import HttpClient
from utils.auth import AuthManager, AuthResult
from scanners.xxe import XXEScanner
from scanners.sqli import SQLiScanner
from scanners.xss import XSSScanner
from scanners.ssrf import SSRFScanner
from scanners.idor import IDORScanner
from scanners.cmdi import CMDiScanner
from scanners.lfi import LFIScanner
from scanners.open_redirect import OpenRedirectScanner
from scanners.headers import HeadersScanner
from scanners.jwt_check import JWTScanner
from scanners.payment_bypass import PaymentBypassScanner
from scanners.php_specific import PhpSpecificScanner
from reporter.generator import ReportGenerator

console = Console()
logger = get_logger(__name__)

BANNER = """
[bold red]
 ██████╗ ██╗   ██╗ ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
 ██╔══██╗██║   ██║██╔════╝ ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
 ██████╔╝██║   ██║██║  ███╗███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
 ██╔══██╗██║   ██║██║   ██║╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
 ██████╔╝╚██████╔╝╚██████╔╝███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
 ╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
[/bold red]
[bold yellow]  Professional Web Vulnerability Scanner | EC-Council Bug Bounty Edition v1.0[/bold yellow]
[dim]  For authorized security testing only | OWASP Top 10 Coverage[/dim]
"""

DISCLAIMER = """[bold red]⚠  LEGAL DISCLAIMER ⚠[/bold red]

This tool is for [bold]authorized security testing only[/bold].
By using this tool you confirm:

  [yellow]•[/yellow] You have [bold green]explicit written permission[/bold green] to test the target
  [yellow]•[/yellow] The target is within your [bold green]authorized bug bounty scope[/bold green], a CTF, or your own system
  [yellow]•[/yellow] You understand unauthorized scanning is [bold red]ILLEGAL[/bold red] under CFAA and similar laws
  [yellow]•[/yellow] You accept full responsibility for your actions

[dim]Use --i-have-permission flag to acknowledge and proceed[/dim]"""

SCANNER_REGISTRY = {
    "xxe": ("XXE Injection", XXEScanner, "A4"),
    "sqli": ("SQL Injection", SQLiScanner, "A3"),
    "xss": ("Cross-Site Scripting", XSSScanner, "A3"),
    "ssrf": ("Server-Side Request Forgery", SSRFScanner, "A10"),
    "idor": ("Insecure Direct Object Reference", IDORScanner, "A1"),
    "cmdi": ("Command Injection", CMDiScanner, "A3"),
    "lfi": ("Path Traversal / LFI", LFIScanner, "A5"),
    "open_redirect": ("Open Redirect", OpenRedirectScanner, "A10"),
    "headers": ("Security Misconfiguration / Headers", HeadersScanner, "A5"),
    "jwt": ("Broken Authentication / JWT", JWTScanner, "A2"),
    "payment": ("Crypto Payment / Balance Bypass", PaymentBypassScanner, "A1"),
    "php":     ("PHP-Specific: DB Dump / File Access / Webshell", PhpSpecificScanner, "A5"),
}


def print_banner():
    console.print(BANNER)


def print_scope_warning():
    console.print(Panel(DISCLAIMER, border_style="red", padding=(1, 2)))


def print_findings_table(all_findings: list):
    """Print a summary table of all findings."""
    severity_colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "cyan",
        "INFO": "dim",
    }

    table = Table(
        title="[bold]Security Scan Results[/bold]",
        box=box.ROUNDED,
        show_lines=True,
        border_style="blue",
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Vulnerability", width=35)
    table.add_column("OWASP", width=8)
    table.add_column("Endpoint", width=45)
    table.add_column("Confirmed", width=10)

    for i, finding in enumerate(all_findings, 1):
        sev = finding.get("severity", "INFO")
        color = severity_colors.get(sev, "white")
        confirmed = "[green]✓ Yes[/green]" if finding.get("confirmed") else "[yellow]? Maybe[/yellow]"
        table.add_row(
            str(i),
            f"[{color}]{sev}[/{color}]",
            finding.get("title", "Unknown"),
            finding.get("owasp", ""),
            finding.get("url", "")[:43],
            confirmed,
        )

    console.print("\n")
    console.print(table)


def print_stats(all_findings: list, scan_duration: float):
    """Print scan statistics."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in all_findings:
        counts[f.get("severity", "INFO")] = counts.get(f.get("severity", "INFO"), 0) + 1

    stats = Table(box=box.SIMPLE, show_header=False)
    stats.add_column("Metric", style="bold cyan")
    stats.add_column("Value", style="white")
    stats.add_row("Total Findings", str(len(all_findings)))
    stats.add_row("Critical", f"[bold red]{counts['CRITICAL']}[/bold red]")
    stats.add_row("High", f"[red]{counts['HIGH']}[/red]")
    stats.add_row("Medium", f"[yellow]{counts['MEDIUM']}[/yellow]")
    stats.add_row("Low", f"[cyan]{counts['LOW']}[/cyan]")
    stats.add_row("Info", f"[dim]{counts['INFO']}[/dim]")
    stats.add_row("Scan Duration", f"{scan_duration:.2f}s")

    console.print(Panel(stats, title="[bold]Scan Statistics[/bold]", border_style="green"))


@click.group()
def cli():
    """BugScanner — Professional Web Vulnerability Scanner for Bug Bounty & CTF Labs."""
    pass


@cli.command()
@click.option("--target", "-t", required=True, help="Target URL (e.g. https://target.com)")
@click.option("--i-have-permission", "permission", is_flag=True, default=False,
              help="Confirm you have explicit authorization to test this target")
@click.option("--modules", "-m", multiple=True,
              type=click.Choice(list(SCANNER_REGISTRY.keys()) + ["all"]),
              default=["all"], help="Modules to run (default: all)")
@click.option("--output", "-o", default="./reports", help="Output directory for reports")
@click.option("--timeout", default=10, help="HTTP request timeout in seconds")
@click.option("--threads", default=5, help="Concurrent request threads")
@click.option("--cookies", default="", help="Cookies string (e.g. 'session=abc; token=xyz')")
@click.option("--headers-extra", default="", help="Extra headers as JSON string")
@click.option("--depth", default=2, help="Crawl depth for link discovery")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Verbose output")
@click.option("--no-pdf", is_flag=True, default=False, help="Skip PDF report generation")
@click.option("--format", "report_format", type=click.Choice(["pdf", "markdown", "both"]),
              default="both", help="Report output format")
# ── Authentication options ────────────────────────────────────────────────────
@click.option("--username", "-u", default="", help="Username/email for target login")
@click.option("--password", "-p", default="", help="Password for target login",
              hide_input=True, confirmation_prompt=False)
@click.option("--login-url", default="", help="Explicit login page URL (auto-detected if omitted)")
@click.option("--auth-type", default="auto",
              type=click.Choice(["auto", "form", "json", "basic"]),
              help="Authentication method: auto (default), form, json (API), basic (HTTP Basic)")
def scan(target, permission, modules, output, timeout, threads, cookies,
         headers_extra, depth, verbose, no_pdf, report_format,
         username, password, login_url, auth_type):
    """Run a full vulnerability scan against a target URL."""

    print_banner()

    # ─── Scope / Permission Gate ─────────────────────────────────────────────
    if not permission:
        print_scope_warning()
        console.print("\n[bold red]ERROR:[/bold red] You must confirm authorization with --i-have-permission\n")
        sys.exit(1)

    # Setup logging
    setup_logger(verbose=verbose)

    # Validate target URL
    scope = ScopeValidator(target)
    if not scope.is_valid_url():
        console.print(f"[bold red]ERROR:[/bold red] Invalid target URL: {target}")
        sys.exit(1)

    # Parse extra headers
    extra_headers = {}
    if headers_extra:
        try:
            extra_headers = json.loads(headers_extra)
        except json.JSONDecodeError:
            console.print("[yellow]WARNING:[/yellow] Could not parse extra headers JSON, ignoring.")

    # Parse cookies
    cookie_dict = {}
    if cookies:
        for part in cookies.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                cookie_dict[k.strip()] = v.strip()

    # Setup HTTP client
    http_client = HttpClient(
        timeout=timeout,
        cookies=cookie_dict,
        extra_headers=extra_headers,
    )

    # ─── Authentication ───────────────────────────────────────────────────────
    auth_result: Optional[AuthResult] = None
    if username:
        if not password:
            password = click.prompt(
                f"  [bold yellow]Password for '{username}'[/bold yellow]",
                hide_input=True,
            )
        console.print(f"\n[bold]🔐 Authenticating as:[/bold] [cyan]{username}[/cyan]", end=" ")
        auth_mgr = AuthManager(session=http_client.session, target_url=target)
        auth_result = auth_mgr.login(
            username=username,
            password=password,
            login_url=login_url or None,
            auth_type=auth_type,
        )
        if auth_result.success:
            console.print(f"[bold green]✓ Success[/bold green]")
            console.print(
                Panel(
                    f"[bold green]✓ Authenticated[/bold green]\n"
                    f"[cyan]Method:[/cyan]    {auth_result.method}\n"
                    f"[cyan]Username:[/cyan]  {auth_result.username}\n"
                    f"[cyan]Login URL:[/cyan] {auth_result.login_url}\n"
                    f"[cyan]Message:[/cyan]   {auth_result.message}\n"
                    f"[cyan]Cookies:[/cyan]   "
                    + (", ".join(auth_result.session_cookies.keys()) or "none"),
                    title="[bold green]🔐 Authentication Status[/bold green]",
                    border_style="green",
                )
            )
            # Propagate all auth state (cookies + headers) to the http_client
            # so every scanner module uses the authenticated session
            http_client.apply_auth_result(auth_result)
        else:
            console.print(f"[bold red]✗ Failed[/bold red]")
            console.print(
                Panel(
                    f"[bold red]✗ Authentication Failed[/bold red]\n"
                    f"[yellow]Reason:[/yellow] {auth_result.message}\n\n"
                    "[dim]The scan will continue unauthenticated.\n"
                    "Tips:\n"
                    "  • Use --login-url to specify the exact login endpoint\n"
                    "  • Try --auth-type basic for HTTP Basic Auth\n"
                    "  • Try --auth-type json for REST API login\n"
                    "  • Manually obtain cookies and use --cookies instead[/dim]",
                    title="[bold red]🔐 Authentication Status[/bold red]",
                    border_style="red",
                )
            )
    # ─── Scan Configuration Panel ─────────────────────────────────────────────

    # Determine which modules to run
    run_modules = list(SCANNER_REGISTRY.keys()) if "all" in modules else list(modules)

    auth_status = (
        f"[green]✓ Authenticated as {username}[/green]"
        if (auth_result and auth_result.success)
        else (f"[yellow]Attempted (failed) — unauthenticated[/yellow]" if username
              else "[dim]None (unauthenticated)[/dim]")
    )

    console.print(Panel(
        f"[bold cyan]Target:[/bold cyan]  {target}\n"
        f"[bold cyan]Auth:[/bold cyan]    {auth_status}\n"
        f"[bold cyan]Modules:[/bold cyan] {', '.join(run_modules)}\n"
        f"[bold cyan]Timeout:[/bold cyan] {timeout}s  |  "
        f"[bold cyan]Threads:[/bold cyan] {threads}  |  "
        f"[bold cyan]Depth:[/bold cyan] {depth}",
        title="[bold green]Scan Configuration[/bold green]",
        border_style="green",
    ))

    scan_start = time.time()
    all_findings = []

    # ─── Run Scanners ─────────────────────────────────────────────────────────
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Scanning...", total=len(run_modules))

        for mod_key in run_modules:
            mod_name, ScannerClass, owasp = SCANNER_REGISTRY[mod_key]
            progress.update(task, description=f"[cyan]Testing: {mod_name:<40}")

            try:
                scanner = ScannerClass(
                    target=target,
                    http_client=http_client,
                    scope=scope,
                    verbose=verbose,
                )
                findings = scanner.run()
                all_findings.extend(findings)

                if findings and verbose:
                    console.print(f"  [green]✓[/green] {mod_name}: {len(findings)} finding(s)")
                elif verbose:
                    console.print(f"  [dim]✗ {mod_name}: No findings[/dim]")

            except Exception as exc:
                logger.warning(f"Scanner {mod_key} error: {exc}")
                if verbose:
                    console.print(f"  [yellow]! {mod_name}: Error — {exc}[/yellow]")

            progress.advance(task)

    scan_duration = time.time() - scan_start

    # ─── Display Results ──────────────────────────────────────────────────────
    if all_findings:
        print_findings_table(all_findings)
    else:
        console.print("\n[bold green]✓ No vulnerabilities detected.[/bold green]\n")

    print_stats(all_findings, scan_duration)

    # ─── Generate Reports ─────────────────────────────────────────────────────
    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    scan_meta = {
        "target": target,
        "scan_date": datetime.now().isoformat(),
        "duration_seconds": round(scan_duration, 2),
        "modules_run": run_modules,
        "total_findings": len(all_findings),
        "scanner_version": "1.0.0",
        "authenticated": bool(auth_result and auth_result.success),
        "auth_user": username if (auth_result and auth_result.success) else "",
        "auth_method": auth_result.method if (auth_result and auth_result.success) else "none",
    }

    generator = ReportGenerator(
        findings=all_findings,
        meta=scan_meta,
        output_dir=output_dir,
    )

    console.print("\n[bold]Generating reports...[/bold]")

    if report_format in ("markdown", "both"):
        md_path = generator.generate_markdown()
        console.print(f"  [green]✓[/green] Markdown report: [link]{md_path}[/link]")

    if report_format in ("pdf", "both") and not no_pdf:
        try:
            pdf_path = generator.generate_pdf()
            console.print(f"  [green]✓[/green] PDF report:      [link]{pdf_path}[/link]")
        except Exception as e:
            console.print(f"  [yellow]! PDF generation failed: {e}[/yellow]")
            console.print("  [dim]  Tip: pip install weasyprint reportlab[/dim]")

    console.print(f"\n[bold green]✓ Scan complete![/bold green] Reports saved to: {output_dir.resolve()}\n")


@cli.command()
@click.option("--target", "-t", required=True, help="Target URL to validate")
def validate_scope(target):
    """Check if a target URL is structurally valid before scanning."""
    print_banner()
    scope = ScopeValidator(target)
    if scope.is_valid_url():
        console.print(f"[green]✓ Valid URL:[/green] {target}")
        console.print(f"[cyan]  Host:[/cyan] {scope.host}")
        console.print(f"[cyan]  Scheme:[/cyan] {scope.scheme}")
    else:
        console.print(f"[red]✗ Invalid URL:[/red] {target}")


@cli.command()
def list_modules():
    """List all available scanner modules."""
    print_banner()
    table = Table(title="Available Scanner Modules", box=box.ROUNDED, border_style="blue")
    table.add_column("Key", style="cyan", width=16)
    table.add_column("Module Name", width=40)
    table.add_column("OWASP Category", width=12)
    table.add_column("CWE(s)", width=20)

    cwe_map = {
        "xxe": "CWE-611",
        "sqli": "CWE-89",
        "xss": "CWE-79",
        "ssrf": "CWE-918",
        "idor": "CWE-639",
        "cmdi": "CWE-78",
        "lfi": "CWE-22",
        "open_redirect": "CWE-601",
        "headers": "CWE-16",
        "jwt": "CWE-287, CWE-347",
        "payment": "CWE-840, CWE-362",
        "php":     "CWE-200, CWE-22, CWE-89, CWE-502, CWE-434, CWE-98",
    }

    for key, (name, _, owasp) in SCANNER_REGISTRY.items():
        table.add_row(key, name, owasp, cwe_map.get(key, ""))

    console.print(table)


@cli.command("test-login")
@click.option("--target", "-t", required=True, help="Target URL")
@click.option("--username", "-u", required=True, help="Username or email")
@click.option("--password", "-p", default="", help="Password (prompted if omitted)", hide_input=True)
@click.option("--login-url", default="", help="Explicit login URL (auto-detected if omitted)")
@click.option("--auth-type", default="auto",
              type=click.Choice(["auto", "form", "json", "basic"]),
              help="Authentication method")
def test_login(target, username, password, login_url, auth_type):
    """Test authentication credentials against a target without running a scan.

    \b
    Examples:
      python main.py test-login -t https://app.example.com -u admin -p secret
      python main.py test-login -t https://api.example.com -u user@mail.com --auth-type json
      python main.py test-login -t https://app.example.com -u admin --login-url /auth/login
    """
    print_banner()
    setup_logger(verbose=True)

    if not password:
        password = click.prompt(f"Password for '{username}'", hide_input=True)

    from utils.http_client import HttpClient
    http_client = HttpClient()
    auth_mgr = AuthManager(session=http_client.session, target_url=target)

    console.print(f"\n[bold]Testing login:[/bold] [cyan]{username}[/cyan] @ [cyan]{target}[/cyan]\n")

    result = auth_mgr.login(
        username=username,
        password=password,
        login_url=login_url or None,
        auth_type=auth_type,
    )

    if result.success:
        console.print(Panel(
            f"[bold green]✅ Authentication Successful[/bold green]\n\n"
            f"[cyan]Method:[/cyan]    {result.method}\n"
            f"[cyan]Username:[/cyan]  {result.username}\n"
            f"[cyan]Login URL:[/cyan] {result.login_url}\n"
            f"[cyan]Message:[/cyan]   {result.message}\n"
            f"[cyan]HTTP Status:[/cyan] {result.response_status}\n\n"
            f"[cyan]Session Cookies:[/cyan]\n"
            + "\n".join(f"  {k} = {v[:40]}..." if len(v) > 40 else f"  {k} = {v}"
                        for k, v in result.session_cookies.items())
            or "  (none)",
            title="[bold green]🔐 Login Test Result[/bold green]",
            border_style="green",
        ))
        console.print(
            "\n[dim]Tip: Use these cookies with --cookies flag for authenticated scanning:[/dim]"
        )
        cookie_str = "; ".join(f"{k}={v}" for k, v in result.session_cookies.items())
        if cookie_str:
            console.print(f'[dim]  --cookies "{cookie_str}"[/dim]\n')
    else:
        console.print(Panel(
            f"[bold red]❌ Authentication Failed[/bold red]\n\n"
            f"[yellow]Reason:[/yellow] {result.message}\n"
            f"[yellow]HTTP Status:[/yellow] {result.response_status}\n\n"
            "[dim]Troubleshooting:\n"
            "  • Verify username and password are correct\n"
            "  • Try --login-url to specify the exact login endpoint\n"
            "  • Try --auth-type basic for HTTP Basic Auth\n"
            "  • Try --auth-type json for REST API endpoints\n"
            "  • Check --verbose output above for request details[/dim]",
            title="[bold red]🔐 Login Test Result[/bold red]",
            border_style="red",
        ))


if __name__ == "__main__":
    cli()
