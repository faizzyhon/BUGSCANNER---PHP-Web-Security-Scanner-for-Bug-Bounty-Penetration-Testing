"""
╔══════════════════════════════════════════════════════════════════════════╗
║          BugScanner — AI-Powered Zero-Day Discovery Engine              ║
║          Author : Muhammad Faizan (faizzyhon@gmail.com)                 ║
║          Module : ai_scanner.py                                         ║
║          Uses   : OpenAI GPT-4 / Anthropic Claude / Ollama (local)     ║
╚══════════════════════════════════════════════════════════════════════════╝

How it finds zero-days:
  1. RESPONSE ANALYSIS      — AI reads every HTTP response and flags anomalies
  2. PAYLOAD GENERATION     — AI generates novel payloads based on app context
  3. JS/SOURCE AUDIT        — AI audits discovered JS/PHP source for logic flaws
  4. BEHAVIOR DIFFING       — AI compares normal vs mutated requests for subtle changes
  5. CHAIN DETECTION        — AI spots multi-step exploit chains (e.g. SSRF→RCE)
  6. BUSINESS LOGIC AI      — AI reasons about the app's intended vs actual behavior

Supported AI Backends:
  • openai    — GPT-4o, GPT-4-turbo (requires API key)
  • anthropic — Claude Opus/Sonnet  (requires API key)
  • ollama    — 100% FREE local LLMs via Ollama (no key needed)
               Models: llama3.2, deepseek-r1, mistral, qwen2.5-coder,
                       phi3, gemma2, llama3.1:70b, codellama, etc.
"""

import re
import json
import time
import base64
import threading
from typing import Optional
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

# ── AI Provider abstraction ───────────────────────────────────────────────────

class AIProvider:
    """
    Universal AI provider — supports OpenAI, Anthropic, and Ollama (local, free).

    Auto-detection rules:
      provider="auto" + key starts with "sk-ant-"  → Anthropic
      provider="auto" + key starts with "sk-"       → OpenAI
      provider="ollama"                              → Ollama local (no key needed)
      provider="auto" + no key                      → Ollama local (fallback)
    """

    OLLAMA_RECOMMENDED = [
        "deepseek-r1:14b",     # best for reasoning / security analysis
        "llama3.2:3b",         # fast, good for payload gen
        "qwen2.5-coder:7b",    # best for source code audit
        "mistral:7b",          # general purpose
        "phi3:mini",           # ultra fast, lightweight
        "codellama:13b",       # code analysis
        "llama3.1:8b",         # balanced quality/speed
    ]

    def __init__(
        self,
        api_key:      str  = "",
        provider:     str  = "auto",
        model:        str  = None,
        ollama_host:  str  = "http://localhost:11434",
    ):
        self.provider    = provider
        self.api_key     = api_key
        self.ollama_host = ollama_host.rstrip("/")
        self._client     = None

        # ── Auto-detect provider ──────────────────────────────────────────────
        if provider == "auto":
            if api_key.startswith("sk-ant-"):
                self.provider = "anthropic"
            elif api_key.startswith("sk-"):
                self.provider = "openai"
            else:
                self.provider = "ollama"   # free local fallback

        # ── OpenAI ───────────────────────────────────────────────────────────
        if self.provider == "openai":
            try:
                import openai
                self._client = openai.OpenAI(api_key=api_key)
                self.model   = model or "gpt-4o"
            except ImportError:
                raise ImportError("Run: pip install openai --break-system-packages")

        # ── Anthropic ────────────────────────────────────────────────────────
        elif self.provider == "anthropic":
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=api_key)
                self.model   = model or "claude-opus-4-5"
            except ImportError:
                raise ImportError("Run: pip install anthropic --break-system-packages")

        # ── Ollama (local, 100% free, no key required) ───────────────────────
        elif self.provider == "ollama":
            self.model = model or self._detect_ollama_model()

        else:
            raise ValueError(f"Unknown provider: {provider}. Use 'openai', 'anthropic', or 'ollama'")

    # ── Ollama helpers ────────────────────────────────────────────────────────

    def _detect_ollama_model(self) -> str:
        """Query Ollama to find the best available model."""
        try:
            r = requests.get(f"{self.ollama_host}/api/tags", timeout=5)
            if r.status_code == 200:
                models = [m["name"] for m in r.json().get("models", [])]
                if not models:
                    console.print("  [yellow]⚠ Ollama is running but no models are pulled.[/yellow]")
                    console.print("  [dim]  Run: ollama pull deepseek-r1  OR  ollama pull llama3.2[/dim]")
                    return "llama3.2"  # default, user will need to pull it
                # Prefer recommended models in priority order
                for preferred in self.OLLAMA_RECOMMENDED:
                    # Match prefix (e.g. "deepseek-r1" matches "deepseek-r1:14b")
                    for available in models:
                        if available.startswith(preferred.split(":")[0]):
                            console.print(f"  [green]✓ Ollama auto-selected model: {available}[/green]")
                            return available
                # Fallback to first available
                console.print(f"  [cyan]Ollama using: {models[0]}[/cyan]")
                return models[0]
            else:
                return "llama3.2"
        except Exception:
            console.print(f"  [red]✗ Cannot reach Ollama at {self.ollama_host}[/red]")
            console.print("  [dim]  Make sure Ollama is running: ollama serve[/dim]")
            return "llama3.2"

    def _ollama_list_models(self) -> list:
        """Return list of all pulled Ollama models."""
        try:
            r = requests.get(f"{self.ollama_host}/api/tags", timeout=5)
            if r.status_code == 200:
                return [m["name"] for m in r.json().get("models", [])]
        except Exception:
            pass
        return []

    def _ollama_ask(self, system: str, user: str, max_tokens: int = 2000) -> str:
        """Call Ollama /api/chat endpoint (OpenAI-compatible format)."""
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
            "stream": False,
            "options": {
                "temperature": 0.2,
                "num_predict": max_tokens,
            },
        }
        try:
            r = requests.post(
                f"{self.ollama_host}/api/chat",
                json=payload,
                timeout=120,   # local models can be slow
            )
            if r.status_code == 200:
                data = r.json()
                return data.get("message", {}).get("content", "").strip()
            else:
                console.print(f"[red]Ollama error {r.status_code}: {r.text[:200]}[/red]")
                return ""
        except requests.exceptions.ConnectionError:
            console.print(f"[red]Cannot connect to Ollama at {self.ollama_host}[/red]")
            console.print("[dim]Start Ollama with: ollama serve[/dim]")
            return ""
        except requests.exceptions.Timeout:
            console.print(f"[yellow]Ollama timeout — model may be loading, retrying...[/yellow]")
            try:
                r = requests.post(
                    f"{self.ollama_host}/api/chat",
                    json=payload,
                    timeout=300,
                )
                return r.json().get("message", {}).get("content", "").strip()
            except Exception:
                return ""

    # ── Main ask methods ──────────────────────────────────────────────────────

    def ask(self, system: str, user: str, max_tokens: int = 2000) -> str:
        """Send a prompt and return the AI's response text."""
        try:
            if self.provider == "openai":
                response = self._client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user",   "content": user},
                    ],
                    max_tokens=max_tokens,
                    temperature=0.2,
                )
                return response.choices[0].message.content.strip()

            elif self.provider == "anthropic":
                response = self._client.messages.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    system=system,
                    messages=[{"role": "user", "content": user}],
                )
                return response.content[0].text.strip()

            elif self.provider == "ollama":
                return self._ollama_ask(system, user, max_tokens)

        except Exception as e:
            console.print(f"[red]AI API error: {e}[/red]")
            return ""

    def ask_json(self, system: str, user: str) -> dict:
        """Ask AI and parse JSON from response."""
        # For Ollama, add extra JSON instruction since local models vary
        json_hint = "\n\nIMPORTANT: Respond ONLY with valid JSON. No explanation, no markdown, no preamble."
        raw = self.ask(system, user + json_hint, max_tokens=3000)
        # Extract JSON block if wrapped in markdown
        match = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", raw)
        if match:
            raw = match.group(1)
        # Strip any leading/trailing non-JSON text
        raw = raw.strip()
        # Find the first [ or { and trim
        for start_char in ["{", "["]:
            idx = raw.find(start_char)
            if idx != -1:
                raw = raw[idx:]
                break
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            # Try to extract partial JSON — try each closing bracket independently
            for end in ["}", "]"]:
                last = raw.rfind(end)
                if last != -1:
                    try:
                        return json.loads(raw[:last + 1])
                    except json.JSONDecodeError:
                        continue
            return {}


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class AIFinding:
    title:       str
    description: str
    severity:    str          # critical / high / medium / low / info
    evidence:    str
    endpoint:    str
    payload:     str = ""
    cvss:        str = ""
    cwe:         str = ""
    chain:       list = field(default_factory=list)   # exploit chain steps
    zero_day:    bool = False


# ── System prompts ────────────────────────────────────────────────────────────

SYSTEM_ANALYST = """You are an elite offensive security researcher with 15 years of experience
in web application penetration testing, CVE discovery, and bug bounty hunting.
You specialize in finding zero-day vulnerabilities that automated scanners miss.
Your job is to analyze HTTP traffic and identify security vulnerabilities.
Be specific, technical, and accurate. Focus on exploitable issues only.
Always provide CVSS 3.1 score estimates and CWE IDs where applicable."""

SYSTEM_PAYLOAD_GEN = """You are a world-class security researcher specializing in
custom payload generation for web application security testing.
You craft payloads that bypass WAFs, filters, and encoding schemes.
Generate novel, context-aware payloads that go beyond standard wordlists.
Focus on the specific technology stack and application behavior provided."""

SYSTEM_CODE_AUDITOR = """You are a source code security auditor specializing in PHP
web applications. You identify logic flaws, injection points, authentication bypasses,
insecure function calls, and zero-day vulnerabilities in source code.
Be extremely thorough — flag anything suspicious, even if it seems minor."""

SYSTEM_CHAIN_ANALYST = """You are an expert in chaining multiple low/medium severity
vulnerabilities into critical exploit chains. Given a list of individual findings,
identify how they can be combined for maximum impact (e.g., SSRF+redirect+RCE,
stored XSS+CSRF+account takeover, IDOR+info disclosure+privilege escalation)."""


# ── Main AI Scanner ───────────────────────────────────────────────────────────

class AIScanner:
    """
    AI-powered vulnerability discovery engine.
    Integrates with OpenAI GPT-4 or Anthropic Claude.
    """

    def __init__(
        self,
        session:      requests.Session,
        base_url:     str,
        ai_api_key:   str  = "",
        ai_provider:  str  = "auto",
        ai_model:     str  = None,
        ollama_host:  str  = "http://localhost:11434",
        verbose:      bool = False,
    ):
        self.session    = session
        self.base_url   = base_url.rstrip("/")
        self.verbose    = verbose
        self.findings:  list[AIFinding] = []
        self._lock      = threading.Lock()

        self.ai = AIProvider(
            api_key=ai_api_key,
            provider=ai_provider,
            model=ai_model,
            ollama_host=ollama_host,
        )

        # Crawled pages cache: url -> (status, headers, body_snippet)
        self._crawled: dict[str, dict] = {}

        # Build info panel
        free_tag = " [bold green](FREE — local)[/bold green]" if self.ai.provider == "ollama" else ""
        console.print(Panel(
            f"[bold green]🤖 AI Zero-Day Engine[/bold green]\n"
            f"Provider : [cyan]{self.ai.provider.upper()}[/cyan]{free_tag}\n"
            f"Model    : [cyan]{self.ai.model}[/cyan]\n"
            f"Host     : [cyan]{'local → ' + ollama_host if self.ai.provider == 'ollama' else 'cloud API'}[/cyan]\n"
            f"Target   : [cyan]{self.base_url}[/cyan]",
            border_style="green",
        ))

    # ─────────────────────────── helpers ──────────────────────────────────────

    def _get(self, path: str, params: dict = None, timeout: int = 12) -> Optional[requests.Response]:
        try:
            url = urljoin(self.base_url + "/", path.lstrip("/"))
            r   = self.session.get(url, params=params, timeout=timeout, allow_redirects=True)
            return r
        except Exception as e:
            if self.verbose:
                console.print(f"[dim]GET {path} → error: {e}[/dim]")
            return None

    def _post(self, path: str, data: dict = None, json_body: dict = None, timeout: int = 12) -> Optional[requests.Response]:
        try:
            url = urljoin(self.base_url + "/", path.lstrip("/"))
            r   = self.session.post(url, data=data, json=json_body, timeout=timeout, allow_redirects=True)
            return r
        except Exception as e:
            if self.verbose:
                console.print(f"[dim]POST {path} → error: {e}[/dim]")
            return None

    def _add_finding(self, finding: AIFinding):
        with self._lock:
            self.findings.append(finding)
            color = {"critical": "red", "high": "red", "medium": "yellow",
                     "low": "cyan", "info": "dim"}.get(finding.severity, "white")
            tag = "[ZERO-DAY] " if finding.zero_day else ""
            console.print(f"  [bold {color}]🔴 {tag}{finding.severity.upper()}[/bold {color}] — {finding.title}")
            if self.verbose:
                console.print(f"     [dim]{finding.description[:120]}...[/dim]")

    # ─────────────────────────── crawl & map ──────────────────────────────────

    def _crawl_target(self, max_pages: int = 30):
        """Crawl the target site and collect HTTP traffic for AI analysis."""
        console.print("\n[bold cyan]► Phase 1: Intelligent Crawl[/bold cyan]")
        visited = set()
        queue   = ["/"]

        while queue and len(visited) < max_pages:
            path = queue.pop(0)
            if path in visited:
                continue
            visited.add(path)

            r = self._get(path)
            if not r:
                continue

            snippet = r.text[:3000]
            self._crawled[path] = {
                "status":   r.status_code,
                "headers":  dict(r.headers),
                "body":     snippet,
                "url":      r.url,
            }

            if self.verbose:
                console.print(f"  [dim]crawled {path} → {r.status_code} ({len(r.text)} bytes)[/dim]")

            # Extract links from HTML
            if "text/html" in r.headers.get("Content-Type", ""):
                soup = BeautifulSoup(r.text, "lxml")
                for tag in soup.find_all(["a", "form", "script", "link"]):
                    href = tag.get("href") or tag.get("action") or tag.get("src") or ""
                    if href and not href.startswith(("http", "//", "mailto:", "#", "javascript:")):
                        href = href.split("?")[0]
                        if href not in visited:
                            queue.append(href)

        console.print(f"  [green]Crawled {len(self._crawled)} pages[/green]")

    # ─────────────────────────── AI response analysis ─────────────────────────

    def _ai_analyze_responses(self):
        """Feed all crawled responses to AI for vulnerability analysis."""
        console.print("\n[bold cyan]► Phase 2: AI Response Analysis[/bold cyan]")

        # Build a compact traffic summary for AI
        traffic_summary = []
        for path, data in self._crawled.items():
            traffic_summary.append({
                "path":    path,
                "status":  data["status"],
                "headers": {k: v for k, v in data["headers"].items()
                            if k.lower() in ["server", "x-powered-by", "content-type",
                                             "set-cookie", "access-control-allow-origin",
                                             "x-frame-options", "content-security-policy",
                                             "x-xss-protection", "strict-transport-security"]},
                "body_snippet": data["body"][:1500],
            })

        prompt = f"""
Target URL: {self.base_url}
Crawled {len(traffic_summary)} pages.

HTTP Traffic Summary:
{json.dumps(traffic_summary, indent=2)[:12000]}

Analyze this traffic for ALL security vulnerabilities including:
- Information disclosure (server version, debug info, stack traces)
- Missing security headers (CSP, HSTS, X-Frame-Options, etc.)
- Cookie security flags (Secure, HttpOnly, SameSite)
- Dangerous HTTP methods (PUT, DELETE, TRACE)
- Exposed admin panels, backup files, git repos
- Error messages leaking internal paths or DB structure
- Authentication issues visible in responses
- Any anomalies that could indicate deeper vulnerabilities
- Zero-day indicators (unusual patterns, custom implementations)

Return a JSON array of findings:
[
  {{
    "title": "Short vulnerability title",
    "description": "Detailed technical description",
    "severity": "critical|high|medium|low|info",
    "evidence": "Exact evidence from the traffic",
    "endpoint": "/path/to/endpoint",
    "cvss": "CVSS:3.1/AV:N/AC:L/...",
    "cwe": "CWE-XXX",
    "zero_day": true/false
  }}
]
"""
        result = self.ai.ask_json(SYSTEM_ANALYST, prompt)
        findings = result if isinstance(result, list) else result.get("findings", [])

        for f in findings:
            self._add_finding(AIFinding(
                title=       f.get("title", "AI Finding"),
                description= f.get("description", ""),
                severity=    f.get("severity", "info"),
                evidence=    f.get("evidence", ""),
                endpoint=    f.get("endpoint", "/"),
                cvss=        f.get("cvss", ""),
                cwe=         f.get("cwe", ""),
                zero_day=    f.get("zero_day", False),
            ))

    # ─────────────────────────── AI payload generation ────────────────────────

    def _ai_generate_and_test_payloads(self):
        """Ask AI to generate custom payloads for each discovered form/parameter."""
        console.print("\n[bold cyan]► Phase 3: AI Payload Generation & Testing[/bold cyan]")

        # Collect all forms and parameters
        forms_found = []
        for path, data in self._crawled.items():
            if "text/html" in data["headers"].get("Content-Type", ""):
                soup = BeautifulSoup(data["body"], "lxml")
                for form in soup.find_all("form"):
                    inputs = []
                    for inp in form.find_all(["input", "textarea", "select"]):
                        inputs.append({
                            "name":  inp.get("name", ""),
                            "type":  inp.get("type", "text"),
                            "value": inp.get("value", ""),
                        })
                    if inputs:
                        forms_found.append({
                            "page":   path,
                            "action": form.get("action", path),
                            "method": form.get("method", "get").upper(),
                            "inputs": inputs,
                        })

        if not forms_found:
            console.print("  [dim]No forms found for payload testing[/dim]")
            return

        # Ask AI to generate payloads for the forms
        prompt = f"""
Target: {self.base_url}
Technology: PHP (identified from headers/responses)

Discovered forms and parameters:
{json.dumps(forms_found, indent=2)[:6000]}

Generate specific, context-aware attack payloads for each form/parameter.
Focus on:
1. SQL injection (including second-order, out-of-band)
2. XSS that bypasses common filters (WAF evasion)
3. PHP-specific injections (SSTI, object injection)
4. Authentication bypass payloads
5. Business logic manipulation values
6. Parameter pollution
7. Zero-day style payloads (novel techniques)

Return JSON:
{{
  "test_cases": [
    {{
      "form_action": "/path",
      "method": "POST",
      "parameter": "param_name",
      "payloads": ["payload1", "payload2", "payload3"],
      "attack_type": "sqli|xss|ssti|auth_bypass|logic",
      "detection_pattern": "regex pattern to detect success in response"
    }}
  ]
}}
"""
        result = self.ai.ask_json(SYSTEM_PAYLOAD_GEN, prompt)
        test_cases = result.get("test_cases", [])

        console.print(f"  [cyan]AI generated {sum(len(tc.get('payloads',[])) for tc in test_cases)} payloads across {len(test_cases)} parameters[/cyan]")

        # Test each payload
        for tc in test_cases:
            action     = tc.get("form_action", "/")
            method     = tc.get("method", "GET").upper()
            param      = tc.get("parameter", "")
            payloads   = tc.get("payloads", [])
            atk_type   = tc.get("attack_type", "unknown")
            detection  = tc.get("detection_pattern", "")

            for payload in payloads[:5]:  # cap at 5 per parameter to avoid flooding
                try:
                    data = {param: payload}
                    if method == "POST":
                        r = self._post(action, data=data)
                    else:
                        r = self._get(action, params=data)

                    if not r:
                        continue

                    # Check detection pattern
                    triggered = False
                    if detection and re.search(detection, r.text, re.IGNORECASE):
                        triggered = True

                    # Also ask AI to evaluate the response
                    if len(r.text) > 100:
                        eval_prompt = f"""
Attack type: {atk_type}
Payload used: {payload}
Parameter: {param}
Endpoint: {action}

HTTP Response (first 2000 chars):
Status: {r.status_code}
Body: {r.text[:2000]}

Does this response indicate a successful or partial exploitation?
Is there evidence of the payload being processed unsafely?
Return JSON: {{"vulnerable": true/false, "evidence": "...", "severity": "critical/high/medium/low", "description": "..."}}
"""
                        eval_result = self.ai.ask_json(SYSTEM_ANALYST, eval_prompt)

                        if eval_result.get("vulnerable") or triggered:
                            self._add_finding(AIFinding(
                                title=       f"AI-Detected {atk_type.upper()} on {param}",
                                description= eval_result.get("description", f"Payload triggered on {param}"),
                                severity=    eval_result.get("severity", "high"),
                                evidence=    eval_result.get("evidence", f"Payload: {payload}"),
                                endpoint=    action,
                                payload=     payload,
                                zero_day=    True,  # AI-discovered = potential zero-day
                            ))

                except Exception as e:
                    if self.verbose:
                        console.print(f"  [dim]Payload test error: {e}[/dim]")

    # ─────────────────────────── JS/Source code audit ─────────────────────────

    def _ai_audit_source_code(self):
        """Collect and AI-audit any JS/PHP source code visible on the site."""
        console.print("\n[bold cyan]► Phase 4: AI Source Code Audit[/bold cyan]")

        sources = []

        # Collect JS files
        for path, data in self._crawled.items():
            if path.endswith(".js") or "javascript" in data["headers"].get("Content-Type", ""):
                sources.append({"type": "javascript", "path": path, "code": data["body"][:4000]})

        # Try common PHP source exposure paths
        php_paths = [
            "/index.php", "/login.php", "/config.php", "/db.php",
            "/includes/db.php", "/includes/config.php",
            "/admin/index.php", "/api/index.php",
        ]
        for php_path in php_paths:
            r = self._get(php_path)
            if r and r.status_code == 200 and "<?php" in r.text:
                sources.append({"type": "php", "path": php_path, "code": r.text[:4000]})

        # Try PHP filter base64 LFI on index.php
        lfi_paths = [
            "?page=php://filter/convert.base64-encode/resource=index",
            "?file=php://filter/convert.base64-encode/resource=config",
            "?include=php://filter/convert.base64-encode/resource=login",
        ]
        for lfi in lfi_paths:
            r = self._get("/" + lfi)
            if r and r.status_code == 200 and len(r.text) > 100:
                try:
                    decoded = base64.b64decode(r.text.strip()).decode("utf-8", errors="ignore")
                    if "<?php" in decoded:
                        sources.append({"type": "php_lfi", "path": lfi, "code": decoded[:4000]})
                        console.print(f"  [bold red]⚠ LFI source disclosure via {lfi}[/bold red]")
                except Exception:
                    pass

        if not sources:
            console.print("  [dim]No source code accessible for audit[/dim]")
            return

        console.print(f"  [cyan]Auditing {len(sources)} source files with AI...[/cyan]")

        for src in sources:
            prompt = f"""
Target: {self.base_url}
File type: {src['type']}
File path: {src['path']}

Source code:
```
{src['code']}
```

Perform a comprehensive security audit. Look for:
1. SQL injection vulnerabilities (unsanitized variables in queries)
2. Command injection (shell_exec, system, exec, passthru)
3. Insecure deserialization (unserialize with user input)
4. File inclusion vulnerabilities (include/require with user input)
5. Hardcoded credentials, API keys, secrets
6. Insecure cryptography (md5 passwords, weak random)
7. Authentication bypass logic flaws
8. Business logic vulnerabilities
9. Race conditions
10. Any zero-day indicators

Return JSON array:
[
  {{
    "title": "Vulnerability name",
    "description": "Detailed description with line reference",
    "severity": "critical|high|medium|low",
    "evidence": "Exact code snippet",
    "cwe": "CWE-XXX",
    "exploitation": "How to exploit this",
    "zero_day": true/false
  }}
]
"""
            findings = self.ai.ask_json(SYSTEM_CODE_AUDITOR, prompt)
            if isinstance(findings, list):
                for f in findings:
                    self._add_finding(AIFinding(
                        title=       f.get("title", "Source Code Finding"),
                        description= f.get("description", "") + "\nExploitation: " + f.get("exploitation", ""),
                        severity=    f.get("severity", "medium"),
                        evidence=    f.get("evidence", ""),
                        endpoint=    src["path"],
                        cwe=         f.get("cwe", ""),
                        zero_day=    f.get("zero_day", False),
                    ))

    # ─────────────────────────── behavior diffing ─────────────────────────────

    def _ai_behavior_diff(self):
        """
        Send identical requests with subtle mutations.
        AI compares responses to detect subtle logic flaws.
        """
        console.print("\n[bold cyan]► Phase 5: AI Behavioral Diff Analysis[/bold cyan]")

        # Target high-value endpoints for diff testing
        diff_targets = [
            ("/login.php",     "POST", {"username": "admin", "password": "wrong"}),
            ("/login.php",     "POST", {"username": "admin'--", "password": "x"}),
            ("/login.php",     "POST", {"username": "admin", "password": "' OR '1'='1"}),
            ("/info.php",      "GET",  {"get_balance": ""}),
            ("/money_add.php", "GET",  {"type": "1"}),
            ("/money_add.php", "GET",  {"type": "-1"}),
            ("/money_add.php", "GET",  {"type": "999999"}),
            ("/money_view.php","GET",  {"check_order": "1"}),
            ("/money_view.php","GET",  {"check_order": "0"}),
            ("/money_view.php","GET",  {"check_order": "-1"}),
            ("/cc_buy.php",    "POST", {"buy_one": "1"}),
            ("/cc_buy.php",    "POST", {"buy_one": "0"}),
        ]

        responses = []
        for path, method, params in diff_targets:
            try:
                if method == "POST":
                    r = self._post(path, data=params)
                else:
                    r = self._get(path, params=params)
                if r:
                    responses.append({
                        "path":    path,
                        "method":  method,
                        "params":  params,
                        "status":  r.status_code,
                        "length":  len(r.text),
                        "body":    r.text[:800],
                    })
            except Exception:
                pass

        if not responses:
            return

        prompt = f"""
Target: {self.base_url} (PHP e-commerce / CVV shop)

I tested multiple requests with variations. Analyze the response DIFFERENCES
to identify logic flaws, injection points, and business logic vulnerabilities.
Pay special attention to:
- Negative numbers or 0 values that bypass validation
- SQL injection in numeric parameters
- Authentication state differences
- Different response lengths indicating conditional branches
- Error messages revealing internal structure
- Race condition indicators
- IDOR through ID enumeration

Request/Response data:
{json.dumps(responses, indent=2)[:10000]}

Return JSON array of vulnerabilities found through behavioral analysis:
[
  {{
    "title": "...",
    "description": "...",
    "severity": "critical|high|medium|low",
    "evidence": "Specific response differences that indicate the flaw",
    "endpoint": "/path",
    "exploitation": "Step-by-step exploit",
    "zero_day": true/false
  }}
]
"""
        findings = self.ai.ask_json(SYSTEM_ANALYST, prompt)
        if isinstance(findings, list):
            for f in findings:
                self._add_finding(AIFinding(
                    title=       f.get("title", "Behavioral Finding"),
                    description= f.get("description", "") + "\n" + f.get("exploitation", ""),
                    severity=    f.get("severity", "medium"),
                    evidence=    f.get("evidence", ""),
                    endpoint=    f.get("endpoint", "/"),
                    zero_day=    f.get("zero_day", False),
                ))

    # ─────────────────────────── exploit chain detection ──────────────────────

    def _ai_chain_analysis(self):
        """Ask AI to chain individual findings into critical exploit paths."""
        console.print("\n[bold cyan]► Phase 6: AI Exploit Chain Detection[/bold cyan]")

        if len(self.findings) < 2:
            console.print("  [dim]Not enough findings to chain[/dim]")
            return

        findings_summary = [
            {
                "title":       f.title,
                "severity":    f.severity,
                "endpoint":    f.endpoint,
                "description": f.description[:300],
            }
            for f in self.findings
        ]

        prompt = f"""
Target: {self.base_url}

Individual vulnerabilities found so far:
{json.dumps(findings_summary, indent=2)}

Analyze how these can be CHAINED together into multi-step exploits.
Think about attack paths like:
- Info disclosure → credential stuffing → full account takeover
- IDOR + authentication bypass → access all accounts
- LFI + file write → RCE
- XSS + CSRF → admin account compromise
- Payment IDOR + race condition → free credits

Return JSON:
{{
  "chains": [
    {{
      "name": "Attack chain name",
      "severity": "critical",
      "steps": [
        "Step 1: Use <finding_title> to...",
        "Step 2: With obtained X, exploit...",
        "Step 3: Result in..."
      ],
      "impact": "Full account takeover / RCE / Data breach / etc.",
      "findings_used": ["finding title 1", "finding title 2"]
    }}
  ]
}}
"""
        result = self.ai.ask_json(SYSTEM_CHAIN_ANALYST, prompt)
        chains = result.get("chains", [])

        for chain in chains:
            steps_text = "\n".join(f"  {i+1}. {s}" for i, s in enumerate(chain.get("steps", [])))
            self._add_finding(AIFinding(
                title=       f"🔗 EXPLOIT CHAIN: {chain.get('name', 'Multi-step Attack')}",
                description= f"Impact: {chain.get('impact', '')}\n\nSteps:\n{steps_text}",
                severity=    chain.get("severity", "critical"),
                evidence=    f"Findings chained: {', '.join(chain.get('findings_used', []))}",
                endpoint=    "multiple",
                chain=       chain.get("steps", []),
                zero_day=    False,
            ))

    # ─────────────────────────── business logic AI ────────────────────────────

    def _ai_business_logic(self):
        """AI reasons about the app's business logic to find logical flaws."""
        console.print("\n[bold cyan]► Phase 7: AI Business Logic Analysis[/bold cyan]")

        # Build context about what we know about this app
        site_context = "\n".join(
            f"{path}: status={d['status']} headers={list(d['headers'].keys())[:5]}"
            for path, d in list(self._crawled.items())[:20]
        )

        prompt = f"""
I am testing a PHP-based CVV/credit card shop (training site for EC-Council Bug Bounty course).

Known endpoints and behavior:
- POST /login.php?login — Login, response '5'=success, '3'=no account, '0'=IP rate limit
- GET /info.php?get_balance — Get current balance
- GET /money_add.php?type=<1-5> — Add money (type determines amount)
- GET /money_view.php?check_order=<id> — View order by ID
- POST /cc_buy.php?buy_one — Buy a credit card
- GET /cc_basket.php?buy — View basket
- POST /ch_password.php — Change password

Crawled pages:
{site_context[:3000]}

Based on this application's business logic, identify ALL possible logic flaws:
1. Can type parameter be manipulated to add unlimited money?
2. Can negative values be used to bypass payment checks?
3. Is order ID sequential (IDOR)?
4. Can race conditions double-add money?
5. Can currency/amount be manipulated in buy requests?
6. Are there parameter pollution attacks?
7. Can you access other users' orders?
8. Is there a way to get cards without payment?
9. Any HTTP parameter tampering opportunities?
10. Mass assignment vulnerabilities?

Return JSON array of business logic vulnerabilities:
[
  {{
    "title": "...",
    "description": "Detailed technical description",
    "severity": "critical|high|medium|low",
    "steps": ["Step 1...", "Step 2..."],
    "endpoint": "/path",
    "evidence": "Why this is exploitable",
    "zero_day": true/false
  }}
]
"""
        findings = self.ai.ask_json(SYSTEM_ANALYST, prompt)
        if isinstance(findings, list):
            for f in findings:
                steps = "\n".join(f"  {i+1}. {s}" for i, s in enumerate(f.get("steps", [])))
                self._add_finding(AIFinding(
                    title=       f.get("title", "Business Logic Flaw"),
                    description= f.get("description", "") + ("\n\nSteps:\n" + steps if steps else ""),
                    severity=    f.get("severity", "high"),
                    evidence=    f.get("evidence", ""),
                    endpoint=    f.get("endpoint", "/"),
                    zero_day=    f.get("zero_day", False),
                ))

    # ─────────────────────────── main run ─────────────────────────────────────

    def run(self) -> list[AIFinding]:
        """Run all AI scanning phases and return findings."""
        start = time.time()

        console.print(f"\n[bold green]🤖 Starting AI Zero-Day Scan on {self.base_url}[/bold green]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task("Running AI analysis...", total=None)

            progress.update(task, description="Phase 1: Crawling target...")
            self._crawl_target()

            progress.update(task, description="Phase 2: AI response analysis...")
            self._ai_analyze_responses()

            progress.update(task, description="Phase 3: AI payload generation...")
            self._ai_generate_and_test_payloads()

            progress.update(task, description="Phase 4: Source code audit...")
            self._ai_audit_source_code()

            progress.update(task, description="Phase 5: Behavioral diff analysis...")
            self._ai_behavior_diff()

            progress.update(task, description="Phase 6: Business logic analysis...")
            self._ai_business_logic()

            progress.update(task, description="Phase 7: Exploit chain detection...")
            self._ai_chain_analysis()

        elapsed = time.time() - start

        # ── Final summary ──────────────────────────────────────────────────────
        zero_days = [f for f in self.findings if f.zero_day]
        crits     = [f for f in self.findings if f.severity == "critical"]
        highs     = [f for f in self.findings if f.severity == "high"]

        table = Table(title="🤖 AI Zero-Day Scan Results", border_style="green")
        table.add_column("Severity",    style="bold")
        table.add_column("Count",       justify="right")
        table.add_column("Highlights")
        table.add_row("[red]Critical[/red]",  str(len(crits)),     ", ".join(f.title[:40] for f in crits[:2]))
        table.add_row("[orange1]High[/orange1]",     str(len(highs)),     ", ".join(f.title[:40] for f in highs[:2]))
        table.add_row("[yellow]Medium[/yellow]",   str(len([f for f in self.findings if f.severity=="medium"])), "")
        table.add_row("[cyan]Low/Info[/cyan]",    str(len([f for f in self.findings if f.severity in ["low","info"]])), "")
        table.add_row("[bold green]Zero-Days[/bold green]", str(len(zero_days)), ", ".join(f.title[:40] for f in zero_days[:2]))
        table.add_row("[dim]Scan Time[/dim]",  f"{elapsed:.1f}s", "")
        console.print(table)

        return self.findings
