#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════╗
║         BugScanner — Web GUI                                            ║
║         Author : Muhammad Faizan (faizzyhon@gmail.com)                  ║
║         Works  : Linux & Windows | Python 3.10+                         ║
║         Run    : python web_gui.py                                       ║
║         Open   : http://localhost:5000                                   ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import json
import time
import queue
import threading
import subprocess
import platform
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template_string, request, jsonify, Response, send_file, redirect, url_for

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ── Globals ────────────────────────────────────────────────────────────────────
REPORTS_DIR   = Path(__file__).parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)
scan_queues   = {}                 # scan_id → queue.Queue (per-scan, prevents SSE cross-contamination)
scan_results  = {}                 # scan_id → findings list
active_scan   = {"running": False, "id": None, "proc": None}

SCANNER_MODULES = [
    ("sqli",          "SQL Injection",                  "A03"),
    ("xss",           "Cross-Site Scripting",           "A03"),
    ("auth",          "Broken Authentication / JWT",    "A07"),
    ("idor",          "Insecure Direct Object Ref",     "A01"),
    ("ssrf",          "Server-Side Request Forgery",    "A10"),
    ("payment",       "Payment / Balance Bypass",       "A04"),
    ("php",           "PHP-Specific Arsenal",           "A05"),
    ("lfi",           "LFI / Path Traversal",          "A05"),
    ("xxe",           "XXE Injection",                  "A04"),
    ("cmdi",          "Command Injection",              "A03"),
    ("open_redirect", "Open Redirect",                  "A10"),
    ("headers",       "Security Headers",               "A05"),
    ("jwt",           "JWT Attacks",                    "A07"),
]

OLLAMA_MODELS = [
    "deepseek-r1",
    "deepseek-r1:14b",
    "llama3.2",
    "llama3.1:8b",
    "qwen2.5-coder:7b",
    "mistral:7b",
    "phi3:mini",
    "codellama:13b",
    "gemma2:9b",
]

# ═══════════════════════════════════════════════════════════════════════════════
#  HTML TEMPLATE
# ═══════════════════════════════════════════════════════════════════════════════
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>BugScanner — Web GUI</title>
<link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@300;400;600;700&family=Orbitron:wght@700;900&display=swap" rel="stylesheet"/>
<style>
  :root {
    --bg:       #0a0e14;
    --bg2:      #0d1117;
    --bg3:      #161b22;
    --border:   #00ff4133;
    --green:    #00ff41;
    --green2:   #39ff14;
    --cyan:     #00d4ff;
    --red:      #ff3838;
    --orange:   #ff8c00;
    --yellow:   #ffd700;
    --dim:      #555e6a;
    --text:     #c9d1d9;
    --font:     'Fira Code', monospace;
    --font2:    'Orbitron', sans-serif;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--font); min-height: 100vh; }

  /* ── Header ── */
  header {
    background: linear-gradient(135deg, #0d1117 0%, #0a1628 50%, #0d1117 100%);
    border-bottom: 1px solid var(--border);
    padding: 16px 32px;
    display: flex; align-items: center; justify-content: space-between;
    position: sticky; top: 0; z-index: 100;
    backdrop-filter: blur(10px);
  }
  .logo { display: flex; align-items: center; gap: 14px; }
  .logo-icon {
    width: 44px; height: 44px;
    background: linear-gradient(135deg, var(--green), var(--cyan));
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 22px; font-weight: 900;
    box-shadow: 0 0 20px var(--green)44;
  }
  .logo-text { font-family: var(--font2); font-size: 20px; font-weight: 900; }
  .logo-text span { color: var(--green); }
  .logo-sub { font-size: 10px; color: var(--dim); letter-spacing: 2px; margin-top: 2px; }
  .header-badges { display: flex; gap: 10px; flex-wrap: wrap; }
  .badge {
    padding: 4px 10px; border-radius: 20px; font-size: 10px; font-weight: 700;
    letter-spacing: 1px; border: 1px solid;
  }
  .badge-green { color: var(--green); border-color: var(--green)55; background: var(--green)11; }
  .badge-cyan  { color: var(--cyan);  border-color: var(--cyan)55;  background: var(--cyan)11;  }
  .badge-red   { color: var(--red);   border-color: var(--red)55;   background: var(--red)11;   }

  /* ── Layout ── */
  .container { display: grid; grid-template-columns: 400px 1fr; gap: 0; height: calc(100vh - 73px); }

  /* ── Sidebar ── */
  .sidebar {
    background: var(--bg2); border-right: 1px solid var(--border);
    overflow-y: auto; padding: 20px;
    display: flex; flex-direction: column; gap: 16px;
  }
  .section {
    background: var(--bg3); border: 1px solid var(--border);
    border-radius: 10px; overflow: hidden;
  }
  .section-header {
    padding: 10px 16px; font-size: 11px; font-weight: 700; letter-spacing: 2px;
    color: var(--green); border-bottom: 1px solid var(--border);
    background: var(--green)08;
    display: flex; align-items: center; gap: 8px;
  }
  .section-body { padding: 14px 16px; display: flex; flex-direction: column; gap: 10px; }

  /* ── Form elements ── */
  label { font-size: 11px; color: var(--dim); letter-spacing: 1px; margin-bottom: 4px; display: block; }
  input[type="text"], input[type="password"], input[type="url"], select {
    width: 100%; background: var(--bg); border: 1px solid var(--border);
    color: var(--text); font-family: var(--font); font-size: 13px;
    padding: 8px 12px; border-radius: 6px; outline: none;
    transition: border-color 0.2s;
  }
  input:focus, select:focus { border-color: var(--green); box-shadow: 0 0 8px var(--green)22; }
  input::placeholder { color: var(--dim); }

  /* ── Checkboxes grid ── */
  .modules-grid {
    display: grid; grid-template-columns: 1fr 1fr; gap: 6px;
  }
  .module-cb {
    display: flex; align-items: center; gap: 6px;
    padding: 5px 8px; border-radius: 5px; cursor: pointer;
    border: 1px solid transparent; font-size: 11px;
    transition: all 0.15s;
  }
  .module-cb:hover { border-color: var(--border); background: var(--green)08; }
  .module-cb input[type="checkbox"] { accent-color: var(--green); width: 13px; height: 13px; }
  .module-cb .owasp { color: var(--dim); font-size: 9px; }

  /* ── Toggle switch ── */
  .toggle-row { display: flex; align-items: center; justify-content: space-between; }
  .toggle { position: relative; width: 44px; height: 22px; }
  .toggle input { opacity: 0; width: 0; height: 0; }
  .toggle-slider {
    position: absolute; inset: 0; background: var(--bg); border: 1px solid var(--border);
    border-radius: 22px; cursor: pointer; transition: 0.2s;
  }
  .toggle-slider:before {
    content: ''; position: absolute; height: 14px; width: 14px;
    left: 3px; bottom: 3px; background: var(--dim);
    border-radius: 50%; transition: 0.2s;
  }
  .toggle input:checked + .toggle-slider { border-color: var(--green); background: var(--green)22; }
  .toggle input:checked + .toggle-slider:before { transform: translateX(22px); background: var(--green); }

  /* ── Buttons ── */
  .btn {
    padding: 10px 20px; border-radius: 8px; border: none;
    font-family: var(--font); font-size: 13px; font-weight: 700;
    letter-spacing: 1px; cursor: pointer; transition: all 0.2s;
    display: flex; align-items: center; justify-content: center; gap: 8px;
  }
  .btn-primary {
    background: linear-gradient(135deg, #00ff41, #00d4ff);
    color: #0a0e14; width: 100%;
    box-shadow: 0 0 20px var(--green)44;
  }
  .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 0 30px var(--green)66; }
  .btn-primary:disabled { opacity: 0.4; cursor: not-allowed; transform: none; }
  .btn-danger {
    background: var(--red)22; color: var(--red);
    border: 1px solid var(--red)55; width: 100%;
  }
  .btn-danger:hover { background: var(--red)33; }

  /* ── Main panel ── */
  .main {
    display: flex; flex-direction: column; overflow: hidden;
  }

  /* ── Tabs ── */
  .tabs {
    display: flex; border-bottom: 1px solid var(--border);
    background: var(--bg2); padding: 0 20px;
  }
  .tab {
    padding: 14px 20px; font-size: 12px; font-weight: 700; letter-spacing: 1px;
    cursor: pointer; border-bottom: 2px solid transparent;
    color: var(--dim); transition: all 0.2s; user-select: none;
  }
  .tab:hover { color: var(--text); }
  .tab.active { color: var(--green); border-bottom-color: var(--green); }

  /* ── Terminal ── */
  #terminal-panel { flex: 1; overflow: hidden; display: flex; flex-direction: column; }
  #terminal {
    flex: 1; overflow-y: auto; padding: 20px;
    font-size: 13px; line-height: 1.7;
    font-family: var(--font);
    background: var(--bg);
  }
  #terminal .t-line { white-space: pre-wrap; word-break: break-all; }
  #terminal .t-green  { color: var(--green); }
  #terminal .t-cyan   { color: var(--cyan); }
  #terminal .t-red    { color: var(--red); }
  #terminal .t-yellow { color: var(--yellow); }
  #terminal .t-orange { color: var(--orange); }
  #terminal .t-dim    { color: var(--dim); }
  #terminal .t-bold   { font-weight: 700; }
  .terminal-bar {
    padding: 8px 20px; background: var(--bg2); border-top: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between;
    font-size: 11px; color: var(--dim);
  }
  .pulse { animation: pulse 1s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }

  /* ── Results panel ── */
  #results-panel { flex: 1; overflow-y: auto; padding: 20px; display: none; }
  .stats-row { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 20px; }
  .stat-card {
    background: var(--bg3); border: 1px solid var(--border);
    border-radius: 10px; padding: 16px; text-align: center;
  }
  .stat-card .stat-num { font-family: var(--font2); font-size: 28px; font-weight: 900; }
  .stat-card .stat-label { font-size: 10px; color: var(--dim); letter-spacing: 1px; margin-top: 4px; }
  .stat-critical { color: var(--red); }
  .stat-high     { color: var(--orange); }
  .stat-medium   { color: var(--yellow); }
  .stat-low      { color: var(--cyan); }
  .stat-ai       { color: var(--green); }

  .findings-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .findings-table th {
    background: var(--bg3); color: var(--dim); font-size: 10px; letter-spacing: 2px;
    padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border);
    position: sticky; top: 0;
  }
  .findings-table td { padding: 10px 12px; border-bottom: 1px solid var(--border)55; vertical-align: top; }
  .findings-table tr:hover td { background: var(--green)05; }
  .sev-badge {
    padding: 3px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; letter-spacing: 1px;
  }
  .sev-CRITICAL { color: var(--red);    background: var(--red)20;    border: 1px solid var(--red)44; }
  .sev-HIGH     { color: var(--orange); background: var(--orange)20; border: 1px solid var(--orange)44; }
  .sev-MEDIUM   { color: var(--yellow); background: var(--yellow)20; border: 1px solid var(--yellow)44; }
  .sev-LOW      { color: var(--cyan);   background: var(--cyan)20;   border: 1px solid var(--cyan)44; }
  .sev-INFO     { color: var(--dim);    background: var(--bg);       border: 1px solid var(--border); }
  .ai-tag {
    display: inline-block; padding: 1px 5px; border-radius: 3px; font-size: 9px;
    color: var(--green); background: var(--green)15; border: 1px solid var(--green)33; margin-left: 4px;
  }
  .zero-day-row td { background: var(--red)08 !important; }
  .zero-day-row:hover td { background: var(--red)12 !important; }

  /* ── Reports panel ── */
  #reports-panel { flex: 1; overflow-y: auto; padding: 20px; display: none; }
  .report-card {
    background: var(--bg3); border: 1px solid var(--border); border-radius: 10px;
    padding: 16px; margin-bottom: 12px; display: flex; align-items: center;
    justify-content: space-between;
  }
  .report-info h4 { font-size: 13px; color: var(--text); }
  .report-info span { font-size: 11px; color: var(--dim); }
  .btn-sm {
    padding: 6px 14px; border-radius: 6px; font-size: 11px; font-weight: 700;
    cursor: pointer; border: 1px solid var(--green)55;
    background: var(--green)11; color: var(--green);
    font-family: var(--font); transition: all 0.2s;
  }
  .btn-sm:hover { background: var(--green)22; }

  /* ── Status bar ── */
  .status-dot {
    width: 8px; height: 8px; border-radius: 50%; display: inline-block; margin-right: 6px;
  }
  .status-dot.idle    { background: var(--dim); }
  .status-dot.running { background: var(--green); animation: pulse 1s infinite; }
  .status-dot.done    { background: var(--cyan); }
  .status-dot.error   { background: var(--red); }

  /* ── AI section ── */
  .ai-provider-tabs { display: flex; gap: 6px; margin-bottom: 10px; }
  .ai-tab {
    padding: 5px 12px; border-radius: 6px; font-size: 11px; font-weight: 700;
    cursor: pointer; border: 1px solid var(--border); background: var(--bg);
    color: var(--dim); transition: all 0.15s;
  }
  .ai-tab.active { color: var(--green); border-color: var(--green); background: var(--green)11; }
  .ai-config { display: none; }
  .ai-config.active { display: flex; flex-direction: column; gap: 8px; }

  /* ── Scrollbar ── */
  ::-webkit-scrollbar { width: 5px; }
  ::-webkit-scrollbar-track { background: var(--bg); }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--green)44; }

  /* ── Responsive ── */
  @media (max-width: 900px) {
    .container { grid-template-columns: 1fr; grid-template-rows: auto 1fr; }
    .sidebar { max-height: 50vh; }
    .stats-row { grid-template-columns: repeat(3, 1fr); }
  }

  /* ── Glow effects ── */
  .glow-text { text-shadow: 0 0 10px currentColor; }
  .section:has(.active-scan) { border-color: var(--green); box-shadow: 0 0 15px var(--green)22; }

  /* ── Recon panel ── */
  #recon-panel { flex: 1; overflow-y: auto; padding: 20px; display: none; gap: 16px; flex-direction: column; }
  .recon-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
  .recon-card {
    background: var(--bg3); border: 1px solid var(--border); border-radius: 10px;
    overflow: hidden;
  }
  .recon-card-header {
    padding: 8px 14px; font-size: 10px; font-weight: 700; letter-spacing: 2px;
    color: var(--cyan); background: var(--cyan)08; border-bottom: 1px solid var(--border);
    display: flex; align-items: center; gap: 6px;
  }
  .recon-card-body { padding: 12px 14px; }
  .recon-kv { display: flex; justify-content: space-between; padding: 4px 0;
              border-bottom: 1px solid var(--border)44; font-size: 12px; }
  .recon-kv:last-child { border-bottom: none; }
  .recon-kv .rk { color: var(--dim); font-size: 11px; }
  .recon-kv .rv { color: var(--text); max-width: 200px; text-align: right;
                  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .recon-kv .rv.green { color: var(--green); }
  .recon-kv .rv.red   { color: var(--red); }
  .recon-kv .rv.yellow{ color: var(--yellow); }
  .port-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .port-table th { background: var(--bg3); color: var(--dim); font-size: 10px; letter-spacing: 1px;
                   padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--border); }
  .port-table td { padding: 8px 10px; border-bottom: 1px solid var(--border)44; }
  .port-open  { color: var(--green); font-weight: 700; }
  .port-danger{ color: var(--red);   font-weight: 700; }
  .tech-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(140px,1fr)); gap: 8px; }
  .tech-badge {
    background: var(--bg); border: 1px solid var(--border); border-radius: 8px;
    padding: 8px 10px; font-size: 11px; text-align: center;
  }
  .tech-badge .tc { color: var(--dim); font-size: 9px; letter-spacing: 1px; margin-bottom: 3px; }
  .tech-badge .tn { color: var(--cyan); font-weight: 700; }
  .tech-badge .tv { color: var(--dim); font-size: 10px; }
  .cve-row-CRITICAL td { background: var(--red)08 !important; }
  .cve-row-HIGH     td { background: var(--orange)08 !important; }
  .waf-badge {
    display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 10px;
    background: var(--yellow)15; color: var(--yellow); border: 1px solid var(--yellow)44;
    margin: 2px;
  }
  .recon-placeholder { text-align: center; padding: 40px; color: var(--dim); font-size: 12px; }
</style>
</head>
<body>

<!-- ══ HEADER ══════════════════════════════════════════════════════════════ -->
<header>
  <div class="logo">
    <div class="logo-icon">🔴</div>
    <div>
      <div class="logo-text"><span>Bug</span>Scanner</div>
      <div class="logo-sub">PHP WEB SECURITY SCANNER</div>
    </div>
  </div>
  <div class="header-badges">
    <span class="badge badge-green">OWASP TOP 10</span>
    <span class="badge badge-cyan">EC-COUNCIL</span>
    <span class="badge badge-red">⚡ AI ZERO-DAY</span>
    <span class="badge badge-green" id="status-badge">
      <span class="status-dot idle" id="status-dot"></span>
      <span id="status-text">IDLE</span>
    </span>
  </div>
</header>

<!-- ══ MAIN LAYOUT ══════════════════════════════════════════════════════════ -->
<div class="container">

  <!-- ══ SIDEBAR ══════════════════════════════════════════════════════════ -->
  <div class="sidebar">

    <!-- Target -->
    <div class="section">
      <div class="section-header">🎯 TARGET</div>
      <div class="section-body">
        <div>
          <label>TARGET URL</label>
          <input type="url" id="target" placeholder="https://cvvhub.tw" value="https://cvvhub.tw"/>
        </div>
        <div>
          <label>USERNAME (optional)</label>
          <input type="text" id="username" placeholder="your_username"/>
        </div>
        <div>
          <label>PASSWORD (optional)</label>
          <input type="password" id="password" placeholder="••••••••"/>
        </div>
      </div>
    </div>

    <!-- Modules -->
    <div class="section">
      <div class="section-header">
        🧩 SCANNER MODULES
        <button onclick="toggleAll()" style="margin-left:auto;background:none;border:none;color:var(--green);cursor:pointer;font-size:10px;font-family:var(--font)">SELECT ALL</button>
      </div>
      <div class="section-body">
        <div class="modules-grid" id="modules-grid">
          {% for key, name, owasp in modules %}
          <label class="module-cb">
            <input type="checkbox" name="module" value="{{ key }}" checked/>
            <div>
              <div>{{ name }}</div>
              <div class="owasp">{{ owasp }}</div>
            </div>
          </label>
          {% endfor %}
        </div>
      </div>
    </div>

    <!-- AI Engine -->
    <div class="section">
      <div class="section-header">🤖 AI ZERO-DAY ENGINE</div>
      <div class="section-body">
        <div class="toggle-row">
          <label style="margin:0">Enable AI Analysis</label>
          <label class="toggle">
            <input type="checkbox" id="ai-enabled" onchange="toggleAI(this.checked)"/>
            <span class="toggle-slider"></span>
          </label>
        </div>

        <div id="ai-config" style="display:none">
          <div class="ai-provider-tabs">
            <div class="ai-tab active" onclick="setAIProvider('ollama', this)">🦙 Ollama</div>
            <div class="ai-tab" onclick="setAIProvider('openai', this)">🟢 OpenAI</div>
            <div class="ai-tab" onclick="setAIProvider('anthropic', this)">🟣 Claude</div>
          </div>

          <div id="ai-ollama" class="ai-config active">
            <label>OLLAMA HOST</label>
            <input type="text" id="ollama-host" value="http://localhost:11434" placeholder="http://localhost:11434"/>
            <label>MODEL</label>
            <select id="ollama-model">
              {% for m in ollama_models %}
              <option value="{{ m }}">{{ m }}</option>
              {% endfor %}
            </select>
            <button class="btn-sm" onclick="checkOllama()" style="margin-top:4px">🔍 Detect Models</button>
            <div id="ollama-status" style="font-size:11px;color:var(--dim)"></div>
          </div>

          <div id="ai-openai" class="ai-config">
            <label>API KEY</label>
            <input type="password" id="openai-key" placeholder="sk-..."/>
            <label>MODEL</label>
            <select id="openai-model">
              <option value="gpt-4o">gpt-4o (recommended)</option>
              <option value="gpt-4-turbo">gpt-4-turbo</option>
              <option value="gpt-4">gpt-4</option>
              <option value="gpt-3.5-turbo">gpt-3.5-turbo</option>
            </select>
          </div>

          <div id="ai-anthropic" class="ai-config">
            <label>API KEY</label>
            <input type="password" id="anthropic-key" placeholder="sk-ant-..."/>
            <label>MODEL</label>
            <select id="anthropic-model">
              <option value="claude-opus-4-5">claude-opus-4-5 (best)</option>
              <option value="claude-sonnet-4-6">claude-sonnet-4-6</option>
            </select>
          </div>
        </div>
      </div>
    </div>

    <!-- Intel / Recon Options -->
    <div class="section">
      <div class="section-header">🔍 PHASE 0 — INTELLIGENCE</div>
      <div class="section-body">
        <div style="font-size:11px;color:var(--dim);margin-bottom:4px">
          Auto-runs before vuln tests: IP, DNS, Whois, ports, tech stack, CVE lookup.
        </div>
        <div class="toggle-row">
          <label style="margin:0">Enable recon + CVE scan</label>
          <label class="toggle">
            <input type="checkbox" id="enable-recon" checked/>
            <span class="toggle-slider"></span>
          </label>
        </div>
        <div class="toggle-row">
          <label style="margin:0">Include port scan</label>
          <label class="toggle">
            <input type="checkbox" id="enable-ports" checked/>
            <span class="toggle-slider"></span>
          </label>
        </div>
      </div>
    </div>

    <!-- Options -->
    <div class="section">
      <div class="section-header">⚙️ OPTIONS</div>
      <div class="section-body">
        <div>
          <label>THREADS</label>
          <input type="text" id="threads" value="10" style="width:80px"/>
        </div>
        <div>
          <label>TIMEOUT (seconds)</label>
          <input type="text" id="timeout" value="15" style="width:80px"/>
        </div>
        <div class="toggle-row">
          <label style="margin:0">Verbose output</label>
          <label class="toggle">
            <input type="checkbox" id="verbose"/>
            <span class="toggle-slider"></span>
          </label>
        </div>
        <div class="toggle-row">
          <label style="margin:0">Generate PDF report</label>
          <label class="toggle">
            <input type="checkbox" id="gen-pdf" checked/>
            <span class="toggle-slider"></span>
          </label>
        </div>
      </div>
    </div>

    <!-- Launch -->
    <button class="btn btn-primary" id="scan-btn" onclick="startScan()">
      ⚡ LAUNCH SCAN
    </button>
    <button class="btn btn-danger" id="stop-btn" onclick="stopScan()" style="display:none">
      ■ STOP SCAN
    </button>

  </div><!-- /sidebar -->

  <!-- ══ MAIN PANEL ═══════════════════════════════════════════════════════ -->
  <div class="main">
    <div class="tabs">
      <div class="tab active" onclick="showTab('terminal')">📟 Terminal</div>
      <div class="tab" onclick="showTab('recon')">🔍 Intel</div>
      <div class="tab" onclick="showTab('results')">🎯 Findings</div>
      <div class="tab" onclick="showTab('reports')">📄 Reports</div>
    </div>

    <!-- Terminal -->
    <div id="terminal-panel">
      <div id="terminal">
        <div class="t-line t-green">╔══════════════════════════════════════════════════════════════╗</div>
        <div class="t-line t-green">║   BugScanner Web GUI — Ready                                 ║</div>
        <div class="t-line t-green">║   Author: Muhammad Faizan | faizzyhon@gmail.com              ║</div>
        <div class="t-line t-green">╚══════════════════════════════════════════════════════════════╝</div>
        <div class="t-line t-dim">  </div>
        <div class="t-line t-cyan">  Configure your scan in the left panel and click LAUNCH SCAN.</div>
        <div class="t-line t-dim">  </div>
        <div class="t-line t-dim">  ⚡ AI Zero-Day Engine: Enable to use Ollama (free local),</div>
        <div class="t-line t-dim">     OpenAI GPT-4, or Anthropic Claude for intelligent analysis.</div>
        <div class="t-line t-dim">  </div>
        <div class="t-line t-yellow">  ⚠ AUTHORIZED TARGETS ONLY — Ethical testing only!</div>
      </div>
      <div class="terminal-bar">
        <span id="term-status">Ready</span>
        <span><button onclick="clearTerminal()" style="background:none;border:none;color:var(--dim);cursor:pointer;font-family:var(--font);font-size:11px">Clear</button></span>
      </div>
    </div>

    <!-- Recon / Intel Panel -->
    <div id="recon-panel">
      <div class="recon-placeholder" id="recon-placeholder">
        🔍 Intelligence data will appear here once a scan starts.<br>
        <span style="font-size:11px">Phase 0 gathers IP, DNS, Whois, open ports, tech stack & CVEs automatically.</span>
      </div>

      <!-- IP / Host Info -->
      <div class="recon-grid" id="recon-info-grid" style="display:none">
        <div class="recon-card" id="card-host">
          <div class="recon-card-header">🌐 HOST INTELLIGENCE</div>
          <div class="recon-card-body" id="host-kv"></div>
        </div>
        <div class="recon-card" id="card-geo">
          <div class="recon-card-header">📍 GEOLOCATION</div>
          <div class="recon-card-body" id="geo-kv"></div>
        </div>
        <div class="recon-card" id="card-ssl">
          <div class="recon-card-header">🔒 SSL / TLS</div>
          <div class="recon-card-body" id="ssl-kv"></div>
        </div>
        <div class="recon-card" id="card-waf">
          <div class="recon-card-header">🛡 WAF DETECTION</div>
          <div class="recon-card-body" id="waf-body"></div>
        </div>
      </div>

      <!-- DNS Records -->
      <div class="recon-card" id="card-dns" style="display:none">
        <div class="recon-card-header">🗂 DNS RECORDS</div>
        <div class="recon-card-body" id="dns-body"></div>
      </div>

      <!-- Open Ports -->
      <div class="recon-card" id="card-ports" style="display:none">
        <div class="recon-card-header">🔌 OPEN PORTS</div>
        <div class="recon-card-body" style="padding:0">
          <table class="port-table">
            <thead><tr><th>PORT</th><th>SERVICE</th><th>BANNER</th><th>RISK</th></tr></thead>
            <tbody id="ports-body"></tbody>
          </table>
        </div>
      </div>

      <!-- Technologies -->
      <div class="recon-card" id="card-tech" style="display:none">
        <div class="recon-card-header">🧬 TECHNOLOGY STACK</div>
        <div class="recon-card-body">
          <div class="tech-grid" id="tech-grid"></div>
        </div>
      </div>

      <!-- CVEs -->
      <div class="recon-card" id="card-cve" style="display:none">
        <div class="recon-card-header">🔥 CVE FINDINGS</div>
        <div class="recon-card-body" style="padding:0">
          <table class="port-table">
            <thead><tr><th>CVE ID</th><th>PRODUCT</th><th>CVSS</th><th>SEVERITY</th><th>DESCRIPTION</th></tr></thead>
            <tbody id="cve-body"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Results -->
    <div id="results-panel">
      <div class="stats-row" id="stats-row">
        <div class="stat-card"><div class="stat-num stat-critical" id="cnt-critical">0</div><div class="stat-label">CRITICAL</div></div>
        <div class="stat-card"><div class="stat-num stat-high"     id="cnt-high">0</div><div class="stat-label">HIGH</div></div>
        <div class="stat-card"><div class="stat-num stat-medium"   id="cnt-medium">0</div><div class="stat-label">MEDIUM</div></div>
        <div class="stat-card"><div class="stat-num stat-low"      id="cnt-low">0</div><div class="stat-label">LOW</div></div>
        <div class="stat-card"><div class="stat-num stat-ai"       id="cnt-ai">0</div><div class="stat-label">ZERO-DAYS</div></div>
      </div>
      <table class="findings-table">
        <thead>
          <tr>
            <th>#</th>
            <th>SEVERITY</th>
            <th>VULNERABILITY</th>
            <th>ENDPOINT</th>
            <th>EVIDENCE</th>
          </tr>
        </thead>
        <tbody id="findings-body"></tbody>
      </table>
      <div id="no-findings" style="text-align:center;padding:60px;color:var(--dim);display:none">
        No findings yet. Run a scan first.
      </div>
    </div>

    <!-- Reports -->
    <div id="reports-panel">
      <div id="reports-list"></div>
      <div id="no-reports" style="text-align:center;padding:60px;color:var(--dim)">
        No reports generated yet.
      </div>
    </div>

  </div><!-- /main -->
</div><!-- /container -->

<script>
// ── State ─────────────────────────────────────────────────────────────────────
let currentProvider = 'ollama';
let eventSource     = null;
let lineCount       = 0;
let allFound        = false;

// ── Tab switching ─────────────────────────────────────────────────────────────
const TAB_NAMES = ['terminal','recon','results','reports'];
function showTab(name) {
  document.querySelectorAll('.tab').forEach((t,i)=>{
    t.classList.toggle('active', TAB_NAMES[i]===name);
  });
  document.getElementById('terminal-panel').style.display = name==='terminal' ? 'flex'   : 'none';
  document.getElementById('recon-panel').style.display    = name==='recon'    ? 'flex'   : 'none';
  document.getElementById('results-panel').style.display  = name==='results'  ? 'block'  : 'none';
  document.getElementById('reports-panel').style.display  = name==='reports'  ? 'block'  : 'none';
  if (name==='reports') loadReports();
}

// ── AI provider switching ─────────────────────────────────────────────────────
function setAIProvider(p, el) {
  currentProvider = p;
  document.querySelectorAll('.ai-tab').forEach(t => t.classList.remove('active'));
  if (el) el.classList.add('active');
  document.querySelectorAll('.ai-config').forEach(d => d.classList.remove('active'));
  document.getElementById('ai-'+p).classList.add('active');
}

function toggleAI(enabled) {
  document.getElementById('ai-config').style.display = enabled ? 'flex' : 'none';
}

// ── Module select all ─────────────────────────────────────────────────────────
let allChecked = true;
function toggleAll() {
  allChecked = !allChecked;
  document.querySelectorAll('input[name="module"]').forEach(cb => cb.checked = allChecked);
}

// ── Ollama detect ─────────────────────────────────────────────────────────────
async function checkOllama() {
  const host = document.getElementById('ollama-host').value;
  const el   = document.getElementById('ollama-status');
  el.textContent = 'Checking...';
  try {
    const r = await fetch('/api/ollama-models?host=' + encodeURIComponent(host));
    const d = await r.json();
    if (d.models && d.models.length > 0) {
      const sel = document.getElementById('ollama-model');
      sel.innerHTML = d.models.map(m=>`<option value="${m}">${m}</option>`).join('');
      el.style.color = 'var(--green)';
      el.textContent = `✓ ${d.models.length} models found`;
    } else {
      el.style.color = 'var(--yellow)';
      el.textContent = '⚠ Ollama running but no models pulled. Run: ollama pull deepseek-r1';
    }
  } catch(e) {
    el.style.color = 'var(--red)';
    el.textContent = '✗ Cannot reach Ollama. Is it running? (ollama serve)';
  }
}

// ── Terminal ──────────────────────────────────────────────────────────────────
function appendLine(text) {
  const term = document.getElementById('terminal');
  const div  = document.createElement('div');
  div.className = 't-line';

  // Color mapping from ANSI-like tags
  text = text
    .replace(/\[bold green\](.*?)\[\/bold green\]/g, '<span class="t-green t-bold">$1</span>')
    .replace(/\[green\](.*?)\[\/green\]/g, '<span class="t-green">$1</span>')
    .replace(/\[cyan\](.*?)\[\/cyan\]/g, '<span class="t-cyan">$1</span>')
    .replace(/\[bold cyan\](.*?)\[\/bold cyan\]/g, '<span class="t-cyan t-bold">$1</span>')
    .replace(/\[red\](.*?)\[\/red\]/g, '<span class="t-red">$1</span>')
    .replace(/\[bold red\](.*?)\[\/bold red\]/g, '<span class="t-red t-bold">$1</span>')
    .replace(/\[yellow\](.*?)\[\/yellow\]/g, '<span class="t-yellow">$1</span>')
    .replace(/\[orange1\](.*?)\[\/orange1\]/g, '<span class="t-orange">$1</span>')
    .replace(/\[dim\](.*?)\[\/dim\]/g, '<span class="t-dim">$1</span>')
    .replace(/\[bold\](.*?)\[\/bold\]/g, '<span class="t-bold">$1</span>')
    .replace(/\[.*?\]/g, '');  // strip remaining tags

  div.innerHTML = text;
  term.appendChild(div);
  lineCount++;
  if (lineCount > 2000) {
    term.removeChild(term.firstChild);
  }
  term.scrollTop = term.scrollHeight;
}

function clearTerminal() {
  document.getElementById('terminal').innerHTML = '';
  lineCount = 0;
}

// ── Set status ────────────────────────────────────────────────────────────────
function setStatus(state, text) {
  const dot  = document.getElementById('status-dot');
  const stxt = document.getElementById('status-text');
  dot.className = 'status-dot ' + state;
  stxt.textContent = text;
}

// ── Start scan ────────────────────────────────────────────────────────────────
async function startScan() {
  const target = document.getElementById('target').value.trim();
  if (!target) { alert('Please enter a target URL'); return; }

  const modules = [...document.querySelectorAll('input[name="module"]:checked')]
    .map(cb => cb.value);
  if (!modules.length) { alert('Select at least one module'); return; }

  const aiEnabled  = document.getElementById('ai-enabled').checked;
  const verbose    = document.getElementById('verbose').checked;
  const genPdf     = document.getElementById('gen-pdf').checked;

  const enableRecon = document.getElementById('enable-recon').checked;
  const enablePorts = document.getElementById('enable-ports').checked;

  const config = {
    target,
    username:  document.getElementById('username').value,
    password:  document.getElementById('password').value,
    modules,
    threads:   document.getElementById('threads').value,
    timeout:   document.getElementById('timeout').value,
    verbose,
    gen_pdf:   genPdf,
    skip_recon: !enableRecon,
    skip_ports: !enablePorts,
    ai_enabled: aiEnabled,
    ai_provider: aiEnabled ? currentProvider : 'none',
    ai_key:    aiEnabled && currentProvider==='openai'    ? document.getElementById('openai-key').value    : '',
    ai_key2:   aiEnabled && currentProvider==='anthropic' ? document.getElementById('anthropic-key').value : '',
    ai_model:  aiEnabled ? (
      currentProvider==='ollama'    ? document.getElementById('ollama-model').value :
      currentProvider==='openai'    ? document.getElementById('openai-model').value :
      document.getElementById('anthropic-model').value
    ) : '',
    ollama_host: document.getElementById('ollama-host').value,
  };

  clearTerminal();
  showTab('terminal');
  document.getElementById('scan-btn').style.display  = 'none';
  document.getElementById('stop-btn').style.display  = 'block';
  setStatus('running', 'SCANNING');
  document.getElementById('term-status').innerHTML = '<span class="t-green pulse">● SCANNING</span>';

  // Reset findings + recon panel
  document.getElementById('findings-body').innerHTML = '';
  document.getElementById('no-findings').style.display = 'none';
  ['critical','high','medium','low','ai'].forEach(k =>
    document.getElementById('cnt-'+k).textContent = '0'
  );
  resetReconPanel();

  // Start scan via POST
  const resp = await fetch('/api/scan/start', {
    method:  'POST',
    headers: {'Content-Type':'application/json'},
    body:    JSON.stringify(config),
  });
  const d = await resp.json();
  if (!d.ok) { appendLine('[red]Error starting scan: ' + d.error + '[/red]'); return; }

  const scanId = d.scan_id;

  // Stream output via SSE
  if (eventSource) eventSource.close();
  eventSource = new EventSource('/api/scan/stream/' + scanId);

  eventSource.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    if (msg.type === 'line') {
      appendLine(msg.data);
    } else if (msg.type === 'finding') {
      addFinding(msg.data);
    } else if (msg.type === 'recon_data') {
      updateReconPanel(msg.data);
      showTab('recon');
    } else if (msg.type === 'port_data') {
      updatePortsPanel(msg.data);
    } else if (msg.type === 'tech_data') {
      updateTechPanel(msg.data);
    } else if (msg.type === 'cve_data') {
      updateCvePanel(msg.data);
    } else if (msg.type === 'done') {
      scanFinished(msg.data);
    } else if (msg.type === 'error') {
      appendLine('[red]ERROR: ' + msg.data + '[/red]');
      scanFinished({});
    }
  };
  eventSource.onerror = () => {
    eventSource.close();
    scanFinished({});
  };
}

// ── Stop scan ─────────────────────────────────────────────────────────────────
async function stopScan() {
  await fetch('/api/scan/stop', {method:'POST'});
  if (eventSource) eventSource.close();
  appendLine('[yellow]⚠ Scan stopped by user[/yellow]');
  scanFinished({});
}

// ── Scan finished ─────────────────────────────────────────────────────────────
function scanFinished(data) {
  document.getElementById('scan-btn').style.display  = 'block';
  document.getElementById('stop-btn').style.display  = 'none';
  setStatus('done', 'DONE');
  document.getElementById('term-status').textContent = 'Scan complete';
  appendLine('[bold green]');
  appendLine('[bold green]✓ Scan complete![/bold green]');
  if (data.report_path) {
    appendLine('[cyan]  Report: ' + data.report_path + '[/cyan]');
  }
}

// ── Add finding to table ──────────────────────────────────────────────────────
function addFinding(f) {
  const tbody = document.getElementById('findings-body');
  const row   = document.createElement('tr');
  const sev   = (f.severity||'INFO').toUpperCase();
  const isAI  = f.ai_generated || f.zero_day;
  if (isAI) row.className = 'zero-day-row';

  const sevMap = {CRITICAL:'cnt-critical', HIGH:'cnt-high', MEDIUM:'cnt-medium', LOW:'cnt-low'};
  if (sevMap[sev]) {
    const el = document.getElementById(sevMap[sev]);
    el.textContent = parseInt(el.textContent)+1;
  }
  if (isAI) {
    const el = document.getElementById('cnt-ai');
    el.textContent = parseInt(el.textContent)+1;
  }

  const url = f.url || f.endpoint || '';
  const urlShort = url.replace(/^https?:\/\/[^/]+/, '') || url;

  row.innerHTML = `
    <td style="color:var(--dim)">${tbody.children.length+1}</td>
    <td><span class="sev-badge sev-${sev}">${sev}</span>${isAI ? '<span class="ai-tag">🤖AI</span>' : ''}</td>
    <td style="max-width:220px">${f.title||'Unknown'}</td>
    <td style="color:var(--cyan);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${url}">${urlShort}</td>
    <td style="color:var(--dim);max-width:200px;font-size:11px">${(f.evidence||'').substring(0,100)}</td>
  `;
  tbody.appendChild(row);
}

// ── Load reports ──────────────────────────────────────────────────────────────
async function loadReports() {
  const r  = await fetch('/api/reports');
  const d  = await r.json();
  const el = document.getElementById('reports-list');
  const nr = document.getElementById('no-reports');
  el.innerHTML = '';
  if (!d.reports || !d.reports.length) { nr.style.display='block'; return; }
  nr.style.display = 'none';
  d.reports.forEach(rep => {
    const card = document.createElement('div');
    card.className = 'report-card';
    card.innerHTML = `
      <div class="report-info">
        <h4>${rep.name}</h4>
        <span>${rep.size} | ${rep.date}</span>
      </div>
      <button class="btn-sm" onclick="downloadReport('${rep.name}')">⬇ Download</button>
    `;
    el.appendChild(card);
  });
}

function downloadReport(name) {
  window.open('/api/reports/download/' + encodeURIComponent(name));
}
</script>
</body>
</html>
"""

# ═══════════════════════════════════════════════════════════════════════════════
#  FLASK ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template_string(
        HTML,
        modules=SCANNER_MODULES,
        ollama_models=OLLAMA_MODELS,
    )


@app.route("/api/ollama-models")
def ollama_models_api():
    host = request.args.get("host", "http://localhost:11434").rstrip("/")
    try:
        import requests as req
        r = req.get(f"{host}/api/tags", timeout=5)
        models = [m["name"] for m in r.json().get("models", [])]
        return jsonify({"models": models})
    except Exception as e:
        return jsonify({"models": [], "error": str(e)})


@app.route("/api/scan/start", methods=["POST"])
def scan_start():
    if active_scan["running"]:
        return jsonify({"ok": False, "error": "A scan is already running"})

    config = request.get_json()
    scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_results[scan_id] = []
    scan_queues[scan_id]  = queue.Queue()

    # Build CLI command
    python_exec = sys.executable
    main_py     = Path(__file__).parent / "main.py"

    modules = config.get("modules", [])
    cmd = [
        python_exec, str(main_py), "scan",
        "--target",  config.get("target", ""),
        "--modules", ",".join(modules) if modules else "all",
        "--threads", str(config.get("threads", 10)),
        "--timeout", str(config.get("timeout", 15)),
        "--output",  str(REPORTS_DIR),
        "--i-have-permission",
    ]

    if config.get("username"):
        cmd += ["--username", config["username"]]
    if config.get("password"):
        cmd += ["--password", config["password"]]
    if config.get("verbose"):
        cmd += ["--verbose"]
    if not config.get("gen_pdf", True):
        cmd += ["--no-pdf"]

    # AI flags
    provider = config.get("ai_provider", "none")
    if provider != "none" and config.get("ai_enabled"):
        if provider == "ollama":
            cmd += [
                "--ai-provider", "ollama",
                "--ollama-host", config.get("ollama_host", "http://localhost:11434"),
            ]
            if config.get("ai_model"):
                cmd += ["--ai-model", config["ai_model"]]
        elif provider == "openai" and config.get("ai_key"):
            cmd += [
                "--ai-key",      config["ai_key"],
                "--ai-provider", "openai",
            ]
            if config.get("ai_model"):
                cmd += ["--ai-model", config["ai_model"]]
        elif provider == "anthropic" and config.get("ai_key2"):
            cmd += [
                "--ai-key",      config["ai_key2"],
                "--ai-provider", "anthropic",
            ]
            if config.get("ai_model"):
                cmd += ["--ai-model", config["ai_model"]]

    def run_scan():
        active_scan["running"] = True
        active_scan["id"]      = scan_id

        try:
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"
            env["PYTHONUNBUFFERED"] = "1"

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env,
                cwd=str(Path(__file__).parent),
            )
            active_scan["proc"] = proc

            q = scan_queues[scan_id]
            q.put(json.dumps({"type": "line", "data": f"[cyan]CMD: {' '.join(cmd[:6])}...[/cyan]"}))
            q.put(json.dumps({"type": "line", "data": f"[dim]Scan ID: {scan_id}[/dim]"}))

            for line in proc.stdout:
                line = line.rstrip()
                q.put(json.dumps({"type": "line", "data": line}))
                # Try to detect findings from output
                _detect_finding(line, scan_id)

            proc.wait()

            # Find generated reports
            reports = list(REPORTS_DIR.glob("*.pdf")) + list(REPORTS_DIR.glob("*.md"))
            report_path = str(reports[-1]) if reports else ""

            q.put(json.dumps({
                "type": "done",
                "data": {"report_path": report_path, "scan_id": scan_id}
            }))

        except Exception as e:
            scan_queues[scan_id].put(json.dumps({"type": "error", "data": str(e)}))
        finally:
            active_scan["running"] = False
            active_scan["proc"]    = None

    t = threading.Thread(target=run_scan, daemon=True)
    t.start()

    return jsonify({"ok": True, "scan_id": scan_id})


def _detect_finding(line: str, scan_id: str):
    """Parse scan output lines to extract findings for the results table."""
    import re
    # Look for Rich markup severity patterns in output
    sev_patterns = [
        (r"CRITICAL", "CRITICAL"),
        (r"HIGH",     "HIGH"),
        (r"MEDIUM",   "MEDIUM"),
        (r"LOW",      "LOW"),
    ]
    clean = re.sub(r"\[.*?\]", "", line)  # strip markup
    for pat, sev in sev_patterns:
        if pat in clean.upper() and ("—" in clean or "-" in clean or ":" in clean):
            # Extract title after severity indicator
            parts = re.split(r"[—\-:]", clean, maxsplit=1)
            title = parts[1].strip() if len(parts) > 1 else clean.strip()
            if len(title) > 5:
                finding = {
                    "severity":     sev,
                    "title":        title[:80],
                    "url":          "",
                    "evidence":     "",
                    "ai_generated": "AI" in clean or "🤖" in line,
                    "zero_day":     "ZERO-DAY" in clean.upper(),
                }
                scan_results[scan_id].append(finding)
                if scan_id in scan_queues:
                    scan_queues[scan_id].put(json.dumps({"type": "finding", "data": finding}))
                break


@app.route("/api/scan/stream/<scan_id>")
def scan_stream(scan_id):
    def event_stream():
        q = scan_queues.get(scan_id)
        if q is None:
            yield f"data: {json.dumps({'type':'error','data':'Scan not found'})}\n\n"
            return
        timeout_counter = 0
        while True:
            try:
                msg = q.get(timeout=1)
                yield f"data: {msg}\n\n"
                timeout_counter = 0
                data = json.loads(msg)
                if data["type"] in ("done", "error"):
                    # Clean up queue after scan completes
                    scan_queues.pop(scan_id, None)
                    break
            except queue.Empty:
                timeout_counter += 1
                yield f"data: {json.dumps({'type':'ping'})}\n\n"
                if timeout_counter > 600:  # 10 min timeout
                    scan_queues.pop(scan_id, None)
                    break

    return Response(
        event_stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":              "no-cache",
            "X-Accel-Buffering":          "no",
            "Access-Control-Allow-Origin": "*",
        },
    )


@app.route("/api/scan/stop", methods=["POST"])
def scan_stop():
    if active_scan.get("proc"):
        active_scan["proc"].terminate()
    active_scan["running"] = False
    return jsonify({"ok": True})


@app.route("/api/reports")
def reports_list():
    reports = []
    for f in sorted(REPORTS_DIR.glob("*"), key=lambda x: x.stat().st_mtime, reverse=True):
        if f.suffix in (".pdf", ".md", ".html"):
            stat = f.stat()
            size = f"{stat.st_size // 1024} KB" if stat.st_size > 1024 else f"{stat.st_size} B"
            date = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
            reports.append({"name": f.name, "size": size, "date": date})
    return jsonify({"reports": reports})


@app.route("/api/reports/download/<filename>")
def report_download(filename):
    path = REPORTS_DIR / filename
    if not path.exists():
        return "Not found", 404
    return send_file(str(path), as_attachment=True)


@app.route("/api/status")
def api_status():
    return jsonify({
        "running":  active_scan["running"],
        "scan_id":  active_scan["id"],
        "platform": platform.system(),
    })


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="BugScanner Web GUI")
    parser.add_argument("--host",  default="0.0.0.0",  help="Host to bind (default: 0.0.0.0)")
    parser.add_argument("--port",  default=5000, type=int, help="Port (default: 5000)")
    parser.add_argument("--debug", action="store_true",  help="Debug mode")
    args = parser.parse_args()

    print(f"""
\033[0;32m
 ██████╗ ██╗   ██╗ ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
 ██╔══██╗██║   ██║██╔════╝ ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
 ██████╔╝██║   ██║██║  ███╗███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
\033[0m
  \033[1;32mBugScanner Web GUI\033[0m — \033[36mAuthor: Muhammad Faizan | faizzyhon@gmail.com\033[0m
  \033[0;32mRunning on: http://localhost:{args.port}\033[0m
  \033[2mPress Ctrl+C to stop\033[0m
""")

    # Auto-open browser
    def open_browser():
        time.sleep(1.2)
        import webbrowser
        webbrowser.open(f"http://localhost:{args.port}")

    threading.Thread(target=open_browser, daemon=True).start()

    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)
