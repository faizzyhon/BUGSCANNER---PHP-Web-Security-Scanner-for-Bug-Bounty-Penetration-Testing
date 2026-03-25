#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║   BugScanner — Linux Installer                              ║
# ║   Author: Muhammad Faizan (faizzyhon@gmail.com)             ║
# ╚══════════════════════════════════════════════════════════════╝
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

echo -e "${RED}"
cat << 'EOF'
 ██████╗ ██╗   ██╗ ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
 ██╔══██╗██║   ██║██╔════╝ ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
 ██████╔╝██║   ██║██║  ███╗███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
 ██╔══██╗██║   ██║██║   ██║╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
 ██████╔╝╚██████╔╝╚██████╔╝███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
 ╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
EOF
echo -e "${RESET}"
echo -e "${CYAN}  PHP Web Security Scanner | EC-Council Bug Bounty Edition${RESET}"
echo -e "${CYAN}  Author: Muhammad Faizan | faizzyhon@gmail.com${RESET}"
echo ""

INSTALL_DIR="$HOME/.bugscanner"
BIN_DIR="$HOME/.local/bin"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Detect OS ─────────────────────────────────────────────────────────────────
OS="$(uname -s)"
DISTRO=""
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO="$ID"
fi

echo -e "${BOLD}[*] Detected OS:${RESET} $OS ($DISTRO)"
echo -e "${BOLD}[*] Source dir:${RESET} $SCRIPT_DIR"
echo -e "${BOLD}[*] Install dir:${RESET} $INSTALL_DIR"
echo ""

# ── Check Python ──────────────────────────────────────────────────────────────
echo -e "${CYAN}[1/6] Checking Python...${RESET}"
if command -v python3 &>/dev/null; then
    PY_VER=$(python3 --version 2>&1 | grep -oP '\d+\.\d+')
    PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
    if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 10 ]; then
        echo -e "  ${GREEN}✓ Python $PY_VER found${RESET}"
        PYTHON="python3"
    else
        echo -e "  ${YELLOW}⚠ Python $PY_VER found but 3.10+ required${RESET}"
        echo -e "  ${YELLOW}  Installing Python 3.11...${RESET}"
        _install_python
    fi
else
    echo -e "  ${RED}✗ Python3 not found — installing...${RESET}"
    _install_python
fi

_install_python() {
    case "$DISTRO" in
        ubuntu|debian|kali|parrot)
            sudo apt-get update -qq
            sudo apt-get install -y python3.11 python3.11-venv python3-pip curl git
            PYTHON="python3.11"
            ;;
        fedora|rhel|centos)
            sudo dnf install -y python3.11 python3-pip curl git
            PYTHON="python3.11"
            ;;
        arch|manjaro)
            sudo pacman -Sy --noconfirm python python-pip curl git
            PYTHON="python3"
            ;;
        *)
            echo -e "${RED}Unsupported distro. Please install Python 3.10+ manually.${RESET}"
            exit 1
            ;;
    esac
}

# ── System dependencies ───────────────────────────────────────────────────────
echo -e "${CYAN}[2/6] Installing system dependencies...${RESET}"
case "$DISTRO" in
    ubuntu|debian|kali|parrot)
        sudo apt-get install -y -qq \
            python3-pip python3-venv \
            libssl-dev libffi-dev \
            build-essential curl git wget \
            libpango-1.0-0 libpangoft2-1.0-0 \
            fonts-liberation 2>/dev/null || true
        echo -e "  ${GREEN}✓ Apt packages installed${RESET}"
        ;;
    arch|manjaro)
        sudo pacman -Sy --noconfirm python-pip pango curl git wget 2>/dev/null || true
        echo -e "  ${GREEN}✓ Pacman packages installed${RESET}"
        ;;
    fedora|rhel|centos)
        sudo dnf install -y python3-pip pango curl git wget 2>/dev/null || true
        echo -e "  ${GREEN}✓ DNF packages installed${RESET}"
        ;;
    *)
        echo -e "  ${YELLOW}⚠ Unknown distro — skipping system deps${RESET}"
        ;;
esac

# ── Create virtual environment ────────────────────────────────────────────────
echo -e "${CYAN}[3/6] Creating virtual environment at $INSTALL_DIR...${RESET}"
$PYTHON -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"
echo -e "  ${GREEN}✓ venv created${RESET}"

# ── Install Python packages ───────────────────────────────────────────────────
echo -e "${CYAN}[4/6] Installing Python dependencies...${RESET}"
pip install --quiet --upgrade pip wheel
pip install --quiet \
    requests beautifulsoup4 lxml \
    click rich \
    Jinja2 \
    reportlab \
    Flask Flask-WTF \
    openai anthropic 2>/dev/null || pip install \
    requests beautifulsoup4 lxml \
    click rich \
    Jinja2 \
    reportlab \
    Flask Flask-WTF

# Try WeasyPrint (optional, may fail on some systems)
pip install --quiet weasyprint 2>/dev/null && \
    echo -e "  ${GREEN}✓ WeasyPrint installed (high-quality PDF)${RESET}" || \
    echo -e "  ${YELLOW}⚠ WeasyPrint skipped (using ReportLab for PDF)${RESET}"

echo -e "  ${GREEN}✓ All Python packages installed${RESET}"

# ── Copy source files ─────────────────────────────────────────────────────────
echo -e "${CYAN}[5/6] Installing BugScanner to $INSTALL_DIR...${RESET}"
mkdir -p "$INSTALL_DIR/app"
cp -r "$SCRIPT_DIR/"* "$INSTALL_DIR/app/" 2>/dev/null || true
mkdir -p "$INSTALL_DIR/reports"
echo -e "  ${GREEN}✓ Files copied${RESET}"

# ── Create launcher scripts ───────────────────────────────────────────────────
echo -e "${CYAN}[6/6] Creating launcher commands...${RESET}"
mkdir -p "$BIN_DIR"

# CLI launcher
cat > "$BIN_DIR/bugscanner" << LAUNCHER
#!/usr/bin/env bash
source "$INSTALL_DIR/venv/bin/activate"
cd "$INSTALL_DIR/app"
python main.py "\$@"
LAUNCHER
chmod +x "$BIN_DIR/bugscanner"

# Web GUI launcher
cat > "$BIN_DIR/bugscanner-web" << LAUNCHER
#!/usr/bin/env bash
source "$INSTALL_DIR/venv/bin/activate"
cd "$INSTALL_DIR/app"
echo ""
echo "  🌐 BugScanner Web GUI starting..."
echo "  Open your browser at: http://localhost:5000"
echo "  Press Ctrl+C to stop"
echo ""
python web_gui.py "\$@"
LAUNCHER
chmod +x "$BIN_DIR/bugscanner-web"

# ── PATH setup ────────────────────────────────────────────────────────────────
SHELL_RC="$HOME/.bashrc"
[ -n "$ZSH_VERSION" ] && SHELL_RC="$HOME/.zshrc"
[ -f "$HOME/.zshrc" ] && SHELL_RC="$HOME/.zshrc"

if ! grep -q "$BIN_DIR" "$SHELL_RC" 2>/dev/null; then
    echo "" >> "$SHELL_RC"
    echo "# BugScanner" >> "$SHELL_RC"
    echo "export PATH=\"\$PATH:$BIN_DIR\"" >> "$SHELL_RC"
fi
export PATH="$PATH:$BIN_DIR"

# ── Ollama detection ──────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Checking Ollama (local AI)...${RESET}"
if command -v ollama &>/dev/null; then
    echo -e "  ${GREEN}✓ Ollama is installed${RESET}"
    MODELS=$(ollama list 2>/dev/null | tail -n +2 | awk '{print $1}' | head -5)
    if [ -n "$MODELS" ]; then
        echo -e "  ${GREEN}✓ Models available: ${MODELS}${RESET}"
    else
        echo -e "  ${YELLOW}⚠ No models pulled yet. Run: ollama pull deepseek-r1${RESET}"
    fi
else
    echo -e "  ${YELLOW}⚠ Ollama not found (optional — for free local AI)${RESET}"
    echo -e "  ${YELLOW}  Install: curl -fsSL https://ollama.com/install.sh | sh${RESET}"
    echo -e "  ${YELLOW}  Then: ollama pull deepseek-r1${RESET}"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}║  ✓ BugScanner installed successfully!                    ║${RESET}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════╣${RESET}"
echo -e "${GREEN}║                                                          ║${RESET}"
echo -e "${GREEN}║  CLI  :  bugscanner scan --url https://target.com        ║${RESET}"
echo -e "${GREEN}║  WEB  :  bugscanner-web                                  ║${RESET}"
echo -e "${GREEN}║          then open http://localhost:5000                  ║${RESET}"
echo -e "${GREEN}║                                                          ║${RESET}"
echo -e "${GREEN}║  Reload shell or run: source ~/.bashrc                   ║${RESET}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  Author: ${CYAN}Muhammad Faizan${RESET} | ${CYAN}faizzyhon@gmail.com${RESET}"
echo -e "  Hack the Planet 🌍"
echo ""
