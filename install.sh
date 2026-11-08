#!/usr/bin/env bash
###############################################################################
#  TOOLS INSTALLATION — Bug Bounty / VAPT Toolkit Installer
#  Target: Kali Linux (also works on Debian/Ubuntu derivatives)
#  Design goal: NEVER crash mid-run. Every tool install is isolated, logged,
#  and failures are collected into a report instead of killing the script.
###############################################################################

# Do NOT use 'set -e' — a single failed tool must not kill the whole run.
set -u
IFS=$'\n\t'

# ---------------------------------------------------------------------------
# 0. PATHS / WORKDIR  (matches your ~/INFORMATION_GATHERING layout)
# ---------------------------------------------------------------------------
WORKDIR="$HOME/INFORMATION_GATHERING"
LOGDIR="$WORKDIR/install_logs"
SUMMARY="$WORKDIR/install_summary.txt"
mkdir -p "$WORKDIR" "$LOGDIR"
cd "$WORKDIR" || { echo "[FATAL] Cannot cd to $WORKDIR"; exit 1; }

# ---------------------------------------------------------------------------
# 1. COLORS / BANNER
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
BOLD='\033[1m'; NC='\033[0m'

banner() {
cat << "EOF"
████████╗ ██████╗  ██████╗ ██╗     ███████╗
╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔════╝
   ██║   ██║   ██║██║   ██║██║     ███████╗
   ██║   ██║   ██║██║   ██║██║     ╚════██║
   ██║   ╚██████╔╝╚██████╔╝███████╗███████║
   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚══════╝
     I N S T A L L A T I O N   S C R I P T
EOF
echo -e "${CYAN}Target dir : $WORKDIR${NC}"
echo -e "${CYAN}Log dir    : $LOGDIR${NC}"
echo -e "${CYAN}Started    : $(date)${NC}"
echo "-----------------------------------------------------------------"
}
banner

# ---------------------------------------------------------------------------
# 2. COUNTERS / TRACKING
# ---------------------------------------------------------------------------
TOTAL=0
OK=0
FAIL=0
SKIP=0
declare -a FAILED_TOOLS=()
declare -a SKIPPED_TOOLS=()

# ---------------------------------------------------------------------------
# 3. CORE ERROR-SAFE RUNNER
#    install_step "N" "Tool Name" "command to run" "binary_to_verify(optional)"
# ---------------------------------------------------------------------------
install_step() {
    local num="$1" name="$2" cmd="$3" verify="${4:-}"
    local logfile="$LOGDIR/$(echo "$name" | tr ' /' '__').log"
    TOTAL=$((TOTAL+1))

    echo -ne "${BOLD}[$num] Installing: $name ... ${NC}"

    # Run in a subshell so a hard failure (even a stray exit) can't kill the parent
    ( eval "$cmd" ) >"$logfile" 2>&1
    local rc=$?

    # Verify: prefer checking the binary actually exists/works over trusting exit code
    if [ -n "$verify" ]; then
        if command -v "$verify" >/dev/null 2>&1; then
            echo -e "${GREEN}OK${NC}"
            OK=$((OK+1))
            return 0
        else
            echo -e "${RED}FAILED${NC} (see $logfile)"
            FAIL=$((FAIL+1))
            FAILED_TOOLS+=("$name")
            return 1
        fi
    else
        if [ $rc -eq 0 ]; then
            echo -e "${GREEN}OK${NC}"
            OK=$((OK+1))
            return 0
        else
            echo -e "${RED}FAILED${NC} (see $logfile)"
            FAIL=$((FAIL+1))
            FAILED_TOOLS+=("$name")
            return 1
        fi
    fi
}

skip_step() {
    local name="$1" reason="$2"
    echo -e "${YELLOW}[SKIP] $name - $reason${NC}"
    SKIP=$((SKIP+1))
    SKIPPED_TOOLS+=("$name ($reason)")
}

###############################################################################
# PHASE 0 — ENVIRONMENT SETUP (fixes 90% of all possible errors before they occur)
###############################################################################
echo -e "\n${BOLD}===== PHASE 0: ENVIRONMENT SETUP =====${NC}\n"

# --- apt lock / update retry (fixes "could not get lock" errors) ---
apt_safe_update() {
    local tries=0
    while [ $tries -lt 3 ]; do
        sudo apt-get update -y >"$LOGDIR/apt_update.log" 2>&1 && return 0
        tries=$((tries+1))
        echo -e "${YELLOW}apt update locked/failed, retrying ($tries/3)...${NC}"
        sleep 5
    done
    echo -e "${RED}apt update failed after 3 tries — continuing anyway${NC}"
}
install_step "0.1" "apt-get update" "apt_safe_update"

# --- base build deps (fixes most 'command not found' / compile failures) ---
install_step "0.2" "Base build dependencies (gcc,make,git,curl,wget,unzip,jq,python3-pip,python3-venv,pipx,golang,ruby,libssl-dev,libffi-dev,libpcap-dev,build-essential)" \
"sudo apt-get install -y gcc make build-essential git curl wget unzip jq \
python3 python3-pip python3-venv python3-dev pipx golang-go ruby ruby-dev \
libssl-dev libffi-dev libpcap-dev libxml2-dev libxslt1-dev zlib1g-dev \
nmap masscan seclists" "git"

# --- pipx path (fixes 'pipx: command not found after install' and PATH issues) ---
install_step "0.3" "pipx ensurepath" "python3 -m pipx ensurepath || true" ""

# --- PEP 668 fix: externally-managed-environment error on Debian/Kali pip ---
# We standardize: use pip3 install --user --break-system-packages everywhere a
# plain pip install would otherwise throw "error: externally-managed-environment".
PIP_INSTALL="python3 -m pip install --user --break-system-packages --upgrade"

install_step "0.4" "pip3 self-upgrade (PEP668-safe)" "$PIP_INSTALL pip setuptools wheel" ""

# --- GOPATH / GOBIN setup (fixes 'go: command not found' and 'tool installed but not found') ---
export GOPATH="$HOME/go"
export GOBIN="$GOPATH/bin"
export PATH="$PATH:/usr/local/go/bin:$GOBIN:$HOME/.local/bin"

add_path_once() {
    local line="$1" rcfile="$2"
    touch "$rcfile"
    grep -qxF "$line" "$rcfile" || echo "$line" >> "$rcfile"
}
for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    add_path_once 'export GOPATH="$HOME/go"' "$rc"
    add_path_once 'export GOBIN="$GOPATH/bin"' "$rc"
    add_path_once 'export PATH="$PATH:/usr/local/go/bin:$GOBIN:$HOME/.local/bin"' "$rc"
done
install_step "0.5" "GOPATH/GOBIN persisted to shell rc files" "true" ""

# --- verify go is actually usable, else install manually (fixes 'golang-go too old') ---
go_ok=false
if command -v go >/dev/null 2>&1; then
    GOVER=$(go version | awk '{print $3}' | sed 's/go//')
    go_ok=true
fi
if [ "$go_ok" = false ]; then
    install_step "0.6" "Go (manual install, apt version missing)" \
    "wget -q https://go.dev/dl/go1.22.5.linux-amd64.tar.gz -O /tmp/go.tar.gz && \
     sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tar.gz" "go"
else
    echo -e "${GREEN}[0.6] Go already present ($GOVER) — skipping manual install${NC}"
fi

mkdir -p "$GOBIN"

###############################################################################
# PHASE 1 — GO-BASED TOOLS  (go install, @latest, auto PATH-safe)
###############################################################################
echo -e "\n${BOLD}===== PHASE 1: GO TOOLS =====${NC}\n"

# name|import_path|binary_to_verify
GO_TOOLS=(
"subfinder|github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest|subfinder"
"httpx|github.com/projectdiscovery/httpx/cmd/httpx@latest|httpx"
"naabu|github.com/projectdiscovery/naabu/v2/cmd/naabu@latest|naabu"
"katana|github.com/projectdiscovery/katana/cmd/katana@latest|katana"
"dnsx|github.com/projectdiscovery/dnsx/cmd/dnsx@latest|dnsx"
"nuclei|github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest|nuclei"
"tlsx|github.com/projectdiscovery/tlsx/cmd/tlsx@latest|tlsx"
"cdncheck|github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest|cdncheck"
"interactsh-client|github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest|interactsh-client"
"notify|github.com/projectdiscovery/notify/cmd/notify@latest|notify"
"mapcidr|github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest|mapcidr"
"asnmap|github.com/projectdiscovery/asnmap/cmd/asnmap@latest|asnmap"
"alterx|github.com/projectdiscovery/alterx/cmd/alterx@latest|alterx"
"urlfinder|github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest|urlfinder"
"cvemap|github.com/projectdiscovery/cvemap/cmd/cvemap@latest|cvemap"
"uncover|github.com/projectdiscovery/uncover/cmd/uncover@latest|uncover"
"proxify|github.com/projectdiscovery/proxify/cmd/proxify@latest|proxify"
"fingerprintx|github.com/praetorian-inc/fingerprintx/cmd/fingerprintx@latest|fingerprintx"
"ffuf|github.com/ffuf/ffuf/v2@latest|ffuf"
"gobuster|github.com/OJ/gobuster/v3@latest|gobuster"
"hakrawler|github.com/hakluke/hakrawler@latest|hakrawler"
"gospider|github.com/jaeles-project/gospider@latest|gospider"
"crawley|github.com/sixdouglas/crawley@latest|crawley"
"assetfinder|github.com/tomnomnom/assetfinder@latest|assetfinder"
"waybackurls|github.com/tomnomnom/waybackurls@latest|waybackurls"
"gau|github.com/lc/gau/v2/cmd/gau@latest|gau"
"anew|github.com/tomnomnom/anew@latest|anew"
"gf|github.com/tomnomnom/gf@latest|gf"
"unfurl|github.com/tomnomnom/unfurl@latest|unfurl"
"qsreplace|github.com/tomnomnom/qsreplace@latest|qsreplace"
"dalfox|github.com/hahwul/dalfox/v2@latest|dalfox"
"jwt-hack|github.com/hahwul/jwt-hack@latest|jwt-hack"
"smugglex|github.com/hahwul/smugglex@latest|smugglex"
"crlfuzz|github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest|crlfuzz"
"ppfuzz|github.com/dwisiswant0/ppfuzz/cmd/ppfuzz@latest|ppfuzz"
"go-dork|github.com/dwisiswant0/go-dork@latest|go-dork"
"GoLinkFinder|github.com/0xsha/GoLinkFinder@latest|GoLinkFinder"
"findomain|github.com/findomain/findomain@latest|findomain"
"subjack|github.com/haccer/subjack@latest|subjack"
"subzy|github.com/PentestPad/subzy@latest|subzy"
"haktrails|github.com/hakluke/haktrails@latest|haktrails"
"hakrevdns|github.com/hakluke/hakrevdns@latest|hakrevdns"
"hakip2host|github.com/hakluke/hakip2host@latest|hakip2host"
"shuffledns|github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest|shuffledns"
"x8|github.com/Sh1Yo/x8@latest|x8"
"gotator|github.com/Josue87/gotator@latest|gotator"
"csprecon|github.com/edoardottt/csprecon/cmd/csprecon@latest|csprecon"
"cariddi|github.com/edoardottt/cariddi/cmd/cariddi@latest|cariddi"
"nomore403|github.com/devploit/nomore403@latest|nomore403"
"toxicache|github.com/xhzeem/toxicache@latest|toxicache"
"cut-cdn|github.com/ImAyrix/cut-cdn@latest|cut-cdn"
"kxss|github.com/Emoe/kxss@latest|kxss"
"Gxss|github.com/KathanP19/Gxss@latest|Gxss"
"gowitness|github.com/sensepost/gowitness@latest|gowitness"
"github-subdomains|github.com/gwen001/github-subdomains@latest|github-subdomains"
"gitlab-subdomains|github.com/gwen001/gitlab-subdomains@latest|gitlab-subdomains"
"github-endpoints|github.com/gwen001/github-endpoints@latest|github-endpoints"
"related-domains|github.com/gwen001/related-domains@latest|related-domains"
"nrich|gitlab.com/shodan-public/nrich@latest|nrich"
)

n=0
for entry in "${GO_TOOLS[@]}"; do
    n=$((n+1))
    IFS='|' read -r name path verify <<< "$entry"
    if command -v "$verify" >/dev/null 2>&1; then
        echo -e "${GREEN}[1.$n] $name already installed — skipping${NC}"
        continue
    fi
    install_step "1.$n" "$name (go)" "GOFLAGS=-insecure go install -v $path 2>&1 || go install -v $path" "$verify"
done

###############################################################################
# PHASE 2 — PYTHON / PIP / PIPX TOOLS  (PEP668-safe everywhere)
###############################################################################
echo -e "\n${BOLD}===== PHASE 2: PYTHON TOOLS (pip/pipx, PEP668-safe) =====${NC}\n"

# name|pip_package|binary_to_verify  -- installed via pip3 --user --break-system-packages
PIP_TOOLS=(
"arjun|arjun|arjun"
"dirsearch|dirsearch|dirsearch"
"corsy|git+https://github.com/s0md3v/Corsy.git|corsy.py"
"xsstrike|git+https://github.com/s0md3v/XSStrike.git|xsstrike.py"
"uro|uro|uro"
"sqlmap|sqlmap|sqlmap"
"theHarvester|theHarvester|theHarvester"
"wafw00f|wafw00f|wafw00f"
"dnsrecon|dnsrecon|dnsrecon"
"wpscan|wpscan|wpscan"
"pwncat-cs|pwncat-cs|pwncat-cs"
"droopescan|droopescan|droopescan"
"CMSeeK|git+https://github.com/Tuhinshubhra/CMSeeK.git|cmseek.py"
"dnstwist|dnstwist|dnstwist"
"s3scanner|s3scanner|s3scanner"
"trufflehog|truffleHog|trufflehog"
"detect-secrets|detect-secrets|detect-secrets"
"commix|commix|commix"
"ghauri|ghauri|ghauri"
)

n=0
for entry in "${PIP_TOOLS[@]}"; do
    n=$((n+1))
    IFS='|' read -r name pkg verify <<< "$entry"
    if command -v "$verify" >/dev/null 2>&1; then
        echo -e "${GREEN}[2.$n] $name already installed — skipping${NC}"
        continue
    fi
    install_step "2.$n" "$name (pip)" "$PIP_INSTALL \"$pkg\"" "$verify"
done

# pipx is preferred for CLI apps that need isolated envs (fixes dependency-conflict errors)
PIPX_TOOLS=(
"wfuzz|wfuzz"
)
n=0
for entry in "${PIPX_TOOLS[@]}"; do
    n=$((n+1))
    IFS='|' read -r name pkg <<< "$entry"
    if command -v "$name" >/dev/null 2>&1; then
        echo -e "${GREEN}[2p.$n] $name already installed — skipping${NC}"
        continue
    fi
    install_step "2p.$n" "$name (pipx)" "python3 -m pipx install $pkg" "$name"
done

###############################################################################
# PHASE 3 — APT-BASED TOOLS  (fastest, Kali repo native)
###############################################################################
echo -e "\n${BOLD}===== PHASE 3: APT TOOLS =====${NC}\n"

APT_TOOLS=(
"nikto|nikto"
"nmap|nmap"
"masscan|masscan"
"gobuster|gobuster"
"whatweb|whatweb"
"feroxbuster|feroxbuster"
"amass|amass"
"sslscan|sslscan"
"testssl.sh|testssl.sh"
"enum4linux-ng|enum4linux-ng"
"smbclient|smbclient"
"smbmap|smbmap"
"ldap-utils|ldapsearch"
"snmp|snmpwalk"
"hydra|hydra"
"responder|responder"
"exploitdb|searchsploit"
"metasploit-framework|msfconsole"
"dnsenum|dnsenum"
"fierce|fierce"
"whois|whois"
"dirb|dirb"
)
n=0
for entry in "${APT_TOOLS[@]}"; do
    n=$((n+1))
    IFS='|' read -r pkg verify <<< "$entry"
    if command -v "$verify" >/dev/null 2>&1; then
        echo -e "${GREEN}[3.$n] $pkg already installed — skipping${NC}"
        continue
    fi
    install_step "3.$n" "$pkg (apt)" "sudo apt-get install -y $pkg" "$verify"
done

###############################################################################
# PHASE 4 — GIT-CLONE-BASED TOOLS (custom setup, non-pip/go)
###############################################################################
echo -e "\n${BOLD}===== PHASE 4: GIT-CLONE TOOLS =====${NC}\n"

TOOLSDIR="$WORKDIR/tools"
mkdir -p "$TOOLSDIR"

git_clone_safe() {
    local name="$1" repo="$2" dest="$3"
    if [ -d "$dest" ]; then
        (cd "$dest" && git pull -q) && return 0
    else
        git clone -q --depth 1 "$repo" "$dest"
    fi
}

install_step "4.1" "SecLists (wordlists)" \
"git_clone_safe seclists https://github.com/danielmiessler/SecLists.git '$TOOLSDIR/SecLists'" ""

install_step "4.2" "PayloadsAllTheThings" \
"git_clone_safe payloads https://github.com/swisskyrepo/PayloadsAllTheThings.git '$TOOLSDIR/PayloadsAllTheThings'" ""

install_step "4.3" "GitTools (dumper/extractor)" \
"git_clone_safe gittools https://github.com/internetwache/GitTools.git '$TOOLSDIR/GitTools' && chmod +x '$TOOLSDIR/GitTools'/*/*.sh" ""

install_step "4.4" "git-dumper" \
"git_clone_safe gitdumper https://github.com/arthaud/git-dumper.git '$TOOLSDIR/git-dumper' && \
 $PIP_INSTALL -r '$TOOLSDIR/git-dumper/requirements.txt'" ""

install_step "4.5" "gf-patterns (pattern set for gf tool)" \
"git_clone_safe gfpatterns https://github.com/1ndianl33t/Gf-Patterns.git '$TOOLSDIR/Gf-Patterns' && \
 mkdir -p \$HOME/.gf && cp '$TOOLSDIR/Gf-Patterns'/*.json \$HOME/.gf/ 2>/dev/null" ""

install_step "4.6" "jwt_tool" \
"git_clone_safe jwt_tool https://github.com/ticarpi/jwt_tool.git '$TOOLSDIR/jwt_tool' && \
 chmod +x '$TOOLSDIR/jwt_tool/jwt_tool.py' && \
 $PIP_INSTALL -r '$TOOLSDIR/jwt_tool/requirements.txt'" ""

install_step "4.7" "Osmedeus" \
"git_clone_safe osmedeus https://github.com/j3ssie/Osmedeus.git '$TOOLSDIR/Osmedeus'" ""

install_step "4.8" "reconFTW" \
"git_clone_safe reconftw https://github.com/six2dez/reconftw.git '$TOOLSDIR/reconftw' && \
 chmod +x '$TOOLSDIR/reconftw/reconftw.sh'" ""

install_step "4.9" "LinkFinder" \
"git_clone_safe linkfinder https://github.com/GerbenJavado/LinkFinder.git '$TOOLSDIR/LinkFinder' && \
 cd '$TOOLSDIR/LinkFinder' && $PIP_INSTALL -r requirements.txt && python3 setup.py install --user; cd '$WORKDIR'" ""

install_step "4.10" "SecretFinder" \
"git_clone_safe secretfinder https://github.com/m4ll0k/SecretFinder.git '$TOOLSDIR/SecretFinder' && \
 $PIP_INSTALL -r '$TOOLSDIR/SecretFinder/requirements.txt'" ""

###############################################################################
# PHASE 5 — CLOUD (AWS/Azure) TOOLS
###############################################################################
echo -e "\n${BOLD}===== PHASE 5: CLOUD TOOLS =====${NC}\n"

install_step "5.1" "AWS CLI" \
"curl -s 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o /tmp/awscliv2.zip && \
 cd /tmp && unzip -q -o awscliv2.zip && sudo ./aws/install --update; cd '$WORKDIR'" "aws"

install_step "5.2" "Pacu (AWS exploitation)" \
"python3 -m venv '$TOOLSDIR/pacu-venv' 2>/dev/null; \
 git_clone_safe pacu https://github.com/RhinoSecurityLabs/pacu.git '$TOOLSDIR/pacu' && \
 cd '$TOOLSDIR/pacu' && bash install.sh; cd '$WORKDIR'" ""

install_step "5.3" "ScoutSuite" \
"$PIP_INSTALL scoutsuite" "scout"

install_step "5.4" "CloudBrute" \
"GOFLAGS=-insecure go install -v github.com/0xsha/CloudBrute@latest" "CloudBrute"

install_step "5.5" "cloud_enum" \
"git_clone_safe cloud_enum https://github.com/initstring/cloud_enum.git '$TOOLSDIR/cloud_enum' && \
 $PIP_INSTALL -r '$TOOLSDIR/cloud_enum/requirements.txt'" ""

install_step "5.6" "Azure CLI" \
"curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash" "az"

install_step "5.7" "ROADtools (Azure AD recon)" \
"$PIP_INSTALL roadrecon" "roadrecon"

###############################################################################
# PHASE 6 — FINAL PATH REFRESH + VERIFICATION PASS
###############################################################################
echo -e "\n${BOLD}===== PHASE 6: VERIFICATION =====${NC}\n"
export PATH="$PATH:/usr/local/go/bin:$GOBIN:$HOME/.local/bin"
hash -r

echo "Re-checking all go-tool binaries are now reachable on PATH..."
for entry in "${GO_TOOLS[@]}"; do
    IFS='|' read -r name path verify <<< "$entry"
    if ! command -v "$verify" >/dev/null 2>&1; then
        skip_step "$name" "binary not found on PATH after install — check $LOGDIR"
    fi
done

###############################################################################
# SUMMARY REPORT
###############################################################################
{
echo "============================================================"
echo " TOOLS INSTALLATION SUMMARY — $(date)"
echo "============================================================"
echo "Total attempted : $TOTAL"
echo "Succeeded        : $OK"
echo "Failed           : $FAIL"
echo "Skipped(dup)     : $SKIP"
echo ""
if [ ${#FAILED_TOOLS[@]} -gt 0 ]; then
    echo "---- FAILED TOOLS (check individual logs in $LOGDIR) ----"
    for t in "${FAILED_TOOLS[@]}"; do echo "  - $t"; done
else
    echo "No failures recorded."
fi
echo ""
if [ ${#SKIPPED_TOOLS[@]} -gt 0 ]; then
    echo "---- SKIPPED / NOT ON PATH ----"
    for t in "${SKIPPED_TOOLS[@]}"; do echo "  - $t"; done
fi
echo "============================================================"
} | tee "$SUMMARY"

echo -e "\n${BOLD}${GREEN}Done.${NC} Full summary saved to: $SUMMARY"
echo -e "${BOLD}${GREEN}Per-tool logs saved to:${NC} $LOGDIR"
echo -e "${YELLOW}Re-open your shell (or 'source ~/.bashrc') so PATH changes take effect.${NC}"
