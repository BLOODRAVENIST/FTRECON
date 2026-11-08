#!/usr/bin/env bash
###############################################################################
#  FTSCAN — Deep Vulnerability Scanning companion to FTRECON
#  made by BLOODRAVENIST
#
#  RECON ===> SCAN.  This script takes an EXISTING ftrecon.sh results folder
#  and dispatches each candidate-parameter file ftrecon already extracted
#  (gf patterns) to the tool built for that vulnerability class. Nothing here
#  re-does recon — it only reads what's already on disk and tests it.
#
#  Usage:
#     ./ftscan.sh <results_folder_name_or_path> [--yes] [--max N] [--hosts N] [--wordlist PATH]
#
#     <folder>     either a full path, or just the folder name ftrecon.sh
#                  created (looked up under ~/INFORMATION_GATHERING/ftrecon_results/)
#     --yes        skip the interactive authorization confirmation
#     --max N      cap candidates tested per class with sqlmap/xsstrike/xsser/
#                  ghauri/commix/oralyzer (default 15) -- keeps runtime sane
#     --hosts N    cap how many live hosts get CORS/CRLF/dirfuzz checked (default 5)
#     --wordlist P use a specific wordlist for directory fuzzing
#
#  SAFETY NOTE ON HOW THIS IS BUILT: every candidate value tested here (URLs
#  pulled from gau/waybackurls/katana/crawling) is untrusted, internet-sourced
#  data. Every tool call below is executed via step()/need(), which pass each
#  argument through exactly as typed (no eval, no shell re-parsing) -- so a
#  crawled URL containing quotes, backticks, $() or semicolons can never break
#  out and run something else on this machine. This matters: it's a real,
#  demonstrable injection class in naive recon scripts, not a theoretical one.
###############################################################################

set -u
set -o pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; NC='\033[0m'

# ---------------------------------------------------------------------------
# BANNER / USAGE / ARGS
# ---------------------------------------------------------------------------
banner() {
  if command -v figlet >/dev/null 2>&1; then
    figlet -f slant "FTSCAN" 2>/dev/null
  else
    echo "==========================================="
    echo "                 F T S C A N                "
    echo "==========================================="
  fi
  echo -e "${CYAN}   Deep Vulnerability Scan  ·  made by BLOODRAVENIST${NC}"
  echo -e "${CYAN}   companion to FTRECON  —  RECON ===> SCAN${NC}"
}

usage() {
  echo "Usage: $0 <ftrecon_results_folder_or_name> [--yes] [--max N] [--hosts N] [--wordlist PATH]"
  echo ""
  echo "  <folder>     path, or just the folder name ftrecon.sh created"
  echo "               (looked up under ~/INFORMATION_GATHERING/ftrecon_results/)"
  echo "  --yes        skip the interactive authorization confirmation"
  echo "  --max N      cap per-class active-tool candidates (default 15)"
  echo "  --hosts N    cap how many live hosts get checked/fuzzed (default 5)"
  echo "  --wordlist P custom wordlist for directory fuzzing"
  exit 1
}

[ $# -lt 1 ] && usage
RAW="$1"; shift
AUTO_YES=false
MAXCAND=15
MAXHOSTS=5
CUSTOM_WORDLIST=""
while [ $# -gt 0 ]; do
  case "$1" in
    --yes) AUTO_YES=true ;;
    --max) shift; MAXCAND="${1:-15}" ;;
    --hosts) shift; MAXHOSTS="${1:-5}" ;;
    --wordlist) shift; CUSTOM_WORDLIST="${1:-}" ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
  shift
done

# ---------------------------------------------------------------------------
# RESOLVE RESULTS FOLDER
# ---------------------------------------------------------------------------
if [ -d "$RAW" ]; then
  RESULTS_DIR="$(cd "$RAW" && pwd)"
elif [ -d "$HOME/INFORMATION_GATHERING/ftrecon_results/$RAW" ]; then
  RESULTS_DIR="$(cd "$HOME/INFORMATION_GATHERING/ftrecon_results/$RAW" && pwd)"
else
  echo -e "${RED}[FATAL] Could not find results folder '$RAW'."
  echo -e "Looked in: ./$RAW  and  $HOME/INFORMATION_GATHERING/ftrecon_results/$RAW${NC}"
  exit 1
fi

FOLDER_NAME=$(basename "$RESULTS_DIR")
DOMAIN_GUESS=$(echo "$FOLDER_NAME" | sed -E 's/_[0-9]{8}_[0-9]{6}$//' | tr '[:upper:]' '[:lower:]')

# Defense in depth: even though this is derived from a folder name ftrecon.sh
# itself created, validate it again before using it in any tool call.
if ! [[ "$DOMAIN_GUESS" =~ ^[a-z0-9.-]+$ ]]; then
  echo -e "${RED}[FATAL] Could not derive a safe domain from folder '$FOLDER_NAME'."
  echo -e "Expected ftrecon.sh naming: <domain>_<YYYYmmdd>_<HHMMSS>${NC}"
  exit 1
fi
URL="https://$DOMAIN_GUESS"

banner
echo -e "${CYAN}Results folder       : $RESULTS_DIR${NC}"
echo -e "${CYAN}Target (from folder) : $DOMAIN_GUESS${NC}"
echo -e "${CYAN}Max candidates/class : $MAXCAND    Max hosts checked : $MAXHOSTS${NC}"
echo "---------------------------------------------------------------"

if [ "$AUTO_YES" = false ]; then
  echo -e "${YELLOW}FTSCAN performs ACTIVE testing (sqlmap, xsser, xsstrike, commix, SSRF OOB"
  echo -e "probes, directory brute force, CMS scanners...) against $DOMAIN_GUESS."
  echo -e "Only continue if you are authorized to test this target. Type YES to proceed:${NC}"
  read -r CONFIRM
  if [ "$CONFIRM" != "YES" ]; then
    echo -e "${RED}Not confirmed. Exiting without scanning.${NC}"
    exit 1
  fi
fi

# ---------------------------------------------------------------------------
# INPUT FILES (produced earlier by ftrecon.sh — never regenerated here)
# ---------------------------------------------------------------------------
SUBS_DIR="$RESULTS_DIR/01_subdomains"
PROBE_DIR="$RESULTS_DIR/04_probe_tech"
URLS_DIR="$RESULTS_DIR/06_urls"
PARAMS_DIR="$RESULTS_DIR/08_params"
GF_DIR="$PARAMS_DIR/gf_patterns"

ALL_SUBS="$SUBS_DIR/all_subdomains.txt"
LIVE_HOSTS="$PROBE_DIR/live_hosts.txt"
ALL_URLS="$URLS_DIR/all_urls_clean.txt"

SQLI_CANDIDATES="$GF_DIR/sqli.txt"
XSS_CANDIDATES="$GF_DIR/xss.txt"
SSRF_CANDIDATES="$GF_DIR/ssrf.txt"
REDIRECT_CANDIDATES="$GF_DIR/redirect.txt"
LFI_CANDIDATES="$GF_DIR/lfi.txt"
RCE_CANDIDATES="$GF_DIR/rce.txt"

# ---------------------------------------------------------------------------
# OUTPUT TREE (new phases, added alongside ftrecon.sh's own numbered folders)
# ---------------------------------------------------------------------------
OUT="$RESULTS_DIR/13_deep_vuln_scan"
AI_DIR="$RESULTS_DIR/14_deep_scan_ai_triage"
LOGDIR="$OUT/_logs"

mkdir -p "$OUT"/{sqli/sqlmap,xss,ssrf,redirect,lfi,rce,cors_crlf,dirfuzz_all_hosts,cms_scan,git_exposure,nuclei_extended} "$AI_DIR" "$LOGDIR"

trap 'echo -e "\n${YELLOW}Interrupted — partial results saved in $OUT${NC}"; exit 130' INT

# ---------------------------------------------------------------------------
# COUNTERS + CORE HELPERS (argv-based — see safety note in the header)
# ---------------------------------------------------------------------------
TOTAL=0; OK=0; FAIL=0; SKIP=0
declare -a FAILED_STEPS=()
declare -a SKIPPED_STEPS=()

step() {
  # step "N" "Name" actual_command arg1 arg2 ...
  local num="$1" name="$2"; shift 2
  local logfile="$LOGDIR/$(echo "$name" | tr ' /()$:#' '______').log"
  TOTAL=$((TOTAL+1))
  echo -ne "${BOLD}[$num] $name ... ${NC}"
  ( "$@" ) >"$logfile" 2>&1
  local rc=$?
  if [ $rc -eq 0 ]; then
    echo -e "${GREEN}done${NC}"; OK=$((OK+1))
  else
    echo -e "${RED}error (non-fatal, continuing — see $logfile)${NC}"
    FAIL=$((FAIL+1)); FAILED_STEPS+=("$name")
  fi
}

need() {
  local tool="$1" hint="${2:-}"
  if command -v "$tool" >/dev/null 2>&1; then return 0; fi
  if [ -n "$hint" ]; then
    echo -e "${YELLOW}[SKIP] $tool not installed — install: $hint${NC}"
  else
    echo -e "${YELLOW}[SKIP] $tool not installed${NC}"
  fi
  SKIP=$((SKIP+1)); SKIPPED_STEPS+=("$tool (not installed)")
  return 1
}

count_lines() { [ -f "$1" ] && wc -l < "$1" | tr -d ' ' || echo 0; }
have_data() { [ -s "$1" ]; }

# Heuristic prioritization: this is plain pattern-matching on PARAMETER NAMES
# commonly associated with each vuln class (id=, file=, redirect=, cmd=, etc).
# It only decides ORDER -- which candidates get tested first within the --max
# cap. It is not an AI judgment and never claims a URL IS vulnerable.
prioritize() {
  local infile="$1" pattern="$2" outfile="$3"
  if ! have_data "$infile"; then : > "$outfile"; return; fi
  { grep -Ei "$pattern" "$infile" 2>/dev/null; grep -Eiv "$pattern" "$infile" 2>/dev/null; } \
    | awk '!seen[$0]++' > "$outfile"
}
SQLI_HOT='[?&](id|uid|pid|item|product|cat|page|user|acct|account|num|order|key|search|q|query|sort)='
XSS_HOT='[?&](q|s|search|query|name|comment|message|text|input|keyword|redirect|callback|ref|url)='
LFI_HOT='[?&](file|page|path|dir|include|template|doc|folder|load|read|view|lang)='
RCE_HOT='[?&](cmd|exec|command|run|ping|proc|system|shell|host|ip)='
REDIRECT_HOT='[?&](redirect|url|next|return|dest|continue|target|rurl|out|view|navigate|to)='

ssrf_probe_via_interactsh() {
  local iclog="$OUT/ssrf/interactsh_session.log"
  interactsh-client -v > "$iclog" 2>&1 &
  local icpid=$!
  sleep 6
  local icdomain
  icdomain=$(grep -oE '[a-z0-9]+\.(oast\.[a-z]+|interact\.sh)' "$iclog" | head -1)
  if [ -z "$icdomain" ]; then
    kill "$icpid" 2>/dev/null
    echo "Could not obtain an interactsh OOB domain." >&2
    return 1
  fi
  echo "Using OOB domain: $icdomain" >> "$iclog"
  local n=0
  while read -r u && [ "$n" -lt "$MAXCAND" ]; do
    n=$((n+1))
    local probe
    probe=$(printf '%s' "$u" | sed -E "s#=[^&]*#=http://$icdomain/ssrf-probe-$n#1")
    curl -s -o /dev/null -m 10 "$probe" 2>/dev/null
  done < "$SSRF_CANDIDATES"
  sleep 25
  kill "$icpid" 2>/dev/null
  cp "$iclog" "$OUT/ssrf/interactsh_log.txt" 2>/dev/null
  if grep -qi "received" "$iclog" 2>/dev/null; then
    echo -e "${RED}!!! Possible OOB interaction logged — check $OUT/ssrf/interactsh_log.txt manually !!!${NC}"
  fi
}

ai_triage_deepscan() {
  local summary_input="$AI_DIR/_combined_summary.txt"
  {
    echo "DOMAIN: $DOMAIN_GUESS"
    echo "== sqlmap output (head) =="; find "$OUT/sqli" -name "*.csv" -o -name "log*" 2>/dev/null | head -5
    echo "== dalfox/xsstrike/xsser findings =="; cat "$OUT"/xss/*.txt 2>/dev/null | head -c 3000
    echo "== open redirect findings =="; cat "$OUT"/redirect/*.txt 2>/dev/null | head -c 2000
    echo "== commix findings =="; find "$OUT/rce" -type d 2>/dev/null | head -10
    echo "== CORS/CRLF =="; cat "$OUT"/cors_crlf/*.log 2>/dev/null | head -c 2000
    echo "== exposed .git hosts =="; cat "$OUT/git_exposure/exposed_hosts.txt" 2>/dev/null
    echo "== extended nuclei =="; cat "$OUT"/nuclei_extended/*.txt 2>/dev/null | head -c 4000
    echo "== CMS scan =="; cat "$OUT"/cms_scan/*.txt 2>/dev/null | head -c 2000
  } > "$summary_input"

  local prompt
  prompt=$(printf 'You are helping a human bug bounty researcher TRIAGE active-scan output they already legally collected for %s. Do not invent findings not present in the data. Produce a short, prioritized list (most-worth-checking-first) of what a human should manually verify next, and briefly explain why. Mark everything as "needs manual verification" -- never claim something is confirmed exploitable. End with a one-paragraph overall risk summary.\n\nDATA:\n%s' "$DOMAIN_GUESS" "$(cat "$summary_input")")
  local payload
  payload=$(jq -n --arg p "$prompt" '{model:"deepseek-chat", messages:[{role:"user", content:$p}], temperature:0.3, max_tokens:1500}')
  curl -s https://api.deepseek.com/chat/completions \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $DEEPSEEK_API_KEY" \
    -d "$payload" | jq -r '.choices[0].message.content // "AI triage request failed — check API key/quota."' \
    > "$AI_DIR/ai_triage_report.md"
}

# ---------------------------------------------------------------------------
# EXPLICIT MAPPING TABLE (candidate file -> tool), printed + saved
# ---------------------------------------------------------------------------
echo -e "\n${BOLD}===== CANDIDATE FILE -> TOOL MAPPING =====${NC}"
{
printf "%-42s -> %s\n" "08_params/gf_patterns/sqli.txt"        "sqlmap, ghauri"
printf "%-42s -> %s\n" "08_params/gf_patterns/xss.txt"         "dalfox, xsstrike, xsser"
printf "%-42s -> %s\n" "08_params/gf_patterns/ssrf.txt"        "interactsh (OOB probe)"
printf "%-42s -> %s\n" "08_params/gf_patterns/redirect.txt"    "openredirex, oralyzer"
printf "%-42s -> %s\n" "08_params/gf_patterns/lfi.txt"         "ffuf + LFI payload wordlist"
printf "%-42s -> %s\n" "08_params/gf_patterns/rce.txt"         "commix"
printf "%-42s -> %s\n" "04_probe_tech/live_hosts.txt"          "corsy, crlfuzz, ffuf (dirfuzz), nuclei (extended)"
printf "%-42s -> %s\n" "04_probe_tech/httpx+whatweb (tech)"    "CMS match -> wpscan / joomscan / droopescan"
printf "%-42s -> %s\n" "04_probe_tech/live_hosts.txt"          ".git exposure check -> git-dumper"
} | tee "$OUT/MAPPING_TABLE.txt"

###############################################################################
# SQLi — sqlmap / ghauri
###############################################################################
echo -e "\n${MAGENTA}===== SQLi — sqlmap / ghauri =====${NC}\n"
prioritize "$SQLI_CANDIDATES" "$SQLI_HOT" "$OUT/sqli/prioritized.txt"
echo -e "${CYAN}-> $(count_lines "$OUT/sqli/prioritized.txt") sqli candidates (testing up to $MAXCAND)${NC}"
if have_data "$OUT/sqli/prioritized.txt"; then
  if need sqlmap "sudo apt install -y sqlmap"; then
    N=0
    while read -r u && [ "$N" -lt "$MAXCAND" ]; do
      N=$((N+1))
      step "SQLi.$N" "sqlmap -> candidate #$N" \
        timeout 300 sqlmap -u "$u" --batch --level=1 --risk=1 --random-agent --output-dir="$OUT/sqli/sqlmap/"
    done < "$OUT/sqli/prioritized.txt"
  fi
  if need ghauri "pip3 install --user --break-system-packages ghauri"; then
    N=0
    while read -r u && [ "$N" -lt 5 ]; do
      N=$((N+1))
      step "SQLi.ghauri.$N" "ghauri -> candidate #$N" \
        timeout 180 ghauri -u "$u" --batch
    done < "$OUT/sqli/prioritized.txt"
  fi
else
  echo -e "${YELLOW}No SQLi candidates in gf_patterns/sqli.txt — nothing to test.${NC}"
fi

###############################################################################
# XSS — dalfox / xsstrike / xsser
###############################################################################
echo -e "\n${MAGENTA}===== XSS — dalfox / xsstrike / xsser =====${NC}\n"
prioritize "$XSS_CANDIDATES" "$XSS_HOT" "$OUT/xss/prioritized.txt"
echo -e "${CYAN}-> $(count_lines "$OUT/xss/prioritized.txt") xss candidates${NC}"
if have_data "$OUT/xss/prioritized.txt"; then
  if need dalfox "go install -v github.com/hahwul/dalfox/v2@latest"; then
    step "XSS.dalfox" "dalfox (batch file scan)" \
      timeout 600 dalfox file "$OUT/xss/prioritized.txt" --silence -o "$OUT/xss/dalfox_results.txt"
  fi
  if need xsstrike "pip3 install --user --break-system-packages git+https://github.com/s0md3v/XSStrike.git"; then
    N=0
    while read -r u && [ "$N" -lt "$MAXCAND" ]; do
      N=$((N+1))
      step "XSS.xsstrike.$N" "xsstrike -> candidate #$N" \
        timeout 180 xsstrike.py -u "$u"
    done < "$OUT/xss/prioritized.txt"
  fi
  if need xsser "sudo apt install -y xsser"; then
    N=0
    while read -r u && [ "$N" -lt "$MAXCAND" ]; do
      N=$((N+1))
      step "XSS.xsser.$N" "xsser -> candidate #$N" \
        timeout 180 xsser --url "$u" --auto
    done < "$OUT/xss/prioritized.txt"
  fi
else
  echo -e "${YELLOW}No XSS candidates — nothing to test.${NC}"
fi

###############################################################################
# SSRF — interactsh OOB probe
###############################################################################
echo -e "\n${MAGENTA}===== SSRF — interactsh OOB probe =====${NC}\n"
if have_data "$SSRF_CANDIDATES" && need interactsh-client "go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"; then
  step "SSRF.1" "interactsh listener + probe" ssrf_probe_via_interactsh
else
  echo -e "${YELLOW}No SSRF candidates, or interactsh-client missing — skipping.${NC}"
fi

###############################################################################
# OPEN REDIRECT — openredirex / oralyzer
###############################################################################
echo -e "\n${MAGENTA}===== OPEN REDIRECT — openredirex / oralyzer =====${NC}\n"
prioritize "$REDIRECT_CANDIDATES" "$REDIRECT_HOT" "$OUT/redirect/prioritized.txt"
if have_data "$OUT/redirect/prioritized.txt"; then
  if need openredirex "pip3 install --user --break-system-packages git+https://github.com/devanshbatham/OpenRedireX.git"; then
    step "Redirect.openredirex" "openredirex (batch)" \
      timeout 300 openredirex.py -l "$OUT/redirect/prioritized.txt" -k
  fi
  if need oralyzer "pip3 install --user --break-system-packages oralyzer"; then
    N=0
    while read -r u && [ "$N" -lt "$MAXCAND" ]; do
      N=$((N+1))
      step "Redirect.oralyzer.$N" "oralyzer -> candidate #$N" \
        timeout 120 oralyzer -u "$u"
    done < "$OUT/redirect/prioritized.txt"
  fi
else
  echo -e "${YELLOW}No open-redirect candidates — nothing to test.${NC}"
fi

###############################################################################
# LFI — ffuf + payload wordlist
###############################################################################
echo -e "\n${MAGENTA}===== LFI — ffuf + payload wordlist =====${NC}\n"
prioritize "$LFI_CANDIDATES" "$LFI_HOT" "$OUT/lfi/prioritized.txt"
if have_data "$OUT/lfi/prioritized.txt" && need ffuf "go install -v github.com/ffuf/ffuf/v2@latest"; then
  LFI_WORDLIST="/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt"
  [ -f "$LFI_WORDLIST" ] || LFI_WORDLIST="/usr/share/wordlists/wfuzz/Injections/Traversal.txt"
  if [ -f "$LFI_WORDLIST" ]; then
    N=0
    while read -r u && [ "$N" -lt "$MAXCAND" ]; do
      N=$((N+1))
      fuzz_url=$(printf '%s' "$u" | sed -E 's#=[^&]*$#=FUZZ#')
      step "LFI.$N" "ffuf LFI -> candidate #$N" \
        timeout 180 ffuf -u "$fuzz_url" -w "$LFI_WORDLIST" -mc 200 -t 20 -silent -o "$OUT/lfi/ffuf_$N.json" -of json
    done < "$OUT/lfi/prioritized.txt"
  else
    echo -e "${YELLOW}No LFI wordlist found (apt install seclists) — skipping.${NC}"
  fi
else
  echo -e "${YELLOW}No LFI candidates, or ffuf missing — skipping.${NC}"
fi

###############################################################################
# RCE / COMMAND INJECTION — commix
###############################################################################
echo -e "\n${MAGENTA}===== RCE / Command Injection — commix =====${NC}\n"
prioritize "$RCE_CANDIDATES" "$RCE_HOT" "$OUT/rce/prioritized.txt"
if have_data "$OUT/rce/prioritized.txt" && need commix "pip3 install --user --break-system-packages commix"; then
  N=0
  while read -r u && [ "$N" -lt "$MAXCAND" ]; do
    N=$((N+1))
    step "RCE.$N" "commix -> candidate #$N" \
      timeout 180 commix --url="$u" --batch --output-dir="$OUT/rce/commix_$N/"
  done < "$OUT/rce/prioritized.txt"
else
  echo -e "${YELLOW}No RCE candidates, or commix missing — skipping.${NC}"
fi

###############################################################################
# CORS / CRLF — across live hosts
###############################################################################
echo -e "\n${MAGENTA}===== CORS / CRLF — corsy / crlfuzz (live hosts) =====${NC}\n"
if have_data "$LIVE_HOSTS"; then
  N=0
  while read -r h && [ "$N" -lt "$MAXHOSTS" ]; do
    N=$((N+1))
    hu="$h"; case "$hu" in http*) ;; *) hu="https://$hu" ;; esac
    if need corsy "pip3 install --user --break-system-packages git+https://github.com/s0md3v/Corsy.git"; then
      step "CORS.$N" "corsy -> $h" timeout 60 corsy.py -u "$hu"
    fi
    if need crlfuzz "go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"; then
      step "CRLF.$N" "crlfuzz -> $h" timeout 60 crlfuzz -u "$hu" -s
    fi
  done < "$LIVE_HOSTS"
else
  echo -e "${YELLOW}No live_hosts.txt found — run ftrecon.sh first.${NC}"
fi

###############################################################################
# DIRECTORY FUZZING — ffuf across multiple live hosts
###############################################################################
echo -e "\n${MAGENTA}===== DIRECTORY FUZZING — ffuf across live hosts =====${NC}\n"
WORDLIST="${CUSTOM_WORDLIST:-/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt}"
[ -f "$WORDLIST" ] || WORDLIST="/usr/share/wordlists/dirb/common.txt"
if have_data "$LIVE_HOSTS" && [ -f "$WORDLIST" ] && need ffuf; then
  N=0
  while read -r h && [ "$N" -lt "$MAXHOSTS" ]; do
    N=$((N+1))
    hu="$h"; case "$hu" in http*) ;; *) hu="https://$hu" ;; esac
    step "Dirfuzz.$N" "ffuf dir brute -> $h" \
      timeout 300 ffuf -u "$hu/FUZZ" -w "$WORDLIST" -mc 200,301,302,403 -t 40 -silent \
        -o "$OUT/dirfuzz_all_hosts/host_$N.json" -of json
  done < "$LIVE_HOSTS"
else
  echo -e "${YELLOW}Skipping (no live hosts, no wordlist, or ffuf missing).${NC}"
fi

###############################################################################
# CMS-CONDITIONAL SCAN — detect from existing tech fingerprint, then dispatch
###############################################################################
echo -e "\n${MAGENTA}===== CMS-CONDITIONAL SCAN =====${NC}\n"
TECH_BLOB=$(cat "$PROBE_DIR/httpx_live.txt" "$PROBE_DIR/whatweb.txt" 2>/dev/null)
if echo "$TECH_BLOB" | grep -qi wordpress; then
  echo -e "${CYAN}-> WordPress fingerprint detected in 04_probe_tech${NC}"
  need wpscan "pip3 install --user --break-system-packages wpscan" && \
    step "CMS.wordpress" "wpscan" \
      timeout 300 wpscan --url "$URL" --enumerate vp,vt,u --random-user-agent --no-banner
elif echo "$TECH_BLOB" | grep -qi joomla; then
  echo -e "${CYAN}-> Joomla fingerprint detected${NC}"
  need joomscan "sudo apt install -y joomscan" && \
    step "CMS.joomla" "joomscan" timeout 300 joomscan -u "$URL"
elif echo "$TECH_BLOB" | grep -qi drupal; then
  echo -e "${CYAN}-> Drupal fingerprint detected${NC}"
  need droopescan "pip3 install --user --break-system-packages droopescan" && \
    step "CMS.drupal" "droopescan" timeout 300 droopescan scan drupal -u "$URL"
else
  echo -e "${YELLOW}No known CMS fingerprinted in 04_probe_tech — skipping CMS-specific scan.${NC}"
fi

###############################################################################
# EXPOSED .git CHECK -> git-dumper
###############################################################################
echo -e "\n${MAGENTA}===== EXPOSED .git CHECK =====${NC}\n"
GIT_HITS="$OUT/git_exposure/exposed_hosts.txt"
: > "$GIT_HITS"
if have_data "$LIVE_HOSTS"; then
  while read -r h; do
    hu="$h"; case "$hu" in http*) ;; *) hu="https://$hu" ;; esac
    code=$(curl -s -o /dev/null -w "%{http_code}" -m 8 "$hu/.git/HEAD" 2>/dev/null)
    [ "$code" = "200" ] && echo "$hu" >> "$GIT_HITS"
  done < "$LIVE_HOSTS"
fi
if have_data "$GIT_HITS"; then
  echo -e "${RED}-> Exposed .git found on $(count_lines "$GIT_HITS") host(s)!${NC}"
  if need git-dumper "git clone https://github.com/arthaud/git-dumper && pip3 install --user --break-system-packages -r git-dumper/requirements.txt"; then
    N=0
    while read -r hu && [ "$N" -lt 5 ]; do
      N=$((N+1))
      step "GitExposure.$N" "git-dumper -> $hu" \
        timeout 180 git-dumper "$hu/.git" "$OUT/git_exposure/dump_$N/"
    done < "$GIT_HITS"
  fi
else
  echo -e "${CYAN}-> No exposed .git directories found.${NC}"
fi

###############################################################################
# EXTENDED NUCLEI — exposures / misconfig / cves / fuzz tags
###############################################################################
echo -e "\n${MAGENTA}===== EXTENDED NUCLEI =====${NC}\n"
if have_data "$LIVE_HOSTS" && need nuclei "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"; then
  step "Nuclei.exposures"   "nuclei -t exposures/"        nuclei -l "$LIVE_HOSTS" -t exposures/ -silent -o "$OUT/nuclei_extended/exposures.txt"
  step "Nuclei.misconfig"   "nuclei -t misconfiguration/" nuclei -l "$LIVE_HOSTS" -t misconfiguration/ -silent -o "$OUT/nuclei_extended/misconfig.txt"
  step "Nuclei.cves"        "nuclei -t cves/ (crit/high)"  nuclei -l "$LIVE_HOSTS" -t cves/ -severity critical,high -silent -o "$OUT/nuclei_extended/cves.txt"
  step "Nuclei.fuzz"        "nuclei -tags fuzz"            nuclei -l "$LIVE_HOSTS" -tags fuzz -silent -o "$OUT/nuclei_extended/fuzzing.txt"
else
  echo -e "${YELLOW}Skipping (no live hosts, or nuclei missing).${NC}"
fi

###############################################################################
# AI-ASSISTED TRIAGE (optional, needs DEEPSEEK_API_KEY)
###############################################################################
echo -e "\n${MAGENTA}===== AI-ASSISTED TRIAGE (optional) =====${NC}\n"
if [ -n "${DEEPSEEK_API_KEY:-}" ] && need jq && need curl; then
  step "AI.1" "DeepSeek deep-scan triage" ai_triage_deepscan
else
  echo -e "${YELLOW}DEEPSEEK_API_KEY not set (or jq/curl missing) — skipping optional AI triage.${NC}"
  echo -e "${YELLOW}This step would only SUMMARIZE the findings above for manual review.${NC}"
fi

###############################################################################
# FINAL REPORT
###############################################################################
echo -e "\n${MAGENTA}===== FINAL REPORT =====${NC}\n"
{
echo "========================================================================"
echo " FTSCAN REPORT — $DOMAIN_GUESS"
echo " Results folder : $RESULTS_DIR"
echo " Generated      : $(date)"
echo " made by BLOODRAVENIST"
echo "========================================================================"
echo ""
echo "Steps run        : $TOTAL"
echo "Succeeded        : $OK"
echo "Non-fatal errors : $FAIL"
echo "Skipped          : $SKIP"
echo ""
echo "WHERE TO LOOK FIRST"
echo "  Exposed .git hosts         : $(count_lines "$GIT_HITS")"
echo "  Extended nuclei findings   : $(cat "$OUT"/nuclei_extended/*.txt 2>/dev/null | wc -l | tr -d ' ')"
echo "  sqlmap / ghauri output     : $OUT/sqli/  (and _logs/SQLi.*.log)"
echo "  dalfox / xsstrike / xsser  : $OUT/xss/   (and _logs/XSS.*.log)"
echo "  SSRF OOB session log       : $OUT/ssrf/interactsh_log.txt"
echo "  CORS/CRLF per-host logs    : _logs/CORS.*.log, _logs/CRLF.*.log"
echo "  Directory fuzzing results  : $OUT/dirfuzz_all_hosts/host_*.json"
echo ""
if [ ${#FAILED_STEPS[@]} -gt 0 ]; then
  echo "NON-FATAL ERRORS (full output in _logs/<name>.log):"
  for s in "${FAILED_STEPS[@]}"; do echo "  - $s"; done
  echo ""
fi
if [ ${#SKIPPED_STEPS[@]} -gt 0 ]; then
  echo "SKIPPED (install hints were printed above when this ran):"
  for s in "${SKIPPED_STEPS[@]}"; do echo "  - $s"; done
  echo ""
fi
echo "Every result here is a LEAD for manual verification, not a confirmed"
echo "finding -- sqlmap/dalfox/etc. still produce false positives. Verify by"
echo "hand before writing up a report."
echo "========================================================================"
} | tee "$RESULTS_DIR/FTSCAN_REPORT.md"

echo -e "\n${BOLD}${GREEN}Directory structure:${NC}"
if command -v tree >/dev/null 2>&1; then
  tree -L 2 "$OUT"
else
  find "$OUT" -maxdepth 2 | sort
fi

echo -e "\n${BOLD}${GREEN}Deep scan output :${NC} $OUT"
echo -e "${BOLD}${GREEN}Master report    :${NC} $RESULTS_DIR/FTSCAN_REPORT.md"
