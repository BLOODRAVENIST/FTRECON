#!/usr/bin/env bash
###############################################################################
#  FTRECON — Automated Recon + VAPT Pipeline
#  made by BLOODRAVENIST
#
#  Usage:
#     ./ftrecon.sh <domain> [--active] [--fast] [--yes]
#
#     <domain>   target, e.g. example.com (http://, https://, trailing paths
#                are stripped automatically)
#     --active   ALSO run SQLi (sqlmap) + XSS (dalfox) ACTIVE validation
#                against candidate parameters found in recon. OFF by default.
#     --fast     skip the slower steps (deep crawl, directory brute force)
#     --yes      skip the interactive authorization confirmation prompt
#
#  Requires: run install_bugbounty_tools.sh first. Missing tools are skipped
#  gracefully (never crash the run) and listed in the final report.
#
#  Optional AI triage: export DEEPSEEK_API_KEY="sk-..." before running to get
#  an AI-generated, human-readable PRIORITIZATION of findings for manual
#  review. This step only summarizes data already collected — it never
#  generates or executes payloads.
###############################################################################

set -u
set -o pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; NC='\033[0m'

# ---------------------------------------------------------------------------
# BANNER
# ---------------------------------------------------------------------------
banner() {
  if command -v figlet >/dev/null 2>&1; then
    figlet -f slant "FTRECON" 2>/dev/null
  else
    echo "==========================================="
    echo "                F T R E C O N               "
    echo "==========================================="
  fi
  echo -e "${CYAN}   Automated Recon + VAPT  ·  made by BLOODRAVENIST${NC}"
}

usage() {
  echo "Usage: $0 <domain> [--active] [--fast] [--yes]"
  echo ""
  echo "  <domain>   target domain, e.g. example.com"
  echo "  --active   also run SQLi (sqlmap) + XSS (dalfox) ACTIVE validation"
  echo "             (off by default — only use on authorized targets)"
  echo "  --fast     skip slow steps (deep crawl, directory brute force)"
  echo "  --yes      skip the interactive authorization confirmation"
  exit 1
}

[ $# -lt 1 ] && usage

RAW_TARGET="$1"; shift
ACTIVE=false
FAST=false
AUTO_YES=false
for arg in "$@"; do
  case "$arg" in
    --active) ACTIVE=true ;;
    --fast) FAST=true ;;
    --yes) AUTO_YES=true ;;
    *) echo "Unknown option: $arg"; usage ;;
  esac
done

# ---------------------------------------------------------------------------
# NORMALIZE + VALIDATE TARGET  (also blocks shell metacharacters -> no injection)
# ---------------------------------------------------------------------------
DOMAIN=$(echo "$RAW_TARGET" | sed -E 's#^https?://##; s#/.*$##; s#:.*$##' | tr '[:upper:]' '[:lower:]')
URL="https://$DOMAIN"

if ! [[ "$DOMAIN" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$ ]]; then
  echo -e "${RED}[FATAL] '$RAW_TARGET' doesn't look like a valid domain. Example: example.com${NC}"
  exit 1
fi

banner
echo -e "${CYAN}Target        : $DOMAIN${NC}"
echo -e "${CYAN}Active phase  : $ACTIVE${NC}"
echo -e "${CYAN}Fast mode     : $FAST${NC}"
echo -e "${CYAN}Started       : $(date)${NC}"
echo "---------------------------------------------------------------"

if [ "$AUTO_YES" = false ]; then
  echo -e "${YELLOW}This actively scans $DOMAIN. Only run it against a domain you own,"
  echo -e "or are explicitly authorized to test (bug bounty scope / written pentest"
  echo -e "authorization / your own lab). Type the domain again to confirm:${NC}"
  read -r CONFIRM
  if [ "$CONFIRM" != "$DOMAIN" ]; then
    echo -e "${RED}Confirmation didn't match '$DOMAIN'. Exiting without scanning.${NC}"
    exit 1
  fi
fi

# ---------------------------------------------------------------------------
# OUTPUT TREE
# ---------------------------------------------------------------------------
BASE="$HOME/INFORMATION_GATHERING/ftrecon_results"
TS=$(date +%Y%m%d_%H%M%S)
OUTDIR="$BASE/${DOMAIN}_${TS}"
LOGDIR="$OUTDIR/_logs"

SUBS_DIR="$OUTDIR/01_subdomains"
DNS_DIR="$OUTDIR/02_dns"
PORTS_DIR="$OUTDIR/03_ports"
PROBE_DIR="$OUTDIR/04_probe_tech"
SHOTS_DIR="$OUTDIR/05_screenshots"
URLS_DIR="$OUTDIR/06_urls"
CONTENT_DIR="$OUTDIR/07_content_discovery"
PARAMS_DIR="$OUTDIR/08_params"
VULN_DIR="$OUTDIR/09_vuln_scan"
TAKEOVER_DIR="$OUTDIR/10_takeover"
ACTIVE_DIR="$OUTDIR/11_active_testing"
AI_DIR="$OUTDIR/12_ai_triage"

mkdir -p "$SUBS_DIR" "$DNS_DIR" "$PORTS_DIR" "$PROBE_DIR" "$SHOTS_DIR" \
         "$URLS_DIR" "$CONTENT_DIR" "$PARAMS_DIR/gf_patterns" "$VULN_DIR" \
         "$TAKEOVER_DIR" "$ACTIVE_DIR/sqlmap" "$ACTIVE_DIR/dalfox" \
         "$AI_DIR" "$LOGDIR"

trap 'echo -e "\n${YELLOW}Interrupted — partial results are saved in $OUTDIR${NC}"; exit 130' INT

# Cross-phase file handles (always absolute -> no relative-path bugs)
ALL_SUBS="$SUBS_DIR/all_subdomains.txt"
LIVE_HOSTS="$PROBE_DIR/live_hosts.txt"
ALL_URLS="$URLS_DIR/all_urls_clean.txt"
SQLI_CANDIDATES="$PARAMS_DIR/gf_patterns/sqli.txt"
XSS_CANDIDATES="$PARAMS_DIR/gf_patterns/xss.txt"

# ---------------------------------------------------------------------------
# COUNTERS + CORE HELPERS
# ---------------------------------------------------------------------------
TOTAL=0; OK=0; FAIL=0; SKIP=0
declare -a FAILED_STEPS=()
declare -a SKIPPED_STEPS=()

step() {
  # step "N" "Name" "command"  -- for STATIC commands only (no crawled/untrusted
  # data embedded in the string). Uses eval, so never pass $u/$h-style candidate
  # URLs through this one -- use step_argv below for those.
  local num="$1" name="$2" cmd="$3"
  local logfile="$LOGDIR/$(echo "$name" | tr ' /()' '____').log"
  TOTAL=$((TOTAL+1))
  echo -ne "${BOLD}[$num] $name ... ${NC}"
  ( eval "$cmd" ) >"$logfile" 2>&1
  local rc=$?
  if [ $rc -eq 0 ]; then
    echo -e "${GREEN}done${NC}"
    OK=$((OK+1))
  else
    echo -e "${RED}error (non-fatal, continuing — see $logfile)${NC}"
    FAIL=$((FAIL+1))
    FAILED_STEPS+=("$name")
  fi
}

step_argv() {
  # step_argv "N" "Name" actual_command arg1 arg2 ...  -- SAFE for candidate
  # URLs pulled from crawled/archived data (gau/waybackurls/katana). No eval:
  # each argument is passed through exactly as-is, so a URL containing quotes,
  # backticks, $(), or semicolons can never break out of the intended command.
  local num="$1" name="$2"; shift 2
  local logfile="$LOGDIR/$(echo "$name" | tr ' /()' '____').log"
  TOTAL=$((TOTAL+1))
  echo -ne "${BOLD}[$num] $name ... ${NC}"
  ( "$@" ) >"$logfile" 2>&1
  local rc=$?
  if [ $rc -eq 0 ]; then
    echo -e "${GREEN}done${NC}"
    OK=$((OK+1))
  else
    echo -e "${RED}error (non-fatal, continuing — see $logfile)${NC}"
    FAIL=$((FAIL+1))
    FAILED_STEPS+=("$name")
  fi
}

need() {
  if command -v "$1" >/dev/null 2>&1; then
    return 0
  else
    echo -e "${YELLOW}[SKIP] $1 not installed — run install_bugbounty_tools.sh first${NC}"
    SKIP=$((SKIP+1))
    SKIPPED_STEPS+=("$1 (not installed)")
    return 1
  fi
}

count_lines() {
  if [ -f "$1" ]; then wc -l < "$1" | tr -d ' '; else echo 0; fi
}

run_ai_triage() {
  local summary_input="$AI_DIR/_combined_summary.txt"
  {
    echo "DOMAIN: $DOMAIN"
    echo ""
    echo "== Subdomains found =="; count_lines "$ALL_SUBS"
    echo ""
    echo "== Live hosts (httpx) =="; head -c 4000 "$PROBE_DIR/httpx_live.txt" 2>/dev/null
    echo ""
    echo "== Nuclei findings =="; head -c 6000 "$VULN_DIR/nuclei_results.txt" 2>/dev/null
    echo ""
    echo "== Nikto findings =="; head -c 3000 "$VULN_DIR/nikto.txt" 2>/dev/null
    echo ""
    echo "== Candidate SQLi-pattern URLs =="; head -c 2000 "$SQLI_CANDIDATES" 2>/dev/null
    echo ""
    echo "== Candidate XSS-pattern URLs =="; head -c 2000 "$XSS_CANDIDATES" 2>/dev/null
    echo ""
    echo "== Subdomain takeover checks =="; head -c 2000 "$TAKEOVER_DIR/subzy.txt" 2>/dev/null
  } > "$summary_input"

  local prompt
  prompt=$(printf 'You are helping a human bug bounty researcher TRIAGE recon/scan data they already legally collected for %s. Do not invent findings not present in the data. Produce a short, prioritized list (most-worth-checking-first) of what a human should manually verify next, and briefly explain why each item looks interesting. Mark everything as "needs manual verification" — never claim something is confirmed exploitable. End with a one-paragraph overall risk summary.\n\nDATA:\n%s' "$DOMAIN" "$(cat "$summary_input")")

  local payload
  payload=$(jq -n --arg p "$prompt" '{model:"deepseek-chat", messages:[{role:"user", content:$p}], temperature:0.3, max_tokens:1500}')

  curl -s https://api.deepseek.com/chat/completions \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $DEEPSEEK_API_KEY" \
    -d "$payload" | jq -r '.choices[0].message.content // "AI triage request failed — check API key/quota in the raw response below."' \
    > "$AI_DIR/ai_triage_report.md"
}

###############################################################################
# PHASE 1/12 — SUBDOMAIN ENUMERATION
###############################################################################
echo -e "\n${MAGENTA}===== PHASE 1/12 — SUBDOMAIN ENUMERATION =====${NC}\n"
cd "$SUBS_DIR" || true

need subfinder && step "1.1" "subfinder" "subfinder -d $DOMAIN -all -silent -o subfinder.txt"
need assetfinder && step "1.2" "assetfinder" "assetfinder --subs-only $DOMAIN > assetfinder.txt"
step "1.3" "crt.sh" "curl -s 'https://crt.sh/?q=%25.$DOMAIN&output=json' | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' > crtsh.txt"
need findomain && step "1.4" "findomain" "findomain -t $DOMAIN -q -u findomain.txt"
need amass && step "1.5" "amass (passive)" "timeout 180 amass enum -passive -d $DOMAIN -timeout 3 -o amass.txt"

cat "$SUBS_DIR"/subfinder.txt "$SUBS_DIR"/assetfinder.txt "$SUBS_DIR"/crtsh.txt \
    "$SUBS_DIR"/findomain.txt "$SUBS_DIR"/amass.txt 2>/dev/null | sed '/^$/d' | sort -u > "$ALL_SUBS"
echo "$DOMAIN" >> "$ALL_SUBS"
sort -u -o "$ALL_SUBS" "$ALL_SUBS"
echo -e "${CYAN}-> $(count_lines "$ALL_SUBS") unique subdomains collected${NC}"

###############################################################################
# PHASE 2/12 — DNS RECON
###############################################################################
echo -e "\n${MAGENTA}===== PHASE 2/12 — DNS RECON =====${NC}\n"
cd "$DNS_DIR" || true

need whois && step "2.1" "whois" "whois $DOMAIN > whois.txt"
need dig && step "2.2" "dig ANY" "dig +short ANY $DOMAIN > dig_any.txt"
need dnsx && step "2.3" "dnsx (resolve subdomains)" "dnsx -l $ALL_SUBS -a -resp -silent -o resolved.txt"

###############################################################################
# PHASE 3/12 — PORT SCANNING
###############################################################################
echo -e "\n${MAGENTA}===== PHASE 3/12 — PORT SCANNING =====${NC}\n"
cd "$PORTS_DIR" || true

need naabu && step "3.1" "naabu (top 1000 ports)" \
"naabu -list $DNS_DIR/resolved.txt -top-ports 1000 -silent -o naabu.txt 2>/dev/null || naabu -host $DOMAIN -top-ports 1000 -silent -o naabu.txt"

###############################################################################
# PHASE 4/12 — HTTP PROBE + TECH FINGERPRINT + WAF
###############################################################################
echo -e "\n${MAGENTA}===== PHASE 4/12 — HTTP PROBE + TECH FINGERPRINT =====${NC}\n"
cd "$PROBE_DIR" || true

need httpx && step "4.1" "httpx probe" "httpx -l $ALL_SUBS -silent -title -tech-detect -status-code -o httpx_live.txt"
need whatweb && step "4.2" "whatweb" "whatweb -a 3 $URL > whatweb.txt"
need wafw00f && step "4.3" "wafw00f" "wafw00f $URL > wafw00f.txt"

awk '{print $1}' "$PROBE_DIR/httpx_live.txt" 2>/dev/null > "$LIVE_HOSTS"
echo -e "${CYAN}-> $(count_lines "$LIVE_HOSTS") live hosts${NC}"

###############################################################################
# PHASE 5/12 — SCREENSHOTS
###############################################################################
echo -e "\n${MAGENTA}===== PHASE 5/12 — SCREENSHOTS =====${NC}\n"
cd "$SHOTS_DIR" || true

need gowitness && step "5.1" "gowitness" \
"gowitness file -f $LIVE_HOSTS -P . --no-http 2>/dev/null || gowitness scan file -f $LIVE_HOSTS -s ."

###############################################################################
# PHASE 6/12 — URL COLLECTION
###############################################################################
echo -e "\n${MAGENTA}===== PHASE 6/12 — URL COLLECTION =====${NC}\n"
cd "$URLS_DIR" || true

need gau && step "6.1" "gau" "gau $DOMAIN --threads 5 > gau.txt"
need waybackurls && step "6.2" "waybackurls" "waybackurls $DOMAIN > waybackurls.txt"
if [ "$FAST" = false ]; then
  need katana && step "6.3" "katana (crawl depth 2)" "katana -u $URL -d 2 -jc -silent -o katana.txt"
else
  echo -e "${YELLOW}[SKIP] katana crawl (--fast mode)${NC}"
fi

cat "$URLS_DIR"/gau.txt "$URLS_DIR"/waybackurls.txt "$URLS_DIR"/katana.txt 2>/dev/null | sed '/^$/d' | sort -u > "$URLS_DIR/all_urls_raw.txt"
if need uro; then
  step "6.4" "uro (dedupe/clean urls)" "cat $URLS_DIR/all_urls_raw.txt | uro -o $ALL_URLS"
fi
[ -s "$ALL_URLS" ] || cp "$URLS_DIR/all_urls_raw.txt" "$ALL_URLS" 2>/dev/null
echo -e "${CYAN}-> $(count_lines "$ALL_URLS") unique URLs collected${NC}"

###############################################################################
# PHASE 7/12 — CONTENT DISCOVERY
###############################################################################
echo -e "\n${MAGENTA}===== PHASE 7/12 — CONTENT DISCOVERY =====${NC}\n"
cd "$CONTENT_DIR" || true

if [ "$FAST" = false ] && need ffuf; then
  WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
  [ -f "$WORDLIST" ] || WORDLIST="/usr/share/wordlists/dirb/common.txt"
  if [ -f "$WORDLIST" ]; then
    step "7.1" "ffuf (dir brute, primary host)" \
    "ffuf -u $URL/FUZZ -w $WORDLIST -mc 200,301,302,403 -t 40 -silent -o ffuf.json -of json"
  else
    echo -e "${YELLOW}[SKIP] ffuf — no wordlist found (install seclists package)${NC}"
  fi
else
  echo -e "${YELLOW}[SKIP] directory brute force (--fast mode or ffuf missing)${NC}"
fi

###############################################################################
# PHASE 8/12 — PARAMETER DISCOVERY + PATTERN TRIAGE
###############################################################################
echo -e "\n${MAGENTA}===== PHASE 8/12 — PARAMETER DISCOVERY + TRIAGE =====${NC}\n"
cd "$PARAMS_DIR" || true

need arjun && step "8.1" "arjun" "arjun -u $URL -oT arjun.txt -t 10"

if need gf; then
  for pattern in xss sqli ssrf redirect lfi rce; do
    step "8.2-$pattern" "gf $pattern triage" \
    "cat $ALL_URLS | gf $pattern 2>/dev/null | sort -u > $PARAMS_DIR/gf_patterns/$pattern.txt"
  done
fi

need kxss && step "8.3" "kxss (reflected param check)" "cat $ALL_URLS | kxss > $PARAMS_DIR/reflected_params.txt"

echo -e "${CYAN}-> $(count_lines "$SQLI_CANDIDATES") sqli-pattern, $(count_lines "$XSS_CANDIDATES") xss-pattern candidate URLs${NC}"

###############################################################################
# PHASE 9/12 — VULNERABILITY SCANNING (NUCLEI + NIKTO)
###############################################################################
echo -e "\n${MAGENTA}===== PHASE 9/12 — VULNERABILITY SCANNING =====${NC}\n"
cd "$VULN_DIR" || true

need nuclei && step "9.1" "nuclei (all live hosts)" "nuclei -l $LIVE_HOSTS -silent -o nuclei_results.txt"
need nikto && step "9.2" "nikto (primary host)" "nikto -h $URL -Tuning 123456789 -o nikto.txt"

CRIT=$(grep -ci '\[critical\]' "$VULN_DIR/nuclei_results.txt" 2>/dev/null); CRIT=${CRIT:-0}
HIGH=$(grep -ci '\[high\]' "$VULN_DIR/nuclei_results.txt" 2>/dev/null); HIGH=${HIGH:-0}
echo -e "${CYAN}-> nuclei: $CRIT critical, $HIGH high severity findings${NC}"

###############################################################################
# PHASE 10/12 — SUBDOMAIN TAKEOVER
###############################################################################
echo -e "\n${MAGENTA}===== PHASE 10/12 — SUBDOMAIN TAKEOVER CHECK =====${NC}\n"
cd "$TAKEOVER_DIR" || true

need subzy && step "10.1" "subzy" "subzy run --targets $ALL_SUBS --hide_fails > subzy.txt"
need nuclei && step "10.2" "nuclei (takeover templates)" "nuclei -l $ALL_SUBS -t http/takeovers/ -silent -o nuclei_takeover.txt"

###############################################################################
# PHASE 11/12 — ACTIVE VALIDATION (off by default — needs --active)
###############################################################################
echo -e "\n${MAGENTA}===== PHASE 11/12 — ACTIVE VALIDATION (SQLi / XSS) =====${NC}\n"
cd "$ACTIVE_DIR" || true

if [ "$ACTIVE" = true ]; then
  if need sqlmap && [ -s "$SQLI_CANDIDATES" ]; then
    N=0
    while read -r u && [ "$N" -lt 15 ]; do
      N=$((N+1))
      # risk=1/level=1 kept deliberately conservative to avoid data-modifying techniques.
      # step_argv (not step/eval): $u came from crawled web data, never shell-reinterpreted.
      step_argv "11.1.$N" "sqlmap -> candidate #$N" \
      timeout 300 sqlmap -u "$u" --batch --level=1 --risk=1 --random-agent --output-dir="$ACTIVE_DIR/sqlmap/"
    done < "$SQLI_CANDIDATES"
  else
    echo -e "${YELLOW}No sqli-pattern candidates to test, or sqlmap missing.${NC}"
  fi

  if need dalfox && [ -s "$XSS_CANDIDATES" ]; then
    step "11.2" "dalfox (batch file scan)" \
    "timeout 600 dalfox file $XSS_CANDIDATES --silence -o $ACTIVE_DIR/dalfox/dalfox_results.txt"
  else
    echo -e "${YELLOW}No xss-pattern candidates to test, or dalfox missing.${NC}"
  fi
else
  echo -e "${YELLOW}[SKIPPED] Active phase is off by default.${NC}"
  echo -e "${YELLOW}Re-run with --active (once authorized) to run sqlmap/dalfox against the${NC}"
  echo -e "${YELLOW}candidates already sitting in 08_params/gf_patterns/.${NC}"
fi

###############################################################################
# PHASE 12/12 — AI-ASSISTED TRIAGE (optional, needs DEEPSEEK_API_KEY)
###############################################################################
echo -e "\n${MAGENTA}===== PHASE 12/12 — AI-ASSISTED TRIAGE (optional) =====${NC}\n"
cd "$AI_DIR" || true

if [ -n "${DEEPSEEK_API_KEY:-}" ]; then
  if need jq && need curl; then
    step "12.1" "DeepSeek triage summary" "run_ai_triage"
  fi
else
  echo -e "${YELLOW}DEEPSEEK_API_KEY not set — skipping AI triage (optional step).${NC}"
  echo -e "${YELLOW}To enable: export DEEPSEEK_API_KEY=\"sk-...\" before running this script.${NC}"
  echo -e "${YELLOW}Note: this sends the recon data already collected above to DeepSeek's API${NC}"
  echo -e "${YELLOW}for a prioritized summary only — it does not generate or run payloads.${NC}"
fi

###############################################################################
# FINAL REPORT
###############################################################################
echo -e "\n${MAGENTA}===== FINAL REPORT =====${NC}\n"
cd "$OUTDIR" || true

{
echo "========================================================================"
echo " FTRECON REPORT — $DOMAIN"
echo " Generated : $(date)"
echo " made by BLOODRAVENIST"
echo "========================================================================"
echo ""
echo "Steps run       : $TOTAL"
echo "Succeeded       : $OK"
echo "Non-fatal errors: $FAIL   (tool ran but returned non-zero — often just 'no results'; check _logs/)"
echo "Skipped         : $SKIP   (tool not installed, or step disabled by mode)"
echo ""
echo "KEY COUNTS"
echo "  Subdomains found        : $(count_lines "$ALL_SUBS")"
echo "  Live hosts               : $(count_lines "$LIVE_HOSTS")"
echo "  URLs collected            : $(count_lines "$ALL_URLS")"
echo "  SQLi-pattern candidates   : $(count_lines "$SQLI_CANDIDATES")"
echo "  XSS-pattern candidates    : $(count_lines "$XSS_CANDIDATES")"
echo "  Nuclei findings total     : $(count_lines "$VULN_DIR/nuclei_results.txt")"
echo "  Nuclei critical / high    : $CRIT / $HIGH"
echo ""
if [ ${#FAILED_STEPS[@]} -gt 0 ]; then
  echo "NON-FATAL ERRORS (full output in _logs/<name>.log):"
  for s in "${FAILED_STEPS[@]}"; do echo "  - $s"; done
  echo ""
fi
if [ ${#SKIPPED_STEPS[@]} -gt 0 ]; then
  echo "SKIPPED STEPS:"
  for s in "${SKIPPED_STEPS[@]}"; do echo "  - $s"; done
  echo ""
fi
echo "RECOMMENDED NEXT STEPS"
echo "  1. Read 09_vuln_scan/nuclei_results.txt and nikto.txt first — highest signal."
echo "  2. Check 10_takeover/ for any subdomain takeover candidates (easy, high-impact)."
echo "  3. Review 08_params/gf_patterns/*.txt for parameters worth manual testing."
if [ "$ACTIVE" = false ]; then
echo "  4. Re-run with --active to validate SQLi/XSS candidates with sqlmap/dalfox."
fi
if [ -f "$AI_DIR/ai_triage_report.md" ]; then
echo "  5. Read 12_ai_triage/ai_triage_report.md for an AI-prioritized summary."
fi
echo "========================================================================"
} | tee "$OUTDIR/FTRECON_REPORT.md"

echo -e "\n${BOLD}${GREEN}Directory structure:${NC}"
if command -v tree >/dev/null 2>&1; then
  tree -L 2 "$OUTDIR"
else
  find "$OUTDIR" -maxdepth 2 | sort
fi

echo -e "\n${BOLD}${GREEN}All output saved to :${NC} $OUTDIR"
echo -e "${BOLD}${GREEN}Master report        :${NC} $OUTDIR/FTRECON_REPORT.md"
