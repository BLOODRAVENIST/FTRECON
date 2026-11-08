<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=900&size=26&duration=2500&pause=600&color=00FF41&center=true&vCenter=true&width=1000&lines=FTRECON;Automated+Recon+%2B+VAPT+Pipeline;118%2B+Tools+%7C+12+Phases+%7C+One+Command" alt="FTRECON" />

# FTRECON
### Automated Recon + VAPT Pipeline — 118+ Tools, 12 Phases, One Command
**Made by [BLOODRAVENIST](https://github.com/BLOODRAVENIST)**
> For Authorized Security Research / Bug Bounty Only

[![Made by BLOODRAVENIST](https://img.shields.io/badge/Made%20by-BLOODRAVENIST-00FF41?style=for-the-badge&logo=github&labelColor=000000)](https://github.com/BLOODRAVENIST)
[![Kali Linux](https://img.shields.io/badge/Kali-Linux-557C94?style=for-the-badge&logo=kalilinux&labelColor=000000)](https://kali.org)
[![Tools](https://img.shields.io/badge/Tools-118%2B-FF6B6B?style=for-the-badge&labelColor=000000)](https://github.com/BLOODRAVENIST/FTRECON)
[![Phases](https://img.shields.io/badge/Phases-12-00C2FF?style=for-the-badge&labelColor=000000)](https://github.com/BLOODRAVENIST/FTRECON)

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:000000,60:00FF41,100:9FEF00&height=80&section=header&text=FTRECON&fontSize=40&fontColor=00FF41&animation=twinkling" width="100%"/>

</div>

## Table of Contents
1. What is FTRECON
2. Features
3. Architecture
4. 12-Phase Pipeline
5. Phase Details
6. Manual Commands Cheatsheet
7. Tool Inventory (118+)
8. Installation
9. Usage
10. Output Structure
11. Bug Bounty Extras
12. Troubleshooting
13. Legal Disclaimer

---

## What is FTRECON?
Single-command automated reconnaissance and VAPT pipeline. Chains 118+ security tools across 12 phases — from subdomain enumeration to AI-assisted triage.

Instead of manual tool juggling, run:

    ./ftrecon.sh example.com

FTRECON handles validation, tool orchestration, output organization, error recovery, and final report.

## Features
| Feature | Description |
|---|---|
| 118+ Tools | 59 Go + 20 Python + 22 APT + 10 Git + 7 Cloud |
| 12 Phases | Subdomain to AI triage |
| Zero-Crash Design | Missing tools skipped, not fatal |
| Smart Output Tree | 01_subdomains to 12_ai_triage |
| Optional Active | --active enables sqlmap + dalfox |
| Fast Mode | --fast skips slow crawl + dir brute |
| AI Triage | Optional DeepSeek summary |
| Safety | Domain regex + shell metachar block |
| Auth Gate | Confirm prompt unless --yes |

---

## Architecture
~~~mermaid
flowchart TD
    A([Target]) --> V[Validate + Confirm]
    V --> P1[Phase 1: Subdomain Enum]
    P1 --> P2[Phase 2: DNS Recon]
    P2 --> P3[Phase 3: Port Scan]
    P3 --> P4[Phase 4: HTTP Probe]
    P4 --> P5[Phase 5: Screenshots]
    P5 --> P6[Phase 6: URL Collection]
    P6 --> P7[Phase 7: Content Discovery]
    P7 --> P8[Phase 8: Params]
    P8 --> P9[Phase 9: Vuln Scan]
    P9 --> P10[Phase 10: Takeover]
    P10 --> ACT{--active?}
    ACT -->|YES| P11[Phase 11: SQLi/XSS]
    ACT -->|NO| P12[Phase 12: AI Triage]
    P11 --> P12
    P12 --> R([FTRECON_REPORT.md])
~~~

### Filesystem
~~~text
FTRECON/
├── ftrecon.sh              # Main orchestration (12 phases)
├── install.sh              # 118+ tool installer
├── README.md
├── LICENSE                 # MIT
└── FTRECONv2/
    ├── FTrecon.sh          # V2 safe version
    └── FTscan.sh           # Scan-only variant
~~~

## 12-Phase Pipeline
| # | Phase | Key Tools | Output |
|---|---|---|---|
| 1 | Subdomain Enum | subfinder, assetfinder, crt.sh, findomain, amass | 01_subdomains/ |
| 2 | DNS Recon | whois, dig, dnsx | 02_dns/ |
| 3 | Port Scan | naabu | 03_ports/ |
| 4 | HTTP Probe | httpx, whatweb, wafw00f | 04_probe_tech/ |
| 5 | Screenshots | gowitness | 05_screenshots/ |
| 6 | URL Collection | gau, waybackurls, katana, uro | 06_urls/ |
| 7 | Content Discovery | ffuf | 07_content_discovery/ |
| 8 | Param Discovery | arjun, gf, kxss | 08_params/ |
| 9 | Vuln Scan | nuclei, nikto | 09_vuln_scan/ |
| 10 | Takeover | subzy, nuclei | 10_takeover/ |
| 11 | Active | sqlmap, dalfox | 11_active_testing/ |
| 12 | AI Triage | DeepSeek | 12_ai_triage/ |

## Phase Details
### Phase 1 — Subdomain Enumeration
subfinder (30+ sources) + assetfinder + crt.sh (SSL certs) + findomain + amass (passive DNS). Result: deduped all_subdomains.txt.

### Phase 2 — DNS Recon
whois + dig ANY (A, AAAA, MX, TXT, NS) + dnsx (resolves every subdomain to IP).

### Phase 3 — Port Scanning
naabu — top 1000 TCP ports.

### Phase 4 — HTTP Probe + Tech + WAF
httpx (probe + tech detect + title) + whatweb (deep fingerprint) + wafw00f (WAF detect).

### Phase 5 — Screenshots
gowitness — headless browser screenshots of every live host.

### Phase 6 — URL Collection
gau + waybackurls + katana (depth 2, JS) + uro (dedupe).

### Phase 7 — Content Discovery
ffuf — directory brute with SecLists raft-medium.

### Phase 8 — Parameter Discovery
arjun (hidden params) + gf (xss, sqli, ssrf, redirect, lfi, rce patterns) + kxss (reflection check).

### Phase 9 — Vulnerability Scan
nuclei (CVEs, misconfigs, exposures) + nikto (legacy scanner).

### Phase 10 — Takeover
subzy (dangling CNAME) + nuclei takeover templates (S3, GitHub Pages, Heroku, Azure).

### Phase 11 — Active Validation (OFF by default)
Only with --active. sqlmap (level=1 risk=1) + dalfox (XSS).

### Phase 12 — AI Triage (optional)
Needs DEEPSEEK_API_KEY. Prioritized manual-review summary only.

---

## Manual Commands Cheatsheet
### Subdomain Enumeration
    subfinder -d example.com -all -silent -o subfinder.txt
    assetfinder --subs-only example.com > assetfinder.txt
    curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r ".[].name_value" | sort -u
    findomain -t example.com -q -u findomain.txt
    amass enum -passive -d example.com -o amass.txt

### DNS + Resolve
    dnsx -l all_subdomains.txt -a -resp -silent -o resolved.txt

### Port Scan
    naabu -list resolved.txt -top-ports 1000 -silent -o naabu.txt

### HTTP Probe
    httpx -l all_subdomains.txt -silent -title -tech-detect -status-code -o httpx_live.txt
    whatweb -a 3 https://example.com
    wafw00f https://example.com

### Screenshots
    gowitness file -f live_hosts.txt -P . --no-http

### URL Collection
    gau example.com --threads 5 > gau.txt
    waybackurls example.com > waybackurls.txt
    katana -u https://example.com -d 2 -jc -silent -o katana.txt
    cat gau.txt waybackurls.txt katana.txt | sort -u | uro > all_urls_clean.txt

### Content Discovery
    ffuf -u https://example.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302,403 -t 40

### Parameters
    arjun -u https://example.com -oT arjun.txt -t 10
    cat all_urls_clean.txt | gf xss > xss_candidates.txt
    cat all_urls_clean.txt | gf sqli > sqli_candidates.txt
    cat all_urls_clean.txt | kxss > reflected_params.txt

### Vulnerability Scan
    nuclei -l live_hosts.txt -silent -o nuclei_results.txt
    nikto -h https://example.com -Tuning 123456789 -o nikto.txt

### Takeover
    subzy run --targets all_subdomains.txt --hide_fails > subzy.txt

### Active (AUTHORIZED ONLY)
    sqlmap -u "https://example.com/page?id=1" --batch --level=1 --risk=1
    dalfox file xss_candidates.txt --silence -o dalfox_results.txt

---

## Tool Inventory (118+)
### Go Tools (59)
Subdomain: subfinder, assetfinder, findomain, shuffledns, github-subdomains, gitlab-subdomains, related-domains, alterx, gotator, csprecon

Probe: httpx, tlsx, cdncheck, fingerprintx

Crawling: katana, hakrawler, gospider, crawley, urlfinder, GoLinkFinder

URL: gau, waybackurls, anew, unfurl, qsreplace

Content: ffuf, gobuster, x8

Vuln: nuclei, dalfox, crlfuzz, ppfuzz, smugglex, jwt-hack, nomore403, toxicache, cariddi

Param: gf, kxss, Gxss

DNS: dnsx, hakrevdns, hakip2host, haktrails

Misc: interactsh-client, notify, mapcidr, asnmap, cvemap, uncover, proxify, cut-cdn, go-dork

Takeover: subjack, subzy

Screenshots: gowitness

### Python Tools (20)
arjun, sqlmap, theHarvester, wpscan, xsstrike, corsy, commix, ghauri, wafw00f, dnsrecon, dirsearch, uro, pwncat-cs, droopescan, CMSeeK, dnstwist, s3scanner, trufflehog, detect-secrets, wfuzz

### APT Tools (22)
nikto, nmap, masscan, gobuster, whatweb, feroxbuster, amass, sslscan, testssl.sh, enum4linux-ng, smbclient, smbmap, ldap-utils, snmp, hydra, responder, exploitdb, metasploit-framework, dnsenum, fierce, whois, dirb

### Git-Cloned (10)
SecLists, PayloadsAllTheThings, GitTools, git-dumper, gf-patterns, jwt_tool, Osmedeus, reconFTW, LinkFinder, SecretFinder

### Cloud (7)
AWS CLI, Pacu, ScoutSuite, CloudBrute, cloud_enum, Azure CLI, ROADtools

Total: 59 + 20 + 22 + 10 + 7 = 118 tools

---

## Installation
    git clone https://github.com/BLOODRAVENIST/FTRECON.git
    cd FTRECON
    chmod +x install.sh ftrecon.sh
    ./install.sh
    source ~/.bashrc

Installer retries apt-get update 3x, sets GOPATH/GOBIN/PATH in shell rc files, installs Go manually if missing, uses pip install --user --break-system-packages (no PEP668 errors), logs everything to ~/INFORMATION_GATHERING/install_logs/, never crashes.

## Usage
    ./ftrecon.sh <domain> [--active] [--fast] [--yes]

| Flag | Description |
|---|---|
| domain | Target, e.g. example.com |
| --active | Phase 11: sqlmap + dalfox (OFF by default) |
| --fast | Skip deep crawl + dir brute |
| --yes | Skip interactive confirmation |

Examples:

    ./ftrecon.sh example.com
    ./ftrecon.sh example.com --fast
    ./ftrecon.sh example.com --active
    ./ftrecon.sh lab.local --fast --yes
    export DEEPSEEK_API_KEY="sk-..." && ./ftrecon.sh example.com

## Output Structure
    ~/INFORMATION_GATHERING/ftrecon_results/<domain>_<timestamp>/
    ├── 01_subdomains/
    ├── 02_dns/
    ├── 03_ports/
    ├── 04_probe_tech/
    ├── 05_screenshots/
    ├── 06_urls/
    ├── 07_content_discovery/
    ├── 08_params/gf_patterns/
    ├── 09_vuln_scan/
    ├── 10_takeover/
    ├── 11_active_testing/
    ├── 12_ai_triage/
    ├── _logs/
    └── FTRECON_REPORT.md

## Bug Bounty Extras
What FTRECON covers: passive subdomain enum, live host discovery, WAF detection, historical URLs, crawling, dir brute, param discovery + pattern triage, nuclei templates, takeover check, optional sqlmap + dalfox.

What you MUST do manually: manual param testing, business logic testing, auth bypass chains, privesc chains, report writing, scope verification.

Recommended workflow:
1. Run ./ftrecon.sh target.com
2. Read 09_vuln_scan/nuclei_results.txt first
3. Check 10_takeover/subzy.txt
4. Review 08_params/gf_patterns/*.txt
5. Look at 05_screenshots/
6. Only THEN use --active if scope allows

## Troubleshooting
| Issue | Fix |
|---|---|
| Permission denied | chmod +x ftrecon.sh install.sh |
| command not found | source ~/.bashrc |
| apt lock | Installer retries 3x |
| externally-managed | Installer uses --break-system-packages |
| go not found | export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin |
| Empty resolved.txt | dnsx missing |
| sqlmap skipped | --active not passed |
| AI skipped | DEEPSEEK_API_KEY not set |
| Nuclei missing | nuclei -update-templates |

## Legal Disclaimer
FOR AUTHORIZED SECURITY TESTING ONLY.

Only run FTRECON against domains you own or have explicit written permission to test. Unauthorized scanning is illegal under CFAA, Computer Misuse Act, IT Act, and similar laws worldwide. You are solely responsible for your actions. --active sends real payloads — use only where permitted.

---

<div align="center">

### Star this repo if FTRECON helped you.

<a href="https://github.com/BLOODRAVENIST"><img src="https://img.shields.io/badge/GitHub-BLOODRAVENIST-00FF41?style=flat-square&logo=github&labelColor=000000" alt="GitHub"/></a>
<a href="https://profile.hackthebox.com/profile/019eff6a-53c1-721f-a94e-f459c94dfc1f"><img src="https://img.shields.io/badge/Hack_The_Box-9FEF00?style=flat-square&logo=hackthebox&logoColor=white&labelColor=111927" alt="HTB"/></a>
<a href="https://buymeacoffee.com/bloodravenist"><img src="https://img.shields.io/badge/Buy_Me_A_Coffee-FFDD00?style=flat-square&logo=buy-me-a-coffee&logoColor=black&labelColor=000000" alt="Coffee"/></a>

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:000000,60:00FF41,100:9FEF00&height=100&section=footer&text=FTRECON&fontSize=34&fontColor=00FF41&animation=twinkling" width="100%"/>

</div>
