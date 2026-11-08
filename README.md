<div align="center">

# FTRECON

### Automated Recon + VAPT Pipeline — 118+ Tools, 12 Phases, One Command

**Made by [BLOODRAVENIST](https://github.com/BLOODRAVENIST)**

> For Authorized Security Research / Bug Bounty Only

</div>

---

## What is FTRECON?

Single-command automated reconnaissance and VAPT pipeline for bug bounty hunters and penetration testers. It chains 118+ industry-standard tools across 12 phases — from subdomain enumeration to AI-assisted triage — and produces a clean, timestamped, report-ready output tree.

No manual tool juggling. No crashes when a tool is missing — missing tools are skipped gracefully and logged.

    ./ftrecon.sh example.com

That is it. Everything else is automated.

## Features

- **118+ Tools** — 59 Go + 20 Python + 22 APT + 10 Git + 7 Cloud
- **12 Phases** — Subdomain, DNS, Ports, HTTP, Screens, URLs, Content, Params, Vuln, Takeover, Active, AI
- **Zero-Crash Design** — every step isolated; missing tools skipped
- **Smart Output Tree** — 01_subdomains to 12_ai_triage, timestamped per target
- **Optional Active Mode** — --active enables sqlmap + dalfox (off by default)
- **Fast Mode** — --fast skips slow crawl + dir brute
- **AI Triage (Optional)** — DeepSeek API prioritization summary

---

## 12-Phase Pipeline

| # | Phase | Tools | Output |
|---|---|---|---|
| 1 | Subdomain Enum | subfinder, assetfinder, crt.sh, findomain, amass | 01_subdomains/ |
| 2 | DNS Recon | whois, dig, dnsx | 02_dns/ |
| 3 | Port Scanning | naabu | 03_ports/ |
| 4 | HTTP Probe | httpx, whatweb, wafw00f | 04_probe_tech/ |
| 5 | Screenshots | gowitness | 05_screenshots/ |
| 6 | URL Collection | gau, waybackurls, katana, uro | 06_urls/ |
| 7 | Content Discovery | ffuf | 07_content_discovery/ |
| 8 | Parameter Discovery | arjun, gf, kxss | 08_params/ |
| 9 | Vulnerability Scan | nuclei, nikto | 09_vuln_scan/ |
| 10 | Subdomain Takeover | subzy, nuclei | 10_takeover/ |
| 11 | Active Validation | sqlmap, dalfox | 11_active_testing/ |
| 12 | AI Triage | DeepSeek API | 12_ai_triage/ |

---

## Tool Inventory (118+)

**Go (59):** subfinder, httpx, naabu, katana, dnsx, nuclei, tlsx, cdncheck, interactsh-client, notify, mapcidr, asnmap, alterx, urlfinder, cvemap, uncover, proxify, fingerprintx, ffuf, gobuster, hakrawler, gospider, crawley, assetfinder, waybackurls, gau, anew, gf, unfurl, qsreplace, dalfox, jwt-hack, smugglex, crlfuzz, ppfuzz, go-dork, GoLinkFinder, findomain, subjack, subzy, haktrails, hakrevdns, hakip2host, shuffledns, x8, gotator, csprecon, cariddi, nomore403, toxicache, cut-cdn, kxss, Gxss, gowitness, github-subdomains, gitlab-subdomains, github-endpoints, related-domains, nrich

**Python (20):** arjun, dirsearch, corsy, xsstrike, uro, sqlmap, theHarvester, wafw00f, dnsrecon, wpscan, pwncat-cs, droopescan, CMSeeK, dnstwist, s3scanner, trufflehog, detect-secrets, commix, ghauri, wfuzz

**APT (22):** nikto, nmap, masscan, gobuster, whatweb, feroxbuster, amass, sslscan, testssl.sh, enum4linux-ng, smbclient, smbmap, ldap-utils, snmp, hydra, responder, exploitdb, metasploit-framework, dnsenum, fierce, whois, dirb

**Git-Cloned (10):** SecLists, PayloadsAllTheThings, GitTools, git-dumper, gf-patterns, jwt_tool, Osmedeus, reconFTW, LinkFinder, SecretFinder

**Cloud (7):** AWS CLI, Pacu, ScoutSuite, CloudBrute, cloud_enum, Azure CLI, ROADtools

---

## Installation

    git clone https://github.com/BLOODRAVENIST/FTRECON.git
    cd FTRECON
    chmod +x install.sh ftrecon.sh
    ./install.sh
    source ~/.bashrc

Installer retries apt-get update 3x, sets GOPATH/GOBIN/PATH in shell rc files, installs Go manually if missing, uses pip install --user --break-system-packages (no PEP668 errors), logs every tool to ~/INFORMATION_GATHERING/install_logs/, and never crashes — failures are collected, not fatal.

## Usage

    ./ftrecon.sh <domain> [--active] [--fast] [--yes]

| Flag | Description |
|---|---|
| domain | Target domain, e.g. example.com |
| --active | Enable Phase 11: sqlmap + dalfox (off by default) |
| --fast | Skip deep crawl + dir brute |
| --yes | Skip interactive authorization confirmation |

Examples:

    ./ftrecon.sh example.com                     # basic recon
    ./ftrecon.sh example.com --fast              # fast recon
    ./ftrecon.sh example.com --active            # full + active validation
    ./ftrecon.sh lab.local --fast --yes          # CI / lab
    export DEEPSEEK_API_KEY=sk-...
    ./ftrecon.sh example.com                     # with AI triage

## Troubleshooting

| Issue | Fix |
|---|---|
| Permission denied | chmod +x ftrecon.sh install.sh |
| command not found after install | source ~/.bashrc |
| apt lock error | Installer retries 3x automatically |
| externally-managed-environment | Installer uses --break-system-packages |
| go: command not found | export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin |
| AI triage skipped | DEEPSEEK_API_KEY not set |

## Legal Disclaimer

**FOR AUTHORIZED SECURITY TESTING ONLY.**

Only run FTRECON against domains you own or have explicit written permission to test (bug bounty scope, signed pentest authorization, or your own lab).

Unauthorized scanning is illegal under CFAA (US), Computer Misuse Act (UK), IT Act (India), and similar laws worldwide. You are solely responsible for your actions.

---

<div align="center">

### If FTRECON helped you, drop a star.

Made by [BLOODRAVENIST](https://github.com/BLOODRAVENIST)

</div>
