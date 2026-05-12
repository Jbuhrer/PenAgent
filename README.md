<div align="center">

<img src="penagent_logo.svg" width="280" alt="PenAgent Logo"/>

# PenAgent

**Autonomous Penetration Testing Agent**

![Python](https://img.shields.io/badge/python-3.10+-blue?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/status-active-brightgreen?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Kali%20Linux-blue?style=flat-square)
![LLM](https://img.shields.io/badge/LLM-Claude%20Sonnet-purple?style=flat-square)

</div>

---

> **Legal Notice:** PenAgent is intended exclusively for authorized penetration testing engagements. Only use against systems you own or have explicit written permission to test. Unauthorized use is illegal.

---

## Overview

PenAgent is an autonomous penetration testing agent that automates the full engagement workflow from live recon through exploitation, post-exploitation, and professional report generation with no manual intervention required.

    Target IP/Range
         ↓
    Live Recon        — 4-phase nmap pipeline (port scan → service fingerprint → OS detection)
         ↓
    Network Agent     — RAG-powered exploit reasoning + Metasploit RPC execution
         ↓
    Exploit Selection — auto-executes if 1 path found, interactive menu if multiple
         ↓
    Web Agent         — gobuster, nikto, sqlmap, LFI, XSS, default creds, nuclei, wpscan, hydra
         ↓
    Web Shell Drop    — Tomcat WAR, SQLmap OS shell, LFI log poisoning, DVWA cmd injection
         ↓
    Post-Exploitation — credential harvesting, privesc enumeration, lateral movement discovery
         ↓
    Report            — professional findings with CVSS scores, CVE refs, evidence, remediation
         ↓
    Root Shell        — interactive shell drop on successful exploitation

---

## Key Features

- **Live recon pipeline** — drives nmap autonomously, no manual XML required
- **Network + Web attack coverage** — service exploitation and full web app testing in one run
- **Exploit selection menu** — auto-executes single paths, presents numbered menu for multiple
- **Web shell drop** — Tomcat WAR upload, SQLmap OS shell, LFI log poisoning, DVWA cmd injection
- **Hybrid RAG knowledge base** — 47,405 chunks from PayloadsAllTheThings + ExploitDB
- **Live CVE lookup** — NIST NVD REST API v2.0 queried in real time
- **Post-exploitation** — credential harvesting, privesc enumeration, neighbor discovery
- **Scope enforcement** — hard YAML scope controls, violations logged
- **Stealth mode** — slow timing (-T2) for IDS evasion
- **Professional reporting** — CVSS v3.1 scored findings, CVE references, remediation
- **Multi-target support** — scan entire subnets, one consolidated report
- **Scan history** — every run saved to ~/.penagent/history/
- **Report diffing** — compare two reports to track remediation progress
- **Webhook notifications** — Discord/Slack alerts on shell acquisition and findings

---

## Tech Stack

### Core

| Component | Technology |
|-----------|------------|
| LLM | Claude Sonnet (Anthropic API) |
| Agent | Anthropic native tool use |
| Embeddings | sentence-transformers/all-MiniLM-L6-v2 |
| CVE data | NIST NVD REST API v2.0 |
| Exploitation | pymetasploit3 via msfrpcd |

### Web Attack Tools

| Tool | Purpose |
|------|---------|
| gobuster | Directory bruteforce |
| feroxbuster | Recursive directory discovery |
| nikto | Web vulnerability scanning |
| sqlmap | SQL injection testing |
| nuclei | Template-based CVE scanning |
| wpscan | WordPress vulnerability scanning |
| wafw00f | WAF detection |
| hydra | Credential brute forcing |
| wfuzz | Parameter fuzzing |
| whatweb | Technology fingerprinting |

---

## Architecture

    main.py
      ├── recon.py              Live nmap orchestration (4-phase pipeline)
      ├── scope.py              Scope enforcement + violation logging
      ├── exploit_selector.py   Exploit selection menu + real-world CVE database
      ├── agent.py              Anthropic native tool use agentic loop
      │   ├── tools/retriever.py    Hybrid FAISS + BM25 RAG search
      │   ├── tools/cve_lookup.py   NIST NVD CVE API
      │   └── tools/msf_exec.py     Metasploit RPC exploit execution
      ├── webagent.py           Web application attack suite + web shell drop
      ├── postex.py             Post-exploitation enumeration
      └── reporter.py           Claude Sonnet report generation

---

## Setup

### Prerequisites

- Kali Linux
- Python 3.10+
- Metasploit Framework
- Anthropic API key

### Install

    git clone https://github.com/Jbuhrer/PenAgent.git
    cd PenAgent
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt

### Configure

    cp .env.example .env

    ANTHROPIC_API_KEY=sk-ant-your-key-here
    MSF_PASSWORD=yourpassword
    MSF_HOST=127.0.0.1
    MSF_PORT=55553
    LHOST=your-kali-ip
    LPORT=4444
    PENAGENT_WEBHOOK=https://discord.com/api/webhooks/...

### Build knowledge base (once)

    python3 build_index.py

### Start Metasploit RPC

    msfrpcd -P yourpassword -S -a 127.0.0.1 &

---

## Usage

### Standard engagement

    python3 main.py --init-scope
    # edit scope.yaml with authorized ranges
    python3 main.py --target 10.10.10.5 --scope scope.yaml --output report.md --shell

### Common commands

    # Single host
    python3 main.py --target 10.10.10.5 --shell

    # Subnet
    python3 main.py --target 10.10.10.0/24 --shell

    # Stealth mode
    python3 main.py --target 10.10.10.5 --stealth --shell

    # Specific ports only
    python3 main.py --target 10.10.10.5 --services 21 445 3306

    # All services
    python3 main.py --target 10.10.10.5 --full --shell

    # With scope enforcement
    python3 main.py --target 10.10.10.0/24 --scope scope.yaml --shell

    # Legacy static scan
    python3 main.py --scan scan.xml --shell

    # Utility
    python3 main.py --history
    python3 main.py --compare report_v1.md report_v2.md
    python3 main.py --init-scope

### All flags

| Flag | Description |
|------|-------------|
| `--target` | Live target: IP, range, or CIDR |
| `--scan` | Static nmap XML (legacy mode) |
| `--scope` | Path to scope.yaml |
| `--stealth` | Slow timing (-T2) for IDS evasion |
| `--output` | Report filename (default: report.md) |
| `--shell` | Drop into root shell after exploitation |
| `--shell-port` | Manually specify shell port |
| `--services` | Target specific ports only |
| `--full` | All discovered services |
| `--history` | View past runs |
| `--compare` | Diff two reports |
| `--init-scope` | Generate scope.yaml template |
| `--recon-dir` | Save recon XML files to directory |

---

## Results

| Target | Services | Time | Findings | Result |
|--------|----------|------|----------|--------|
| Metasploitable2 | 23 | ~6 min | 7+ critical | Root shell + LFI + SQLi + default creds |
| HackTheBox Archetype | Windows/MSSQL | ~5 min | 3 | xp_cmdshell path identified |

---

## License

MIT License. Use only against authorized targets.
