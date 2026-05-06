<div align="center">

<img src="penagent_logo.svg" width="280" alt="PenAgent Logo"/>

# PenAgent

**Autonomous Penetration Testing Agent**

*Final Project — CSC 7644: Applied LLM Development — Louisiana State University*

![Python](https://img.shields.io/badge/python-3.10+-blue?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/status-research%20prototype-yellow?style=flat-square)
![Target](https://img.shields.io/badge/use-authorized%20labs%20only-red?style=flat-square)
![LLM](https://img.shields.io/badge/LLM-Claude%20Sonnet-purple?style=flat-square)

</div>

---

> **Legal Notice:** PenAgent is a research prototype intended exclusively for use against systems you own or have explicit written permission to test. All development and testing was performed against Metasploitable2 and HackTheBox authorized lab environments. Unauthorized use is illegal and unethical.

---

## Project Overview

PenAgent is an agentic, retrieval-augmented LLM application that automates the end-to-end penetration testing workflow. Traditional penetration testing requires a skilled practitioner to manually chain together reconnaissance, vulnerability research, exploitation, and reporting — a process that is time-intensive and requires deep domain expertise. PenAgent addresses this by combining a LangChain ReAct agent, a hybrid RAG knowledge base, live CVE lookup, and Metasploit RPC integration into a single autonomous pipeline.

Given a raw nmap XML scan as input, PenAgent independently reasons about each discovered service, retrieves relevant exploit techniques, attempts exploitation via Metasploit, and produces a professional penetration test report — all without human intervention.

This project was built as the final project for **CSC 7644: Applied LLM Development** at Louisiana State University, and demonstrates practical application of ReAct-style agentic reasoning, retrieval-augmented generation, tool use, and structured LLM output generation.

---

## Key Features

- **Autonomous attack pipeline** — parses nmap XML, retrieves exploits, fires Metasploit, generates report in one command
- **Hybrid RAG knowledge base** — combines ChromaDB vector search and BM25 keyword search over 47,405 indexed chunks from PayloadsAllTheThings and ExploitDB
- **Live CVE lookup** — queries NIST NVD REST API v2.0 in real time for up-to-date vulnerability data
- **Multi-target support** — scans and attacks multiple hosts in a single run, producing one consolidated report
- **LangChain ReAct agent** — reasons step-by-step, selects tools, interprets results, and iterates until exploitation succeeds or options are exhausted
- **Three service scope modes** — default (top 6 priority services), targeted (specific ports), or full (all services)
- **Professional report generation** — Claude Sonnet synthesizes findings into a structured report with CVSS scores, CVE references, evidence, quick-access commands, and remediation guidance
- **Scan history** — automatically saves every run to `~/.penagent/history/` with timestamp, findings count, and elapsed time
- **Report comparison** — diff any two reports to identify what changed between assessments
- **Webhook notifications** — fires Slack or Discord alerts when a shell is acquired or findings are complete
- **Styled terminal UI** — rich-colored phase output, findings summary table, and interactive shell panel

---

## Tech Stack and Architecture

### LLMs and APIs

| Component | Technology |
|-----------|------------|
| LLM | Claude Sonnet 4 (Anthropic API) |
| Agent framework | LangChain ReAct (`create_react_agent`) |
| Embeddings | `sentence-transformers/all-MiniLM-L6-v2` |
| CVE data | NIST NVD REST API v2.0 |
| Exploitation | `pymetasploit3` via `msfrpcd` RPC daemon |

### Knowledge Base and Retrieval

| Component | Technology |
|-----------|------------|
| Vector store | ChromaDB |
| Keyword search | BM25 (rank-bm25) |
| Retrieval strategy | Hybrid fusion (vector + keyword) |
| Corpus | PayloadsAllTheThings + ExploitDB (47,405 chunks) |

### Infrastructure

| Component | Technology |
|-----------|------------|
| CLI interface | `rich` (styled terminal output) |
| Environment | Python 3.10+, Kali Linux |
| Exploitation backend | Metasploit Framework + msfrpcd |

### Architecture Diagram

```
nmap XML input
      │
      ▼
 parser.py          Parses host/port/service/version from XML
      │
      ▼
 agent.py           LangChain ReAct agent — per-host reasoning loop
      ├── tools/retriever.py    Hybrid ChromaDB + BM25 RAG search
      ├── tools/cve_lookup.py   Live NIST NVD CVE API queries
      └── tools/msf_exec.py     Metasploit RPC exploit execution
      │
      ▼
 reporter.py        Claude Sonnet generates structured markdown report
      │
      ▼
 report.md  +  optional interactive root shell
```

---

## Setup Instructions

### Prerequisites

- **OS:** Kali Linux (recommended) or any Debian-based Linux with Metasploit installed
- **Python:** 3.10 or higher
- **Metasploit Framework:** must be installed and `msfrpcd` must be available
- **Anthropic API key:** required for Claude Sonnet access
- **pip / venv:** standard Python tooling

### 1. Clone the repository

```bash
git clone https://github.com/Jbuhrer/csc7644-final-project-buhrer.git
cd csc7644-final-project-buhrer
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

```bash
cp .env.example .env
```

Open `.env` and fill in your values:

```env
# Required
ANTHROPIC_API_KEY=sk-ant-your-key-here

# Required — must match the password used to start msfrpcd
MSF_PASSWORD=yourpassword
MSF_HOST=127.0.0.1
MSF_PORT=55553

# Optional — Slack or Discord webhook URL for shell/findings notifications
PENAGENT_WEBHOOK=https://discord.com/api/webhooks/...

# Optional — increases NVD rate limit from 5 to 50 requests per 30 seconds
NVD_API_KEY=your-nvd-key
```

### 5. Build the knowledge base

This downloads and indexes PayloadsAllTheThings and ExploitDB into ChromaDB. Only needs to run once.

```bash
python3 build_index.py
```

### 6. Start Metasploit RPC daemon

Open a separate terminal and run:

```bash
msfrpcd -P yourpassword -S -f
```

Leave this running. PenAgent connects to it to fire exploit modules.

---

## Running the Application

### Basic usage

```bash
nmap -sV -Pn -oX scan.xml <target_ip>
python3 main.py --scan scan.xml --output report.md
```

### Full pipeline with interactive shell

```bash
python3 main.py --scan scan.xml --output report.md --shell
```

### Service scope modes

```bash
# Default — top 6 highest-priority services only (fastest, cheapest)
python3 main.py --scan scan.xml --output report.md --shell

# Targeted — only investigate specific ports you choose
python3 main.py --scan scan.xml --output report.md --services 21 445 3306 --shell

# Full — investigate all discovered services (slowest, most thorough)
python3 main.py --scan scan.xml --output report.md --full --shell
```

### Multi-target

```bash
nmap -sV -Pn -oX scan.xml <ip1> <ip2>
python3 main.py --scan scan.xml --output report.md --shell
```

### View scan history

```bash
python3 main.py --history
```

### Compare two reports

```bash
python3 main.py --compare report_v1.md report_v2.md
```

### All flags

| Flag | Required | Description |
|------|----------|-------------|
| `--scan` | Yes* | Path to nmap XML file |
| `--output` | No | Output report filename (default: `report.md`) |
| `--shell` | No | Drop into interactive shell after exploitation |
| `--shell-port` | No | Manually specify shell port (overrides auto-detect) |
| `--services` | No | Target specific ports only, e.g. `--services 21 445` |
| `--full` | No | Investigate all discovered services |
| `--history` | No | Display table of all past runs |
| `--compare` | No | Diff two report files: `--compare old.md new.md` |

*Not required when using `--history` or `--compare`

---

## Repository Organization

```
PenAgent/
├── main.py              Entry point — argument parsing, pipeline orchestration,
│                        history, compare, webhook notifications, shell drop
├── agent.py             LangChain ReAct agent — per-host reasoning, OS detection,
│                        service filtering, tool orchestration, multi-target loop
├── reporter.py          Report generation — Claude Sonnet prompt construction
│                        and structured markdown output
├── parser.py            nmap XML parser — extracts host/port/service/version data
├── banner.py            Terminal UI — rich-styled banner, phase output,
│                        findings table, shell panel
├── build_index.py       Knowledge base builder — downloads corpus, chunks text,
│                        builds ChromaDB + BM25 index
├── tools/
│   ├── retriever.py     Hybrid RAG — ChromaDB vector search + BM25 keyword fusion
│   ├── cve_lookup.py    CVE lookup — NIST NVD REST API v2.0 queries
│   └── msf_exec.py      Metasploit RPC — pymetasploit3 exploit execution
├── .env.example         Environment variable template
├── requirements.txt     Python dependencies
├── penagent_logo.svg    Project logo
└── README.md            This file
```

---

## Results

PenAgent was tested against two authorized lab targets:

| Target | OS | Time | Findings | Result |
|--------|----|------|----------|--------|
| Metasploitable2 | Linux | ~3.5 min | 9 | `root@metasploitable` shell |
| HackTheBox Unified | Linux | ~4 min | 3 | Tomcat/Log4Shell path identified |

**Comparison with PentestGPT (Deng et al., USENIX 2024):** Both systems achieved root-level access on Metasploitable2. PentestGPT produced a CTF-style flag summary. PenAgent produced a structured professional report with CVSS scores, CVE references, exploitation evidence, quick-access commands, and remediation guidance.

---

## Attributions and Citations

- Yao et al. (2023). ReAct: Synergizing Reasoning and Acting in Language Models. *ICLR 2023*. https://arxiv.org/abs/2210.03629
- Lewis et al. (2020). Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks. *NeurIPS 2020*. https://arxiv.org/abs/2005.11401
- Deng et al. (2023). PentestGPT: An LLM-Empowered Automatic Penetration Testing Tool. *arXiv:2308.06782*. https://arxiv.org/abs/2308.06782
- LangChain ReAct agent documentation: https://docs.langchain.com
- PayloadsAllTheThings knowledge base: https://github.com/swisskyrepo/PayloadsAllTheThings
- NIST National Vulnerability Database API: https://nvd.nist.gov/developers
- Anthropic Claude API documentation: https://docs.anthropic.com
- pymetasploit3 library: https://github.com/DanMcInerney/pymetasploit3

---

## License

MIT License.

*Built for CSC 7644: Applied LLM Development — Louisiana State University*
