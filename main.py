import os
import warnings
os.environ["TRANSFORMERS_VERBOSITY"] = "error"
os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
os.environ["TOKENIZERS_PARALLELISM"] = "false"
warnings.filterwarnings("ignore")

import re
import time
import argparse
import subprocess

from banner import (
    print_banner, print_scan_header, print_phase,
    print_shell_drop, print_report_summary,
    status, success, warn, error
)
from parser import parse_nmap
from agent import run_agent
from reporter import generate_report


def parse_findings_from_report(report_text: str) -> list:
    """
    Extract findings from the generated markdown report.
    Looks for ### headings in the Findings section and pulls
    out title, CVSS score, and CVE references.
    """
    findings = []

    # Split on ### headers — each finding is its own block
    blocks = re.split(r'\n(?=###\s)', report_text)

    for block in blocks:
        # Skip non-finding blocks
        if not re.search(r'CVSS|CVE|exploit|vulnerab', block, re.IGNORECASE):
            continue

        title_match = re.search(r'###\s+(?:Finding\s+\d+[:\-\s]+)?(.+)', block)
        cvss_match  = re.search(r'CVSS[^\d]*(\d+(?:\.\d+)?)', block, re.IGNORECASE)
        cve_match   = re.search(r'(CVE-\d{4}-\d+)', block, re.IGNORECASE)

        if not title_match:
            continue

        title = title_match.group(1).strip()
        title = re.sub(r'[*#`]', '', title).strip()

        if len(title) < 5:
            continue

        cvss = float(cvss_match.group(1)) if cvss_match else 0.0
        cve  = cve_match.group(1) if cve_match else ""

        findings.append({"title": title[:55], "cvss": cvss, "cve": cve})

    # Deduplicate
    seen, unique = set(), []
    for f in findings:
        if f["title"] not in seen:
            seen.add(f["title"])
            unique.append(f)

    # Sort by CVSS descending
    unique.sort(key=lambda x: x["cvss"], reverse=True)

    return unique if unique else [
        {"title": "See report.md for full findings", "cvss": 0.0, "cve": ""}
    ]


def main():
    print_banner()

    p = argparse.ArgumentParser(description="PenAgent — Autonomous Penetration Testing Agent")
    p.add_argument("--scan",       required=True,       help="Path to nmap XML file")
    p.add_argument("--output",     default="report.md", help="Output report filename")
    p.add_argument("--shell",      action="store_true", help="Drop into shell after report")
    p.add_argument("--shell-port", default=None,        help="Port to connect to for shell (default: auto-detect)")
    args = p.parse_args()

    start = time.time()

    # ── Phase 1: Parse ────────────────────────────────────────────────────────
    print_phase(1, "PARSE", f"Loading {args.scan}")
    targets   = parse_nmap(args.scan)
    target_ip = targets[0]["ip"] if targets else "unknown"
    services  = targets[0].get("services", []) if targets else []
    status(f"{len(targets)} host(s) found  |  {len(services)} services fingerprinted")
    print_scan_header(target_ip, args.scan)

    # ── Phase 2: Retrieve ─────────────────────────────────────────────────────
    print_phase(2, "RETRIEVE", "Querying RAG knowledge base + NVD CVE API")
    status("Knowledge base: 47,405 chunks indexed")

    # ── Phase 3: Execute ──────────────────────────────────────────────────────
    print_phase(3, "EXECUTE", "LangChain ReAct agent  →  Metasploit RPC")
    agent_output = run_agent(targets)
    success("Agent run complete")

    # ── Phase 4: Report ───────────────────────────────────────────────────────
    print_phase(4, "REPORT", f"Writing findings to {args.output}")
    status("Generating report with Claude...")
    report = generate_report(targets, agent_output)

    with open(args.output, "w") as f:
        f.write(report)

    # Parse real findings from the generated report markdown
    findings = parse_findings_from_report(report)

    elapsed = time.time() - start
    print_report_summary(findings, args.output, elapsed)
    success(f"Report saved to {args.output}")

    # ── Shell drop ────────────────────────────────────────────────────────────
    if args.shell:
        if not targets:
            error("No target IP found")
            return

        open_ports = [str(svc["port"]) for svc in services]

        if args.shell_port:
            port = args.shell_port
        elif "1524" in open_ports:
            port = "1524"
            status("Detected Metasploitable2 — backdoor shell on port 1524")
        elif "4444" in open_ports:
            port = "4444"
            status("Detected Meterpreter shell on port 4444")
        else:
            print()
            warn(f"No backdoor port detected automatically for {target_ip}")
            port = input("  [?] Enter port to connect to (or Enter to skip): ").strip()
            if not port:
                status("Skipping shell. Connect manually:  nc <ip> <port>  or  evil-winrm")
                return

        print_shell_drop(target_ip)
        subprocess.run(["nc", target_ip, port])


if __name__ == "__main__":
    main()
