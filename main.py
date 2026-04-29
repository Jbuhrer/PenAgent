import os
import warnings
os.environ["TRANSFORMERS_VERBOSITY"] = "error"
os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
os.environ["TOKENIZERS_PARALLELISM"] = "false"
warnings.filterwarnings("ignore")

import re
import json
import time
import difflib
import argparse
import subprocess
from datetime import datetime
from pathlib import Path

from banner import (
    print_banner, print_scan_header, print_phase,
    print_shell_drop, print_report_summary,
    status, success, warn, error
)
from parser import parse_nmap
from agent import run_agent
from reporter import generate_report


# ── History directory ─────────────────────────────────────────────────────────
HISTORY_DIR = Path.home() / ".penagent" / "history"


def save_history(target_ip: str, findings: list, report_path: str, elapsed: float):
    """Save run metadata to ~/.penagent/history/"""
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    entry = {
        "timestamp":    timestamp,
        "target":       target_ip,
        "findings":     len(findings),
        "elapsed":      round(elapsed, 1),
        "report":       str(Path(report_path).resolve()),
        "top_finding":  findings[0]["title"] if findings else "none",
        "top_cvss":     findings[0]["cvss"]  if findings else 0.0,
    }

    history_file = HISTORY_DIR / f"{timestamp}_{target_ip.replace('.', '_')}.json"
    with open(history_file, "w") as f:
        json.dump(entry, f, indent=2)

    status(f"Run saved to history: {history_file.name}")
    return history_file


def print_history():
    """Print all past runs from ~/.penagent/history/"""
    from rich.table import Table
    from rich.console import Console
    from rich import box

    console = Console()

    if not HISTORY_DIR.exists() or not list(HISTORY_DIR.glob("*.json")):
        warn("No scan history found.")
        return

    tbl = Table(
        title="SCAN HISTORY",
        box=box.SIMPLE_HEAD,
        border_style="dim yellow",
        header_style="bold cyan",
        padding=(0, 1),
    )
    tbl.add_column("Timestamp",   style="dim",       width=18)
    tbl.add_column("Target",      style="cyan",      width=18)
    tbl.add_column("Findings",    style="white",     width=10)
    tbl.add_column("Top Finding", style="white",     min_width=30)
    tbl.add_column("CVSS",        style="white",     width=6)
    tbl.add_column("Time",        style="dim",       width=8)

    files = sorted(HISTORY_DIR.glob("*.json"), reverse=True)
    for f in files:
        with open(f) as fh:
            e = json.load(fh)
        cvss = e.get("top_cvss", 0.0)
        if   cvss >= 9.0: cvss_str = f"[bold red]{cvss}[/bold red]"
        elif cvss >= 7.0: cvss_str = f"[bright_red]{cvss}[/bright_red]"
        elif cvss >= 4.0: cvss_str = f"[yellow]{cvss}[/yellow]"
        else:             cvss_str = f"[green]{cvss}[/green]"

        tbl.add_row(
            e.get("timestamp", ""),
            e.get("target", ""),
            str(e.get("findings", 0)),
            e.get("top_finding", "")[:50],
            cvss_str,
            f"{e.get('elapsed', 0)}s",
        )

    console.print(tbl)


# ── Slack / Discord notification ──────────────────────────────────────────────
def notify_shell(target_ip: str, exploit: str):
    """
    Send a webhook notification when a shell is acquired.
    Set PENAGENT_WEBHOOK in your .env to a Slack or Discord webhook URL.
    """
    webhook_url = os.getenv("PENAGENT_WEBHOOK")
    if not webhook_url:
        return

    try:
        import requests
        msg = f"[PenAgent] ROOT SHELL acquired on `{target_ip}` via `{exploit}`"

        # Discord uses "content", Slack uses "text"
        if "discord" in webhook_url:
            payload = {"content": msg}
        else:
            payload = {"text": msg}

        requests.post(webhook_url, json=payload, timeout=5)
        status("Webhook notification sent")
    except Exception as e:
        warn(f"Webhook failed: {e}")


def notify_findings(target_ip: str, findings: list):
    """Send findings summary to webhook."""
    webhook_url = os.getenv("PENAGENT_WEBHOOK")
    if not webhook_url or not findings:
        return

    try:
        import requests
        critical = [f for f in findings if f["cvss"] >= 9.0]
        lines = [f"[PenAgent] Scan complete on `{target_ip}` — {len(findings)} findings"]
        if critical:
            lines.append(f"CRITICAL ({len(critical)}): " +
                         ", ".join(f["title"] for f in critical[:3]))

        msg = "\n".join(lines)
        payload = {"content": msg} if "discord" in webhook_url else {"text": msg}
        requests.post(webhook_url, json=payload, timeout=5)
    except Exception:
        pass


# ── Report diff / compare ─────────────────────────────────────────────────────
def compare_reports(report_a: str, report_b: str):
    """Diff two report files and print what changed."""
    from rich.console import Console
    from rich.text import Text

    console = Console()

    try:
        with open(report_a) as f: lines_a = f.readlines()
        with open(report_b) as f: lines_b = f.readlines()
    except FileNotFoundError as e:
        error(f"Could not open report: {e}")
        return

    diff = list(difflib.unified_diff(
        lines_a, lines_b,
        fromfile=f"Previous: {report_a}",
        tofile=f"Current:  {report_b}",
        lineterm=""
    ))

    if not diff:
        success("No differences found between reports.")
        return

    console.print()
    console.print("[bold cyan]REPORT DIFF[/bold cyan]")
    console.print("[dim]─" * 60 + "[/dim]")

    added   = 0
    removed = 0
    for line in diff:
        if line.startswith("+") and not line.startswith("+++"):
            console.print(Text(line, style="green"))
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            console.print(Text(line, style="red"))
            removed += 1
        elif line.startswith("@@"):
            console.print(Text(line, style="cyan"))
        else:
            console.print(Text(line, style="dim"))

    console.print()
    console.print(f"  [green]+{added} lines added[/green]   [red]-{removed} lines removed[/red]")
    console.print()


# ── Finding parser ────────────────────────────────────────────────────────────
def parse_findings_from_report(report_text: str) -> list:
    findings = []
    blocks = re.split(r'\n(?=###\s)', report_text)

    for block in blocks:
        if not re.search(r'CVSS|CVE|exploit|vulnerab', block, re.IGNORECASE):
            continue

        title_match = re.search(r'###\s+(?:Finding\s+\d+[:\-\s]+)?(.+)', block)
        cvss_match  = re.search(r'CVSS[^\d]*(\d+(?:\.\d+)?)', block, re.IGNORECASE)
        cve_match   = re.search(r'(CVE-\d{4}-\d+)', block, re.IGNORECASE)

        if not title_match:
            continue

        title = re.sub(r'[*#`]', '', title_match.group(1)).strip()
        if len(title) < 5:
            continue

        findings.append({
            "title": title[:55],
            "cvss":  float(cvss_match.group(1)) if cvss_match else 0.0,
            "cve":   cve_match.group(1) if cve_match else "",
        })

    seen, unique = set(), []
    for f in findings:
        if f["title"] not in seen:
            seen.add(f["title"])
            unique.append(f)

    unique.sort(key=lambda x: x["cvss"], reverse=True)
    return unique or [{"title": "See report.md for full findings", "cvss": 0.0, "cve": ""}]


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print_banner()

    p = argparse.ArgumentParser(description="PenAgent - Autonomous Penetration Testing Agent")
    p.add_argument("--scan",        required=False,      help="Path to nmap XML file")
    p.add_argument("--output",      default="report.md", help="Output report filename")
    p.add_argument("--shell",       action="store_true", help="Drop into shell after report")
    p.add_argument("--shell-port",  default=None,        help="Port to connect to for shell")
    p.add_argument("--history",     action="store_true", help="Show scan history")
    p.add_argument("--compare",     nargs=2,             metavar=("REPORT_A", "REPORT_B"),
                                                         help="Diff two report files")
    args = p.parse_args()

    # ── History mode ──────────────────────────────────────────────────────────
    if args.history:
        print_history()
        return

    # ── Compare mode ──────────────────────────────────────────────────────────
    if args.compare:
        compare_reports(args.compare[0], args.compare[1])
        return

    if not args.scan:
        error("--scan is required unless using --history or --compare")
        return

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

    findings = parse_findings_from_report(report)
    elapsed  = time.time() - start

    print_report_summary(findings, args.output, elapsed)
    success(f"Report saved to {args.output}")

    # Save to history
    save_history(target_ip, findings, args.output, elapsed)

    # Webhook: findings summary
    notify_findings(target_ip, findings)

    # ── Shell drop ────────────────────────────────────────────────────────────
    if args.shell:
        if not targets:
            error("No target IP found")
            return

        open_ports = [str(svc["port"]) for svc in services]
        exploit_used = findings[0]["title"] if findings else "unknown"

        if args.shell_port:
            port = args.shell_port
        elif "1524" in open_ports:
            port = "1524"
            status("Detected Metasploitable2 - backdoor shell on port 1524")
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

        # Webhook: shell acquired
        notify_shell(target_ip, exploit_used)

        print_shell_drop(target_ip)
        subprocess.run(["nc", target_ip, port])


if __name__ == "__main__":
    main()
