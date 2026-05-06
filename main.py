"""
main.py — PenAgent CLI Entry Point

Orchestrates the full penetration testing pipeline:
    1. Parse nmap XML into structured target data
    2. Retrieve exploits via hybrid RAG + CVE lookup
    3. Execute ReAct agent against each target
    4. Generate consolidated professional report
    5. Optional interactive shell drop

Additional modes:
    --history   display table of all past runs
    --compare   diff two report files
"""

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
    status, success, warn, error, console
)
from parser import parse_nmap
from agent import run_agent
from reporter import generate_report


# ── History ───────────────────────────────────────────────────────────────────
HISTORY_DIR = Path.home() / ".penagent" / "history"


def save_history(targets: list, findings: list, report_path: str, elapsed: float):
    """Save run metadata to ~/.penagent/history/ as a JSON file."""
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    ips = [t["ip"] for t in targets]
    entry = {
        "timestamp":   timestamp,
        "targets":     ips,
        "host_count":  len(targets),
        "findings":    len(findings),
        "elapsed":     round(elapsed, 1),
        "report":      str(Path(report_path).resolve()),
        "top_finding": findings[0]["title"] if findings else "none",
        "top_cvss":    findings[0]["cvss"]  if findings else 0.0,
    }
    label = ips[0].replace(".", "_") if len(ips) == 1 else f"{len(ips)}_hosts"
    history_file = HISTORY_DIR / f"{timestamp}_{label}.json"
    with open(history_file, "w") as f:
        json.dump(entry, f, indent=2)
    status(f"Run saved to history: {history_file.name}")


def print_history():
    """Print a formatted table of all past PenAgent runs."""
    from rich.table import Table
    from rich import box as rbox

    if not HISTORY_DIR.exists() or not list(HISTORY_DIR.glob("*.json")):
        warn("No scan history found.")
        return

    tbl = Table(
        title="SCAN HISTORY",
        box=rbox.SIMPLE_HEAD,
        border_style="dim yellow",
        header_style="bold cyan",
        padding=(0, 1),
    )
    tbl.add_column("Timestamp",   style="dim",   width=18)
    tbl.add_column("Targets",     style="cyan",  width=22)
    tbl.add_column("Hosts",       style="white", width=6)
    tbl.add_column("Findings",    style="white", width=10)
    tbl.add_column("Top Finding", style="white", min_width=28)
    tbl.add_column("CVSS",        style="white", width=6)
    tbl.add_column("Time",        style="dim",   width=8)

    for f in sorted(HISTORY_DIR.glob("*.json"), reverse=True):
        with open(f) as fh:
            e = json.load(fh)
        cvss = e.get("top_cvss", 0.0)
        if   cvss >= 9.0: cs = f"[bold red]{cvss}[/bold red]"
        elif cvss >= 7.0: cs = f"[bright_red]{cvss}[/bright_red]"
        elif cvss >= 4.0: cs = f"[yellow]{cvss}[/yellow]"
        else:             cs = f"[green]{cvss}[/green]"
        targets_str = ", ".join(e.get("targets", [e.get("target", "?")]))[:20]
        tbl.add_row(
            e.get("timestamp", ""),
            targets_str,
            str(e.get("host_count", 1)),
            str(e.get("findings", 0)),
            e.get("top_finding", "")[:40],
            cs,
            f"{e.get('elapsed', 0)}s",
        )
    console.print(tbl)


# ── Webhooks ──────────────────────────────────────────────────────────────────
def notify_shell(target_ip: str, exploit: str):
    """Send a webhook notification when a root shell is acquired."""
    webhook_url = os.getenv("PENAGENT_WEBHOOK")
    if not webhook_url:
        return
    try:
        import requests
        msg = f"[PenAgent] ROOT SHELL acquired on `{target_ip}` via `{exploit}`"
        payload = {"content": msg} if "discord" in webhook_url else {"text": msg}
        requests.post(webhook_url, json=payload, timeout=5)
        status("Webhook notification sent")
    except Exception as e:
        warn(f"Webhook failed: {e}")


def notify_findings(targets: list, findings: list):
    """Send a webhook notification summarizing findings after report generation."""
    webhook_url = os.getenv("PENAGENT_WEBHOOK")
    if not webhook_url or not findings:
        return
    try:
        import requests
        ips = ", ".join(t["ip"] for t in targets)
        critical = [f for f in findings if f["cvss"] >= 9.0]
        lines = [f"[PenAgent] Scan complete on `{ips}` — {len(findings)} findings across {len(targets)} host(s)"]
        if critical:
            lines.append(f"CRITICAL ({len(critical)}): " + ", ".join(f["title"] for f in critical[:3]))
        msg = "\n".join(lines)
        payload = {"content": msg} if "discord" in webhook_url else {"text": msg}
        requests.post(webhook_url, json=payload, timeout=5)
    except Exception:
        pass


# ── Compare ───────────────────────────────────────────────────────────────────
def compare_reports(report_a: str, report_b: str):
    """Diff two report files and print additions/removals with color."""
    from rich.text import Text
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
        lineterm="",
    ))

    if not diff:
        success("No differences found between reports.")
        return

    console.print()
    console.print("[bold cyan]REPORT DIFF[/bold cyan]")
    console.print("[dim]" + "─" * 60 + "[/dim]")
    added = removed = 0
    for line in diff:
        if line.startswith("+") and not line.startswith("+++"):
            console.print(Text(line, style="green")); added += 1
        elif line.startswith("-") and not line.startswith("---"):
            console.print(Text(line, style="red")); removed += 1
        elif line.startswith("@@"):
            console.print(Text(line, style="cyan"))
        else:
            console.print(Text(line, style="dim"))
    console.print()
    console.print(f"  [green]+{added} lines added[/green]   [red]-{removed} lines removed[/red]")
    console.print()


# ── Finding parser ────────────────────────────────────────────────────────────
def parse_findings_from_report(report_text: str) -> list:
    """
    Extract structured findings from the generated markdown report.

    Splits on '## Finding' headers and pulls out title, CVSS score,
    CVE reference, and host IP from each finding block.

    Args:
        report_text (str): Full markdown report text.

    Returns:
        list: List of finding dicts with title, cvss, cve, host keys.
    """
    findings = []
    blocks = re.split(r'\n(?=## Finding)', report_text)
    for block in blocks:
        if not block.strip().startswith("## Finding"):
            continue
        title_match = re.search(r'^## Finding\s+\d+\s*[-—]+\s*(.+)', block, re.MULTILINE)
        cvss_match  = re.search(r'\|\s*\*?\*?CVSS[^|]*Score\*?\*?\s*\|\s*\*?\*?(\d+\.\d+)\*?\*?\s*\|', block, re.IGNORECASE)
        cve_match   = re.search(r'\|\s*\*?\*?CVE\*?\*?\s*\|\s*(CVE-\d{4}-\d+)', block, re.IGNORECASE)
        host_match  = re.search(r'\|\s*\*?\*?Host\*?\*?\s*\|\s*(\d+\.\d+\.\d+\.\d+)', block, re.IGNORECASE)

        if not title_match:
            continue
        title = re.sub(r'[*#`]', '', title_match.group(1)).strip()
        if len(title) < 5:
            continue
        findings.append({
            "title": title[:55],
            "cvss":  float(cvss_match.group(1)) if cvss_match else 0.0,
            "cve":   cve_match.group(1) if cve_match else "",
            "host":  host_match.group(1) if host_match else "",
        })

    seen, unique = set(), []
    for f in findings:
        if f["title"] not in seen:
            seen.add(f["title"])
            unique.append(f)
    unique.sort(key=lambda x: x["cvss"], reverse=True)
    return unique or [{"title": "See report.md for full findings", "cvss": 0.0, "cve": "", "host": ""}]


# ── Shell selector ────────────────────────────────────────────────────────────
def drop_shell(targets: list, findings: list, shell_port: str = None):
    """
    Handle interactive shell drop for single or multiple targets.

    For single targets, connects immediately. For multiple targets,
    presents a selection menu.

    Args:
        targets (list): List of parsed target dicts.
        findings (list): Parsed findings list (used to identify exploit used).
        shell_port (str): Optional manually specified port override.
    """
    if len(targets) == 1:
        _connect_shell(targets[0], findings, shell_port)
    else:
        console.print()
        console.print("[bold cyan]  Multiple targets — select a host to connect to:[/bold cyan]")
        for i, t in enumerate(targets, 1):
            console.print(f"    [{i}] {t['ip']}")
        console.print("    [0] Skip")
        console.print()

        choice = input("  [?] Enter number: ").strip()
        if choice == "0" or not choice:
            status("Skipping shell.")
            return
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(targets):
                _connect_shell(targets[idx], findings, shell_port)
            else:
                warn("Invalid choice.")
        except ValueError:
            warn("Invalid input.")


def _connect_shell(target: dict, findings: list, shell_port: str = None):
    """
    Connect to a shell on the target host via netcat.

    Auto-detects common backdoor ports (1524 for Metasploitable2,
    4444 for Meterpreter) or prompts the user if none are found.

    Args:
        target (dict): Target dict with 'ip' and 'services'.
        findings (list): Findings list for webhook notification.
        shell_port (str): Optional manually specified port override.
    """
    ip = target["ip"]
    open_ports = [str(svc["port"]) for svc in target.get("services", [])]
    exploit_used = findings[0]["title"] if findings else "unknown"

    if shell_port:
        port = shell_port
    elif "1524" in open_ports:
        port = "1524"
        status("Detected Metasploitable2 — backdoor shell on port 1524")
    elif "4444" in open_ports:
        port = "4444"
        status("Detected Meterpreter shell on port 4444")
    else:
        warn(f"No backdoor port detected automatically for {ip}")
        port = input("  [?] Enter port to connect to (or Enter to skip): ").strip()
        if not port:
            status(f"Skipping {ip}. Connect manually:  nc {ip} <port>")
            return

    notify_shell(ip, exploit_used)
    print_shell_drop(ip)
    subprocess.run(["nc", ip, port])


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    """
    Main entry point for PenAgent.

    Parses CLI arguments, runs the appropriate mode (history, compare,
    or full pipeline), and handles output and shell drop.
    """
    print_banner()

    p = argparse.ArgumentParser(
        description="PenAgent - Autonomous Penetration Testing Agent",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("--scan",       required=False,      help="Path to nmap XML file")
    p.add_argument("--output",     default="report.md", help="Output report filename (default: report.md)")
    p.add_argument("--shell",      action="store_true", help="Drop into interactive shell after exploitation")
    p.add_argument("--shell-port", default=None,        help="Manually specify shell port (overrides auto-detect)")
    p.add_argument("--history",    action="store_true", help="Show table of all past runs")
    p.add_argument("--compare",    nargs=2,             metavar=("REPORT_A", "REPORT_B"),
                                                        help="Diff two report files")

    # ── Service scope flags ───────────────────────────────────────────────────
    scope = p.add_mutually_exclusive_group()
    scope.add_argument(
        "--services",
        nargs="+",
        metavar="PORT",
        help=(
            "Target specific ports only, e.g. --services 21 445 3306\n"
            "Agent will only investigate services on these ports."
        ),
    )
    scope.add_argument(
        "--full",
        action="store_true",
        help=(
            "Investigate ALL discovered services (slowest, most thorough).\n"
            "Warning: significantly increases API usage and runtime."
        ),
    )
    # Default (no flag) = priority mode: top 6 highest-value services only

    args = p.parse_args()

    # ── Utility modes ─────────────────────────────────────────────────────────
    if args.history:
        print_history()
        return

    if args.compare:
        compare_reports(args.compare[0], args.compare[1])
        return

    if not args.scan:
        error("--scan is required unless using --history or --compare")
        return

    # ── Determine service scope mode ──────────────────────────────────────────
    if args.full:
        mode = "full"
        ports = None
    elif args.services:
        mode = "targeted"
        ports = [str(p) for p in args.services]
    else:
        mode = "default"
        ports = None

    start = time.time()

    # ── Phase 1: Parse ────────────────────────────────────────────────────────
    print_phase(1, "PARSE", f"Loading {args.scan}")
    targets = parse_nmap(args.scan)
    total_services = sum(len(t.get("services", [])) for t in targets)
    status(f"{len(targets)} host(s) found  |  {total_services} total services fingerprinted")

    # Display mode info so user knows what's being investigated
    if mode == "default":
        status("Mode: DEFAULT — top 6 priority services per host")
    elif mode == "targeted":
        status(f"Mode: TARGETED — ports {', '.join(ports)}")
    elif mode == "full":
        status(f"Mode: FULL — all {total_services} services (this will take a while)")

    for t in targets:
        print_scan_header(t["ip"], args.scan)

    # ── Phase 2: Retrieve ─────────────────────────────────────────────────────
    print_phase(2, "RETRIEVE", "Querying RAG knowledge base + NVD CVE API")
    status("Knowledge base: 47,405 chunks indexed")

    # ── Phase 3: Execute ──────────────────────────────────────────────────────
    print_phase(3, "EXECUTE", f"LangChain ReAct agent  →  Metasploit RPC  ({len(targets)} host(s))")
    agent_results = run_agent(targets, mode=mode, ports=ports)
    for ip in agent_results:
        success(f"Agent complete for {ip}")

    # ── Phase 4: Report ───────────────────────────────────────────────────────
    print_phase(4, "REPORT", f"Writing findings to {args.output}")
    status("Generating consolidated report with Claude...")
    report = generate_report(targets, agent_results)

    with open(args.output, "w") as f:
        f.write(report)

    findings = parse_findings_from_report(report)
    elapsed  = time.time() - start

    print_report_summary(findings, args.output, elapsed)
    success(f"Report saved to {args.output}")

    save_history(targets, findings, args.output, elapsed)
    notify_findings(targets, findings)

    # ── Shell drop ────────────────────────────────────────────────────────────
    if args.shell:
        if not targets:
            error("No targets found")
            return
        drop_shell(targets, findings, args.shell_port)


if __name__ == "__main__":
    main()
