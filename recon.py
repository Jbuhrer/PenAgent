"""
recon.py — Live Recon Pipeline

Replaces static nmap XML input with a multi-phase active recon orchestrator.
Drives nmap through 5 progressive phases and returns structured target data
identical to parser.parse_nmap() output so agent.py needs zero changes.

Phases:
    1. Host discovery     — ping sweep, find live hosts
    2. Port scan          — SYN scan top 1000 ports
    3. Service fingerprint— -sV -sC deep service detection
    4. OS detection       — -O fingerprinting
    5. Vuln scripts       — --script vuln on discovered services
"""

import os
import subprocess
import tempfile
import shutil
from pathlib import Path
from parser import parse_nmap
from banner import status, success, warn, error


def _nmap_available() -> bool:
    return shutil.which("nmap") is not None


def _run_nmap(args: list, output_xml: str, label: str) -> bool:
    """
    Run an nmap command and save XML output.

    Args:
        args: nmap argument list (without -oX)
        output_xml: path to write XML output
        label: phase label for status messages

    Returns:
        True if nmap exited cleanly, False otherwise
    """
    cmd = ["nmap"] + args + ["-oX", output_xml, "--open"]
    status(f"{label}: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=900
        )
        if result.returncode != 0:
            warn(f"{label} returned non-zero: {result.stderr[:200]}")
            return False
        return True
    except subprocess.TimeoutExpired:
        warn(f"{label} timed out after 300s")
        return False
    except Exception as e:
        error(f"{label} failed: {e}")
        return False


def run_recon(
    target: str,
    stealth: bool = False,
    skip_vuln: bool = False,
    work_dir: str = None
) -> tuple[list, str]:
    """
    Run the full multi-phase recon pipeline against a target.

    Args:
        target:     IP, range, or CIDR — e.g. '10.10.10.5' or '192.168.1.0/24'
        stealth:    If True, use slower timing (-T2) to avoid detection
        skip_vuln:  If True, skip Phase 5 vuln scripts (faster)
        work_dir:   Directory to save intermediate XML files (temp if None)

    Returns:
        tuple: (targets_list, final_xml_path)
            targets_list — same format as parser.parse_nmap() output
            final_xml_path — path to the deepest scan XML (for --scan compat)
    """
    if not _nmap_available():
        error("nmap not found. Install with: sudo apt install nmap")
        raise RuntimeError("nmap not found")

    timing = "-T2" if stealth else "-T4"

    # Set up working directory
    cleanup = False
    if work_dir is None:
        work_dir = tempfile.mkdtemp(prefix="penagent_recon_")
        cleanup = False  # keep for debugging; set True to auto-clean

    work_path = Path(work_dir)
    work_path.mkdir(parents=True, exist_ok=True)

    status(f"Recon target: {target}  |  stealth={stealth}  |  timing={timing}")

    # ── Phase 1: Host Discovery ───────────────────────────────────────────────
    # Skip ping sweep for single IPs — saves 30-60s
    import re as _re
    is_single_ip = bool(_re.match(r"^\d+\.\d+\.\d+\.\d+$", target.strip()))
    status("Phase 1/5 — Host discovery" + (" (skipped — single IP)" if is_single_ip else ""))
    discovery_xml = str(work_path / "phase1_discovery.xml")
    if not is_single_ip:
        _run_nmap(
            ["-sn", timing, target],
            discovery_xml,
            "host-discovery"
        )

    # ── Phase 2+3: Port Scan + Service Fingerprint (combined) ───────────────
    status("Phase 2/5 — Port scan + service fingerprint (combined)")
    portscan_xml = str(work_path / "phase2_portscan.xml")
    _run_nmap(
        ["-sS", "-sV", "-sC", "--top-ports", "1000", "--version-intensity", "5", timing, target],
        portscan_xml,
        "port-scan+service"
    )

    try:
        port_targets = parse_nmap(portscan_xml)
    except Exception:
        port_targets = []

    if not port_targets:
        warn("No open ports found. Trying with -Pn.")
        _run_nmap(
            ["-sS", "-sV", "-Pn", "--top-ports", "1000", "--version-intensity", "5", timing, target],
            portscan_xml,
            "port-scan-noping"
        )
        try:
            port_targets = parse_nmap(portscan_xml)
        except Exception:
            port_targets = []

    if not port_targets:
        warn("No hosts responded. Check target is reachable and in scope.")
        return [], portscan_xml

    live_ips = " ".join(t["ip"] for t in port_targets)
    status(f"Live hosts: {live_ips}")

    service_xml = portscan_xml
    service_targets = port_targets
    status("Phase 3/5 — Service fingerprint (done in phase 2)")

    # ── Phase 4: OS Detection (non-blocking, best-effort) ────────────────────
    status("Phase 4/5 — OS detection (-O)")
    os_xml = str(work_path / "phase4_os.xml")
    _run_nmap(
        ["-O", "--osscan-guess", "--max-os-tries", "1", timing, live_ips],
        os_xml,
        "os-detection"
    )

    # Enrich service_targets with OS info if detected
    try:
        import xml.etree.ElementTree as ET
        os_tree = ET.parse(os_xml)
        os_map = {}
        for host in os_tree.getroot().findall("host"):
            addr = host.find("address")
            if addr is None:
                continue
            ip = addr.get("addr")
            osmatch = host.find(".//osmatch")
            if osmatch is not None:
                os_map[ip] = {
                    "os_name": osmatch.get("name", ""),
                    "os_accuracy": osmatch.get("accuracy", ""),
                }
        for t in service_targets:
            if t["ip"] in os_map:
                t.update(os_map[t["ip"]])
    except Exception:
        pass  # OS enrichment is best-effort

    # ── Phase 5: Vuln Scripts (removed — RAG+CVE lookup covers this) ─────────
    final_xml = service_xml
    status("Phase 5/5 — Skipped (RAG knowledge base + NVD CVE API used instead)")

    total_services = sum(len(t.get("services", [])) for t in service_targets)
    success(f"Recon complete — {len(service_targets)} host(s), {total_services} services")
    success(f"Scan data saved to: {work_dir}")

    return service_targets, final_xml
