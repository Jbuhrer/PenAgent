"""
reporter.py — Penetration Test Report Generator

Uses Claude Sonnet via the Anthropic API to synthesize agent findings
into a structured professional penetration test report in markdown format.
"""

import anthropic
import os
from dotenv import load_dotenv

load_dotenv()


def generate_report(targets: list, agent_output: dict) -> str:
    """
    Generate a consolidated penetration test report for all assessed targets.

    Constructs a prompt from the target profiles and per-host agent findings,
    then calls Claude Sonnet to produce a structured markdown report including
    executive summary, methodology, per-finding details with CVSS scores and
    CVE references, exploitation evidence, quick-access commands, and remediation.

    Args:
        targets (list): List of target dicts from parser.parse_nmap(), each
                        containing 'ip' and 'services'.
        agent_output (dict): Dict keyed by IP address mapping to the agent's
                             final findings string for that host.

    Returns:
        str: Full penetration test report in markdown format.

    Example:
        >>> report = generate_report(targets, {"192.168.1.1": "Found vsftpd backdoor..."})
        >>> with open("report.md", "w") as f:
        ...     f.write(report)
    """
    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

    # Build per-host findings sections for the prompt
    host_sections = []
    for target in targets:
        ip = target.get("ip", "unknown")
        output = agent_output.get(ip, "No output recorded.")
        host_sections.append(f"### Host: {ip}\n{output}")

    hosts_text = "\n\n".join(host_sections)
    num_hosts = len(targets)

    prompt = f"""You are writing a professional penetration test report covering {num_hosts} target host(s).

Targets assessed:
{targets}

Agent findings per host:
{hosts_text}

Write a professional report with these sections:

1. Executive Summary
   - Overall risk rating
   - Number of hosts assessed
   - Key findings across all hosts
   - Business impact

2. Scope and Methodology

3. Findings
   For EACH host, list its findings. For each finding include:
   - ## Finding N - Title
   - A metadata table with: Host IP, CVE, CVSS v3.1 Score, CVSS v3.1 Vector, Severity
   - ### Description
   - ### Evidence
   - ### Quick Access Commands
     Include exact terminal commands to reproduce exploitation.
     Use real IP addresses from the target profile above.
   - ### Remediation

4. Quick Reference
   A single consolidated table of ALL quick access commands from every finding,
   organized by host IP and port number.

Be specific. Use actual IPs, ports, service versions, and exploit outcomes.
Group findings clearly by host when multiple hosts are present.
"""

    msg = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=8000,
        messages=[{"role": "user", "content": prompt}],
    )
    return msg.content[0].text
