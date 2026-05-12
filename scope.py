"""
scope.py — Scope Enforcement Module

Hard scope controls for real engagements. Every tool call checks against
a scope.yaml before executing. Blocks out-of-scope targets with logging.

scope.yaml format:
    targets:
      - 10.10.10.0/24
      - 192.168.1.50-100
      - 10.10.10.5
    excluded:
      - 10.10.10.1
      - 10.10.10.254
    allowed_ports: [80, 443, 22, 8080, 8443]   # empty = all ports allowed
    max_scan_rate: 500                          # packets/sec (0 = no limit)
    stealth_mode: false
"""

import ipaddress
import re
import yaml
import logging
from pathlib import Path
from datetime import datetime

# ── Scope violation log ───────────────────────────────────────────────────────
LOG_DIR = Path.home() / ".penagent" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
_scope_log = LOG_DIR / f"scope_{datetime.now().strftime('%Y%m%d')}.log"

logging.basicConfig(
    filename=str(_scope_log),
    level=logging.WARNING,
    format="%(asctime)s  SCOPE  %(message)s",
)


class ScopeViolation(Exception):
    """Raised when an action targets an out-of-scope host or port."""
    pass


class Scope:
    """
    Loads and enforces a scope definition from a YAML file.

    Args:
        scope_file (str): Path to scope.yaml. If None, all targets allowed.
    """

    def __init__(self, scope_file: str = None):
        self.enabled = False
        self.allowed_networks = []
        self.excluded_ips = set()
        self.allowed_ports = set()
        self.max_scan_rate = 0
        self.stealth_mode = False
        self.scope_file = scope_file

        if scope_file and Path(scope_file).exists():
            self._load(scope_file)
        elif scope_file:
            raise FileNotFoundError(f"Scope file not found: {scope_file}")

    def _load(self, path: str):
        with open(path) as f:
            data = yaml.safe_load(f)

        self.enabled = True
        raw_targets  = data.get("targets", [])
        raw_excluded = data.get("excluded", [])
        raw_ports    = data.get("allowed_ports", [])

        self.max_scan_rate = int(data.get("max_scan_rate", 0))
        self.stealth_mode  = bool(data.get("stealth_mode", False))

        # Parse allowed targets into networks or ranges
        for entry in raw_targets:
            entry = str(entry).strip()
            # Range format: 192.168.1.50-100
            if re.match(r"^\d+\.\d+\.\d+\.\d+-\d+$", entry):
                self.allowed_networks.append(("range", entry))
            else:
                try:
                    net = ipaddress.ip_network(entry, strict=False)
                    self.allowed_networks.append(("network", net))
                except ValueError:
                    try:
                        ip = ipaddress.ip_address(entry)
                        net = ipaddress.ip_network(ip)
                        self.allowed_networks.append(("network", net))
                    except ValueError:
                        pass

        # Parse excluded IPs
        for entry in raw_excluded:
            try:
                self.excluded_ips.add(str(ipaddress.ip_address(str(entry).strip())))
            except ValueError:
                pass

        # Parse allowed ports
        for p in raw_ports:
            if isinstance(p, int):
                self.allowed_ports.add(p)
            elif isinstance(p, str) and "-" in p:
                lo, hi = p.split("-")
                self.allowed_ports.update(range(int(lo), int(hi) + 1))
            else:
                try:
                    self.allowed_ports.add(int(p))
                except ValueError:
                    pass

    def _ip_in_range(self, ip: str, range_str: str) -> bool:
        """Check if IP falls within a x.x.x.low-high range string."""
        parts = range_str.rsplit("-", 1)
        base  = parts[0]
        hi    = int(parts[1])
        base_parts = base.split(".")
        lo = int(base_parts[-1])
        prefix = ".".join(base_parts[:-1])
        try:
            last_octet = int(ip.split(".")[-1])
            ip_prefix  = ".".join(ip.split(".")[:-1])
            return ip_prefix == prefix and lo <= last_octet <= hi
        except (ValueError, IndexError):
            return False

    def ip_allowed(self, ip: str) -> bool:
        """
        Check if an IP address is within scope.

        Args:
            ip: IP address string to check.

        Returns:
            True if in scope, False otherwise.
        """
        if not self.enabled:
            return True

        # Exclusions are hard blocks regardless of target list
        if ip in self.excluded_ips:
            return False

        if not self.allowed_networks:
            return True

        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False

        for kind, net in self.allowed_networks:
            if kind == "network" and ip_obj in net:
                return True
            if kind == "range" and self._ip_in_range(ip, net):
                return True

        return False

    def port_allowed(self, port: int) -> bool:
        """
        Check if a port is within scope.

        Args:
            port: Port number to check.

        Returns:
            True if allowed (or no port restriction defined).
        """
        if not self.enabled or not self.allowed_ports:
            return True
        return int(port) in self.allowed_ports

    def check(self, ip: str, port: int = None, action: str = "access"):
        """
        Assert that an IP (and optional port) is in scope.
        Logs and raises ScopeViolation if not.

        Args:
            ip:     Target IP address.
            port:   Target port (optional).
            action: Description of what was being attempted (for logging).

        Raises:
            ScopeViolation: If IP or port is out of scope.
        """
        if not self.ip_allowed(ip):
            msg = f"OUT-OF-SCOPE IP blocked — {action} on {ip}"
            logging.warning(msg)
            raise ScopeViolation(f"[SCOPE] {msg}")

        if port is not None and not self.port_allowed(port):
            msg = f"OUT-OF-SCOPE PORT blocked — {action} on {ip}:{port}"
            logging.warning(msg)
            raise ScopeViolation(f"[SCOPE] {msg}")

    def filter_targets(self, targets: list) -> list:
        """
        Filter a targets list (from parser/recon) to only in-scope hosts and ports.

        Args:
            targets: List of target dicts from parse_nmap() or run_recon().

        Returns:
            Filtered list with out-of-scope hosts/ports removed.
        """
        if not self.enabled:
            return targets

        filtered = []
        for t in targets:
            ip = t.get("ip", "")
            if not self.ip_allowed(ip):
                logging.warning(f"Host removed from target list (out of scope): {ip}")
                continue

            # Filter services by allowed ports
            if self.allowed_ports:
                in_scope_svcs = [
                    s for s in t.get("services", [])
                    if self.port_allowed(int(s.get("port", 0)))
                ]
                t = {**t, "services": in_scope_svcs}

            filtered.append(t)

        return filtered

    def summary(self) -> str:
        """Return a human-readable scope summary."""
        if not self.enabled:
            return "Scope: UNRESTRICTED (no scope file loaded)"

        nets = []
        for kind, net in self.allowed_networks:
            nets.append(str(net))

        lines = [
            f"Scope file:    {self.scope_file}",
            f"Targets:       {', '.join(nets) if nets else 'all'}",
            f"Excluded IPs:  {', '.join(self.excluded_ips) if self.excluded_ips else 'none'}",
            f"Allowed ports: {sorted(self.allowed_ports) if self.allowed_ports else 'all'}",
            f"Stealth mode:  {self.stealth_mode}",
            f"Max scan rate: {self.max_scan_rate if self.max_scan_rate else 'unlimited'} pps",
            f"Violation log: {_scope_log}",
        ]
        return "\n".join(lines)


def generate_scope_template(output_path: str = "scope.yaml"):
    """Write a commented scope.yaml template to disk."""
    template = """\
# PenAgent Scope Definition
# --------------------------
# Define the authorized target range for this engagement.
# PenAgent will hard-block any action outside these bounds.

targets:
  - 10.10.10.0/24          # CIDR range
  - 192.168.1.50-100       # IP range
  - 10.10.10.5             # Single host

excluded:
  - 10.10.10.1             # Gateway — do not touch
  - 10.10.10.254           # Management interface

# Leave empty to allow all ports
allowed_ports:
  - 22
  - 80
  - 443
  - 8080
  - 8443

# Packets per second — set low for stealth engagements
max_scan_rate: 500

# Slow timing (-T2) to evade IDS
stealth_mode: false
"""
    with open(output_path, "w") as f:
        f.write(template)
    return output_path
