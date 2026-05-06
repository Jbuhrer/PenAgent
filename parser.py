"""
parser.py — nmap XML Parser

Parses nmap XML scan output into a structured list of target hosts,
each containing the host IP and a list of open services with version info.
"""

import xml.etree.ElementTree as ET


def parse_nmap(xml_file: str) -> list:
    """
    Parse an nmap XML output file into a list of target host dictionaries.

    Each target dictionary contains:
        - ip (str): The host's IP address.
        - services (list): List of open service dicts with port, protocol,
          service name, product, version, and optional vuln hints.

    Args:
        xml_file (str): Path to the nmap XML output file.

    Returns:
        list: A list of target dicts, one per host with open ports.

    Example:
        >>> targets = parse_nmap("scan.xml")
        >>> print(targets[0]["ip"])
        '192.168.211.128'
    """
    tree = ET.parse(xml_file)
    root = tree.getroot()
    targets = []

    for host in root.findall("host"):
        # Extract IP address from address element
        addr = host.find("address")
        if addr is None:
            continue
        ip = addr.get("addr")
        services = []

        for port in host.findall(".//port"):
            # Skip ports that are not open
            if port.find("state").get("state") != "open":
                continue

            svc = port.find("service")
            entry = {
                "port":     port.get("portid"),
                "protocol": port.get("protocol"),
                "service":  svc.get("name", "")    if svc is not None else "",
                "product":  svc.get("product", "") if svc is not None else "",
                "version":  svc.get("version", "") if svc is not None else "",
            }

            # Attach any NSE vulnerability script output as a hint
            for script in port.findall("script"):
                if "vuln" in script.get("id", ""):
                    entry["vuln_hint"] = script.get("output", "")[:300]

            services.append(entry)

        # Only include hosts that have at least one open service
        if services:
            targets.append({"ip": ip, "services": services})

    return targets


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python3 parser.py <nmap_xml_file>")
        sys.exit(1)

    targets = parse_nmap(sys.argv[1])
    print(json.dumps(targets, indent=2))
