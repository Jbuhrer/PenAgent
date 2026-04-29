import xml.etree.ElementTree as ET

def parse_nmap(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    targets = []

    for host in root.findall('host'):
        addr = host.find('address')
        if addr is None:
            continue
        ip = addr.get('addr')
        services = []

        for port in host.findall('.//port'):
            if port.find('state').get('state') != 'open':
                continue
            svc = port.find('service')
            entry = {
                'port': port.get('portid'),
                'protocol': port.get('protocol'),
                'service': svc.get('name', '') if svc else '',
                'product': svc.get('product', '') if svc else '',
                'version': svc.get('version', '') if svc else '',
            }
            for script in port.findall('script'):
                if 'vuln' in script.get('id', ''):
                    entry['vuln_hint'] = script.get('output', '')[:300]
            services.append(entry)

        if services:
            targets.append({'ip': ip, 'services': services})

    return targets


if __name__ == '__main__':
    import sys, json
    targets = parse_nmap(sys.argv[1])
    print(json.dumps(targets, indent=2))
