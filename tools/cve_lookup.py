import requests

def lookup_cve(keyword: str) -> str:
    """Look up CVEs for a product or service. Input: product name and version."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    try:
        r = requests.get(url, params={'keywordSearch': keyword,
                                      'resultsPerPage': 3}, timeout=10)
        data = r.json()
        out = []
        for item in data.get('vulnerabilities', []):
            cve = item['cve']
            desc = cve['descriptions'][0]['value']
            out.append(f"{cve['id']}: {desc[:200]}")
        return '\n'.join(out) if out else "No CVEs found."
    except Exception as e:
        return f"CVE lookup error: {e}"
