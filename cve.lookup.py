"""
cve_lookup.py — Query NIST's National Vulnerability Database for CVE details.

Usage:
    python3 cve_lookup.py CVE-2021-44228
    python3 cve_lookup.py CVE-2024-3094 CVE-2023-4966

What it does:
    Takes one or more CVE IDs and pulls back the description, CVSS score,
    severity, and whether known exploits exist. Like searching the NVD
    website but scriptable — useful for bulk lookups or piping into reports.
"""

import sys
import requests


def lookup_cve(cve_id):
    """Query NVD API for a single CVE and return structured results."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"[ERROR] Failed to query NVD for {cve_id}: {e}")
        return None

    data = response.json()
    vulns = data.get("vulnerabilities", [])

    if not vulns:
        print(f"[NOT FOUND] {cve_id} not found in NVD.")
        return None

    cve = vulns[0]["cve"]
    description = cve["descriptions"][0]["value"]
    metrics = cve.get("metrics", {})

    # Try CVSS v3.1 first, fall back to v3.0, then v2
    score = "N/A"
    severity = "N/A"
    vector = "N/A"

    if "cvssMetricV31" in metrics:
        cvss = metrics["cvssMetricV31"][0]["cvssData"]
        score = cvss["baseScore"]
        severity = cvss["baseSeverity"]
        vector = cvss.get("attackVector", "N/A")
    elif "cvssMetricV30" in metrics:
        cvss = metrics["cvssMetricV30"][0]["cvssData"]
        score = cvss["baseScore"]
        severity = cvss["baseSeverity"]
        vector = cvss.get("attackVector", "N/A")
    elif "cvssMetricV2" in metrics:
        cvss = metrics["cvssMetricV2"][0]["cvssData"]
        score = cvss["baseScore"]
        severity = "See v2 scoring"

    result = {
        "cve_id": cve_id,
        "score": score,
        "severity": severity,
        "attack_vector": vector,
        "description": description
    }

    return result


def print_result(result):
    """Display CVE lookup results in a readable format."""
    if not result:
        return

    print(f"\n{'='*60}")
    print(f"  CVE ID:         {result['cve_id']}")
    print(f"  CVSS Score:     {result['score']}")
    print(f"  Severity:       {result['severity']}")
    print(f"  Attack Vector:  {result['attack_vector']}")
    print(f"  Description:    {result['description'][:200]}...")
    print(f"{'='*60}")

    # Flag critical/high for immediate attention
    if isinstance(result["score"], (int, float)):
        if result["score"] >= 9.0:
            print("  🔴 CRITICAL — prioritize remediation immediately")
        elif result["score"] >= 7.0:
            print("  🟠 HIGH — remediate within SLA window")
        elif result["score"] >= 4.0:
            print("  🟡 MEDIUM — schedule for next maintenance cycle")
        else:
            print("  🟢 LOW — monitor and remediate as capacity allows")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 cve_lookup.py CVE-2021-44228 [CVE-2024-3094 ...]")
        sys.exit(1)

    cve_ids = sys.argv[1:]
    print(f"Looking up {len(cve_ids)} CVE(s)...")

    for cve_id in cve_ids:
        result = lookup_cve(cve_id.strip().upper())
        print_result(result)
