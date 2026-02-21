"""
ip_reputation.py — Check IP addresses against AbuseIPDB threat intelligence.

Usage:
    python3 ip_reputation.py 118.25.6.39
    python3 ip_reputation.py --file suspicious_ips.txt

What it does:
    Takes IPs (from command line or a file) and checks them against
    AbuseIPDB — a community threat intel database. Returns abuse score,
    country, ISP, and report count. Useful for triaging IPs found in
    your logs (pairs well with log_analyzer.py).

    Get a free API key at: https://www.abuseipdb.com
    Set it as: export ABUSEIPDB_KEY="your_key_here"
"""

import os
import sys
import requests

API_URL = "https://api.abuseipdb.com/api/v2/check"


def get_api_key():
    """Get API key from environment variable."""
    key = os.environ.get("ABUSEIPDB_KEY")
    if not key:
        print("[ERROR] Set your API key:")
        print("  export ABUSEIPDB_KEY='your_key_here'")
        print("  Get a free key at: https://www.abuseipdb.com")
        sys.exit(1)
    return key


def check_ip(ip_address, api_key):
    """Query AbuseIPDB for a single IP address."""
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": 90}

    try:
        response = requests.get(API_URL, headers=headers,
                                params=params, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"  [ERROR] Failed to check {ip_address}: {e}")
        return None

    return response.json().get("data")


def assess_risk(score):
    """Classify risk level based on abuse confidence score."""
    if score >= 75:
        return "HIGH", "🔴"
    elif score >= 25:
        return "MODERATE", "🟡"
    else:
        return "LOW", "🟢"


def print_result(data):
    """Display IP reputation results."""
    if not data:
        return

    score = data["abuseConfidenceScore"]
    risk_level, icon = assess_risk(score)

    print(f"\n  IP:              {data['ipAddress']}")
    print(f"  Abuse Score:     {score}%")
    print(f"  Risk Level:      {icon} {risk_level}")
    print(f"  Country:         {data.get('countryCode', 'Unknown')}")
    print(f"  ISP:             {data.get('isp', 'Unknown')}")
    print(f"  Total Reports:   {data.get('totalReports', 0)}")
    print(f"  Last Reported:   {data.get('lastReportedAt', 'Never')}")

    if score >= 75:
        print(f"  ⚠️  RECOMMENDATION: Block this IP at the firewall")
    elif score >= 25:
        print(f"  ⚠️  RECOMMENDATION: Investigate activity from this IP")


def check_multiple_ips(filepath, api_key):
    """Check a file of IPs (one per line)."""
    with open(filepath, "r") as f:
        ips = [line.strip() for line in f if line.strip()]

    print(f"\nChecking {len(ips)} IP(s)...\n")
    print("=" * 55)

    results = {"HIGH": [], "MODERATE": [], "LOW": []}

    for ip in ips:
        data = check_ip(ip, api_key)
        if data:
            print_result(data)
            risk_level, _ = assess_risk(data["abuseConfidenceScore"])
            results[risk_level].append(ip)

    # Summary
    print("\n" + "=" * 55)
    print("  SUMMARY")
    print("=" * 55)
    print(f"  🔴 High Risk:      {len(results['HIGH'])}")
    print(f"  🟡 Moderate Risk:  {len(results['MODERATE'])}")
    print(f"  🟢 Low Risk:       {len(results['LOW'])}")

    if results["HIGH"]:
        print(f"\n  Block list:")
        for ip in results["HIGH"]:
            print(f"    {ip}")

    print("=" * 55)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 ip_reputation.py <ip_address>")
        print("  python3 ip_reputation.py --file suspicious_ips.txt")
        print("\nRequires ABUSEIPDB_KEY environment variable.")
        sys.exit(1)

    api_key = get_api_key()

    if sys.argv[1] == "--file":
        if len(sys.argv) < 3:
            print("[ERROR] Provide a file path: --file ips.txt")
            sys.exit(1)
        check_multiple_ips(sys.argv[2], api_key)
    else:
        data = check_ip(sys.argv[1], api_key)
        print_result(data)
