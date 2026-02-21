"""
sla_monitor.py — Monitor vulnerability SLA compliance and generate reports.

Usage:
    python3 sla_monitor.py

What it does:
    Reads a list of vulnerabilities (from CSV or JSON), calculates SLA
    deadlines based on severity, and produces a compliance report showing
    what's on track, what's at risk, and what's overdue. This is the kind
    of report you'd present in a weekly remediation forum or send to
    leadership.

    In a real environment, this would pull from Jira/ServiceNow/Splunk.
    Here it reads from a CSV file so you can test it easily.
"""

import csv
import os
import sys
from datetime import datetime, timedelta

# SLA windows — same as your organization would define
SLA_DAYS = {
    "CRITICAL": 7,
    "HIGH": 30,
    "MEDIUM": 90,
    "LOW": 180,
}

SAMPLE_CSV = "sample_vulns.csv"


def create_sample_data():
    """Create a sample CSV to demonstrate the monitor."""
    today = datetime.now()
    rows = [
        ["CVE-2021-44228", "CRITICAL", "web-prod-01", "platform_team",
         (today - timedelta(days=10)).strftime("%Y-%m-%d"), "OPEN"],
        ["CVE-2021-44228", "CRITICAL", "api-prod-03", "api_team",
         (today - timedelta(days=10)).strftime("%Y-%m-%d"), "CLOSED"],
        ["CVE-2023-44487", "HIGH", "lb-prod-01", "infra_team",
         (today - timedelta(days=25)).strftime("%Y-%m-%d"), "OPEN"],
        ["CVE-2024-3094", "CRITICAL", "build-srv-02", "devops_team",
         (today - timedelta(days=3)).strftime("%Y-%m-%d"), "OPEN"],
        ["CVE-2023-4966", "HIGH", "vpn-gw-01", "network_team",
         (today - timedelta(days=35)).strftime("%Y-%m-%d"), "OPEN"],
        ["CVE-2022-22965", "MEDIUM", "app-stg-01", "app_team",
         (today - timedelta(days=60)).strftime("%Y-%m-%d"), "OPEN"],
        ["CVE-2023-36884", "HIGH", "ws-dev-05", "endpoint_team",
         (today - timedelta(days=15)).strftime("%Y-%m-%d"), "CLOSED"],
        ["CVE-2024-21887", "CRITICAL", "vpn-gw-02", "network_team",
         (today - timedelta(days=2)).strftime("%Y-%m-%d"), "OPEN"],
    ]

    with open(SAMPLE_CSV, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["cve_id", "severity", "hostname", "owner",
                         "date_found", "status"])
        writer.writerows(rows)

    print(f"Sample data written to {SAMPLE_CSV}")


def load_vulns_from_csv(filepath):
    """Load vulnerabilities from a CSV file."""
    vulns = []
    with open(filepath, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            vulns.append(row)
    return vulns


def calculate_sla_status(vuln):
    """Determine SLA status: ON_TRACK, AT_RISK (>75% elapsed), or OVERDUE."""
    if vuln["status"] == "CLOSED":
        return "CLOSED"

    severity = vuln["severity"].upper()
    sla_days = SLA_DAYS.get(severity, 90)
    date_found = datetime.strptime(vuln["date_found"], "%Y-%m-%d")
    deadline = date_found + timedelta(days=sla_days)
    today = datetime.now()

    if today > deadline:
        return "OVERDUE"
    elif (today - date_found).days > (sla_days * 0.75):
        return "AT_RISK"
    else:
        return "ON_TRACK"


def days_remaining(vuln):
    """Calculate days remaining until SLA deadline."""
    severity = vuln["severity"].upper()
    sla_days = SLA_DAYS.get(severity, 90)
    date_found = datetime.strptime(vuln["date_found"], "%Y-%m-%d")
    deadline = date_found + timedelta(days=sla_days)
    remaining = (deadline - datetime.now()).days
    return remaining


def generate_report(vulns):
    """Generate the full SLA compliance report."""
    # Calculate status for each vuln
    for v in vulns:
        v["sla_status"] = calculate_sla_status(v)
        v["days_remaining"] = days_remaining(v)

    open_vulns = [v for v in vulns if v["status"] == "OPEN"]
    closed_vulns = [v for v in vulns if v["status"] == "CLOSED"]
    overdue = [v for v in vulns if v["sla_status"] == "OVERDUE"]
    at_risk = [v for v in vulns if v["sla_status"] == "AT_RISK"]
    on_track = [v for v in vulns if v["sla_status"] == "ON_TRACK"]

    # Calculate SLA compliance rate
    total_actionable = len(open_vulns) + len(closed_vulns)
    compliant = len(closed_vulns) + len(on_track) + len(at_risk)
    compliance_rate = (compliant / total_actionable * 100) if total_actionable else 0

    print("\n" + "=" * 70)
    print("  SLA COMPLIANCE REPORT")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("=" * 70)

    # Summary
    print(f"\n  Total Vulnerabilities:  {len(vulns)}")
    print(f"  Open:                   {len(open_vulns)}")
    print(f"  Closed:                 {len(closed_vulns)}")
    print(f"  SLA Compliance Rate:    {compliance_rate:.1f}%")

    # Status breakdown
    print(f"\n  SLA Status Breakdown:")
    print(f"    ✅ On Track:    {len(on_track)}")
    print(f"    🟡 At Risk:     {len(at_risk)}")
    print(f"    🔴 Overdue:     {len(overdue)}")

    # Overdue details — this is what leadership cares about
    if overdue:
        print(f"\n  {'─'*60}")
        print(f"  🔴 OVERDUE — REQUIRES IMMEDIATE ACTION ({len(overdue)})")
        print(f"  {'─'*60}")
        for v in sorted(overdue, key=lambda x: x["days_remaining"]):
            print(f"    {v['cve_id']:20s} [{v['severity']:8s}] "
                  f"on {v['hostname']:15s}")
            print(f"      Owner: {v['owner']:15s} | "
                  f"{abs(v['days_remaining'])} days past deadline")

    # At risk details
    if at_risk:
        print(f"\n  {'─'*60}")
        print(f"  🟡 AT RISK — APPROACHING DEADLINE ({len(at_risk)})")
        print(f"  {'─'*60}")
        for v in sorted(at_risk, key=lambda x: x["days_remaining"]):
            print(f"    {v['cve_id']:20s} [{v['severity']:8s}] "
                  f"on {v['hostname']:15s}")
            print(f"      Owner: {v['owner']:15s} | "
                  f"{v['days_remaining']} days remaining")

    # Owner accountability
    owner_overdue = {}
    for v in overdue:
        owner_overdue.setdefault(v["owner"], []).append(v)

    if owner_overdue:
        print(f"\n  {'─'*60}")
        print(f"  OVERDUE BY OWNER")
        print(f"  {'─'*60}")
        for owner, owner_vulns in sorted(owner_overdue.items(),
                                         key=lambda x: len(x[1]),
                                         reverse=True):
            print(f"    {owner}: {len(owner_vulns)} overdue")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    if not os.path.exists(SAMPLE_CSV):
        print("No data file found. Creating sample data...")
        create_sample_data()

    vulns = load_vulns_from_csv(SAMPLE_CSV)
    generate_report(vulns)
