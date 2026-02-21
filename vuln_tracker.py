"""
vuln_tracker.py — Track vulnerabilities with SLA deadlines, ownership, and status.

Usage:
    python3 vuln_tracker.py --add
    python3 vuln_tracker.py --report
    python3 vuln_tracker.py --overdue

What it does:
    A lightweight vulnerability tracking system that assigns SLA deadlines
    based on severity, tracks ownership, and flags overdue items. This is
    the kind of tracking system you'd build to supplement Jira or
    ServiceNow — making sure nothing falls through the cracks.

    SLA windows:
        CRITICAL  → 7 days
        HIGH      → 30 days
        MEDIUM    → 90 days
        LOW       → 180 days
"""

import json
import os
import sys
from datetime import datetime, timedelta

VULN_DB = "vuln_database.json"

# SLA deadlines in days, based on severity
SLA_DAYS = {
    "CRITICAL": 7,
    "HIGH": 30,
    "MEDIUM": 90,
    "LOW": 180,
}


def load_vulns():
    """Load vulnerability database from JSON file."""
    if os.path.exists(VULN_DB):
        with open(VULN_DB, "r") as f:
            return json.load(f)
    return []


def save_vulns(vulns):
    """Save vulnerability database to JSON file."""
    with open(VULN_DB, "w") as f:
        json.dump(vulns, f, indent=2)


def add_vuln(cve_id, hostname, owner, severity):
    """Add a vulnerability with automatic SLA deadline calculation."""
    severity = severity.upper()
    if severity not in SLA_DAYS:
        print(f"[ERROR] Severity must be one of: {list(SLA_DAYS.keys())}")
        return

    vulns = load_vulns()
    now = datetime.now()
    sla_deadline = now + timedelta(days=SLA_DAYS[severity])

    vuln = {
        "id": len(vulns) + 1,
        "cve_id": cve_id,
        "hostname": hostname,
        "owner": owner,
        "severity": severity,
        "status": "OPEN",
        "date_found": now.strftime("%Y-%m-%d"),
        "sla_deadline": sla_deadline.strftime("%Y-%m-%d"),
        "date_closed": None,
        "notes": "",
    }

    vulns.append(vuln)
    save_vulns(vulns)
    print(f"[ADDED] {cve_id} on {hostname} — Owner: {owner} — "
          f"SLA: {sla_deadline.strftime('%Y-%m-%d')} ({SLA_DAYS[severity]} days)")


def close_vuln(vuln_id):
    """Mark a vulnerability as remediated with closure date."""
    vulns = load_vulns()
    for v in vulns:
        if v["id"] == vuln_id:
            v["status"] = "CLOSED"
            v["date_closed"] = datetime.now().strftime("%Y-%m-%d")
            save_vulns(vulns)
            print(f"[CLOSED] #{vuln_id} — {v['cve_id']} on {v['hostname']}")
            return
    print(f"[ERROR] Vulnerability #{vuln_id} not found.")


def get_overdue():
    """Find all open vulnerabilities past their SLA deadline."""
    vulns = load_vulns()
    today = datetime.now().date()
    overdue = []

    for v in vulns:
        if v["status"] == "OPEN":
            deadline = datetime.strptime(v["sla_deadline"], "%Y-%m-%d").date()
            if today > deadline:
                days_over = (today - deadline).days
                v["days_overdue"] = days_over
                overdue.append(v)

    return overdue


def print_report():
    """Generate a summary report of all tracked vulnerabilities."""
    vulns = load_vulns()
    if not vulns:
        print("No vulnerabilities tracked yet.")
        return

    open_vulns = [v for v in vulns if v["status"] == "OPEN"]
    closed_vulns = [v for v in vulns if v["status"] == "CLOSED"]
    overdue = get_overdue()

    print("\n" + "=" * 65)
    print("  VULNERABILITY MANAGEMENT REPORT")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("=" * 65)

    print(f"\n  Total Tracked:   {len(vulns)}")
    print(f"  Open:            {len(open_vulns)}")
    print(f"  Closed:          {len(closed_vulns)}")
    print(f"  Overdue:         {len(overdue)}")

    # Breakdown by severity
    print("\n  Open by Severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = len([v for v in open_vulns if v["severity"] == sev])
        if count > 0:
            print(f"    {sev:10s}  {count}")

    # Overdue details
    if overdue:
        print(f"\n  ⚠️  OVERDUE VULNERABILITIES ({len(overdue)}):")
        for v in sorted(overdue, key=lambda x: x["days_overdue"], reverse=True):
            print(f"    [{v['severity']:8s}] {v['cve_id']:20s} "
                  f"on {v['hostname']:15s} — Owner: {v['owner']:10s} "
                  f"— {v['days_overdue']} days overdue")

    # Open items by owner
    owners = {}
    for v in open_vulns:
        owners.setdefault(v["owner"], []).append(v)

    if owners:
        print("\n  Open by Owner:")
        for owner, owner_vulns in sorted(owners.items()):
            print(f"    {owner}: {len(owner_vulns)} open")

    print("\n" + "=" * 65)


def print_overdue_report():
    """Print just the overdue vulnerabilities — the ones that need action NOW."""
    overdue = get_overdue()
    if not overdue:
        print("✅ No overdue vulnerabilities. All within SLA.")
        return

    print(f"\n🔴 {len(overdue)} OVERDUE VULNERABILITIES:\n")
    for v in sorted(overdue, key=lambda x: x["days_overdue"], reverse=True):
        print(f"  #{v['id']} [{v['severity']}] {v['cve_id']} on {v['hostname']}")
        print(f"     Owner: {v['owner']} | Deadline: {v['sla_deadline']} | "
              f"{v['days_overdue']} days overdue")
        print()


# --- Demo: load sample data to show how it works ---

def load_demo_data():
    """Load sample vulnerabilities to demonstrate the tracker."""
    demo_vulns = [
        ("CVE-2021-44228", "web-prod-01", "platform_team", "CRITICAL"),
        ("CVE-2021-44228", "api-prod-03", "api_team", "CRITICAL"),
        ("CVE-2023-44487", "lb-prod-01", "infra_team", "HIGH"),
        ("CVE-2024-3094", "build-server-02", "devops_team", "CRITICAL"),
        ("CVE-2023-4966", "vpn-gateway-01", "network_team", "HIGH"),
        ("CVE-2022-22965", "app-staging-01", "app_team", "MEDIUM"),
    ]

    # Clear existing data for demo
    save_vulns([])

    for cve, host, owner, sev in demo_vulns:
        add_vuln(cve, host, owner, sev)

    # Close a couple to show mixed status
    close_vuln(1)
    close_vuln(2)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 vuln_tracker.py --demo      Load sample data")
        print("  python3 vuln_tracker.py --report    Full status report")
        print("  python3 vuln_tracker.py --overdue   Show overdue only")
        sys.exit(1)

    command = sys.argv[1]

    if command == "--demo":
        load_demo_data()
        print("\nDemo data loaded. Run --report to see the dashboard.")
    elif command == "--report":
        print_report()
    elif command == "--overdue":
        print_overdue_report()
    else:
        print(f"Unknown command: {command}")
