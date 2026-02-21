"""
evidence_collector.py — Gather compliance evidence snapshots for audit readiness.

Usage:
    python3 evidence_collector.py
    python3 evidence_collector.py --output /path/to/evidence/

What it does:
    Collects system configuration evidence that auditors commonly request
    during SOC 2, FedRAMP, or FDIC examinations. Captures point-in-time
    snapshots of security-relevant configurations and saves them as
    timestamped files.

    Think of it as automating the evidence collection you'd normally do
    manually before an audit — user lists, firewall rules, service status,
    patch levels, etc.
"""

import os
import sys
import subprocess
import json
from datetime import datetime


def run_cmd(cmd, description):
    """Run a command and capture the output for evidence."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True,
                                text=True, timeout=30)
        return {
            "command": cmd,
            "description": description,
            "output": result.stdout.strip(),
            "error": result.stderr.strip() if result.returncode != 0 else "",
            "exit_code": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "command": cmd,
            "description": description,
            "output": "",
            "error": "Command timed out",
            "exit_code": -1,
        }


# Evidence collection commands mapped to compliance controls
EVIDENCE_ITEMS = [
    {
        "category": "User Access",
        "control": "AC-2 Account Management",
        "items": [
            ("cat /etc/passwd | grep -v nologin | grep -v false",
             "Active user accounts"),
            ("cat /etc/group",
             "Group memberships"),
            ("lastlog 2>/dev/null | head -20",
             "Last login times for accounts"),
            ("awk -F: '($3 == 0) {print $1}' /etc/passwd",
             "Accounts with UID 0 (root-level)"),
        ]
    },
    {
        "category": "Network Security",
        "control": "SC-7 Boundary Protection",
        "items": [
            ("iptables -L -n 2>/dev/null || echo 'iptables not available'",
             "Firewall rules"),
            ("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",
             "Listening ports and services"),
            ("cat /etc/hosts.allow 2>/dev/null",
             "TCP Wrappers allow rules"),
            ("cat /etc/hosts.deny 2>/dev/null",
             "TCP Wrappers deny rules"),
        ]
    },
    {
        "category": "Audit & Logging",
        "control": "AU-2 Audit Events",
        "items": [
            ("systemctl status rsyslog 2>/dev/null || systemctl status syslog 2>/dev/null",
             "Syslog service status"),
            ("systemctl status auditd 2>/dev/null",
             "Audit daemon status"),
            ("ls -la /var/log/ 2>/dev/null | head -20",
             "Log file inventory"),
            ("cat /etc/logrotate.conf 2>/dev/null | head -20",
             "Log rotation configuration"),
        ]
    },
    {
        "category": "System Configuration",
        "control": "CM-6 Configuration Settings",
        "items": [
            ("uname -a",
             "System identification"),
            ("cat /etc/os-release 2>/dev/null",
             "Operating system version"),
            ("cat /etc/ssh/sshd_config 2>/dev/null | grep -v '^#' | grep -v '^$'",
             "SSH configuration (active settings)"),
            ("sysctl -a 2>/dev/null | grep -E 'net.ipv4.ip_forward|net.ipv4.conf.all' | head -10",
             "Network kernel parameters"),
        ]
    },
    {
        "category": "Patch Management",
        "control": "SI-2 Flaw Remediation",
        "items": [
            ("apt list --installed 2>/dev/null | tail -20 || rpm -qa --last 2>/dev/null | head -20",
             "Recently installed packages"),
            ("apt list --upgradable 2>/dev/null || yum check-update 2>/dev/null | head -20",
             "Available updates"),
            ("cat /var/log/apt/history.log 2>/dev/null | tail -30 || cat /var/log/yum.log 2>/dev/null | tail -30",
             "Recent patch history"),
        ]
    },
    {
        "category": "Cryptographic Controls",
        "control": "SC-13 Cryptographic Protection",
        "items": [
            ("openssl version 2>/dev/null",
             "OpenSSL version"),
            ("cat /etc/ssl/openssl.cnf 2>/dev/null | grep -i 'MinProtocol\\|CipherString' | head -5",
             "TLS minimum protocol settings"),
        ]
    },
]


def collect_evidence(output_dir):
    """Run all evidence collection commands and save results."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname = os.uname().nodename

    all_evidence = {
        "metadata": {
            "hostname": hostname,
            "collected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "collector": "evidence_collector.py",
            "os": f"{os.uname().sysname} {os.uname().release}",
        },
        "categories": []
    }

    print("\n" + "=" * 60)
    print("  COMPLIANCE EVIDENCE COLLECTION")
    print(f"  Host:  {hostname}")
    print(f"  Time:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    for section in EVIDENCE_ITEMS:
        category = section["category"]
        control = section["control"]
        print(f"\n  Collecting: {category} ({control})...")

        category_evidence = {
            "category": category,
            "control": control,
            "items": []
        }

        for cmd, description in section["items"]:
            result = run_cmd(cmd, description)
            category_evidence["items"].append(result)

            status = "✅" if result["exit_code"] == 0 else "⚠️"
            print(f"    {status} {description}")

        all_evidence["categories"].append(category_evidence)

    # Save the evidence
    output_file = os.path.join(
        output_dir, f"evidence_{hostname}_{timestamp}.json"
    )
    with open(output_file, "w") as f:
        json.dump(all_evidence, f, indent=2)

    # Also save a human-readable text version
    text_file = os.path.join(
        output_dir, f"evidence_{hostname}_{timestamp}.txt"
    )
    with open(text_file, "w") as f:
        f.write(f"COMPLIANCE EVIDENCE COLLECTION\n")
        f.write(f"Host: {hostname}\n")
        f.write(f"Date: {all_evidence['metadata']['collected_at']}\n")
        f.write(f"OS:   {all_evidence['metadata']['os']}\n")
        f.write("=" * 60 + "\n\n")

        for cat in all_evidence["categories"]:
            f.write(f"\n{'─'*60}\n")
            f.write(f"{cat['category']} ({cat['control']})\n")
            f.write(f"{'─'*60}\n\n")

            for item in cat["items"]:
                f.write(f">> {item['description']}\n")
                f.write(f"   Command: {item['command']}\n")
                f.write(f"   Output:\n")
                for line in item["output"].split("\n"):
                    f.write(f"     {line}\n")
                f.write("\n")

    print(f"\n  {'─'*50}")
    print(f"  ✅ Evidence saved:")
    print(f"     JSON: {output_file}")
    print(f"     Text: {text_file}")
    print(f"  {'─'*50}")

    return output_file


if __name__ == "__main__":
    output_dir = "."

    if "--output" in sys.argv:
        idx = sys.argv.index("--output") + 1
        if idx < len(sys.argv):
            output_dir = sys.argv[idx]

    os.makedirs(output_dir, exist_ok=True)
    collect_evidence(output_dir)
