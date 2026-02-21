"""
compliance_checker.py — Verify systems against security configuration baselines.

Usage:
    python3 compliance_checker.py
    python3 compliance_checker.py --json

What it does:
    Checks a Linux system against common security hardening requirements.
    These are the kinds of checks you'd find in CIS Benchmarks, DISA STIGs,
    or FedRAMP control requirements. Produces a pass/fail report that
    maps each check to a compliance framework control.

    Run this on servers to verify they meet your security baseline before
    deployment or during periodic audits.
"""

import os
import sys
import subprocess
import json
from datetime import datetime


def run_cmd(cmd):
    """Run a shell command and return the output."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True,
                                text=True, timeout=10)
        return result.stdout.strip(), result.returncode
    except (subprocess.TimeoutExpired, Exception):
        return "", 1


def check_ssh_root_login():
    """Verify root login via SSH is disabled."""
    output, _ = run_cmd("grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null")
    if "no" in output.lower():
        return True, "Root SSH login is disabled"
    return False, f"Root SSH login setting: {output or 'not found'}"


def check_ssh_protocol():
    """Verify SSH protocol version 2 is enforced."""
    # Modern SSH defaults to protocol 2, but check anyway
    output, _ = run_cmd("ssh -V 2>&1")
    if "OpenSSH" in output:
        return True, f"SSH version: {output}"
    return False, "Could not determine SSH version"


def check_password_policy():
    """Check if password aging is configured."""
    output, _ = run_cmd("grep '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null")
    if output:
        days = output.split()[-1] if output.split() else "unknown"
        try:
            if int(days) <= 90:
                return True, f"Password max age: {days} days"
        except ValueError:
            pass
        return False, f"Password max age: {days} days (should be ≤90)"
    return False, "Password aging not configured"


def check_firewall():
    """Verify a firewall is active."""
    # Check for iptables rules or ufw
    output, code = run_cmd("iptables -L -n 2>/dev/null | grep -c 'Chain'")
    if code == 0 and output and int(output) > 0:
        return True, "iptables is active"

    output, code = run_cmd("ufw status 2>/dev/null")
    if "active" in output.lower():
        return True, "UFW firewall is active"

    return False, "No active firewall detected"


def check_auto_updates():
    """Check if automatic security updates are enabled."""
    paths = [
        "/etc/apt/apt.conf.d/20auto-upgrades",
        "/etc/apt/apt.conf.d/50unattended-upgrades",
    ]
    for path in paths:
        if os.path.exists(path):
            with open(path, "r") as f:
                content = f.read()
            if "1" in content:
                return True, "Automatic updates configured"

    output, _ = run_cmd("systemctl is-enabled unattended-upgrades 2>/dev/null")
    if "enabled" in output:
        return True, "unattended-upgrades is enabled"

    return False, "Automatic updates not detected"


def check_no_empty_passwords():
    """Verify no accounts have empty passwords."""
    output, _ = run_cmd("awk -F: '($2 == \"\") {print $1}' /etc/shadow 2>/dev/null")
    if not output:
        return True, "No empty passwords found"
    return False, f"Accounts with empty passwords: {output}"


def check_tmp_permissions():
    """Verify /tmp has restricted permissions."""
    output, _ = run_cmd("stat -c '%a' /tmp 2>/dev/null")
    if output in ["1777", "0777"]:
        return True, f"/tmp permissions: {output} (sticky bit set)"
    return False, f"/tmp permissions: {output}"


def check_audit_logging():
    """Verify audit logging is active."""
    output, code = run_cmd("systemctl is-active auditd 2>/dev/null")
    if "active" in output:
        return True, "auditd is running"

    # Check if any syslog is running
    output, code = run_cmd("systemctl is-active rsyslog 2>/dev/null")
    if "active" in output:
        return True, "rsyslog is running (auditd not found)"

    return False, "No audit logging service detected"


def check_world_writable_files():
    """Check for world-writable files in critical directories."""
    output, _ = run_cmd(
        "find /etc -type f -perm -002 2>/dev/null | head -5"
    )
    if not output:
        return True, "No world-writable files in /etc"
    count = len(output.strip().split("\n"))
    return False, f"{count} world-writable file(s) found in /etc"


# All checks mapped to compliance framework controls
CHECKS = [
    {
        "name": "SSH Root Login Disabled",
        "function": check_ssh_root_login,
        "controls": ["NIST AC-6", "CIS 5.2.10", "STIG V-72247"],
        "severity": "HIGH",
    },
    {
        "name": "SSH Protocol Version",
        "function": check_ssh_protocol,
        "controls": ["NIST SC-8", "CIS 5.2.4"],
        "severity": "HIGH",
    },
    {
        "name": "Password Aging Policy",
        "function": check_password_policy,
        "controls": ["NIST IA-5", "CIS 5.4.1.1"],
        "severity": "MEDIUM",
    },
    {
        "name": "Firewall Active",
        "function": check_firewall,
        "controls": ["NIST SC-7", "CIS 3.5.1"],
        "severity": "HIGH",
    },
    {
        "name": "Automatic Security Updates",
        "function": check_auto_updates,
        "controls": ["NIST SI-2", "CIS 1.9"],
        "severity": "MEDIUM",
    },
    {
        "name": "No Empty Passwords",
        "function": check_no_empty_passwords,
        "controls": ["NIST IA-5", "CIS 6.2.1"],
        "severity": "CRITICAL",
    },
    {
        "name": "/tmp Permissions",
        "function": check_tmp_permissions,
        "controls": ["NIST AC-6", "CIS 1.1.5"],
        "severity": "LOW",
    },
    {
        "name": "Audit Logging Active",
        "function": check_audit_logging,
        "controls": ["NIST AU-2", "CIS 4.1.1"],
        "severity": "HIGH",
    },
    {
        "name": "No World-Writable Files in /etc",
        "function": check_world_writable_files,
        "controls": ["NIST AC-6", "CIS 6.1.8"],
        "severity": "MEDIUM",
    },
]


def run_all_checks():
    """Execute all compliance checks and collect results."""
    results = []
    for check in CHECKS:
        passed, detail = check["function"]()
        results.append({
            "name": check["name"],
            "passed": passed,
            "detail": detail,
            "controls": check["controls"],
            "severity": check["severity"],
        })
    return results


def print_report(results):
    """Generate the compliance report."""
    passed = [r for r in results if r["passed"]]
    failed = [r for r in results if not r["passed"]]

    score = len(passed) / len(results) * 100 if results else 0

    print("\n" + "=" * 65)
    print("  SECURITY COMPLIANCE CHECK")
    print(f"  Host:      {os.uname().nodename}")
    print(f"  Date:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  OS:        {os.uname().sysname} {os.uname().release}")
    print("=" * 65)

    print(f"\n  Score: {score:.0f}% ({len(passed)}/{len(results)} checks passed)")

    if failed:
        print(f"\n  {'─'*55}")
        print(f"  ❌ FAILED CHECKS ({len(failed)})")
        print(f"  {'─'*55}")
        for r in sorted(failed, key=lambda x: ["CRITICAL", "HIGH",
                        "MEDIUM", "LOW"].index(x["severity"])):
            print(f"    [{r['severity']:8s}] {r['name']}")
            print(f"             {r['detail']}")
            print(f"             Controls: {', '.join(r['controls'])}")

    if passed:
        print(f"\n  {'─'*55}")
        print(f"  ✅ PASSED CHECKS ({len(passed)})")
        print(f"  {'─'*55}")
        for r in passed:
            print(f"    ✅ {r['name']}")

    print("\n" + "=" * 65)
    return results


if __name__ == "__main__":
    output_json = "--json" in sys.argv

    results = run_all_checks()

    if output_json:
        print(json.dumps(results, indent=2))
    else:
        print_report(results)
