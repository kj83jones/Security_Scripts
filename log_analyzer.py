"""
log_analyzer.py — Parse authentication logs for brute-force detection.

Usage:
    python3 log_analyzer.py /var/log/auth.log
    python3 log_analyzer.py --demo

What it does:
    Reads Linux auth logs (or any syslog-style log) and extracts failed
    SSH login attempts. Counts attempts by IP address and username, flags
    likely brute-force attacks, and identifies patterns like credential
    stuffing (one IP trying many usernames) vs password spraying (many
    IPs trying one username).

    In a real SOC, this analysis feeds into SIEM alerts and firewall
    block rules. This script gives you the raw visibility.
"""

import re
import sys
import os
from collections import Counter
from datetime import datetime

# Pattern matches "Failed password for [invalid user] <user> from <ip>"
FAILED_LOGIN = re.compile(
    r"(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password for "
    r"(?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
)

# Threshold for flagging an IP as brute-force
BRUTE_FORCE_THRESHOLD = 10


def generate_sample_log():
    """Create a sample auth.log for testing."""
    sample_file = "sample_auth.log"
    lines = [
        "Feb 10 03:14:22 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2",
        "Feb 10 03:14:25 server sshd[1235]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2",
        "Feb 10 03:14:28 server sshd[1236]: Failed password for invalid user root from 192.168.1.100 port 22 ssh2",
        "Feb 10 03:14:30 server sshd[1237]: Failed password for invalid user test from 192.168.1.100 port 22 ssh2",
        "Feb 10 03:15:01 server sshd[1238]: Failed password for invalid user admin from 10.0.0.55 port 22 ssh2",
        "Feb 10 03:15:05 server sshd[1239]: Failed password for invalid user admin from 10.0.0.55 port 22 ssh2",
        "Feb 10 04:22:10 server sshd[1240]: Failed password for invalid user root from 203.0.113.42 port 22 ssh2",
        "Feb 10 04:22:11 server sshd[1241]: Failed password for invalid user root from 203.0.113.42 port 22 ssh2",
        "Feb 10 04:22:12 server sshd[1242]: Failed password for invalid user admin from 203.0.113.42 port 22 ssh2",
        "Feb 10 04:22:13 server sshd[1243]: Failed password for invalid user user from 203.0.113.42 port 22 ssh2",
        "Feb 10 04:22:14 server sshd[1244]: Failed password for invalid user guest from 203.0.113.42 port 22 ssh2",
        "Feb 10 04:22:15 server sshd[1245]: Failed password for invalid user oracle from 203.0.113.42 port 22 ssh2",
        "Feb 10 04:22:16 server sshd[1246]: Failed password for invalid user postgres from 203.0.113.42 port 22 ssh2",
        "Feb 10 04:22:17 server sshd[1247]: Failed password for invalid user ubuntu from 203.0.113.42 port 22 ssh2",
        "Feb 10 04:22:18 server sshd[1248]: Failed password for invalid user deploy from 203.0.113.42 port 22 ssh2",
        "Feb 10 04:22:19 server sshd[1249]: Failed password for invalid user jenkins from 203.0.113.42 port 22 ssh2",
        "Feb 10 04:22:20 server sshd[1250]: Failed password for invalid user ansible from 203.0.113.42 port 22 ssh2",
        "Feb 10 04:22:21 server sshd[1251]: Failed password for invalid user vagrant from 203.0.113.42 port 22 ssh2",
        "Feb 10 05:00:00 server sshd[1252]: Failed password for jerry from 172.16.0.10 port 22 ssh2",
        "Feb 10 05:00:05 server sshd[1253]: Failed password for jerry from 172.16.0.10 port 22 ssh2",
    ]

    with open(sample_file, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Sample log created: {sample_file}")
    return sample_file


def analyze_log(filepath):
    """Parse auth log and extract failed login data."""
    ip_counter = Counter()
    user_counter = Counter()
    ip_users = {}       # Track which usernames each IP tried
    ip_timestamps = {}  # Track timing of attempts

    with open(filepath, "r") as f:
        for line in f:
            match = FAILED_LOGIN.search(line)
            if match:
                timestamp_str = match.group(1)
                username = match.group(2)
                ip = match.group(3)

                ip_counter[ip] += 1
                user_counter[username] += 1

                # Track unique usernames per IP
                if ip not in ip_users:
                    ip_users[ip] = set()
                ip_users[ip].add(username)

    return ip_counter, user_counter, ip_users


def classify_attack(ip, count, unique_users):
    """Classify the type of attack based on the pattern."""
    if count < BRUTE_FORCE_THRESHOLD:
        return "LOW ACTIVITY"

    if unique_users > 5:
        return "CREDENTIAL STUFFING"  # One IP, many usernames
    elif unique_users == 1:
        return "BRUTE FORCE"  # One IP, one username, many attempts
    else:
        return "MIXED ATTACK"


def print_report(ip_counter, user_counter, ip_users):
    """Generate the threat detection report."""
    total_failures = sum(ip_counter.values())

    print("\n" + "=" * 65)
    print("  FAILED LOGIN ANALYSIS")
    print(f"  Log analyzed: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("=" * 65)

    print(f"\n  Total failed attempts:   {total_failures}")
    print(f"  Unique source IPs:       {len(ip_counter)}")
    print(f"  Unique usernames tried:  {len(user_counter)}")

    # Top offending IPs
    print(f"\n  {'─'*55}")
    print("  TOP OFFENDING IPs")
    print(f"  {'─'*55}")
    for ip, count in ip_counter.most_common(10):
        unique_users = len(ip_users.get(ip, set()))
        attack_type = classify_attack(ip, count, unique_users)

        flag = ""
        if count >= BRUTE_FORCE_THRESHOLD:
            flag = " ⚠️"

        print(f"    {ip:20s}  {count:5d} attempts  "
              f"({unique_users} users)  [{attack_type}]{flag}")

    # Most targeted usernames
    print(f"\n  {'─'*55}")
    print("  MOST TARGETED USERNAMES")
    print(f"  {'─'*55}")
    for user, count in user_counter.most_common(10):
        print(f"    {user:20s}  {count:5d} attempts")

    # Actionable recommendations
    brute_force_ips = [ip for ip, count in ip_counter.items()
                       if count >= BRUTE_FORCE_THRESHOLD]

    if brute_force_ips:
        print(f"\n  {'─'*55}")
        print(f"  🔴 RECOMMENDED ACTIONS")
        print(f"  {'─'*55}")
        print(f"    Block these IPs at the firewall:")
        for ip in brute_force_ips:
            print(f"      iptables -A INPUT -s {ip} -j DROP")

    print("\n" + "=" * 65)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 log_analyzer.py /var/log/auth.log")
        print("  python3 log_analyzer.py --demo")
        sys.exit(1)

    if sys.argv[1] == "--demo":
        filepath = generate_sample_log()
    else:
        filepath = sys.argv[1]

    if not os.path.exists(filepath):
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)

    ip_counter, user_counter, ip_users = analyze_log(filepath)
    print_report(ip_counter, user_counter, ip_users)
