# Security Operations Scripts

Python tools for vulnerability management, threat detection, compliance checking, and security automation. Built by a security operations engineer with 15+ years of experience securing regulated cloud environments (FedRAMP, FDIC, SOC 2, PCI DSS).

These scripts reflect real-world security operations workflows — the kind of work that keeps vulnerability programs running, incidents contained, and auditors satisfied.

## Scripts

### Vulnerability Management
- **cve_lookup.py** — Query NIST NVD for CVE details, CVSS scores, and severity ratings
- **vuln_tracker.py** — Track vulnerabilities with SLA deadlines, ownership, and status reporting
- **sla_monitor.py** — Flag overdue vulnerabilities and generate SLA compliance reports

### Threat Detection
- **log_analyzer.py** — Parse auth logs for brute-force detection, rank offending IPs
- **port_scanner.py** — Scan hosts for open ports and identify running services
- **ip_reputation.py** — Check IPs against AbuseIPDB threat intelligence

### Compliance & Integrity
- **file_integrity.py** — Monitor critical files for unauthorized changes (SHA-256 baseline comparison)
- **compliance_checker.py** — Verify systems against security configuration baselines
- **evidence_collector.py** — Gather compliance evidence snapshots for audit readiness

## Requirements

```
Python 3.8+
pip install requests
```

## Usage

Each script runs standalone:
```bash
python3 cve_lookup.py CVE-2021-44228
python3 log_analyzer.py /var/log/auth.log
python3 vuln_tracker.py --report
```

## About

Built to support security operations in regulated environments. These tools automate the repetitive parts of vulnerability management and threat detection so engineers can focus on judgment, prioritization, and remediation.

## Author

Kerri Jones | Information Security Engineer
[LinkedIn](https://www.linkedin.com/in/kj83jones)
