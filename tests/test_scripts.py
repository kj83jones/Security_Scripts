"""
tests/test_scripts.py — Tests for security operations scripts.

Run with: python -m pytest tests/ -v

Why tests matter:
    In security operations, you need to KNOW your tools work correctly.
    A vulnerability tracker that miscalculates SLA deadlines or a log
    analyzer that misses attack patterns is worse than no tool at all.
    These tests verify the core logic of each script.
"""

import os
import sys
import json
import tempfile
from datetime import datetime, timedelta

# Add parent directory to path so we can import our scripts
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ============================================================
# Tests for vuln_tracker.py
# ============================================================

class TestVulnTracker:
    """Test vulnerability tracking and SLA logic."""

    def setup_method(self):
        """Create a temp database for each test."""
        import vuln_tracker
        self.tracker = vuln_tracker
        self.original_db = vuln_tracker.VULN_DB
        self.temp_db = tempfile.mktemp(suffix=".json")
        vuln_tracker.VULN_DB = self.temp_db

    def teardown_method(self):
        """Clean up temp files."""
        self.tracker.VULN_DB = self.original_db
        if os.path.exists(self.temp_db):
            os.remove(self.temp_db)

    def test_add_vulnerability(self):
        """Adding a vuln should save it with correct SLA deadline."""
        self.tracker.add_vuln("CVE-2021-44228", "web-01", "team_a", "CRITICAL")
        vulns = self.tracker.load_vulns()
        assert len(vulns) == 1
        assert vulns[0]["cve_id"] == "CVE-2021-44228"
        assert vulns[0]["status"] == "OPEN"
        assert vulns[0]["severity"] == "CRITICAL"

    def test_sla_deadline_critical(self):
        """Critical vulns should get a 7-day SLA."""
        self.tracker.add_vuln("CVE-2021-44228", "web-01", "team_a", "CRITICAL")
        vulns = self.tracker.load_vulns()
        found_date = datetime.strptime(vulns[0]["date_found"], "%Y-%m-%d")
        deadline = datetime.strptime(vulns[0]["sla_deadline"], "%Y-%m-%d")
        assert (deadline - found_date).days == 7

    def test_sla_deadline_high(self):
        """High vulns should get a 30-day SLA."""
        self.tracker.add_vuln("CVE-2023-44487", "lb-01", "team_b", "HIGH")
        vulns = self.tracker.load_vulns()
        found_date = datetime.strptime(vulns[0]["date_found"], "%Y-%m-%d")
        deadline = datetime.strptime(vulns[0]["sla_deadline"], "%Y-%m-%d")
        assert (deadline - found_date).days == 30

    def test_close_vulnerability(self):
        """Closing a vuln should set status and closure date."""
        self.tracker.add_vuln("CVE-2021-44228", "web-01", "team_a", "CRITICAL")
        self.tracker.close_vuln(1)
        vulns = self.tracker.load_vulns()
        assert vulns[0]["status"] == "CLOSED"
        assert vulns[0]["date_closed"] is not None

    def test_invalid_severity_rejected(self):
        """Invalid severity should not create a vulnerability."""
        self.tracker.add_vuln("CVE-2021-44228", "web-01", "team_a", "BOGUS")
        vulns = self.tracker.load_vulns()
        assert len(vulns) == 0

    def test_multiple_vulns_tracked(self):
        """Should track multiple vulnerabilities independently."""
        self.tracker.add_vuln("CVE-2021-44228", "web-01", "team_a", "CRITICAL")
        self.tracker.add_vuln("CVE-2023-44487", "lb-01", "team_b", "HIGH")
        self.tracker.add_vuln("CVE-2022-22965", "app-01", "team_c", "MEDIUM")
        vulns = self.tracker.load_vulns()
        assert len(vulns) == 3
        assert vulns[0]["id"] == 1
        assert vulns[1]["id"] == 2
        assert vulns[2]["id"] == 3


# ============================================================
# Tests for log_analyzer.py
# ============================================================

class TestLogAnalyzer:
    """Test log parsing and attack classification."""

    def setup_method(self):
        import log_analyzer
        self.analyzer = log_analyzer

    def test_parse_failed_login(self):
        """Should extract IP and username from a failed login line."""
        line = ("Feb 10 03:14:22 server sshd[1234]: "
                "Failed password for invalid user admin from 192.168.1.100 port 22 ssh2")
        match = self.analyzer.FAILED_LOGIN.search(line)
        assert match is not None
        assert match.group(2) == "admin"
        assert match.group(3) == "192.168.1.100"

    def test_parse_valid_user_failure(self):
        """Should also catch failed logins for valid usernames."""
        line = ("Feb 10 05:00:00 server sshd[1252]: "
                "Failed password for jerry from 172.16.0.10 port 22 ssh2")
        match = self.analyzer.FAILED_LOGIN.search(line)
        assert match is not None
        assert match.group(2) == "jerry"
        assert match.group(3) == "172.16.0.10"

    def test_classify_brute_force(self):
        """One IP, one username, many attempts = brute force."""
        result = self.analyzer.classify_attack("1.2.3.4", 100, 1)
        assert result == "BRUTE FORCE"

    def test_classify_credential_stuffing(self):
        """One IP, many usernames = credential stuffing."""
        result = self.analyzer.classify_attack("1.2.3.4", 50, 10)
        assert result == "CREDENTIAL STUFFING"

    def test_classify_low_activity(self):
        """Few attempts = low activity, not flagged."""
        result = self.analyzer.classify_attack("1.2.3.4", 3, 1)
        assert result == "LOW ACTIVITY"

    def test_analyze_sample_log(self):
        """Should correctly count IPs and users from a sample log."""
        sample_file = self.analyzer.generate_sample_log()
        ip_counter, user_counter, ip_users = self.analyzer.analyze_log(sample_file)

        # 203.0.113.42 has the most attempts in sample data
        assert ip_counter["203.0.113.42"] > 5
        # admin is the most targeted username
        assert user_counter["admin"] >= 3

        os.remove(sample_file)


# ============================================================
# Tests for sla_monitor.py
# ============================================================

class TestSLAMonitor:
    """Test SLA calculation logic."""

    def setup_method(self):
        import sla_monitor
        self.monitor = sla_monitor

    def test_overdue_detection(self):
        """A critical vuln found 10 days ago should be overdue (7-day SLA)."""
        vuln = {
            "severity": "CRITICAL",
            "date_found": (datetime.now() - timedelta(days=10)).strftime("%Y-%m-%d"),
            "status": "OPEN",
        }
        status = self.monitor.calculate_sla_status(vuln)
        assert status == "OVERDUE"

    def test_on_track_detection(self):
        """A high vuln found 5 days ago should be on track (30-day SLA)."""
        vuln = {
            "severity": "HIGH",
            "date_found": (datetime.now() - timedelta(days=5)).strftime("%Y-%m-%d"),
            "status": "OPEN",
        }
        status = self.monitor.calculate_sla_status(vuln)
        assert status == "ON_TRACK"

    def test_at_risk_detection(self):
        """A high vuln found 25 days ago should be at risk (>75% of 30-day SLA)."""
        vuln = {
            "severity": "HIGH",
            "date_found": (datetime.now() - timedelta(days=25)).strftime("%Y-%m-%d"),
            "status": "OPEN",
        }
        status = self.monitor.calculate_sla_status(vuln)
        assert status == "AT_RISK"

    def test_closed_vuln_status(self):
        """Closed vulns should return CLOSED regardless of timing."""
        vuln = {
            "severity": "CRITICAL",
            "date_found": (datetime.now() - timedelta(days=100)).strftime("%Y-%m-%d"),
            "status": "CLOSED",
        }
        status = self.monitor.calculate_sla_status(vuln)
        assert status == "CLOSED"

    def test_days_remaining_positive(self):
        """Should return positive days when within SLA."""
        vuln = {
            "severity": "HIGH",
            "date_found": datetime.now().strftime("%Y-%m-%d"),
        }
        remaining = self.monitor.days_remaining(vuln)
        assert remaining > 0

    def test_days_remaining_negative(self):
        """Should return negative days when past SLA."""
        vuln = {
            "severity": "CRITICAL",
            "date_found": (datetime.now() - timedelta(days=14)).strftime("%Y-%m-%d"),
        }
        remaining = self.monitor.days_remaining(vuln)
        assert remaining < 0


# ============================================================
# Tests for file_integrity.py
# ============================================================

class TestFileIntegrity:
    """Test file hashing and integrity checking."""

    def setup_method(self):
        import file_integrity
        self.fim = file_integrity

    def test_hash_consistency(self):
        """Same file should produce the same hash every time."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                         delete=False) as f:
            f.write("test content for hashing")
            temp_path = f.name

        hash1 = self.fim.hash_file(temp_path)
        hash2 = self.fim.hash_file(temp_path)
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 produces 64 hex characters

        os.remove(temp_path)

    def test_different_content_different_hash(self):
        """Different files should produce different hashes."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                         delete=False) as f1:
            f1.write("content A")
            path1 = f1.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                         delete=False) as f2:
            f2.write("content B")
            path2 = f2.name

        hash1 = self.fim.hash_file(path1)
        hash2 = self.fim.hash_file(path2)
        assert hash1 != hash2

        os.remove(path1)
        os.remove(path2)

    def test_nonexistent_file_returns_none(self):
        """Hashing a file that doesn't exist should return None."""
        result = self.fim.hash_file("/nonexistent/file.txt")
        assert result is None
