"""
file_integrity.py — Monitor critical files for unauthorized changes.

Usage:
    python3 file_integrity.py --baseline /etc /usr/local/bin
    python3 file_integrity.py --check

What it does:
    A simplified file integrity monitoring tool (like OSSEC or AIDE).
    Step 1: Scan critical directories and save SHA-256 hashes of every
    file — this is your "known good" baseline.
    Step 2: Run periodic checks comparing current hashes to baseline.
    Alerts on modified files, deleted files, and new files that appeared.

    Schedule the --check with cron for daily monitoring.
"""

import hashlib
import json
import os
import sys
from datetime import datetime

BASELINE_FILE = "integrity_baseline.json"


def hash_file(filepath):
    """Generate SHA-256 hash of a file's contents."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None


def build_baseline(directories):
    """Scan directories and save hash baseline."""
    baseline = {
        "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "directories": directories,
        "files": {},
    }

    file_count = 0
    error_count = 0

    for directory in directories:
        if not os.path.isdir(directory):
            print(f"  [SKIP] Not a directory: {directory}")
            continue

        print(f"  Scanning {directory}...", end=" ", flush=True)
        dir_count = 0

        for root, _, files in os.walk(directory):
            for filename in files:
                filepath = os.path.join(root, filename)
                file_hash = hash_file(filepath)

                if file_hash:
                    baseline["files"][filepath] = {
                        "hash": file_hash,
                        "size": os.path.getsize(filepath),
                        "modified": os.path.getmtime(filepath),
                    }
                    file_count += 1
                    dir_count += 1
                else:
                    error_count += 1

        print(f"{dir_count} files")

    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)

    print(f"\n  ✅ Baseline saved: {file_count} files recorded")
    if error_count:
        print(f"  ⚠️  {error_count} files skipped (permission denied)")
    print(f"  Baseline file: {BASELINE_FILE}")


def check_integrity():
    """Compare current file state against saved baseline."""
    if not os.path.exists(BASELINE_FILE):
        print("[ERROR] No baseline found. Run --baseline first.")
        sys.exit(1)

    with open(BASELINE_FILE, "r") as f:
        baseline = json.load(f)

    files = baseline["files"]
    created = baseline["created"]

    modified = []
    deleted = []
    new_files = []

    print(f"\n  Checking {len(files)} files against baseline from {created}...")

    # Check each baselined file
    for filepath, info in files.items():
        if not os.path.exists(filepath):
            deleted.append(filepath)
            continue

        current_hash = hash_file(filepath)
        if current_hash and current_hash != info["hash"]:
            modified.append({
                "path": filepath,
                "old_hash": info["hash"][:16] + "...",
                "new_hash": current_hash[:16] + "...",
                "old_size": info["size"],
                "new_size": os.path.getsize(filepath),
            })

    # Check for new files in baselined directories
    for directory in baseline.get("directories", []):
        if os.path.isdir(directory):
            for root, _, filenames in os.walk(directory):
                for filename in filenames:
                    filepath = os.path.join(root, filename)
                    if filepath not in files:
                        new_files.append(filepath)

    # Report
    print("\n" + "=" * 60)
    print("  FILE INTEGRITY CHECK")
    print(f"  Baseline: {created}")
    print(f"  Checked:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    total_alerts = len(modified) + len(deleted) + len(new_files)

    if total_alerts == 0:
        print("\n  ✅ All files match baseline. No changes detected.")
    else:
        print(f"\n  ⚠️  {total_alerts} ALERT(S) DETECTED")

        if modified:
            print(f"\n  {'─'*50}")
            print(f"  🟠 MODIFIED FILES ({len(modified)})")
            print(f"  {'─'*50}")
            for m in modified:
                print(f"    {m['path']}")
                print(f"      Hash: {m['old_hash']} → {m['new_hash']}")
                print(f"      Size: {m['old_size']} → {m['new_size']}")

        if deleted:
            print(f"\n  {'─'*50}")
            print(f"  🔴 DELETED FILES ({len(deleted)})")
            print(f"  {'─'*50}")
            for d in deleted:
                print(f"    {d}")

        if new_files:
            print(f"\n  {'─'*50}")
            print(f"  🟡 NEW FILES ({len(new_files)})")
            print(f"  {'─'*50}")
            for n in new_files[:20]:  # Limit output
                print(f"    {n}")
            if len(new_files) > 20:
                print(f"    ... and {len(new_files) - 20} more")

    print("\n" + "=" * 60)
    return total_alerts


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 file_integrity.py --baseline /etc /usr/local/bin")
        print("  python3 file_integrity.py --check")
        sys.exit(1)

    if sys.argv[1] == "--baseline":
        dirs = sys.argv[2:] if len(sys.argv) > 2 else ["/etc"]
        print(f"\n  Building baseline for: {', '.join(dirs)}")
        build_baseline(dirs)

    elif sys.argv[1] == "--check":
        alerts = check_integrity()
        sys.exit(1 if alerts > 0 else 0)

    else:
        print(f"Unknown command: {sys.argv[1]}")
