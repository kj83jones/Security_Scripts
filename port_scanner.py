"""
port_scanner.py — Scan hosts for open ports and identify services.

Usage:
    python3 port_scanner.py 192.168.1.1
    python3 port_scanner.py 192.168.1.1 --ports 22,80,443,8080

What it does:
    Checks if ports are open on a target host by attempting TCP connections.
    Identifies common services running on open ports. Uses threading to
    scan quickly. This is a lightweight alternative to Nmap for quick
    checks during incident response or asset discovery.

    ⚠️  Only scan systems you own or have written authorization to test.
"""

import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# Common ports and their typical services
COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet ⚠️",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MS-RPC ⚠️",
    139: "NetBIOS ⚠️",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB ⚠️",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP ⚠️",
    5432: "PostgreSQL",
    5900: "VNC ⚠️",
    6379: "Redis ⚠️",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB ⚠️",
}

# Ports flagged with ⚠️ are commonly targeted by attackers


def scan_port(host, port, timeout=1):
    """Attempt TCP connection to a single port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return port if result == 0 else None
    except (socket.error, OSError):
        return None


def get_service_name(port):
    """Look up the service running on a port."""
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"


def scan_host(host, ports=None):
    """Scan a host for open ports using parallel threads."""
    if ports is None:
        ports = list(range(1, 1025))

    print(f"\n{'='*55}")
    print(f"  PORT SCAN REPORT")
    print(f"  Target: {host}")
    print(f"  Ports:  {len(ports)} ports to scan")
    print(f"  Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*55}\n")

    print("  Scanning", end="", flush=True)

    open_ports = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, host, p): p for p in ports}
        for i, future in enumerate(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)
            # Progress dots
            if i % 100 == 0:
                print(".", end="", flush=True)

    print(" done.\n")

    open_ports.sort()

    if not open_ports:
        print("  No open ports found.")
        print("  (Host may be down, filtered, or all ports closed.)")
    else:
        print(f"  {'PORT':<8} {'STATE':<8} {'SERVICE':<20} {'RISK'}")
        print(f"  {'─'*50}")

        risky_ports = []
        for port in open_ports:
            service = get_service_name(port)
            risk = ""
            if "⚠️" in service:
                risk = "⚠️  Review exposure"
                risky_ports.append((port, service))
                service = service.replace(" ⚠️", "")

            print(f"  {port:<8} {'OPEN':<8} {service:<20} {risk}")

        print(f"\n  Found {len(open_ports)} open port(s).")

        # Security recommendations
        if risky_ports:
            print(f"\n  {'─'*50}")
            print(f"  🔴 SECURITY REVIEW NEEDED:")
            for port, service in risky_ports:
                svc = service.replace(" ⚠️", "")
                print(f"    Port {port} ({svc}) — commonly targeted, "
                      f"verify this should be exposed")

    print(f"\n{'='*55}")
    return open_ports


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 port_scanner.py <host>")
        print("  python3 port_scanner.py <host> --ports 22,80,443")
        print("\n⚠️  Only scan systems you own or have authorization to test.")
        sys.exit(1)

    host = sys.argv[1]
    ports = None

    if "--ports" in sys.argv:
        port_idx = sys.argv.index("--ports") + 1
        if port_idx < len(sys.argv):
            ports = [int(p) for p in sys.argv[port_idx].split(",")]

    scan_host(host, ports)
