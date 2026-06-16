"""
NetGuard Port Scanner
Scans all known devices for open ports and flags dangerous services.
"""

import socket
import sqlite3
import time
from datetime import datetime, timezone

DB_PATH = "netguard.db"
SCAN_INTERVAL = 300  # 5 minutes
TIMEOUT = 1.0

# Ports to scan and their service names
PORTS_TO_SCAN = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    554: "RTSP",
    1900: "UPNP",
    3389: "RDP",
    5000: "UPNP-Dev",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9100: "Printer",
}

# Dangerous ports and why
DANGEROUS_PORTS = {
    23: "Unencrypted remote access protocol - high hijack risk",
    21: "Unencrypted file transfer - credentials sent in plaintext",
    445: "Common ransomware attack vector",
    3389: "Common brute force target if exposed",
    1900: "Often exploited for DDoS amplification",
}


def init_db():
    """Create the open_ports table if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS open_ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            service_name TEXT,
            is_dangerous INTEGER DEFAULT 0,
            risk_reason TEXT,
            scanned_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def get_online_devices():
    """Fetch all currently online device IPs from the devices table."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT ip_address FROM devices WHERE status = 'online'"
    ).fetchall()
    conn.close()
    return [row["ip_address"] for row in rows]


def scan_port(ip, port):
    """Try to open a TCP connection to ip:port. Return True if open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def scan_device(ip):
    """Scan all configured ports on a single device. Return list of open ports."""
    open_ports = []
    for port, service in PORTS_TO_SCAN.items():
        if scan_port(ip, port):
            is_dangerous = 1 if port in DANGEROUS_PORTS else 0
            risk_reason = DANGEROUS_PORTS.get(port, "")
            open_ports.append({
                "port": port,
                "service": service,
                "is_dangerous": is_dangerous,
                "risk_reason": risk_reason
            })
    return open_ports


def save_results(ip, open_ports):
    """Clear old results for this device and save fresh scan results."""
    conn = sqlite3.connect(DB_PATH)
    timestamp = datetime.now(timezone.utc).isoformat()

    # Clear stale entries for this device
    conn.execute("DELETE FROM open_ports WHERE device_ip = ?", (ip,))

    for p in open_ports:
        conn.execute("""
            INSERT INTO open_ports (device_ip, port, service_name, is_dangerous, risk_reason, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (ip, p["port"], p["service"], p["is_dangerous"], p["risk_reason"], timestamp))

    conn.commit()
    conn.close()


def run_scan_cycle():
    """Scan every online device and print a clean results table."""
    devices = get_online_devices()
    print(f"\n[*] Starting port scan cycle — {len(devices)} online devices")
    print(f"{'Device IP':<16} {'Port':<6} {'Service':<12} {'Risk'}")
    print("-" * 70)

    for ip in devices:
        open_ports = scan_device(ip)
        save_results(ip, open_ports)

        if not open_ports:
            continue

        for p in open_ports:
            risk = "DANGEROUS" if p["is_dangerous"] else "ok"
            print(f"{ip:<16} {p['port']:<6} {p['service']:<12} {risk}")

    print(f"[*] Scan cycle complete. Next scan in {SCAN_INTERVAL} seconds.\n")


def main():
    print("NetGuard Port Scanner starting...")
    print(f"Database: {DB_PATH}")
    print(f"Scan interval: {SCAN_INTERVAL}s")
    print(f"Ports scanned per device: {list(PORTS_TO_SCAN.keys())}")
    print("Press Ctrl+C to stop.\n")

    init_db()

    try:
        while True:
            run_scan_cycle()
            time.sleep(SCAN_INTERVAL)
    except KeyboardInterrupt:
        print("\n[*] Port scanner stopped by user.")


if __name__ == "__main__":
    main()