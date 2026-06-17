#!/usr/bin/env python3
"""
NetGuard ARP Spoof Detector
Monitors for ARP spoofing / MITM attacks by detecting unexpected MAC
address changes for known IP addresses on the local network.
"""

import os
import sqlite3
import time
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CHECK_INTERVAL_SECONDS = 15

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DB_PATH = os.path.join(PROJECT_ROOT, "netguard.db")

GATEWAY_IP = "192.168.1.1"


# ---------------------------------------------------------------------------
# Database operations
# ---------------------------------------------------------------------------

def init_database(db_path: str) -> None:
    """Create mac_history and alerts tables if they do not already exist."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS mac_history (
            ip_address   TEXT PRIMARY KEY,
            known_mac    TEXT,
            last_verified TEXT
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp        TEXT,
            severity         TEXT,
            alert_type       TEXT,
            device_ip        TEXT,
            description      TEXT,
            is_acknowledged  INTEGER DEFAULT 0
        )
        """
    )
    conn.commit()
    conn.close()


def get_device_macs(db_path: str) -> list[tuple[str, str]]:
    """Return all current ip_address / mac_address pairs from the devices table."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT ip_address, mac_address FROM devices")
    pairs = [(row[0], row[1].upper()) for row in cursor.fetchall()]
    conn.close()
    return pairs


def get_known_mac(db_path: str, ip_address: str) -> str | None:
    """Return the stored baseline MAC for an IP, or None if not yet recorded."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT known_mac FROM mac_history WHERE ip_address = ?",
        (ip_address,),
    )
    row = cursor.fetchone()
    conn.close()
    return row[0].upper() if row else None


def set_baseline(db_path: str, ip_address: str, mac_address: str, timestamp: str) -> None:
    """Store or update the baseline MAC for an IP address."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO mac_history (ip_address, known_mac, last_verified)
        VALUES (?, ?, ?)
        ON CONFLICT(ip_address) DO UPDATE SET
            known_mac = excluded.known_mac,
            last_verified = excluded.last_verified
        """,
        (ip_address, mac_address, timestamp),
    )
    conn.commit()
    conn.close()


def insert_alert(
    db_path: str,
    timestamp: str,
    severity: str,
    device_ip: str,
    description: str,
) -> None:
    """Record an ARP spoof alert in the alerts table."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO alerts (timestamp, severity, alert_type, device_ip, description)
        VALUES (?, ?, 'arp_spoof', ?, ?)
        """,
        (timestamp, severity, device_ip, description),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Detection logic
# ---------------------------------------------------------------------------

def check_for_spoofing(db_path: str) -> bool:
    """
    Compare current device MACs against stored baselines.

    Returns True if at least one MAC change was detected this cycle.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    device_macs = get_device_macs(db_path)
    changes_detected = False

    for ip_address, current_mac in device_macs:
        known_mac = get_known_mac(db_path, ip_address)

        if known_mac is None:
            set_baseline(db_path, ip_address, current_mac, timestamp)
            continue

        if current_mac == known_mac:
            continue

        changes_detected = True
        severity = "Critical" if ip_address == GATEWAY_IP else "High"
        description = (
            f"Possible ARP spoofing on {ip_address}: "
            f"MAC changed from {known_mac} to {current_mac}"
        )

        insert_alert(db_path, timestamp, severity, ip_address, description)
        set_baseline(db_path, ip_address, current_mac, timestamp)

        print()
        print("=" * 70)
        print(f"  [!] ARP SPOOF ALERT — {severity}")
        print(f"  IP:       {ip_address}")
        print(f"  Old MAC:  {known_mac}")
        print(f"  New MAC:  {current_mac}")
        print(f"  Time:     {timestamp}")
        print("=" * 70)
        print()

    return changes_detected


def run_check_cycle(db_path: str) -> None:
    """Run one detection cycle and print a status line if the network is clean."""
    changes = check_for_spoofing(db_path)
    if not changes:
        timestamp = datetime.now(timezone.utc).isoformat()
        print(f"[{timestamp}] Network clean — no MAC address changes detected.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    print("NetGuard ARP Spoof Detector starting...")
    print(f"Database: {DB_PATH}")
    print(f"Check interval: {CHECK_INTERVAL_SECONDS}s")
    print(f"Gateway IP (Critical severity): {GATEWAY_IP}")
    print("Press Ctrl+C to stop.\n")

    init_database(DB_PATH)

    try:
        while True:
            run_check_cycle(DB_PATH)
            time.sleep(CHECK_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\n[*] ARP spoof detector stopped by user.")


if __name__ == "__main__":
    main()
