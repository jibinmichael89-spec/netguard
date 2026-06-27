#!/usr/bin/env python3
"""
NetGuard Rogue DHCP Detector
Sniffs DHCP OFFER/ACK traffic to detect unauthorized DHCP servers —
a common MITM attack vector on local networks.
"""

import os
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone

from scapy.all import BOOTP, DHCP, Ether, IP, sniff

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

if getattr(sys, "frozen", False):
    _daemon_dir = os.path.join(sys._MEIPASS, "daemon")
else:
    _daemon_dir = os.path.join(PROJECT_ROOT, "daemon")

if os.path.isdir(_daemon_dir) and _daemon_dir not in sys.path:
    sys.path.insert(0, _daemon_dir)

from db_path import resolve_db_path

DB_PATH = resolve_db_path(PROJECT_ROOT)

DHCP_BPF_FILTER = "udp port 67 or udp port 68"
HEARTBEAT_INTERVAL_SECONDS = 30

DHCP_MESSAGE_OFFER = 2
DHCP_MESSAGE_ACK = 5


# ---------------------------------------------------------------------------
# Privilege check
# ---------------------------------------------------------------------------

def require_root() -> None:
    """Ensure the process is running with administrator/root privileges."""
    if os.name == "nt":
        try:
            import ctypes

            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("[!] Error: Administrator privileges are required.")
                sys.exit(1)
        except (AttributeError, OSError):
            pass
        return

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[!] Error: Root privileges are required. Run with sudo.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Database operations
# ---------------------------------------------------------------------------

def init_database(db_path: str) -> None:
    """Create dhcp_servers and alerts tables if they do not already exist."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS dhcp_servers (
            mac_address TEXT PRIMARY KEY,
            ip_address  TEXT,
            first_seen  TEXT,
            last_seen   TEXT,
            is_trusted  INTEGER DEFAULT 1
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


def count_dhcp_servers(db_path: str) -> int:
    """Return the number of known DHCP servers stored in the database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM dhcp_servers")
    count = cursor.fetchone()[0]
    conn.close()
    return count


def get_dhcp_server(db_path: str, mac_address: str) -> dict | None:
    """Return the dhcp_servers row for a MAC address, or None if unknown."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM dhcp_servers WHERE mac_address = ?",
        (mac_address.upper(),),
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def insert_dhcp_server(
    db_path: str,
    mac_address: str,
    ip_address: str,
    timestamp: str,
    is_trusted: int,
) -> None:
    """Record a newly observed DHCP server."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO dhcp_servers (mac_address, ip_address, first_seen, last_seen, is_trusted)
        VALUES (?, ?, ?, ?, ?)
        """,
        (mac_address.upper(), ip_address, timestamp, timestamp, is_trusted),
    )
    conn.commit()
    conn.close()


def update_dhcp_server_last_seen(
    db_path: str,
    mac_address: str,
    ip_address: str,
    timestamp: str,
) -> None:
    """Update last_seen (and IP if changed) for a known DHCP server."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE dhcp_servers
        SET last_seen = ?, ip_address = ?
        WHERE mac_address = ?
        """,
        (timestamp, ip_address, mac_address.upper()),
    )
    conn.commit()
    conn.close()


def insert_alert(
    db_path: str,
    timestamp: str,
    device_ip: str,
    description: str,
) -> None:
    """Record a rogue DHCP alert in the alerts table."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO alerts (timestamp, severity, alert_type, device_ip, description)
        VALUES (?, 'Critical', 'rogue_dhcp', ?, ?)
        """,
        (timestamp, device_ip, description),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# DHCP packet parsing
# ---------------------------------------------------------------------------

def format_ip_value(value) -> str:
    """Format a Scapy IP option value (single address or list) for display."""
    if value is None:
        return "none"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value) if value else "none"
    return str(value)


def parse_dhcp_options(dhcp_layer: DHCP) -> dict:
    """Extract relevant DHCP options from a Scapy DHCP layer."""
    parsed = {
        "message_type": None,
        "server_id": None,
        "dns_servers": None,
        "router": None,
    }

    for option in dhcp_layer.options:
        if not isinstance(option, tuple) or len(option) < 2:
            continue
        if option[0] == "end":
            break

        key, value = option[0], option[1]
        if key == "message-type":
            parsed["message_type"] = value
        elif key in ("server_id", "dhcp_server_identifier"):
            parsed["server_id"] = str(value)
        elif key in ("name_server", "dns_server"):
            parsed["dns_servers"] = value
        elif key == "router":
            parsed["router"] = value

    return parsed


def extract_dhcp_server_info(packet) -> dict | None:
    """
    Parse a DHCP OFFER or ACK packet and return server/offer details.

    Returns None if the packet is not a relevant DHCP server response.
    """
    if not packet.haslayer(Ether) or not packet.haslayer(BOOTP) or not packet.haslayer(DHCP):
        return None

    options = parse_dhcp_options(packet[DHCP])
    message_type = options["message_type"]
    if message_type not in (DHCP_MESSAGE_OFFER, DHCP_MESSAGE_ACK):
        return None

    source_mac = packet[Ether].src.upper()
    source_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
    offered_ip = str(packet[BOOTP].yiaddr)
    server_id = options["server_id"] or source_ip

    return {
        "source_mac": source_mac,
        "source_ip": source_ip,
        "offered_ip": offered_ip,
        "server_id": server_id,
        "dns_servers": options["dns_servers"],
        "router": options["router"],
        "message_type": "OFFER" if message_type == DHCP_MESSAGE_OFFER else "ACK",
    }


# ---------------------------------------------------------------------------
# Detection logic
# ---------------------------------------------------------------------------

last_dhcp_activity = time.time()
activity_lock = threading.Lock()


def mark_dhcp_activity() -> None:
    """Record that DHCP server traffic was recently observed."""
    global last_dhcp_activity
    with activity_lock:
        last_dhcp_activity = time.time()


def print_rogue_dhcp_alert(info: dict, description: str, timestamp: str) -> None:
    """Print a formatted rogue DHCP warning to the console."""
    print()
    print("=" * 70)
    print("  [!] ROGUE DHCP SERVER ALERT — Critical")
    print(f"  Type:        DHCP {info['message_type']}")
    print(f"  Server MAC:  {info['source_mac']}")
    print(f"  Server IP:   {info['source_ip']}")
    print(f"  Server ID:   {info['server_id']}")
    print(f"  Offered IP:  {info['offered_ip']}")
    print(f"  Gateway:     {format_ip_value(info['router'])}")
    print(f"  DNS:         {format_ip_value(info['dns_servers'])}")
    print(f"  Time:        {timestamp}")
    print(f"  Detail:      {description}")
    print("=" * 70)
    print()


def handle_dhcp_server_packet(info: dict) -> None:
    """Evaluate a DHCP OFFER/ACK and record trusted or rogue server state."""
    timestamp = datetime.now(timezone.utc).isoformat()
    mark_dhcp_activity()

    mac_address = info["source_mac"]
    device_ip = info["source_ip"] if info["source_ip"] != "0.0.0.0" else info["server_id"]
    gateway = format_ip_value(info["router"])
    dns = format_ip_value(info["dns_servers"])

    known = get_dhcp_server(DB_PATH, mac_address)

    if known is None:
        is_first = count_dhcp_servers(DB_PATH) == 0
        is_trusted = 1 if is_first else 0
        insert_dhcp_server(DB_PATH, mac_address, device_ip, timestamp, is_trusted)

        if is_first:
            print(
                f"[{timestamp}] Trusted DHCP server baseline established — "
                f"MAC {mac_address} at {device_ip}"
            )
            return

        description = (
            f"Possible rogue DHCP server detected (MAC {mac_address}). "
            f"Server IP {device_ip}, offered gateway {gateway}, "
            f"offered DNS {dns}. This may indicate a MITM attack."
        )
        insert_alert(DB_PATH, timestamp, device_ip, description)
        print_rogue_dhcp_alert(info, description, timestamp)
        return

    if known["is_trusted"]:
        update_dhcp_server_last_seen(DB_PATH, mac_address, device_ip, timestamp)
        return

    update_dhcp_server_last_seen(DB_PATH, mac_address, device_ip, timestamp)


def process_packet(packet) -> None:
    """Scapy callback invoked for every captured DHCP packet."""
    try:
        info = extract_dhcp_server_info(packet)
        if info is None:
            return
        handle_dhcp_server_packet(info)
    except Exception as exc:
        print(f"[!] Error processing DHCP packet: {exc}")


def heartbeat_loop(stop_event: threading.Event) -> None:
    """Print a status line every 30 seconds when no DHCP activity is seen."""
    while not stop_event.wait(HEARTBEAT_INTERVAL_SECONDS):
        with activity_lock:
            idle_seconds = time.time() - last_dhcp_activity

        if idle_seconds >= HEARTBEAT_INTERVAL_SECONDS:
            timestamp = datetime.now(timezone.utc).isoformat()
            print(
                f"[{timestamp}] Monitoring DHCP — no new DHCP server activity."
            )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    print("NetGuard Rogue DHCP Detector starting...")
    print(f"Database: {DB_PATH}")
    print("[!] This module requires administrator/root privileges for packet capture.")
    print(f"Capture filter: {DHCP_BPF_FILTER}")
    print(f"Heartbeat interval: {HEARTBEAT_INTERVAL_SECONDS}s")
    print("Press Ctrl+C to stop.\n")

    require_root()
    init_database(DB_PATH)

    stop_event = threading.Event()
    heartbeat_thread = threading.Thread(
        target=heartbeat_loop,
        args=(stop_event,),
        daemon=True,
    )
    heartbeat_thread.start()

    try:
        sniff(
            filter=DHCP_BPF_FILTER,
            prn=process_packet,
            store=False,
        )
    except KeyboardInterrupt:
        print("\n[*] Rogue DHCP detector stopped by user.")
        stop_event.set()
        sys.exit(0)
    except PermissionError:
        print("[!] Permission denied. Run with sudo / as Administrator.")
        stop_event.set()
        sys.exit(1)
    except OSError as exc:
        print(f"[!] Network capture error: {exc}")
        stop_event.set()
        sys.exit(1)


if __name__ == "__main__":
    main()
