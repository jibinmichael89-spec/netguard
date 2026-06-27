#!/usr/bin/env python3
"""
NetGuard Inbound Connection Detector
Sniffs TCP SYN packets and alerts when external hosts attempt to connect
to devices on the monitored local network.
"""

import ipaddress
import os
import socket
import sqlite3
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

from scapy.all import IP, TCP, conf, sniff

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

DEFAULT_LOCAL_SUBNET = "192.168.1.0/24"
DEDUP_WINDOW_SECONDS = 300
DEVICE_CACHE_SECONDS = 30
HEARTBEAT_INTERVAL_SECONDS = 60

TCP_SYN_BPF_FILTER = "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0"

LOCAL_SUBNET = os.environ.get("NETGUARD_LOCAL_SUBNET", DEFAULT_LOCAL_SUBNET).strip()
CAPTURE_INTERFACE = os.environ.get("NETGUARD_CAPTURE_IFACE", "").strip() or None


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
# Network helpers
# ---------------------------------------------------------------------------

def detect_local_ip() -> str:
    """Return the primary local IPv4 address."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]


def detect_local_subnet() -> str:
    """Detect the local subnet in CIDR notation, with env override support."""
    if LOCAL_SUBNET != DEFAULT_LOCAL_SUBNET:
        return LOCAL_SUBNET

    local_ip = detect_local_ip()
    octets = local_ip.split(".")
    return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"


def detect_capture_interface() -> str | None:
    """
    Select the Scapy capture interface for the current host OS.

    Returns None to let Scapy choose the default when no match is found.
    """
    if CAPTURE_INTERFACE:
        return CAPTURE_INTERFACE

    local_ip = detect_local_ip()

    for iface in conf.ifaces.values():
        iface_ip = getattr(iface, "ip", None)
        if iface_ip == local_ip:
            return iface.network_name

    if os.name == "nt":
        return conf.iface

    return conf.iface


def is_external_ip(ip_address: str, local_network: ipaddress.IPv4Network) -> bool:
    """Return True when ip_address is outside the monitored local subnet."""
    try:
        return ipaddress.ip_address(ip_address) not in local_network
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Database operations
# ---------------------------------------------------------------------------

def init_database(db_path: str) -> None:
    """Ensure alerts table exists with inbound-connection columns."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
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
    cursor.execute("PRAGMA table_info(alerts)")
    columns = {row[1] for row in cursor.fetchall()}

    if "source_ip" not in columns:
        cursor.execute("ALTER TABLE alerts ADD COLUMN source_ip TEXT")
    if "source_port" not in columns:
        cursor.execute("ALTER TABLE alerts ADD COLUMN source_port INTEGER")
    if "destination_port" not in columns:
        cursor.execute("ALTER TABLE alerts ADD COLUMN destination_port INTEGER")

    conn.commit()
    conn.close()


def get_device_ips(db_path: str) -> set[str]:
    """Return all IP addresses currently stored in the devices table."""
    if not os.path.exists(db_path):
        return set()

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT ip_address FROM devices")
        ips = {row[0] for row in cursor.fetchall()}
    except sqlite3.OperationalError:
        ips = set()
    finally:
        conn.close()
    return ips


def recent_alert_exists(
    db_path: str,
    device_ip: str,
    source_ip: str,
    source_port: int,
    destination_port: int,
    cutoff_iso: str,
) -> bool:
    """Return True if a matching alert was recorded within the dedup window."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id FROM alerts
        WHERE alert_type = 'inbound_connection'
          AND device_ip = ?
          AND source_ip = ?
          AND source_port = ?
          AND destination_port = ?
          AND timestamp >= ?
        LIMIT 1
        """,
        (device_ip, source_ip, source_port, destination_port, cutoff_iso),
    )
    exists = cursor.fetchone() is not None
    conn.close()
    return exists


def insert_inbound_alert(
    db_path: str,
    timestamp: str,
    device_ip: str,
    source_ip: str,
    source_port: int,
    destination_port: int,
    description: str,
) -> None:
    """Persist an inbound connection alert."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO alerts (
            timestamp,
            severity,
            alert_type,
            device_ip,
            source_ip,
            source_port,
            destination_port,
            description
        )
        VALUES (?, 'CRITICAL', 'inbound_connection', ?, ?, ?, ?, ?)
        """,
        (
            timestamp,
            device_ip,
            source_ip,
            source_port,
            destination_port,
            description,
        ),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Detection state
# ---------------------------------------------------------------------------

class InboundDetectorState:
    """Shared runtime state for packet handling and deduplication."""

    def __init__(self, db_path: str, local_network: ipaddress.IPv4Network) -> None:
        self.db_path = db_path
        self.local_network = local_network
        self.device_ips: set[str] = set()
        self.device_ips_loaded_at = 0.0
        self.recent_alerts: dict[tuple[str, int, str, int], float] = {}
        self.lock = threading.Lock()
        self.last_detection_at = time.time()

    def refresh_device_ips(self, force: bool = False) -> None:
        """Reload monitored device IPs from the database on a timer."""
        now = time.time()
        if not force and now - self.device_ips_loaded_at < DEVICE_CACHE_SECONDS:
            return

        self.device_ips = get_device_ips(self.db_path)
        self.device_ips_loaded_at = now

    def is_duplicate(self, key: tuple[str, int, str, int], now: float) -> bool:
        """Check in-memory and database deduplication within five minutes."""
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=DEDUP_WINDOW_SECONDS)).isoformat()

        with self.lock:
            self._prune_recent_alerts(now)
            if key in self.recent_alerts:
                return True

        device_ip, destination_port, source_ip, source_port = (
            key[2],
            key[3],
            key[0],
            key[1],
        )
        if recent_alert_exists(
            self.db_path,
            device_ip,
            source_ip,
            source_port,
            destination_port,
            cutoff,
        ):
            with self.lock:
                self.recent_alerts[key] = now
            return True

        return False

    def mark_alerted(self, key: tuple[str, int, str, int], now: float) -> None:
        with self.lock:
            self.recent_alerts[key] = now
            self.last_detection_at = now

    def _prune_recent_alerts(self, now: float) -> None:
        expired = [
            key
            for key, seen_at in self.recent_alerts.items()
            if now - seen_at >= DEDUP_WINDOW_SECONDS
        ]
        for key in expired:
            del self.recent_alerts[key]


# ---------------------------------------------------------------------------
# Packet handling
# ---------------------------------------------------------------------------

def print_detection_table(
    source_ip: str,
    source_port: int,
    device_ip: str,
    destination_port: int,
    timestamp: str,
) -> None:
    """Print a formatted console table row for a detected inbound attempt."""
    print()
    print("-" * 88)
    print(f"  {'Source':<24} {'Destination':<24} {'Port':<8} {'Time'}")
    print("-" * 88)
    print(
        f"  {source_ip}:{source_port:<15} {device_ip:<24} {destination_port:<8} {timestamp[:19]}"
    )
    print("-" * 88)
    print(
        f"[CRITICAL] [Inbound] {source_ip}:{source_port} -> "
        f"{device_ip}:{destination_port} {timestamp}"
    )
    print()


def handle_syn_packet(packet, state: InboundDetectorState) -> None:
    """Evaluate a TCP SYN packet and create an alert when appropriate."""
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    tcp_layer = packet[TCP]
    if not (tcp_layer.flags & 0x02):  # SYN
        return
    if tcp_layer.flags & 0x10:  # ACK — ignore SYN-ACK responses
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    source_port = int(tcp_layer.sport)
    destination_port = int(tcp_layer.dport)

    if not is_external_ip(source_ip, state.local_network):
        return

    state.refresh_device_ips()
    if destination_ip not in state.device_ips:
        return

    dedup_key = (source_ip, source_port, destination_ip, destination_port)
    now = time.time()
    if state.is_duplicate(dedup_key, now):
        return

    timestamp = datetime.now(timezone.utc).isoformat()
    description = (
        f"Inbound connection attempt from {source_ip}:{source_port} "
        f"to port {destination_port}"
    )

    try:
        insert_inbound_alert(
            state.db_path,
            timestamp,
            destination_ip,
            source_ip,
            source_port,
            destination_port,
            description,
        )
        state.mark_alerted(dedup_key, now)
        print_detection_table(
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            timestamp,
        )
    except sqlite3.Error as exc:
        print(f"[!] Database error while recording inbound alert: {exc}")


def process_packet_factory(state: InboundDetectorState):
    """Return a Scapy callback bound to the shared detector state."""

    def process_packet(packet) -> None:
        try:
            handle_syn_packet(packet, state)
        except Exception as exc:
            print(f"[!] Error processing packet: {exc}")

    return process_packet


def heartbeat_loop(state: InboundDetectorState, stop_event: threading.Event) -> None:
    """Print periodic status when no inbound attempts are detected."""
    while not stop_event.wait(HEARTBEAT_INTERVAL_SECONDS):
        idle_seconds = time.time() - state.last_detection_at
        if idle_seconds >= HEARTBEAT_INTERVAL_SECONDS:
            timestamp = datetime.now(timezone.utc).isoformat()
            print(
                f"[{timestamp}] Monitoring inbound TCP SYN packets — "
                f"tracking {len(state.device_ips)} device(s)."
            )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    local_subnet = detect_local_subnet()
    local_network = ipaddress.ip_network(local_subnet, strict=False)
    capture_iface = detect_capture_interface()

    print("NetGuard Inbound Connection Detector starting...")
    print(f"Database:         {DB_PATH}")
    print(f"Local subnet:     {local_subnet}")
    print(f"Capture filter:   {TCP_SYN_BPF_FILTER}")
    print(f"Capture interface:{capture_iface or 'default'}")
    print(f"Dedup window:     {DEDUP_WINDOW_SECONDS}s")
    print("[!] Requires administrator/root privileges for packet capture.")
    print("Press Ctrl+C to stop.\n")

    require_root()

    if not os.path.exists(DB_PATH):
        print(f"[!] Database not found: {DB_PATH}")
        print("    Start the ARP scanner first.")
        sys.exit(1)

    init_database(DB_PATH)

    state = InboundDetectorState(DB_PATH, local_network)
    state.refresh_device_ips(force=True)

    stop_event = threading.Event()
    heartbeat_thread = threading.Thread(
        target=heartbeat_loop,
        args=(state, stop_event),
        daemon=True,
    )
    heartbeat_thread.start()

    process_packet = process_packet_factory(state)

    try:
        sniff(
            filter=TCP_SYN_BPF_FILTER,
            prn=process_packet,
            store=False,
            iface=capture_iface,
        )
    except KeyboardInterrupt:
        print("\n[*] Inbound connection detector stopped by user.")
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
