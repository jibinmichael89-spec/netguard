#!/usr/bin/env python3
"""
NetGuard Passive OS Fingerprinting
Sniffs TCP SYN-ACK and DHCP traffic to infer operating systems and device
categories, persisting results to the shared SQLite database.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import sqlite3
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from scapy.all import BOOTP, DHCP, IP, TCP, conf, sniff
from scapy.layers.inet import UDP

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

if getattr(sys, "frozen", False):
    _daemon_dir = os.path.join(sys._MEIPASS, "daemon")
    _bundle_root = sys._MEIPASS
else:
    _daemon_dir = os.path.join(PROJECT_ROOT, "daemon")
    _bundle_root = PROJECT_ROOT

if os.path.isdir(_daemon_dir) and _daemon_dir not in sys.path:
    sys.path.insert(0, _daemon_dir)

from db_path import resolve_db_path

DB_PATH = resolve_db_path(PROJECT_ROOT)
SIGNATURES_PATH = os.path.join(_bundle_root, "daemon", "data", "os_signatures.json")

REFINGERPRINT_HOURS = 6
HEARTBEAT_INTERVAL_SECONDS = 120
DEVICE_CACHE_SECONDS = 30
INITIAL_TTLS = (64, 128, 255)
WINDOW_TOLERANCE = 512

TCP_SYNACK_BPF = "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack != 0"
DHCP_BPF = "udp and (port 67 or port 68)"
COMBINED_BPF = f"(({TCP_SYNACK_BPF}) or ({DHCP_BPF}))"

DEFAULT_LOCAL_SUBNET = "192.168.1.0/24"
LOCAL_SUBNET = os.environ.get("NETGUARD_LOCAL_SUBNET", DEFAULT_LOCAL_SUBNET).strip()
CAPTURE_INTERFACE = os.environ.get("NETGUARD_CAPTURE_IFACE", "").strip() or None

CONFIDENCE_RANK = {"Low": 1, "Medium": 2, "High": 3}

SMART_TV_PORTS = {8080, 8001, 9080}
VENDOR_CATEGORY_ORDER = (
    "Gaming Console",
    "IoT",
    "Printer",
    "Router",
    "Smart TV",
    "Phone",
    "Computer",
)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TcpSignal:
    ip_address: str
    ttl: int
    window_size: int
    os_name: str
    confidence: str
    seen_at: float = field(default_factory=time.time)


@dataclass
class DhcpSignal:
    mac_address: str
    option_55: str
    os_name: str
    confidence: str
    seen_at: float = field(default_factory=time.time)


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
    """Select the Scapy capture interface for the current host OS."""
    if CAPTURE_INTERFACE:
        return CAPTURE_INTERFACE

    local_ip = detect_local_ip()
    for iface in conf.ifaces.values():
        iface_ip = getattr(iface, "ip", None)
        if iface_ip == local_ip:
            return iface.network_name

    return conf.iface


def is_local_ip(ip_address: str, local_network: ipaddress.IPv4Network) -> bool:
    """Return True when ip_address belongs to the monitored local subnet."""
    try:
        return ipaddress.ip_address(ip_address) in local_network
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Signature loading and matching
# ---------------------------------------------------------------------------

def load_signatures(path: str = SIGNATURES_PATH) -> dict:
    """Load passive OS fingerprint rules from JSON."""
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def confidence_rank(level: str) -> int:
    return CONFIDENCE_RANK.get(level, 0)


def estimate_initial_ttl(observed_ttl: int) -> int:
    """Map an observed TTL to the closest common initial TTL (64/128/255)."""
    within_range = [
        candidate
        for candidate in INITIAL_TTLS
        if abs(observed_ttl - candidate) <= 10
    ]
    if within_range:
        return min(within_range, key=lambda value: abs(observed_ttl - value))
    return min(INITIAL_TTLS, key=lambda value: abs(observed_ttl - value))


def ttl_matches_range(observed_ttl: int, ttl_range: list[int]) -> bool:
    """Return True when observed or estimated initial TTL fits the rule range."""
    if len(ttl_range) != 2:
        return False
    ttl_min, ttl_max = ttl_range
    initial_ttl = estimate_initial_ttl(observed_ttl)
    return (
        ttl_min <= observed_ttl <= ttl_max
        or ttl_min <= initial_ttl <= ttl_max
        or abs(observed_ttl - ttl_min) <= 10
        or abs(observed_ttl - ttl_max) <= 10
    )


def window_matches(observed_window: int, allowed_windows: list[int]) -> tuple[bool, bool]:
    """
    Return (matched, exact_match).

    Exact matches are preferred; close matches allow WINDOW_TOLERANCE slack.
    """
    if observed_window in allowed_windows:
        return True, True

    closest = min(allowed_windows, key=lambda value: abs(value - observed_window))
    if abs(closest - observed_window) <= WINDOW_TOLERANCE:
        return True, False
    return False, False


def match_tcp_signature(
    observed_ttl: int,
    observed_window: int,
    signatures: list[dict],
) -> tuple[str, str] | None:
    """Match TCP SYN-ACK characteristics against the ruleset."""
    best: tuple[str, str] | None = None
    best_score = -1

    for entry in signatures:
        if not ttl_matches_range(observed_ttl, entry.get("ttl_range", [])):
            continue

        window_ok, exact_window = window_matches(
            observed_window, entry.get("window_sizes", [])
        )
        if not window_ok:
            continue

        initial_ttl = estimate_initial_ttl(observed_ttl)
        ttl_min, ttl_max = entry["ttl_range"]
        score = 0
        if ttl_min <= observed_ttl <= ttl_max:
            score += 2
        if ttl_min <= initial_ttl <= ttl_max:
            score += 2
        if exact_window:
            score += 3
        else:
            score += 1
        score += confidence_rank(entry.get("confidence", "Low"))

        if score > best_score:
            best_score = score
            best = (entry["os_name"], entry.get("confidence", "Low"))

    return best


def pattern_overlap(pattern: str, observed: str) -> float:
    """Return overlap ratio between two comma-separated option lists."""
    pattern_set = {part.strip() for part in pattern.split(",") if part.strip()}
    observed_set = {part.strip() for part in observed.split(",") if part.strip()}
    if not pattern_set:
        return 0.0
    return len(pattern_set & observed_set) / len(pattern_set)


def match_dhcp_signature(
    option_55: str,
    fingerprints: list[dict],
) -> tuple[str, str] | None:
    """Match DHCP option 55 against known OS fingerprints."""
    normalized = ",".join(part.strip() for part in option_55.split(",") if part.strip())
    if not normalized:
        return None

    best: tuple[str, str] | None = None
    best_score = -1.0

    for entry in fingerprints:
        pattern = entry.get("option_55_pattern", "")
        if not pattern:
            continue

        if normalized == pattern:
            return entry["os_name"], "High"

        overlap = pattern_overlap(pattern, normalized)
        if overlap >= 0.7:
            confidence = "Medium"
            score = overlap + confidence_rank(confidence)
            if score > best_score:
                best_score = score
                best = (entry["os_name"], confidence)
        elif overlap >= 0.5:
            confidence = entry.get("confidence", "Low")
            if confidence_rank(confidence) <= confidence_rank("Medium"):
                confidence = "Low"
            score = overlap
            if score > best_score:
                best_score = score
                best = (entry["os_name"], confidence)

    return best


def merge_os_guess(
    tcp: TcpSignal | None,
    dhcp: DhcpSignal | None,
) -> tuple[str | None, str | None, str | None]:
    """
    Combine TCP and DHCP guesses.

    Returns (os_name, confidence, fingerprint_source).
    """
    if tcp and dhcp:
        if _os_names_compatible(tcp.os_name, dhcp.os_name):
            return tcp.os_name, "High", "tcp+dhcp"
        return dhcp.os_name, "Medium", "dhcp"

    if dhcp:
        return dhcp.os_name, dhcp.confidence, "dhcp"

    if tcp:
        return tcp.os_name, tcp.confidence, "tcp"

    return None, None, None


def _os_names_compatible(tcp_name: str, dhcp_name: str) -> bool:
    """Return True when two OS labels refer to the same family."""
    tcp_lower = tcp_name.lower()
    dhcp_lower = dhcp_name.lower()

    if tcp_lower == dhcp_lower:
        return True

    pairs = (
        ("windows", "windows"),
        ("macos", "ios"),
        ("ios", "macos"),
        ("linux", "linux"),
        ("android", "android"),
    )
    for left, right in pairs:
        if left in tcp_lower and right in dhcp_lower:
            return True
        if right in tcp_lower and left in dhcp_lower:
            return True

    return False


def _vendor_matches(vendor_lower: str, keywords: list[str]) -> bool:
    return any(keyword.lower() in vendor_lower for keyword in keywords)


def _classify_gaming_console(
    vendor_lower: str,
    hostname_lower: str,
    port_set: set[int],
    gaming_rule: dict,
) -> str | None:
    """
    Prefer Gaming Console over Smart TV for console vendors.

    Applies when the vendor matches Sony/Microsoft/Nintendo/Valve, the device
    lacks smart-TV-typical ports, and either exposes gaming ports or has no
    friendly hostname (common for PS/Xbox).
    """
    if not _vendor_matches(vendor_lower, gaming_rule.get("vendor_keywords", [])):
        return None

    if port_set & SMART_TV_PORTS:
        return None

    gaming_ports = set(gaming_rule.get("common_ports", []))
    has_gaming_ports = bool(port_set & gaming_ports)
    no_hostname = not hostname_lower.strip()

    if has_gaming_ports or no_hostname:
        return "Gaming Console"

    return None


def classify_device_category(
    os_guess: str | None,
    vendor: str | None,
    hostname: str | None,
    open_ports: list[int],
    rules: dict,
) -> str:
    """Apply category rules with gaming-console disambiguation and vendor priority."""
    vendor_lower = (vendor or "").lower()
    hostname_lower = (hostname or "").lower()
    os_lower = (os_guess or "").lower()
    port_set = set(open_ports)

    gaming_rule = rules.get("Gaming Console", {})
    gaming_match = _classify_gaming_console(
        vendor_lower, hostname_lower, port_set, gaming_rule
    )
    if gaming_match:
        return gaming_match

    for category in VENDOR_CATEGORY_ORDER:
        rule = rules.get(category)
        if not rule:
            continue
        if category == "Gaming Console":
            continue
        for keyword in rule.get("vendor_keywords", []):
            if keyword.lower() in vendor_lower:
                return category

    for category in VENDOR_CATEGORY_ORDER:
        rule = rules.get(category)
        if not rule:
            continue
        for port in rule.get("common_ports", []):
            if port in port_set:
                return category

    for category in VENDOR_CATEGORY_ORDER:
        rule = rules.get(category)
        if not rule:
            continue
        for keyword in rule.get("os_keywords", []):
            if keyword.lower() in os_lower:
                return category

    for category in VENDOR_CATEGORY_ORDER:
        rule = rules.get(category)
        if not rule:
            continue
        for keyword in rule.get("hostname_keywords", []):
            if keyword.lower() in hostname_lower:
                return category

    return "Unknown"


# ---------------------------------------------------------------------------
# Database operations
# ---------------------------------------------------------------------------

def get_db_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    """Open a SQLite connection to the NetGuard database."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_database(db_path: str) -> None:
    """Ensure devices table exists with fingerprint columns."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS devices (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address  TEXT    NOT NULL,
            mac_address TEXT    NOT NULL UNIQUE,
            vendor      TEXT,
            hostname    TEXT,
            first_seen  TEXT    NOT NULL,
            last_seen   TEXT    NOT NULL,
            status      TEXT    NOT NULL DEFAULT 'online'
        )
        """
    )
    cursor.execute("PRAGMA table_info(devices)")
    columns = {row[1] for row in cursor.fetchall()}

    fingerprint_columns = {
        "os_guess": "TEXT",
        "os_confidence": "TEXT",
        "device_category": "TEXT",
        "fingerprint_source": "TEXT",
        "last_fingerprint_at": "TEXT",
    }
    for column_name, column_type in fingerprint_columns.items():
        if column_name not in columns:
            cursor.execute(
                f"ALTER TABLE devices ADD COLUMN {column_name} {column_type}"
            )

    conn.commit()
    conn.close()


def get_device_by_ip(conn: sqlite3.Connection, ip_address: str) -> sqlite3.Row | None:
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices WHERE ip_address = ?", (ip_address,))
    return cursor.fetchone()


def get_device_by_mac(conn: sqlite3.Connection, mac_address: str) -> sqlite3.Row | None:
    normalized = mac_address.upper().replace("-", ":")
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT * FROM devices
        WHERE REPLACE(UPPER(mac_address), '-', ':') = ?
        """,
        (normalized,),
    )
    return cursor.fetchone()


def get_open_ports_for_device(conn: sqlite3.Connection, ip_address: str) -> list[int]:
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT port FROM open_ports WHERE device_ip = ?",
            (ip_address,),
        )
        return [int(row[0]) for row in cursor.fetchall()]
    except sqlite3.OperationalError:
        return []


def should_update_fingerprint(
    last_fingerprint_at: str | None,
    existing_confidence: str | None,
    new_confidence: str,
) -> bool:
    """Decide whether a fingerprint result should be written to the database."""
    if existing_confidence and confidence_rank(new_confidence) < confidence_rank(
        existing_confidence
    ):
        return False

    if not last_fingerprint_at:
        return True

    try:
        last_at = datetime.fromisoformat(last_fingerprint_at)
    except ValueError:
        return True

    if datetime.now(timezone.utc) - last_at >= timedelta(hours=REFINGERPRINT_HOURS):
        return True

    if not existing_confidence:
        return True

    return confidence_rank(new_confidence) > confidence_rank(existing_confidence)


def update_device_fingerprint(
    db_path: str,
    device_id: int,
    os_guess: str,
    os_confidence: str,
    device_category: str,
    fingerprint_source: str,
) -> bool:
    """Persist fingerprint fields when update rules allow it."""
    timestamp = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT os_confidence, last_fingerprint_at FROM devices WHERE id = ?", (device_id,))
    row = cursor.fetchone()
    if row is None:
        conn.close()
        return False

    if not should_update_fingerprint(row["last_fingerprint_at"], row["os_confidence"], os_confidence):
        conn.close()
        return False

    cursor.execute(
        """
        UPDATE devices
        SET os_guess = ?,
            os_confidence = ?,
            device_category = ?,
            fingerprint_source = ?,
            last_fingerprint_at = ?
        WHERE id = ?
        """,
        (
            os_guess,
            os_confidence,
            device_category,
            fingerprint_source,
            timestamp,
            device_id,
        ),
    )
    conn.commit()
    conn.close()
    return True


# ---------------------------------------------------------------------------
# Packet parsing
# ---------------------------------------------------------------------------

def extract_tcp_synack(packet) -> tuple[str, int, int] | None:
    """Extract source IP, TTL, and TCP window from a SYN-ACK packet."""
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return None

    tcp_layer = packet[TCP]
    if not (tcp_layer.flags & 0x02):  # SYN
        return None
    if not (tcp_layer.flags & 0x10):  # ACK
        return None

    return packet[IP].src, int(packet[IP].ttl), int(tcp_layer.window)


def extract_dhcp_option_55(packet) -> tuple[str, str] | None:
    """
    Extract source MAC and DHCP option 55 from Discover/Request packets.

    Returns (mac_address, option_55_pattern) or None.
    """
    if not packet.haslayer(BOOTP) or not packet.haslayer(DHCP):
        return None

    message_type = None
    option_55 = None
    for option in packet[DHCP].options:
        if not isinstance(option, tuple):
            continue
        if option[0] == "message-type":
            message_type = option[1]
        elif option[0] == "param_req_list":
            option_55 = ",".join(str(value) for value in option[1])

    if message_type not in (1, 3):  # Discover or Request
        return None
    if not option_55:
        return None

    mac_bytes = bytes(packet[BOOTP].chaddr[:6])
    if mac_bytes == b"\x00" * 6:
        return None

    mac_address = ":".join(f"{byte:02X}" for byte in mac_bytes)
    return mac_address, option_55


# ---------------------------------------------------------------------------
# Detector state
# ---------------------------------------------------------------------------

class OsFingerprintState:
    """Shared runtime state for passive fingerprinting."""

    def __init__(
        self,
        db_path: str,
        local_network: ipaddress.IPv4Network,
        signatures: dict,
    ) -> None:
        self.db_path = db_path
        self.local_network = local_network
        self.signatures = signatures
        self.lock = threading.Lock()
        self.tcp_signals: dict[str, TcpSignal] = {}
        self.dhcp_signals: dict[str, DhcpSignal] = {}
        self.device_ips: set[str] = set()
        self.device_macs: set[str] = set()
        self.device_cache_loaded_at = 0.0
        self.last_fingerprint_at = time.time()
        self.fingerprint_count = 0

    def refresh_device_cache(self, force: bool = False) -> None:
        now = time.time()
        if not force and now - self.device_cache_loaded_at < DEVICE_CACHE_SECONDS:
            return

        if not os.path.exists(self.db_path):
            self.device_ips = set()
            self.device_macs = set()
            self.device_cache_loaded_at = now
            return

        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT ip_address, mac_address FROM devices")
            rows = cursor.fetchall()
            self.device_ips = {row["ip_address"] for row in rows}
            self.device_macs = {
                row["mac_address"].upper().replace("-", ":") for row in rows
            }
        except sqlite3.OperationalError:
            self.device_ips = set()
            self.device_macs = set()
        finally:
            conn.close()

        self.device_cache_loaded_at = now

    def record_tcp_signal(self, signal: TcpSignal) -> None:
        with self.lock:
            self.tcp_signals[signal.ip_address] = signal
        self._finalize_for_ip(signal.ip_address)

    def record_dhcp_signal(self, signal: DhcpSignal) -> None:
        with self.lock:
            self.dhcp_signals[signal.mac_address.upper().replace("-", ":")] = signal
        self._finalize_for_mac(signal.mac_address)

    def _finalize_for_ip(self, ip_address: str) -> None:
        with self.lock:
            tcp = self.tcp_signals.get(ip_address)
            dhcp = None
            if tcp:
                conn = get_db_connection(self.db_path)
                device = get_device_by_ip(conn, ip_address)
                if device:
                    mac_key = device["mac_address"].upper().replace("-", ":")
                    dhcp = self.dhcp_signals.get(mac_key)
                conn.close()
        self._apply_fingerprint(ip_address=ip_address, tcp=tcp, dhcp=dhcp)

    def _finalize_for_mac(self, mac_address: str) -> None:
        mac_key = mac_address.upper().replace("-", ":")
        with self.lock:
            dhcp = self.dhcp_signals.get(mac_key)
            tcp = None
            ip_address = None
            conn = get_db_connection(self.db_path)
            device = get_device_by_mac(conn, mac_address)
            if device:
                ip_address = device["ip_address"]
                tcp = self.tcp_signals.get(ip_address)
            conn.close()

        if ip_address:
            self._apply_fingerprint(ip_address=ip_address, tcp=tcp, dhcp=dhcp)

    def _apply_fingerprint(
        self,
        ip_address: str,
        tcp: TcpSignal | None,
        dhcp: DhcpSignal | None,
    ) -> None:
        os_name, confidence, source = merge_os_guess(tcp, dhcp)
        if not os_name or not confidence or not source:
            return

        conn = get_db_connection(self.db_path)
        device = get_device_by_ip(conn, ip_address)
        if device is None:
            conn.close()
            return

        open_ports = get_open_ports_for_device(conn, ip_address)
        conn.close()

        category = classify_device_category(
            os_name,
            device["vendor"],
            device["hostname"],
            open_ports,
            self.signatures.get("device_category_rules", {}),
        )

        updated = update_device_fingerprint(
            self.db_path,
            int(device["id"]),
            os_name,
            confidence,
            category,
            source,
        )
        if not updated:
            return

        self.last_fingerprint_at = time.time()
        self.fingerprint_count += 1
        print(
            f"[FINGERPRINT] {ip_address} -> {os_name} ({confidence} confidence) "
            f"| Category: {category}"
        )


# ---------------------------------------------------------------------------
# Packet handling
# ---------------------------------------------------------------------------

def handle_tcp_synack(packet, state: OsFingerprintState) -> None:
    extracted = extract_tcp_synack(packet)
    if extracted is None:
        return

    source_ip, ttl, window_size = extracted
    if not is_local_ip(source_ip, state.local_network):
        return

    state.refresh_device_cache()
    if source_ip not in state.device_ips:
        return

    match = match_tcp_signature(
        ttl,
        window_size,
        state.signatures.get("tcp_signatures", []),
    )
    if match is None:
        return

    os_name, confidence = match
    state.record_tcp_signal(
        TcpSignal(
            ip_address=source_ip,
            ttl=ttl,
            window_size=window_size,
            os_name=os_name,
            confidence=confidence,
        )
    )


def handle_dhcp_packet(packet, state: OsFingerprintState) -> None:
    extracted = extract_dhcp_option_55(packet)
    if extracted is None:
        return

    mac_address, option_55 = extracted
    mac_key = mac_address.upper().replace("-", ":")

    state.refresh_device_cache()
    if mac_key not in state.device_macs:
        return

    match = match_dhcp_signature(
        option_55,
        state.signatures.get("dhcp_fingerprints", []),
    )
    if match is None:
        return

    os_name, confidence = match
    state.record_dhcp_signal(
        DhcpSignal(
            mac_address=mac_address,
            option_55=option_55,
            os_name=os_name,
            confidence=confidence,
        )
    )


def process_packet_factory(state: OsFingerprintState):
    """Return a Scapy callback bound to the shared detector state."""

    def process_packet(packet) -> None:
        try:
            if packet.haslayer(TCP):
                handle_tcp_synack(packet, state)
            elif packet.haslayer(UDP):
                handle_dhcp_packet(packet, state)
        except Exception as exc:
            print(f"[!] Error processing packet: {exc}")

    return process_packet


def heartbeat_loop(state: OsFingerprintState, stop_event: threading.Event) -> None:
    """Print periodic status while the daemon is monitoring traffic."""
    while not stop_event.wait(HEARTBEAT_INTERVAL_SECONDS):
        idle_seconds = time.time() - state.last_fingerprint_at
        if idle_seconds >= HEARTBEAT_INTERVAL_SECONDS:
            timestamp = datetime.now(timezone.utc).isoformat()
            print(
                f"[{timestamp}] Passive OS fingerprinting active — "
                f"tracking {len(state.device_ips)} device(s), "
                f"{state.fingerprint_count} fingerprint(s) recorded."
            )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    local_subnet = detect_local_subnet()
    local_network = ipaddress.ip_network(local_subnet, strict=False)
    capture_iface = detect_capture_interface()

    print("NetGuard Passive OS Fingerprinting starting...")
    print(f"Database:         {DB_PATH}")
    print(f"Signatures:       {SIGNATURES_PATH}")
    print(f"Local subnet:     {local_subnet}")
    print(f"Capture filter:   {COMBINED_BPF}")
    print(f"Capture interface:{capture_iface or 'default'}")
    print(f"Re-fingerprint:   every {REFINGERPRINT_HOURS} hours")
    print("[!] Requires administrator/root privileges for packet capture.")
    print("Press Ctrl+C to stop.\n")

    require_root()

    if not os.path.exists(SIGNATURES_PATH):
        print(f"[!] Signature file not found: {SIGNATURES_PATH}")
        sys.exit(1)

    if not os.path.exists(DB_PATH):
        print(f"[!] Database not found: {DB_PATH}")
        print("    Start the network scanner first.")
        sys.exit(1)

    try:
        signatures = load_signatures()
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[!] Failed to load signatures: {exc}")
        sys.exit(1)

    init_database(DB_PATH)

    state = OsFingerprintState(DB_PATH, local_network, signatures)
    state.refresh_device_cache(force=True)

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
            filter=COMBINED_BPF,
            prn=process_packet,
            store=False,
            iface=capture_iface,
        )
    except KeyboardInterrupt:
        print("\n[*] OS fingerprinting daemon stopped by user.")
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
