#!/usr/bin/env python3
"""
NetGuard ARP Network Scanner
Continuously scans the local network using ARP requests, discovers active
devices, and persists results to a SQLite database.
"""

import ipaddress
import os
import socket
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone

import requests
from scapy.all import ARP, Ether, srp

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Scan interval in seconds between network sweeps
SCAN_INTERVAL_SECONDS = 30

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

if getattr(sys, "frozen", False):
    _daemon_dir = os.path.join(sys._MEIPASS, "daemon")
else:
    _daemon_dir = os.path.join(PROJECT_ROOT, "daemon")

if os.path.isdir(_daemon_dir) and _daemon_dir not in sys.path:
    sys.path.insert(0, _daemon_dir)

_scanner_dir = os.path.join(_daemon_dir, "scanner")
if os.path.isdir(_scanner_dir) and _scanner_dir not in sys.path:
    sys.path.insert(0, _scanner_dir)

from db_path import resolve_db_path
from database import init_netguard_database
from port_scanner import run_port_scan_cycle
from windows_dns import poll_windows_dns_cache

DB_PATH = resolve_db_path(PROJECT_ROOT)

# MAC vendor lookup API endpoint (free tier, rate-limited)
MAC_VENDOR_API = "https://api.macvendors.com/{mac}"


# ---------------------------------------------------------------------------
# Network detection
# ---------------------------------------------------------------------------

def detect_local_subnet() -> str:
    """
    Automatically detect the local network subnet in CIDR notation.

    Uses a UDP socket trick to find the primary local IP, then reads the
    netmask from the system routing table (Linux/Pi via `ip` command).
    Falls back to a /24 subnet if detection fails.
    """
    local_ip = _detect_local_ip()

    # Try to read the CIDR from the `ip` command (works on Raspberry Pi OS)
    try:
        result = subprocess.run(
            ["ip", "-o", "-4", "addr", "show"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        for line in result.stdout.splitlines():
            if local_ip in line:
                for part in line.split():
                    if "/" in part and part.count(".") == 3:
                        network = ipaddress.IPv4Interface(part).network
                        return str(network)
    except (subprocess.SubprocessError, FileNotFoundError, ValueError):
        pass

    octets = local_ip.split(".")
    return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"


def _detect_local_ip() -> str:
    """Return the primary local IPv4 address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        pass

    if sys.platform == "win32":
        try:
            result = subprocess.run(
                ["ipconfig"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            for line in result.stdout.splitlines():
                if "IPv4" in line and ":" in line:
                    ip = line.split(":")[-1].strip()
                    if ip.count(".") == 3 and not ip.startswith("169.254"):
                        return ip
        except (subprocess.SubprocessError, OSError):
            pass

    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError as exc:
        raise RuntimeError(
            "Could not detect your network address. Connect to Wi-Fi/Ethernet and try again."
        ) from exc


# ---------------------------------------------------------------------------
# Device enrichment
# ---------------------------------------------------------------------------

def lookup_vendor(mac_address: str) -> str:
    """
    Look up the hardware vendor name from the MAC OUI database.

    Queries macvendors.com via HTTP. Returns 'Unknown' on failure.
    """
    try:
        response = requests.get(
            MAC_VENDOR_API.format(mac=mac_address),
            timeout=5,
        )
        if response.status_code == 200 and response.text.strip():
            return response.text.strip()
    except requests.RequestException:
        pass
    return "Unknown"


def lookup_hostname(ip_address: str) -> str | None:
    """
    Attempt a reverse DNS lookup to resolve a hostname for the given IP.

    Returns None if no hostname is available.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


# ---------------------------------------------------------------------------
# ARP scanning
# ---------------------------------------------------------------------------

def arp_scan_scapy(subnet: str, timeout: int = 3) -> list[dict]:
    """Send ARP requests across the subnet using Scapy (requires Npcap on Windows)."""
    arp_request = ARP(pdst=subnet)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered, _ = srp(packet, timeout=timeout, verbose=False, retry=2)

    devices = []
    for _, response in answered:
        devices.append(
            {
                "ip_address": response.psrc,
                "mac_address": response.hwsrc.upper(),
            }
        )
    return devices


def _is_valid_mac(mac_raw: str) -> bool:
    mac = mac_raw.replace("-", ":").upper()
    if mac in ("INCOMPLETE", "FAILED"):
        return False
    parts = mac.split(":")
    if len(parts) != 6:
        return False
    return all(len(part) == 2 and all(c in "0123456789ABCDEF" for c in part) for part in parts)


def _normalize_mac(mac_raw: str) -> str:
    return mac_raw.replace("-", ":").upper()


def _read_windows_arp_table(network: ipaddress.IPv4Network) -> list[dict]:
    result = subprocess.run(
        ["arp", "-a"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )

    devices: list[dict] = []
    seen: set[str] = set()
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("Interface") or line.startswith("Internet"):
            continue
        parts = line.split()
        if len(parts) < 2 or parts[0].count(".") != 3:
            continue
        ip = parts[0]
        mac_raw = parts[1]
        if not _is_valid_mac(mac_raw):
            continue
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if addr not in network:
            continue
        if ip in seen:
            continue
        seen.add(ip)
        devices.append({"ip_address": ip, "mac_address": _normalize_mac(mac_raw)})
    return devices


def _windows_ping_sweep(local_ip: str) -> None:
    """Ping common hosts to populate the ARP cache."""
    octets = local_ip.split(".")
    gateway = f"{octets[0]}.{octets[1]}.{octets[2]}.1"
    for target in (gateway, local_ip):
        subprocess.run(
            ["ping", "-n", "1", "-w", "500", target],
            capture_output=True,
            timeout=3,
            check=False,
        )
    for last_octet in range(1, 255):
        if last_octet == int(octets[3]):
            continue
        subprocess.run(
            [
                "ping",
                "-n",
                "1",
                "-w",
                "50",
                f"{octets[0]}.{octets[1]}.{octets[2]}.{last_octet}",
            ],
            capture_output=True,
            timeout=1,
            check=False,
        )


def arp_scan_windows(subnet: str) -> list[dict]:
    """
    Discover devices using the Windows ARP table (and ping sweep if needed).

    Works without Npcap and does not require administrator privileges,
    though running as admin can improve results.
    """
    network = ipaddress.IPv4Network(subnet, strict=False)
    print("[*] Using Windows ARP table discovery ...")

    devices = _read_windows_arp_table(network)
    if devices:
        print(f"[*] Found {len(devices)} device(s) in ARP cache.")
        return devices

    print("[*] ARP cache empty, running quick ping sweep ...")
    _windows_ping_sweep(_detect_local_ip())
    devices = _read_windows_arp_table(network)
    if devices:
        print(f"[*] Found {len(devices)} device(s) after ping sweep.")
    return devices


def arp_scan(subnet: str, timeout: int = 3) -> list[dict]:
    """
    Send ARP requests across the subnet and collect responses.

    On Windows, falls back to ping + `arp -a` when Scapy/Npcap is unavailable.
    """
    if sys.platform == "win32":
        try:
            devices = arp_scan_scapy(subnet, timeout)
            if devices:
                return devices
            print("[!] Scapy scan found no devices, trying Windows ARP table...")
        except Exception as exc:
            print(f"[!] Scapy scan unavailable: {exc}")
        return arp_scan_windows(subnet)

    return arp_scan_scapy(subnet, timeout)


# ---------------------------------------------------------------------------
# Database operations
# ---------------------------------------------------------------------------

def init_database(db_path: str) -> None:
    """Create the devices table if it does not already exist."""
    init_netguard_database(db_path)

def get_known_macs(db_path: str) -> set[str]:
    """Return the set of all MAC addresses currently stored in the database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT mac_address FROM devices")
    macs = {row[0] for row in cursor.fetchall()}
    conn.close()
    return macs


def upsert_device(
    db_path: str,
    ip_address: str,
    mac_address: str,
    vendor: str,
    hostname: str | None,
    timestamp: str,
) -> bool:
    """
    Insert a new device or update an existing one.

    Returns True if this is a brand-new device (first time seen).
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id FROM devices WHERE mac_address = ?",
        (mac_address,),
    )
    existing = cursor.fetchone()

    if existing is None:
        cursor.execute(
            """
            INSERT INTO devices
                (ip_address, mac_address, vendor, hostname, first_seen, last_seen, status)
            VALUES (?, ?, ?, ?, ?, ?, 'online')
            """,
            (ip_address, mac_address, vendor, hostname, timestamp, timestamp),
        )
        conn.commit()
        conn.close()
        return True

    cursor.execute(
        """
        UPDATE devices
        SET ip_address = ?,
            vendor     = ?,
            hostname   = COALESCE(?, hostname),
            last_seen  = ?,
            status     = 'online'
        WHERE mac_address = ?
        """,
        (ip_address, vendor, hostname, timestamp, mac_address),
    )
    conn.commit()
    conn.close()
    return False


def mark_offline_devices(
    db_path: str, seen_macs: set[str], timestamp: str
) -> list[dict]:
    """
    Mark devices not seen in the current scan as offline.

    Returns a list of devices that transitioned to offline this cycle.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM devices WHERE status = 'online'"
    )
    previously_online = cursor.fetchall()

    offline_devices = []
    for row in previously_online:
        if row["mac_address"] not in seen_macs:
            cursor.execute(
                """
                UPDATE devices
                SET status = 'offline', last_seen = ?
                WHERE mac_address = ?
                """,
                (timestamp, row["mac_address"]),
            )
            offline_devices.append(dict(row))

    conn.commit()
    conn.close()
    return offline_devices


def get_all_devices(db_path: str) -> list[dict]:
    """Fetch every device record from the database."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices ORDER BY ip_address")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


# ---------------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------------

def print_scan_results(
    online_devices: list[dict],
    new_macs: set[str],
    offline_devices: list[dict],
) -> None:
    """
    Print a formatted table of discovered devices to the console.

    Tags newly discovered devices with [NEW] and missing devices with [OFFLINE].
    """
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    separator = "=" * 100

    print(f"\n{separator}")
    print(f"  NetGuard ARP Scan - {now_str}")
    print(separator)

    headers = ["Tag", "IP Address", "MAC Address", "Vendor", "Hostname", "First Seen", "Last Seen"]
    col_widths = [10, 16, 18, 22, 24, 22, 22]

    header_line = "  ".join(h.ljust(w) for h, w in zip(headers, col_widths))
    print(header_line)
    print("-" * len(header_line))

    for device in online_devices:
        tag = "[NEW]" if device["mac_address"] in new_macs else ""
        hostname = device.get("hostname") or "-"
        row = [
            tag.ljust(col_widths[0]),
            device["ip_address"].ljust(col_widths[1]),
            device["mac_address"].ljust(col_widths[2]),
            (device.get("vendor") or "Unknown")[: col_widths[3] - 1].ljust(col_widths[3]),
            hostname[: col_widths[4] - 1].ljust(col_widths[4]),
            device["first_seen"][:19].ljust(col_widths[5]),
            device["last_seen"][:19].ljust(col_widths[6]),
        ]
        print("  ".join(row))

    for device in offline_devices:
        hostname = device.get("hostname") or "-"
        row = [
            "[OFFLINE]".ljust(col_widths[0]),
            device["ip_address"].ljust(col_widths[1]),
            device["mac_address"].ljust(col_widths[2]),
            (device.get("vendor") or "Unknown")[: col_widths[3] - 1].ljust(col_widths[3]),
            hostname[: col_widths[4] - 1].ljust(col_widths[4]),
            device["first_seen"][:19].ljust(col_widths[5]),
            device["last_seen"][:19].ljust(col_widths[6]),
        ]
        print("  ".join(row))

    total = len(online_devices)
    new_count = len(new_macs)
    offline_count = len(offline_devices)
    print(separator)
    print(
        f"  Online: {total}  |  New: {new_count}  |  Offline: {offline_count}"
    )
    print(separator)


# ---------------------------------------------------------------------------
# Main scan cycle
# ---------------------------------------------------------------------------

def run_scan_cycle(db_path: str, subnet: str) -> None:
    """
    Execute one full scan cycle: ARP sweep, enrich, persist, and display.

    Compares results against the database to detect new and offline devices.
    """
    timestamp = datetime.now(timezone.utc).isoformat()

    print(f"\n[*] Scanning subnet {subnet} ...")
    raw_devices = arp_scan(subnet)

    if not raw_devices:
        print("[!] No devices responded to ARP scan.")

    seen_macs: set[str] = set()
    new_macs: set[str] = set()

    for raw in raw_devices:
        mac = raw["mac_address"]
        ip = raw["ip_address"]
        seen_macs.add(mac)

        vendor = lookup_vendor(mac)
        hostname = lookup_hostname(ip)

        is_new = upsert_device(db_path, ip, mac, vendor, hostname, timestamp)
        if is_new:
            new_macs.add(mac)

    offline_devices = mark_offline_devices(db_path, seen_macs, timestamp)

    all_devices = get_all_devices(db_path)
    online_devices = [d for d in all_devices if d["status"] == "online"]

    print_scan_results(online_devices, new_macs, offline_devices)

    if online_devices:
        try:
            run_port_scan_cycle(db_path)
        except Exception as exc:
            print(f"[!] Port scan failed: {exc}")

    if sys.platform == "win32":
        try:
            poll_windows_dns_cache(db_path)
        except Exception as exc:
            print(f"[!] DNS cache poll failed: {exc}")


def _configure_console_encoding() -> None:
    if sys.platform != "win32":
        return
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass


def _pause_before_exit(code: int = 1) -> None:
    if getattr(sys, "frozen", False):
        print("")
        input("Press Enter to close...")
    sys.exit(code)


def main() -> None:
    """
    Entry point: initialise the database and run continuous scan loop.

    Scans the local network every SCAN_INTERVAL_SECONDS until interrupted.
    """
    print("NetGuard Network Scanner starting ...")
    _configure_console_encoding()
    print(f"Database: {DB_PATH}")
    print("Services: device discovery, port scan, DNS cache (Windows)")

    try:
        init_database(DB_PATH)
    except OSError as exc:
        print(f"[!] Cannot create database at {DB_PATH}: {exc}")
        _pause_before_exit(1)

    try:
        subnet = detect_local_subnet()
    except RuntimeError as exc:
        print(f"[!] {exc}")
        _pause_before_exit(1)

    print(f"Detected subnet: {subnet}")
    print(f"Scan interval:   {SCAN_INTERVAL_SECONDS}s")
    if sys.platform == "win32":
        print("Running in background - leave minimized. No manual steps needed.")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            try:
                run_scan_cycle(DB_PATH, subnet)
            except Exception as exc:
                print(f"[!] Scan cycle failed: {exc}")
                print("[*] Will retry on the next interval.")
            print(f"\n[*] Next scan in {SCAN_INTERVAL_SECONDS} seconds ...")
            time.sleep(SCAN_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\n[!] Scanner stopped by user.")
        sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"[!] Fatal error: {exc}")
        _pause_before_exit(1)
