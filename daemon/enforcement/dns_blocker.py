#!/usr/bin/env python3
"""
NetGuard DNS Block Enforcer

Watches the shared database for devices marked is_blocked=1 and drops DNS
traffic from those IPs using iptables. Intended for Pi deployments where
the NetGuard host is the LAN DNS resolver.

Run with root:
    sudo python3 daemon/enforcement/dns_blocker.py

Limitations:
- Linux only (iptables).
- Requires root for iptables manipulation.
- Blocks DNS to/from the Pi for listed source IPs (INPUT + FORWARD).
- Rules are not persistent across reboot unless saved separately;
  this daemon re-applies blocked-device rules on startup.
"""

from __future__ import annotations

import os
import socket
import sqlite3
import subprocess
import sys
import time

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

if getattr(sys, "frozen", False):
    _daemon_dir = os.path.join(sys._MEIPASS, "daemon")
else:
    _daemon_dir = os.path.join(PROJECT_ROOT, "daemon")

if os.path.isdir(_daemon_dir) and _daemon_dir not in sys.path:
    sys.path.insert(0, _daemon_dir)

from db_path import resolve_db_path

DB_PATH = resolve_db_path(PROJECT_ROOT)
POLL_INTERVAL_SECONDS = 10
IPTABLES_TIMEOUT_SECONDS = 10

DNS_BLOCK_CHAINS = ("FORWARD", "INPUT")
DNS_BLOCK_PROTOCOLS = ("udp", "tcp")


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def detect_local_ip() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]


def get_blocked_ips(skip_ips: set[str]) -> set[str]:
    """Return IP addresses for all devices currently marked blocked."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT ip_address
        FROM devices
        WHERE COALESCE(is_blocked, 0) = 1
        ORDER BY ip_address
        """
    )
    rows = cursor.fetchall()
    conn.close()

    blocked: set[str] = set()
    for row in rows:
        ip_address = row["ip_address"]
        if ip_address and ip_address not in skip_ips:
            blocked.add(ip_address)
    return blocked


def _run_iptables(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["iptables", *args],
        capture_output=True,
        text=True,
        timeout=IPTABLES_TIMEOUT_SECONDS,
    )


def _rule_spec(ip: str, protocol: str) -> list[str]:
    return ["-s", ip, "-p", protocol, "--dport", "53", "-j", "DROP"]


def dns_block_rule_exists(chain: str, ip: str, protocol: str) -> bool:
    result = _run_iptables(["-C", chain, *_rule_spec(ip, protocol)])
    return result.returncode == 0


def add_dns_block_rule(chain: str, ip: str, protocol: str) -> bool:
    if dns_block_rule_exists(chain, ip, protocol):
        return True
    result = _run_iptables(["-I", chain, *_rule_spec(ip, protocol)])
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        print(f"[!] iptables add failed ({chain}/{protocol} {ip}): {detail}")
        return False
    return True


def remove_dns_block_rule(chain: str, ip: str, protocol: str) -> bool:
    if not dns_block_rule_exists(chain, ip, protocol):
        return True
    result = _run_iptables(["-D", chain, *_rule_spec(ip, protocol)])
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        print(f"[!] iptables delete failed ({chain}/{protocol} {ip}): {detail}")
        return False
    return True


def apply_dns_block(ip: str) -> bool:
    """Insert iptables rules that drop DNS traffic sourced from ip."""
    success = True
    for chain in DNS_BLOCK_CHAINS:
        for protocol in DNS_BLOCK_PROTOCOLS:
            if not add_dns_block_rule(chain, ip, protocol):
                success = False
    return success


def remove_dns_block(ip: str) -> bool:
    """Remove iptables DNS drop rules for ip."""
    success = True
    for chain in DNS_BLOCK_CHAINS:
        for protocol in DNS_BLOCK_PROTOCOLS:
            if not remove_dns_block_rule(chain, ip, protocol):
                success = False
    return success


def sync_blocked_dns_rules(
    desired_ips: set[str],
    active_ips: set[str],
) -> set[str]:
    """
    Apply iptables changes for blocked-device set differences.

    Returns the updated active blocked IP set.
    """
    to_block = desired_ips - active_ips
    to_unblock = active_ips - desired_ips
    updated = set(active_ips)

    for ip in sorted(to_unblock):
        if remove_dns_block(ip):
            print(f"[DNS-UNBLOCK] Unblocking {ip} — DNS restored")
            updated.discard(ip)
        else:
            print(f"[!] Failed to fully unblock DNS for {ip}")

    for ip in sorted(to_block):
        if apply_dns_block(ip):
            print(f"[DNS-BLOCK] Blocking {ip} — DNS queries will fail")
            updated.add(ip)
        else:
            print(f"[!] Failed to fully block DNS for {ip}")

    return updated


def require_root() -> None:
    if sys.platform == "win32":
        print("[!] DNS blocking via iptables is not supported on Windows.")
        print("    Run this daemon on your Raspberry Pi or Linux host with sudo.")
        sys.exit(1)

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[!] Root privileges required for iptables DNS enforcement.")
        print("    Run: sudo python3 daemon/enforcement/dns_blocker.py")
        sys.exit(1)


def main() -> None:
    require_root()

    if not os.path.exists(DB_PATH):
        print(f"[!] Database not found: {DB_PATH}")
        print("    Start the ARP scanner first.")
        sys.exit(1)

    local_ip = detect_local_ip()
    skip_ips = {local_ip}

    print("NetGuard DNS Block Enforcer starting ...")
    print(f"Database:  {DB_PATH}")
    print(f"Local IP:  {local_ip} (never DNS-blocked)")
    print(f"Poll:      every {POLL_INTERVAL_SECONDS}s")
    print("Press Ctrl+C to stop.\n")

    active_blocked_ips: set[str] = set()

    try:
        while True:
            desired_blocked_ips = get_blocked_ips(skip_ips)

            if desired_blocked_ips != active_blocked_ips:
                if not active_blocked_ips and desired_blocked_ips:
                    print(
                        f"[*] Syncing DNS blocks for "
                        f"{len(desired_blocked_ips)} device(s) ..."
                    )
                active_blocked_ips = sync_blocked_dns_rules(
                    desired_blocked_ips,
                    active_blocked_ips,
                )

            time.sleep(POLL_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\n[!] DNS block enforcer stopped.")
        print("    iptables rules remain active until removed or the host reboots.")
        sys.exit(0)


if __name__ == "__main__":
    main()
