#!/usr/bin/env python3
"""
NetGuard Network Block Enforcer

Watches the shared database for devices marked is_blocked=1 and isolates
them from the network using ARP cache poisoning (requires root + Linux).

Run alongside the ARP scanner:
    sudo python3 daemon/enforcement/network_blocker.py

Limitations:
- NetGuard must run on the same LAN segment as blocked devices.
- Requires root for raw ARP packets (Scapy).
- Does not work on Windows; use a Raspberry Pi or Linux host.
- Some routers/APs with client isolation may reduce effectiveness.
- Blocking is active only while this daemon is running.
"""

from __future__ import annotations

import os
import socket
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass

from scapy.all import ARP, Ether, conf, get_if_hwaddr, sendp, srp

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DB_PATH = os.path.join(PROJECT_ROOT, "netguard.db")

POLL_INTERVAL_SECONDS = 5
ARP_REFRESH_INTERVAL_SECONDS = 3
BLACKHOLE_MAC = "00:00:00:00:00:00"

GATEWAY_IP = os.environ.get("NETGUARD_GATEWAY_IP", "").strip() or None


@dataclass(frozen=True)
class BlockTarget:
    device_id: int
    ip_address: str
    mac_address: str


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def detect_local_ip() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]


def detect_default_gateway() -> str:
    """Return the default gateway IP from the routing table."""
    if GATEWAY_IP:
        return GATEWAY_IP

    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        parts = result.stdout.split()
        if "via" in parts:
            return parts[parts.index("via") + 1]
    except (subprocess.SubprocessError, FileNotFoundError, ValueError, IndexError):
        pass

    octets = detect_local_ip().split(".")
    return f"{octets[0]}.{octets[1]}.{octets[2]}.1"


def resolve_mac(ip_address: str, timeout: int = 2) -> str | None:
    """Resolve an IP to a MAC address via ARP."""
    answered, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address),
        timeout=timeout,
        verbose=False,
        retry=2,
    )
    if not answered:
        return None
    return answered[0][1].hwsrc.upper()


def get_blocked_devices(db_path: str, local_ip: str, gateway_ip: str) -> list[BlockTarget]:
    """Return online blocked devices, excluding NetGuard host and gateway."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, ip_address, mac_address
        FROM devices
        WHERE COALESCE(is_blocked, 0) = 1
          AND status = 'online'
        ORDER BY ip_address
        """
    )
    rows = cursor.fetchall()
    conn.close()

    targets: list[BlockTarget] = []
    skip_ips = {local_ip, gateway_ip}
    for row in rows:
        ip = row["ip_address"]
        mac = row["mac_address"].upper()
        if ip in skip_ips:
            continue
        targets.append(BlockTarget(row["id"], ip, mac))
    return targets


def poison_arp_cache(
    target: BlockTarget,
    gateway_ip: str,
    gateway_mac: str,
    iface: str,
) -> None:
    """
    Isolate a device by pointing both it and the gateway at a blackhole MAC.

    - Victim thinks the gateway is unreachable.
    - Gateway thinks the victim is unreachable.
    """
    to_victim = (
        Ether(dst=target.mac_address)
        / ARP(
            op=2,
            hwsrc=BLACKHOLE_MAC,
            psrc=gateway_ip,
            hwdst=target.mac_address,
            pdst=target.ip_address,
        )
    )
    to_gateway = (
        Ether(dst=gateway_mac)
        / ARP(
            op=2,
            hwsrc=BLACKHOLE_MAC,
            psrc=target.ip_address,
            hwdst=gateway_mac,
            pdst=gateway_ip,
        )
    )
    sendp(to_victim, iface=iface, verbose=False)
    sendp(to_gateway, iface=iface, verbose=False)


def choose_iface(local_ip: str) -> str:
    """Pick the Scapy interface that owns local_ip."""
    for iface in conf.ifaces.values():
        if getattr(iface, "ip", None) == local_ip:
            return iface.network_name
    return conf.iface


def main() -> None:
    if sys.platform == "win32":
        print("[!] Network blocking is not supported on Windows.")
        print("    Run this daemon on your Raspberry Pi or Linux host with sudo.")
        sys.exit(1)

    if os.geteuid() != 0:
        print("[!] Root privileges required for ARP enforcement.")
        print("    Run: sudo python3 daemon/enforcement/network_blocker.py")
        sys.exit(1)

    if not os.path.exists(DB_PATH):
        print(f"[!] Database not found: {DB_PATH}")
        print("    Start the ARP scanner first.")
        sys.exit(1)

    local_ip = detect_local_ip()
    gateway_ip = detect_default_gateway()
    iface = choose_iface(local_ip)
    local_mac = get_if_hwaddr(iface).upper()

    print("NetGuard Network Block Enforcer starting ...")
    print(f"Database:  {DB_PATH}")
    print(f"Interface: {iface} ({local_ip} / {local_mac})")
    print(f"Gateway:   {gateway_ip}")
    print(f"Poll:      every {POLL_INTERVAL_SECONDS}s")
    print("Press Ctrl+C to stop.\n")

    gateway_mac: str | None = None
    gateway_mac_last_resolve = 0.0
    last_arp_refresh: dict[int, float] = {}
    active_target_ids: set[int] = set()

    try:
        while True:
            now = time.time()
            if gateway_mac is None or now - gateway_mac_last_resolve > 60:
                gateway_mac = resolve_mac(gateway_ip)
                gateway_mac_last_resolve = now
                if gateway_mac is None:
                    print(f"[!] Could not resolve gateway MAC for {gateway_ip}")
                else:
                    print(f"[*] Gateway MAC: {gateway_mac}")

            targets = get_blocked_devices(DB_PATH, local_ip, gateway_ip)
            target_ids = {target.device_id for target in targets}

            if target_ids != active_target_ids:
                removed = active_target_ids - target_ids
                added = target_ids - active_target_ids
                for device_id in removed:
                    last_arp_refresh.pop(device_id, None)
                    print(f"[*] Stopped network block for device id {device_id}")
                for target in targets:
                    if target.device_id in added:
                        print(
                            f"[BLOCK] Isolating {target.ip_address} "
                            f"({target.mac_address}) from network"
                        )
                active_target_ids = target_ids

            if not targets:
                pass
            elif gateway_mac is None:
                pass
            else:
                for target in targets:
                    last = last_arp_refresh.get(target.device_id, 0.0)
                    if now - last >= ARP_REFRESH_INTERVAL_SECONDS:
                        poison_arp_cache(target, gateway_ip, gateway_mac, iface)
                        last_arp_refresh[target.device_id] = now

            time.sleep(POLL_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\n[!] Block enforcer stopped. Blocked devices may regain connectivity.")
        sys.exit(0)


if __name__ == "__main__":
    main()
