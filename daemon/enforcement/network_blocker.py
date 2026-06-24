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
- Mesh WiFi (Velop, Eero, Orbi) may ignore or bypass ARP isolation.
- Phones with WiFi privacy (randomized MAC) need live ARP resolution.
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

_daemon_dir = os.path.join(PROJECT_ROOT, "daemon")
if os.path.isdir(_daemon_dir) and _daemon_dir not in sys.path:
    sys.path.insert(0, _daemon_dir)

from db_path import resolve_db_path

DB_PATH = resolve_db_path(PROJECT_ROOT)

POLL_INTERVAL_SECONDS = 5
ARP_REFRESH_INTERVAL_SECONDS = 2
IPTABLES_TIMEOUT_SECONDS = 10
ARP_POISON_BURST_COUNT = 3

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


def is_randomized_mac(mac_address: str) -> bool:
    """Return True for locally administered (privacy/randomized) MAC addresses."""
    try:
        first_octet = int(mac_address.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first_octet & 0x02)


def count_blocked_devices() -> int:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COUNT(*) AS total FROM devices WHERE COALESCE(is_blocked, 0) = 1"
    )
    total = int(cursor.fetchone()["total"])
    conn.close()
    return total


def get_blocked_devices(local_ip: str, gateway_ip: str) -> list[BlockTarget]:
    """Return blocked devices, excluding the NetGuard host and gateway."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, ip_address, mac_address
        FROM devices
        WHERE COALESCE(is_blocked, 0) = 1
        ORDER BY ip_address
        """
    )
    rows = cursor.fetchall()
    conn.close()

    targets: list[BlockTarget] = []
    skip_ips = {local_ip, gateway_ip}
    for row in rows:
        ip = row["ip_address"]
        mac = (row["mac_address"] or "").upper()
        if not ip or ip in skip_ips or not mac:
            continue
        targets.append(BlockTarget(row["id"], ip, mac))
    return targets


def _run_iptables(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["iptables", *args],
        capture_output=True,
        text=True,
        timeout=IPTABLES_TIMEOUT_SECONDS,
    )


def _iptables_rule_exists(chain: str, rule_args: list[str]) -> bool:
    return _run_iptables(["-C", chain, *rule_args]).returncode == 0


def _iptables_add(chain: str, rule_args: list[str]) -> bool:
    if _iptables_rule_exists(chain, rule_args):
        return True
    result = _run_iptables(["-I", chain, *rule_args])
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        print(f"[!] iptables add failed ({chain} {' '.join(rule_args)}): {detail}")
        return False
    return True


def _iptables_delete(chain: str, rule_args: list[str]) -> bool:
    if not _iptables_rule_exists(chain, rule_args):
        return True
    result = _run_iptables(["-D", chain, *rule_args])
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        print(f"[!] iptables delete failed ({chain} {' '.join(rule_args)}): {detail}")
        return False
    return True


def _traffic_block_rules(ip: str) -> list[tuple[str, list[str]]]:
    return [
        ("INPUT", ["-s", ip, "-j", "DROP"]),
        ("FORWARD", ["-s", ip, "-j", "DROP"]),
        ("FORWARD", ["-d", ip, "-j", "DROP"]),
    ]


def apply_traffic_block(ip: str) -> bool:
    success = True
    for chain, rule_args in _traffic_block_rules(ip):
        if not _iptables_add(chain, rule_args):
            success = False
    return success


def remove_traffic_block(ip: str) -> bool:
    success = True
    for chain, rule_args in _traffic_block_rules(ip):
        if not _iptables_delete(chain, rule_args):
            success = False
    return success


def sync_traffic_blocks(desired_ips: set[str], active_ips: set[str]) -> set[str]:
    updated = set(active_ips)
    for ip in sorted(active_ips - desired_ips):
        if remove_traffic_block(ip):
            updated.discard(ip)
    for ip in sorted(desired_ips - active_ips):
        if apply_traffic_block(ip):
            updated.add(ip)
    return updated


def resolve_target_mac(target: BlockTarget, iface: str) -> str:
    """
    Prefer a live ARP lookup over the database MAC.

    Privacy/randomized WiFi MACs in the database are often stale.
    """
    live_mac = resolve_mac(target.ip_address, timeout=1)
    if live_mac:
        if live_mac != target.mac_address:
            privacy_note = ""
            if is_randomized_mac(live_mac) or is_randomized_mac(target.mac_address):
                privacy_note = " [privacy MAC]"
            print(
                f"[*] Live MAC for {target.ip_address}: {live_mac} "
                f"(database had {target.mac_address}){privacy_note}"
            )
        return live_mac
    return target.mac_address


def poison_arp_cache(
    target: BlockTarget,
    victim_mac: str,
    gateway_ip: str,
    gateway_mac: str,
    local_mac: str,
    iface: str,
) -> None:
    """
    Isolate a device with bidirectional ARP cache poisoning.

    Both the victim and gateway are told the other party lives at the Pi MAC.
    Traffic destined for either side is delivered to the Pi and dropped via
    iptables rules applied for the victim IP.
    """
    to_victim = (
        Ether(dst=victim_mac)
        / ARP(
            op=2,
            hwsrc=local_mac,
            psrc=gateway_ip,
            hwdst=victim_mac,
            pdst=target.ip_address,
        )
    )
    to_gateway = (
        Ether(dst=gateway_mac)
        / ARP(
            op=2,
            hwsrc=local_mac,
            psrc=target.ip_address,
            hwdst=gateway_mac,
            pdst=gateway_ip,
        )
    )
    for _ in range(ARP_POISON_BURST_COUNT):
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
    blocked_count = count_blocked_devices()
    if blocked_count:
        print(f"[*] {blocked_count} device(s) marked blocked in database")
    print(
        "[*] Note: mesh WiFi (Velop/Eero/Orbi) may bypass ARP blocking — "
        "use your router app for guaranteed enforcement."
    )
    print("Press Ctrl+C to stop.\n")

    gateway_mac: str | None = None
    gateway_mac_last_resolve = 0.0
    last_arp_refresh: dict[int, float] = {}
    active_target_ids: set[int] = set()
    active_blocked_ips: set[str] = set()
    last_idle_warning = 0.0
    last_mesh_warning: dict[int, float] = {}

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

            targets = get_blocked_devices(local_ip, gateway_ip)
            target_ids = {target.device_id for target in targets}
            desired_ips = {target.ip_address for target in targets}

            if desired_ips != active_blocked_ips:
                active_blocked_ips = sync_traffic_blocks(
                    desired_ips,
                    active_blocked_ips,
                )

            if target_ids != active_target_ids:
                removed = active_target_ids - target_ids
                added = target_ids - active_target_ids
                for device_id in removed:
                    last_arp_refresh.pop(device_id, None)
                    last_mesh_warning.pop(device_id, None)
                    if count_blocked_devices() == 0 or device_id not in {
                        target.device_id for target in targets
                    }:
                        print(f"[*] Stopped network block for device id {device_id}")
                for target in targets:
                    if target.device_id in added:
                        privacy = (
                            " [privacy/randomized MAC — using live ARP lookup]"
                            if is_randomized_mac(target.mac_address)
                            else ""
                        )
                        print(
                            f"[BLOCK] Isolating {target.ip_address} "
                            f"({target.mac_address}) from network{privacy}"
                        )
                active_target_ids = target_ids

            if not targets and count_blocked_devices() > 0:
                if now - last_idle_warning >= 60:
                    print(
                        "[!] Blocked device(s) in database but none are being "
                        "enforced — check IP/MAC data or gateway IP setting"
                    )
                    last_idle_warning = now
            elif targets and gateway_mac is None:
                if now - last_idle_warning >= 60:
                    print(
                        "[!] Cannot ARP-isolate blocked devices until the "
                        f"gateway MAC for {gateway_ip} is resolved"
                    )
                    last_idle_warning = now
            else:
                for target in targets:
                    last = last_arp_refresh.get(target.device_id, 0.0)
                    if now - last < ARP_REFRESH_INTERVAL_SECONDS:
                        continue

                    victim_mac = resolve_target_mac(target, iface)
                    if victim_mac != target.mac_address:
                        last_warn = last_mesh_warning.get(target.device_id, 0.0)
                        if now - last_warn >= 120:
                            print(
                                f"[!] {target.ip_address} MAC changed since scan — "
                                "ARP isolation may fail on mesh WiFi networks"
                            )
                            last_mesh_warning[target.device_id] = now

                    poison_arp_cache(
                        target,
                        victim_mac,
                        gateway_ip,
                        gateway_mac,
                        local_mac,
                        iface,
                    )
                    last_arp_refresh[target.device_id] = now

            time.sleep(POLL_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\n[!] Block enforcer stopped. Blocked devices may regain connectivity.")
        sys.exit(0)


if __name__ == "__main__":
    main()
