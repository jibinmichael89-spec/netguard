"""TCP port scanning for discovered network devices."""

from __future__ import annotations

import os
import socket
import sqlite3
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

if getattr(sys, "frozen", False):
    _daemon_dir = os.path.join(sys._MEIPASS, "daemon")
else:
    _daemon_dir = os.path.join(os.path.dirname(__file__), "..")

if os.path.isdir(_daemon_dir) and _daemon_dir not in sys.path:
    sys.path.insert(0, _daemon_dir)

from database import init_netguard_database

# Slightly longer than before so slow IoT/printer stacks are less likely to
# be missed; keep scans bounded for the 30s ARP cycle.
SCAN_TIMEOUT = float(os.environ.get("NETGUARD_PORT_SCAN_TIMEOUT", "0.8"))
MAX_WORKERS = int(os.environ.get("NETGUARD_PORT_SCAN_WORKERS", "64"))

# Curated LAN/home/SOHO TCP ports — not a full 1–65535 sweep (too slow/noisy).
PORTS_TO_SCAN: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    548: "AFP",
    554: "RTSP",
    587: "Submission",
    631: "IPP",
    636: "LDAPS",
    873: "Rsync",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    1720: "H.323",
    1723: "PPTP",
    1883: "MQTT",
    1900: "UPNP",
    2049: "NFS",
    2222: "SSH-Alt",
    2375: "Docker",
    2376: "Docker-TLS",
    3000: "Dev-HTTP",
    3306: "MySQL",
    3389: "RDP",
    5000: "UPnP/Flask",
    5001: "Synology",
    5432: "PostgreSQL",
    5555: "ADB",
    5672: "AMQP",
    5900: "VNC",
    5901: "VNC-1",
    5984: "CouchDB",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    6379: "Redis",
    8000: "HTTP-8000",
    8008: "HTTP-8008",
    8009: "AJP",
    8080: "HTTP-Alt",
    8081: "HTTP-8081",
    8443: "HTTPS-Alt",
    8883: "MQTTS",
    8888: "HTTP-8888",
    9000: "Sonar/Portainer",
    9090: "Prometheus/Web",
    9100: "Printer",
    9200: "Elasticsearch",
    9443: "HTTPS-9443",
    10000: "Webmin",
    11211: "Memcached",
    15672: "RabbitMQ",
    25565: "Minecraft",
    27017: "MongoDB",
    32400: "Plex",
    50070: "Hadoop",
    62078: "iPhone-Sync",
}


def _parse_extra_ports(raw: str) -> dict[int, str]:
    """Parse NETGUARD_EXTRA_PORTS=80,8123,9001 into port→service entries."""
    extra: dict[int, str] = {}
    for part in raw.split(","):
        token = part.strip()
        if not token:
            continue
        try:
            port = int(token)
        except ValueError:
            continue
        if 1 <= port <= 65535:
            extra[port] = _lookup_service_name(port)
    return extra


def _lookup_service_name(port: int) -> str:
    known = PORTS_TO_SCAN.get(port)
    if known:
        return known
    try:
        return socket.getservbyport(port, "tcp").upper()
    except OSError:
        return "Unknown"


def _ports_for_scan() -> dict[int, str]:
    ports = dict(PORTS_TO_SCAN)
    extra_raw = os.environ.get("NETGUARD_EXTRA_PORTS", "").strip()
    if extra_raw:
        ports.update(_parse_extra_ports(extra_raw))
    return ports


DANGEROUS_PORTS = {
    21: "Unencrypted file transfer - credentials sent in plaintext",
    23: "Unencrypted remote access protocol - high hijack risk",
    135: "Windows RPC - often abused for lateral movement",
    139: "Legacy NetBIOS file sharing",
    445: "Common ransomware attack vector",
    1433: "Database should not be exposed on the LAN without need",
    1521: "Database should not be exposed on the LAN without need",
    2375: "Docker API without TLS - remote container control risk",
    3389: "Common brute force target if exposed",
    5555: "Android Debug Bridge - full device control if exposed",
    1900: "Often exploited for DDoS amplification",
    5900: "Remote desktop often targeted when exposed",
    6379: "Redis often left unauthenticated on the internet",
    11211: "Memcached - amplification / data exposure risk",
    27017: "MongoDB often left without authentication",
}


def _scan_port(ip: str, port: int, timeout: float) -> tuple[int, bool]:
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        open_port = sock.connect_ex((ip, port)) == 0
        return port, open_port
    except OSError:
        return port, False
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _scan_device(ip: str, ports: dict[int, str], timeout: float) -> list[dict]:
    open_ports: list[dict] = []
    if not ports:
        return open_ports

    workers = max(1, min(len(ports), MAX_WORKERS))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_scan_port, ip, port, timeout): port for port in ports
        }
        for future in as_completed(futures):
            port, is_open = future.result()
            if not is_open:
                continue
            open_ports.append(
                {
                    "port": port,
                    "service": ports.get(port) or _lookup_service_name(port),
                    "is_dangerous": 1 if port in DANGEROUS_PORTS else 0,
                    "risk_reason": DANGEROUS_PORTS.get(port, ""),
                }
            )
    open_ports.sort(key=lambda item: item["port"])
    return open_ports


def _get_online_devices(db_path: str) -> list[str]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT ip_address FROM devices WHERE status = 'online'"
    ).fetchall()
    conn.close()
    return [row["ip_address"] for row in rows]


def _save_results(db_path: str, ip: str, open_ports: list[dict]) -> None:
    conn = sqlite3.connect(db_path)
    timestamp = datetime.now(timezone.utc).isoformat()
    conn.execute("DELETE FROM open_ports WHERE device_ip = ?", (ip,))
    for entry in open_ports:
        conn.execute(
            """
            INSERT INTO open_ports
                (device_ip, port, service_name, is_dangerous, risk_reason, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                ip,
                entry["port"],
                entry["service"],
                entry["is_dangerous"],
                entry["risk_reason"],
                timestamp,
            ),
        )
    conn.commit()
    conn.close()


def run_port_scan_cycle(db_path: str) -> int:
    """Scan online devices for open TCP ports. Returns total open ports found."""
    init_netguard_database(db_path)
    devices = _get_online_devices(db_path)
    if not devices:
        print("[*] Port scan skipped - no online devices.")
        return 0

    ports = _ports_for_scan()
    timeout = SCAN_TIMEOUT
    print(
        f"[*] Port scan starting for {len(devices)} online device(s) "
        f"({len(ports)} TCP ports, timeout={timeout}s) ..."
    )
    total_open = 0
    for ip in devices:
        open_ports = _scan_device(ip, ports, timeout)
        _save_results(db_path, ip, open_ports)
        total_open += len(open_ports)
        if open_ports:
            summary = ", ".join(
                f"{entry['port']}/{entry['service']}" for entry in open_ports
            )
            print(f"    {ip}: {len(open_ports)} open ({summary})")

    print(f"[*] Port scan complete - {total_open} open port(s) across network.")
    return total_open
