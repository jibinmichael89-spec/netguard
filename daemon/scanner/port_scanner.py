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

SCAN_TIMEOUT = 0.4
MAX_WORKERS = 32

PORTS_TO_SCAN = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    554: "RTSP",
    873: "Rsync",
    1433: "MSSQL",
    1521: "Oracle",
    1900: "UPNP",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5984: "CouchDB",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9100: "Printer",
    9200: "Elasticsearch",
    27017: "MongoDB",
    50070: "Hadoop",
}

DANGEROUS_PORTS = {
    21: "Unencrypted file transfer - credentials sent in plaintext",
    23: "Unencrypted remote access protocol - high hijack risk",
    445: "Common ransomware attack vector",
    3389: "Common brute force target if exposed",
    1900: "Often exploited for DDoS amplification",
    5900: "Remote desktop often targeted when exposed",
    6379: "Redis often left unauthenticated on the internet",
}


def _scan_port(ip: str, port: int) -> tuple[int, bool]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SCAN_TIMEOUT)
        open_port = sock.connect_ex((ip, port)) == 0
        sock.close()
        return port, open_port
    except OSError:
        return port, False


def _scan_device(ip: str) -> list[dict]:
    open_ports: list[dict] = []
    with ThreadPoolExecutor(max_workers=min(len(PORTS_TO_SCAN), MAX_WORKERS)) as pool:
        futures = {
            pool.submit(_scan_port, ip, port): port for port in PORTS_TO_SCAN
        }
        for future in as_completed(futures):
            port, is_open = future.result()
            if not is_open:
                continue
            open_ports.append(
                {
                    "port": port,
                    "service": PORTS_TO_SCAN[port],
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

    print(f"[*] Port scan starting for {len(devices)} online device(s) ...")
    total_open = 0
    for ip in devices:
        open_ports = _scan_device(ip)
        _save_results(db_path, ip, open_ports)
        total_open += len(open_ports)
        if open_ports:
            summary = ", ".join(str(entry["port"]) for entry in open_ports)
            print(f"    {ip}: {len(open_ports)} open ({summary})")

    print(f"[*] Port scan complete - {total_open} open port(s) across network.")
    return total_open
