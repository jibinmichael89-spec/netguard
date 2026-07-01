#!/usr/bin/env python3
"""
NetGuard Service Banner Grabber
Periodically probes open ports on known devices and records service banners
(HTTP Server header, SSH banner, TLS certificate subject) without admin privileges.
"""

from __future__ import annotations

import os
import re
import socket
import sqlite3
import ssl
import sys
import time
from datetime import datetime, timezone
from typing import Any

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

if getattr(sys, "frozen", False):
    _daemon_dir = os.path.join(sys._MEIPASS, "daemon")
else:
    _daemon_dir = os.path.join(PROJECT_ROOT, "daemon")

if os.path.isdir(_daemon_dir) and _daemon_dir not in sys.path:
    sys.path.insert(0, _daemon_dir)

from db_path import resolve_db_path

DB_PATH = resolve_db_path(PROJECT_ROOT)

SCAN_INTERVAL_SECONDS = 3600
CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 5.0

HTTP_PORTS = {80, 8080}
TLS_PORTS = {443, 8443}
SSH_PORT = 22
SKIP_PORTS = {1433, 3306, 5432, 6379, 27017}

_PRODUCT_VERSION_RE = re.compile(r"^([^/\s]+)/(\S+)")
_OPENSSH_VERSION_RE = re.compile(r"OpenSSH[_-](\S+)", re.IGNORECASE)


def _confidence(product: str | None, version: str | None) -> str:
    if version:
        return "High"
    if product:
        return "Low"
    return "None"


def _display_label(product: str | None, version: str | None) -> str:
    if product and version:
        return f"{product}/{version}"
    if product:
        return product
    return "unknown"


def _parse_server_header(value: str) -> tuple[str | None, str | None]:
    token = value.strip().split()[0] if value.strip() else ""
    match = _PRODUCT_VERSION_RE.match(token)
    if match:
        return match.group(1), match.group(2)
    if token:
        return token, None
    return None, None


def _parse_ssh_banner(line: str) -> tuple[str | None, str | None]:
    text = line.strip()
    if not text:
        return None, None
    product = "OpenSSH" if "openssh" in text.lower() else "SSH"
    match = _OPENSSH_VERSION_RE.search(text)
    if match:
        return product, match.group(1)
    return product, None


def _parse_tls_subject(subject: Any) -> tuple[str | None, str | None]:
    if not subject:
        return None, None
    for component in subject:
        for key, value in component:
            if key == "commonName" and value:
                return value, None
    return None, None


def _grab_http_banner(host: str, port: int) -> tuple[str | None, str | None, str | None]:
    request = (
        f"HEAD / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: NetGuard-BannerGrabber/1.0\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("ascii", errors="ignore")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT)
    try:
        sock.connect((host, port))
        sock.sendall(request)
        sock.settimeout(READ_TIMEOUT)
        chunks: list[bytes] = []
        while True:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
            if len(b"".join(chunks)) > 8192:
                break
        raw = b"".join(chunks).decode("latin-1", errors="replace")
    except OSError:
        return None, None, None
    finally:
        sock.close()

    server = None
    for line in raw.splitlines():
        if line.lower().startswith("server:"):
            server = line.split(":", 1)[1].strip()
            break
    if not server:
        return None, None, None
    product, version = _parse_server_header(server)
    return server, product, version


def _grab_ssh_banner(host: str, port: int) -> tuple[str | None, str | None, str | None]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT)
    try:
        sock.connect((host, port))
        sock.settimeout(READ_TIMEOUT)
        data = sock.recv(512)
    except OSError:
        return None, None, None
    finally:
        sock.close()

    line = data.decode("utf-8", errors="replace").splitlines()[0] if data else ""
    if not line.strip():
        return None, None, None
    product, version = _parse_ssh_banner(line)
    return line.strip(), product, version


def _grab_tls_banner(host: str, port: int) -> tuple[str | None, str | None, str | None]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT)
    try:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            cert = tls_sock.getpeercert()
    except OSError:
        return None, None, None

    product, version = _parse_tls_subject(cert.get("subject") if cert else None)
    banner = product or ""
    return banner or None, product, version


def grab_banner(host: str, port: int) -> dict[str, Any]:
    """Probe a single host:port and return parsed banner fields."""
    if port in SKIP_PORTS:
        return {
            "banner_text": None,
            "parsed_product": None,
            "parsed_version": None,
            "confidence": "None",
        }

    banner_text: str | None
    product: str | None
    version: str | None

    if port in HTTP_PORTS:
        banner_text, product, version = _grab_http_banner(host, port)
    elif port == SSH_PORT:
        banner_text, product, version = _grab_ssh_banner(host, port)
    elif port in TLS_PORTS:
        banner_text, product, version = _grab_tls_banner(host, port)
    else:
        return {
            "banner_text": None,
            "parsed_product": None,
            "parsed_version": None,
            "confidence": "None",
        }

    return {
        "banner_text": banner_text,
        "parsed_product": product,
        "parsed_version": version,
        "confidence": _confidence(product, version),
    }


def _open_targets(db_path: str) -> list[tuple[str, int]]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT device_ip, port
        FROM open_ports
        WHERE port NOT IN (1433, 3306, 5432, 6379, 27017)
        ORDER BY device_ip, port
        """
    ).fetchall()
    conn.close()
    return [(row["device_ip"], int(row["port"])) for row in rows]


def _save_banner(
    conn: sqlite3.Connection,
    device_ip: str,
    port: int,
    result: dict[str, Any],
    captured_at: str,
) -> None:
    conn.execute(
        """
        INSERT INTO service_banners (
            device_ip, port, banner_text, parsed_product, parsed_version,
            confidence, captured_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(device_ip, port) DO UPDATE SET
            banner_text = excluded.banner_text,
            parsed_product = excluded.parsed_product,
            parsed_version = excluded.parsed_version,
            confidence = excluded.confidence,
            captured_at = excluded.captured_at
        """,
        (
            device_ip,
            port,
            result["banner_text"],
            result["parsed_product"],
            result["parsed_version"],
            result["confidence"],
            captured_at,
        ),
    )


def run_banner_grab_cycle(db_path: str) -> int:
    """Grab banners for all open ports in the database. Returns rows updated."""
    from database import init_netguard_database
    from schema_extensions import apply_schema_extensions

    init_netguard_database(db_path)
    conn = sqlite3.connect(db_path)
    apply_schema_extensions(conn)

    targets = _open_targets(db_path)
    if not targets:
        conn.close()
        print("[*] Banner grab skipped — no open ports to probe.")
        return 0

    captured_at = datetime.now(timezone.utc).isoformat()
    updated = 0
    print(f"[*] Banner grab starting for {len(targets)} open port(s) ...")

    for device_ip, port in targets:
        result = grab_banner(device_ip, port)
        _save_banner(conn, device_ip, port, result, captured_at)
        updated += 1

        label = _display_label(result["parsed_product"], result["parsed_version"])
        confidence = result["confidence"]
        if result["banner_text"]:
            print(f"[BANNER] {device_ip}:{port} → {label} ({confidence})")
        else:
            print(f"[BANNER] {device_ip}:{port} → no data ({confidence})")

    conn.commit()
    conn.close()
    print(f"[*] Banner grab complete — {updated} port(s) processed.")
    return updated


def _load_install_env() -> None:
    from db_path import load_netguard_env

    load_netguard_env()


if __name__ == "__main__":
    _load_install_env()
    db = resolve_db_path(str(PROJECT_ROOT))
    interval = int(os.environ.get("NETGUARD_BANNER_INTERVAL_SECONDS", str(SCAN_INTERVAL_SECONDS)))
    print(f"NetGuard Banner Grabber — interval {interval}s")
    while True:
        try:
            run_banner_grab_cycle(db)
        except sqlite3.OperationalError as exc:
            print(f"[!] Banner grab database error: {exc}")
        except OSError as exc:
            print(f"[!] Banner grab I/O error: {exc}")
        time.sleep(interval)
