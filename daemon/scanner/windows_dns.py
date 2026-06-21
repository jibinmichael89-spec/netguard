"""Windows DNS cache polling for standalone NetGuard installs."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone

if getattr(sys, "frozen", False):
    _daemon_dir = os.path.join(sys._MEIPASS, "daemon")
else:
    _daemon_dir = os.path.join(os.path.dirname(__file__), "..")

if os.path.isdir(_daemon_dir) and _daemon_dir not in sys.path:
    sys.path.insert(0, _daemon_dir)

from database import init_netguard_database

SUSPICIOUS_TLDS = (".ru", ".cn", ".tk", ".pw", ".top")
BAD_KEYWORDS = ("malware", "botnet", "c2", "payload", "shell", "exploit")


def _detect_local_ip() -> str:
    import socket

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def _classify_domain(domain: str) -> tuple[int, str | None]:
    lowered = domain.lower()
    for tld in SUSPICIOUS_TLDS:
        if lowered.endswith(tld):
            return 1, f"High-risk TLD: {tld}"
    for keyword in BAD_KEYWORDS:
        if keyword in lowered:
            return 1, f"Suspicious keyword: {keyword}"
    return 0, None


def _read_dns_cache_domains() -> list[str]:
    script = (
        "Get-DnsClientCache | Where-Object { "
        "$_.Entry -and $_.Entry -match '\\.' -and $_.Entry -notmatch 'in-addr\\.arpa$' "
        "} | ForEach-Object { $_.Entry.ToString().Trim().TrimEnd('.') }"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", script],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    domains: list[str] = []
    seen: set[str] = set()
    for line in result.stdout.splitlines():
        domain = line.strip().rstrip(".")
        if not domain or domain in seen:
            continue
        seen.add(domain)
        domains.append(domain)
    return domains


def _recently_logged(
    conn: sqlite3.Connection, source_ip: str, domain: str, hours: int = 6
) -> bool:
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    row = conn.execute(
        """
        SELECT 1 FROM dns_queries
        WHERE source_ip = ? AND domain = ? AND timestamp >= ?
        LIMIT 1
        """,
        (source_ip, domain, cutoff),
    ).fetchone()
    return row is not None


def poll_windows_dns_cache(db_path: str) -> int:
    """
    Import new entries from this PC's DNS resolver cache.

    On Windows standalone installs this captures DNS lookups made on this
    machine (not full network-wide DNS like the Pi sensor).
    """
    if sys.platform != "win32":
        return 0

    init_netguard_database(db_path)
    source_ip = _detect_local_ip()
    timestamp = datetime.now(timezone.utc).isoformat()

    try:
        domains = _read_dns_cache_domains()
    except (subprocess.SubprocessError, OSError) as exc:
        print(f"[!] DNS cache read failed: {exc}")
        return 0

    if not domains:
        return 0

    conn = sqlite3.connect(db_path)
    added = 0
    for domain in domains:
        if _recently_logged(conn, source_ip, domain):
            continue
        suspicious, reason = _classify_domain(domain)
        conn.execute(
            """
            INSERT INTO dns_queries
                (timestamp, source_ip, domain, query_type, response_ip, is_suspicious, reason)
            VALUES (?, ?, ?, 'A', NULL, ?, ?)
            """,
            (timestamp, source_ip, domain, suspicious, reason),
        )
        added += 1

    conn.commit()
    conn.close()
    if added:
        print(f"[*] DNS cache: recorded {added} new lookup(s) from this PC.")
    return added
