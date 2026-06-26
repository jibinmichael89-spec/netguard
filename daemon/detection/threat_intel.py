#!/usr/bin/env python3
"""Threat intelligence feed management for DNS blocking and alerts."""

from __future__ import annotations

import os
import sqlite3
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DAEMON_DIR = PROJECT_ROOT / "daemon"


def _configure_daemon_path() -> None:
    daemon_str = str(DAEMON_DIR)
    if daemon_str not in sys.path:
        sys.path.insert(0, daemon_str)
DEFAULT_FEED_URL = os.environ.get(
    "NETGUARD_THREAT_FEED_URL",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
)
CACHE_PATH = PROJECT_ROOT / "daemon" / "data" / "threat_intel_cache.txt"


def _normalize_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def _parse_hosts_file(content: str, source: str) -> list[tuple[str, str]]:
    domains: list[tuple[str, str]] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        domain = _normalize_domain(parts[1])
        if domain and domain not in ("localhost", "localhost.localdomain"):
            domains.append((domain, source))
    return domains


def download_feed(url: str = DEFAULT_FEED_URL, timeout: int = 60) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "NetGuard/1.2"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def update_threat_intel(db_path: str, url: str = DEFAULT_FEED_URL) -> int:
    """
    Download a hosts-style blocklist and merge into threat_intel_domains.

    Returns the number of domains stored.
    """
    content = download_feed(url)
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_text(content, encoding="utf-8")

    domains = _parse_hosts_file(content, source="steven_black_hosts")
    now = datetime.now(timezone.utc).isoformat()

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    for domain, source in domains:
        cursor.execute(
            """
            INSERT INTO threat_intel_domains (domain, category, source, first_seen, last_seen)
            VALUES (?, 'malware_tracking', ?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                last_seen = excluded.last_seen,
                source = excluded.source
            """,
            (domain, source, now, now),
        )
    conn.commit()
    count = conn.execute("SELECT COUNT(*) FROM threat_intel_domains").fetchone()[0]
    conn.close()
    return int(count)


def lookup_threat_domain(db_path: str, domain: str) -> dict | None:
    """Check exact domain and parent suffixes against threat_intel_domains."""
    domain = _normalize_domain(domain)
    labels = domain.split(".")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    for index in range(len(labels) - 1):
        candidate = ".".join(labels[index:])
        cursor.execute(
            """
            SELECT domain, category, source FROM threat_intel_domains
            WHERE domain = ?
            """,
            (candidate,),
        )
        row = cursor.fetchone()
        if row:
            conn.close()
            return {
                "domain": row[0],
                "category": row[1],
                "source": row[2],
                "matched": candidate,
            }
    conn.close()
    return None


def is_domain_blocked(db_path: str, domain: str, site_id: str = "default") -> bool:
    domain = _normalize_domain(domain)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    labels = domain.split(".")
    for index in range(len(labels) - 1):
        candidate = ".".join(labels[index:])
        cursor.execute(
            """
            SELECT 1 FROM blocked_domains
            WHERE domain = ? AND site_id IN (?, 'default')
            """,
            (candidate, site_id),
        )
        if cursor.fetchone():
            conn.close()
            return True
    conn.close()
    return False


def block_domain(
    db_path: str,
    domain: str,
    source: str = "manual",
    site_id: str = "default",
) -> None:
    domain = _normalize_domain(domain)
    now = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        INSERT INTO blocked_domains (domain, site_id, source, blocked_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(domain) DO UPDATE SET
            source = excluded.source,
            blocked_at = excluded.blocked_at
        """,
        (domain, site_id, source, now),
    )
    conn.commit()
    conn.close()


if __name__ == "__main__":
    _configure_daemon_path()
    from db_path import resolve_db_path
    from schema_extensions import apply_schema_extensions

    db = resolve_db_path(str(PROJECT_ROOT))
    conn = sqlite3.connect(db)
    apply_schema_extensions(conn)
    conn.close()
    total = update_threat_intel(db)
    print(f"Threat intel updated: {total} domains")
