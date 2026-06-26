#!/usr/bin/env python3
"""Threat intelligence feed management for DNS blocking and alerts."""

from __future__ import annotations

import os
import sqlite3
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DAEMON_DIR = PROJECT_ROOT / "daemon"
BATCH_SIZE = 2000

DEFAULT_FEED_URL = os.environ.get(
    "NETGUARD_THREAT_FEED_URL",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
)
CACHE_PATH = PROJECT_ROOT / "daemon" / "data" / "threat_intel_cache.txt"


def _configure_daemon_path() -> None:
    daemon_str = str(DAEMON_DIR)
    if daemon_str not in sys.path:
        sys.path.insert(0, daemon_str)


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


def _open_db(db_path: str) -> sqlite3.Connection:
    from db_path import open_db_connection

    return open_db_connection(db_path, timeout=60)


def ensure_threat_intel_schema(db_path: str) -> None:
    """Ensure threat-intel tables exist without running full schema migration."""
    from schema_extensions import apply_schema_extensions

    conn = _open_db(db_path)
    try:
        apply_schema_extensions(conn)
        conn.commit()
    finally:
        conn.close()


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
    rows = [(domain, source, now, now) for domain, source in domains]

    conn = _open_db(db_path)
    try:
        insert_sql = """
            INSERT INTO threat_intel_domains (domain, category, source, first_seen, last_seen)
            VALUES (?, 'malware_tracking', ?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                last_seen = excluded.last_seen,
                source = excluded.source
        """
        for offset in range(0, len(rows), BATCH_SIZE):
            conn.executemany(insert_sql, rows[offset : offset + BATCH_SIZE])
            conn.commit()
        count = conn.execute("SELECT COUNT(*) FROM threat_intel_domains").fetchone()[0]
    finally:
        conn.close()
    return int(count)


def lookup_threat_domain(db_path: str, domain: str) -> dict | None:
    """Check exact domain and parent suffixes against threat_intel_domains."""
    domain = _normalize_domain(domain)
    labels = domain.split(".")
    conn = _open_db(db_path)
    try:
        for index in range(len(labels) - 1):
            candidate = ".".join(labels[index:])
            row = conn.execute(
                """
                SELECT domain, category, source FROM threat_intel_domains
                WHERE domain = ?
                """,
                (candidate,),
            ).fetchone()
            if row:
                return {
                    "domain": row[0],
                    "category": row[1],
                    "source": row[2],
                    "matched": candidate,
                }
    finally:
        conn.close()
    return None


def is_domain_blocked(db_path: str, domain: str, site_id: str = "default") -> bool:
    domain = _normalize_domain(domain)
    conn = _open_db(db_path)
    try:
        labels = domain.split(".")
        for index in range(len(labels) - 1):
            candidate = ".".join(labels[index:])
            row = conn.execute(
                """
                SELECT 1 FROM blocked_domains
                WHERE domain = ? AND site_id IN (?, 'default')
                """,
                (candidate, site_id),
            ).fetchone()
            if row:
                return True
    finally:
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
    conn = _open_db(db_path)
    try:
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
    finally:
        conn.close()


def _load_install_env() -> None:
    """Load Pi production env when running manually under sudo."""
    if os.environ.get("NETGUARD_DB_PATH"):
        return
    env_file = os.environ.get("NETGUARD_ENV_FILE", "/etc/netguard/netguard.env")
    if not os.path.isfile(env_file):
        return
    with open(env_file, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())


def _run_with_lock_retries(action, attempts: int = 6) -> int:
    for attempt in range(attempts):
        try:
            return action()
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() or attempt == attempts - 1:
                raise
            wait_seconds = 2 * (attempt + 1)
            print(
                f"[!] Database busy, retrying in {wait_seconds}s "
                f"({attempt + 1}/{attempts})..."
            )
            time.sleep(wait_seconds)
    raise RuntimeError("unreachable")


if __name__ == "__main__":
    _configure_daemon_path()
    _load_install_env()
    from db_path import resolve_db_path

    db = resolve_db_path(str(PROJECT_ROOT))
    print(f"Using database: {db}")

    def _run_update() -> int:
        ensure_threat_intel_schema(db)
        return update_threat_intel(db)

    total = _run_with_lock_retries(_run_update)
    print(f"Threat intel updated: {total} domains")
