"""SQLite schema migrations for NetGuard v1.2+ features."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    if not _table_exists(conn, table):
        return set()
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA table_info({table})")
    return {row[1] for row in cursor.fetchall()}


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    return row is not None


def _add_column(conn: sqlite3.Connection, table: str, column: str, typedef: str) -> None:
    if not _table_exists(conn, table):
        return
    if column not in _columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {typedef}")


def apply_schema_extensions(conn: sqlite3.Connection) -> None:
    """Apply incremental schema changes for alerts, devices, threat intel, and MSP hooks."""
    cursor = conn.cursor()

    for column, typedef in (
        ("is_false_positive", "INTEGER DEFAULT 0"),
        ("snoozed_until", "TEXT"),
        ("acknowledged_at", "TEXT"),
        ("site_id", "TEXT DEFAULT 'default'"),
        ("recommended_action", "TEXT"),
    ):
        _add_column(conn, "alerts", column, typedef)

    for column, typedef in (
        ("site_id", "TEXT DEFAULT 'default'"),
        ("owner", "TEXT"),
        ("profile", "TEXT"),
        ("criticality", "TEXT DEFAULT 'normal'"),
        ("is_approved", "INTEGER DEFAULT 1"),
        ("approval_status", "TEXT DEFAULT 'approved'"),
        ("notes", "TEXT"),
    ):
        _add_column(conn, "devices", column, typedef)

    for column, typedef in (
        ("threat_intel_hit", "INTEGER DEFAULT 0"),
        ("threat_category", "TEXT"),
    ):
        _add_column(conn, "dns_queries", column, typedef)

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS alert_suppressions (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            site_id          TEXT NOT NULL DEFAULT 'default',
            suppression_type TEXT NOT NULL,
            value            TEXT NOT NULL,
            reason           TEXT,
            created_at       TEXT NOT NULL,
            expires_at       TEXT
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS blocked_domains (
            domain     TEXT PRIMARY KEY,
            site_id    TEXT NOT NULL DEFAULT 'default',
            source     TEXT NOT NULL DEFAULT 'manual',
            blocked_at TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS threat_intel_domains (
            domain     TEXT PRIMARY KEY,
            category   TEXT,
            source     TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen  TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS policy_violations (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            site_id          TEXT NOT NULL DEFAULT 'default',
            policy_id        TEXT NOT NULL,
            device_ip        TEXT,
            severity         TEXT NOT NULL,
            description      TEXT NOT NULL,
            timestamp        TEXT NOT NULL,
            is_acknowledged  INTEGER DEFAULT 0
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS sites (
            id         TEXT PRIMARY KEY,
            name       TEXT NOT NULL,
            tenant_id  TEXT NOT NULL DEFAULT 'default',
            created_at TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS notification_config (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS device_events (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            site_id    TEXT NOT NULL DEFAULT 'default',
            device_ip  TEXT NOT NULL,
            event_type TEXT NOT NULL,
            summary    TEXT NOT NULL,
            details    TEXT,
            timestamp  TEXT NOT NULL
        )
        """
    )

    now = datetime.now(timezone.utc).isoformat()
    cursor.execute(
        """
        INSERT OR IGNORE INTO sites (id, name, tenant_id, created_at)
        VALUES ('default', 'Default Site', 'default', ?)
        """,
        (now,),
    )
    conn.commit()


def log_device_event(
    conn: sqlite3.Connection,
    device_ip: str,
    event_type: str,
    summary: str,
    details: str | None = None,
    site_id: str = "default",
) -> None:
    """Append a row to the device timeline event log."""
    conn.execute(
        """
        INSERT INTO device_events (site_id, device_ip, event_type, summary, details, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            site_id,
            device_ip,
            event_type,
            summary,
            details,
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()


def is_alert_suppressed(
    conn: sqlite3.Connection,
    alert_type: str,
    device_ip: str | None,
    site_id: str = "default",
) -> bool:
    """Return True if an alert should be suppressed by active rules."""
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.cursor()
    checks: list[tuple[str, str]] = [("alert_type", alert_type)]
    if device_ip:
        checks.append(("device_ip", device_ip))

    for suppression_type, value in checks:
        cursor.execute(
            """
            SELECT 1 FROM alert_suppressions
            WHERE site_id = ?
              AND suppression_type = ?
              AND value = ?
              AND (expires_at IS NULL OR expires_at > ?)
            LIMIT 1
            """,
            (site_id, suppression_type, value, now),
        )
        if cursor.fetchone():
            return True
    return False
