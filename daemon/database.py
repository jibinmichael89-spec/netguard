"""Shared NetGuard SQLite schema initialization."""

import sqlite3

from db_path import ensure_db_directory


def _ensure_device_trust_columns(conn: sqlite3.Connection) -> None:
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(devices)")
    columns = {row[1] for row in cursor.fetchall()}
    if "is_trusted" not in columns:
        cursor.execute(
            "ALTER TABLE devices ADD COLUMN is_trusted INTEGER DEFAULT 0"
        )
    if "is_blocked" not in columns:
        cursor.execute(
            "ALTER TABLE devices ADD COLUMN is_blocked INTEGER DEFAULT 0"
        )
    conn.commit()


def init_netguard_database(db_path: str) -> None:
    """Create core tables used by the API and daemons."""
    ensure_db_directory(db_path)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS devices (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address  TEXT    NOT NULL,
            mac_address TEXT    NOT NULL UNIQUE,
            vendor      TEXT,
            hostname    TEXT,
            device_tag  TEXT    DEFAULT NULL,
            is_trusted  INTEGER DEFAULT 0,
            is_blocked  INTEGER DEFAULT 0,
            first_seen  TEXT    NOT NULL,
            last_seen   TEXT    NOT NULL,
            status      TEXT    NOT NULL DEFAULT 'online'
        )
        """
    )
    _ensure_device_trust_columns(conn)
    cursor.execute("PRAGMA table_info(devices)")
    columns = {row[1] for row in cursor.fetchall()}
    if "device_tag" not in columns:
        cursor.execute(
            "ALTER TABLE devices ADD COLUMN device_tag TEXT DEFAULT NULL"
        )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS open_ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            service_name TEXT,
            is_dangerous INTEGER DEFAULT 0,
            risk_reason TEXT,
            scanned_at TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp        TEXT,
            severity         TEXT,
            alert_type       TEXT,
            device_ip        TEXT,
            description      TEXT,
            is_acknowledged  INTEGER DEFAULT 0,
            source_ip        TEXT,
            source_port      INTEGER,
            destination_port INTEGER
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS dns_queries (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     TEXT    NOT NULL,
            source_ip     TEXT    NOT NULL,
            domain        TEXT    NOT NULL,
            query_type    TEXT    NOT NULL,
            response_ip   TEXT,
            is_suspicious INTEGER NOT NULL DEFAULT 0,
            reason        TEXT
        )
        """
    )
    conn.commit()
    conn.close()
