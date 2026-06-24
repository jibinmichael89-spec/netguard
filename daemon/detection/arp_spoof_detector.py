#!/usr/bin/env python3
"""
NetGuard ARP Spoof Detector
Monitors for ARP spoofing / MITM attacks by detecting unexpected MAC
address changes for known IP addresses on the local network.

Mesh Wi-Fi networks often report alternating MAC addresses for the same IP
(bridge / node proxy ARP). This module requires stable readings before
alerting and suppresses known A↔B flip patterns.
"""

from __future__ import annotations

import os
import sqlite3
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CHECK_INTERVAL_SECONDS = 15

# Consecutive cycles the same new MAC must be seen before alerting.
STABILITY_CYCLES = 4
GATEWAY_STABILITY_CYCLES = 2

# Minimum time between alerts for the same IP.
ALERT_COOLDOWN_SECONDS = 3600

# Suppress flip-flop false positives (typical mesh behaviour).
OSCILLATION_SUPPRESS_SECONDS = 86400
RECENT_MACS_LIMIT = 8

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

_daemon_dir = os.path.join(PROJECT_ROOT, "daemon")
if os.path.isdir(_daemon_dir) and _daemon_dir not in sys.path:
    sys.path.insert(0, _daemon_dir)

from db_path import resolve_db_path

DB_PATH = resolve_db_path(PROJECT_ROOT)
GATEWAY_IP = os.environ.get("NETGUARD_GATEWAY_IP", "192.168.1.1").strip()


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class MacHistoryState:
    ip_address: str
    known_mac: str | None
    last_verified: str | None
    candidate_mac: str | None
    candidate_count: int
    recent_macs: list[str]
    suppressed_until: str | None
    last_alert_at: str | None


@dataclass
class EvaluationResult:
    alerted: bool
    suppressed_oscillation: bool = False
    tracking_candidate: bool = False


# ---------------------------------------------------------------------------
# Database operations
# ---------------------------------------------------------------------------

def init_database(db_path: str) -> None:
    """Create mac_history and alerts tables if they do not already exist."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS mac_history (
            ip_address        TEXT PRIMARY KEY,
            known_mac         TEXT,
            last_verified     TEXT,
            candidate_mac     TEXT,
            candidate_count   INTEGER DEFAULT 0,
            recent_macs       TEXT,
            suppressed_until  TEXT,
            last_alert_at     TEXT
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
            is_acknowledged  INTEGER DEFAULT 0
        )
        """
    )

    cursor.execute("PRAGMA table_info(mac_history)")
    existing_columns = {row[1] for row in cursor.fetchall()}
    for column, typedef in (
        ("candidate_mac", "TEXT"),
        ("candidate_count", "INTEGER DEFAULT 0"),
        ("recent_macs", "TEXT"),
        ("suppressed_until", "TEXT"),
        ("last_alert_at", "TEXT"),
    ):
        if column not in existing_columns:
            cursor.execute(f"ALTER TABLE mac_history ADD COLUMN {column} {typedef}")

    conn.commit()
    conn.close()


def _normalize_mac(mac_address: str) -> str:
    return mac_address.upper().replace("-", ":")


def _parse_recent_macs(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [_normalize_mac(mac) for mac in raw.split("|") if mac.strip()]


def _serialize_recent_macs(recent_macs: list[str]) -> str:
    return "|".join(recent_macs)


def get_online_device_macs(db_path: str) -> dict[str, str]:
    """
    Return one MAC per online IP address.

    When multiple online rows share an IP (mesh duplicate MAC records), keep the
    most recently seen device.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT ip_address, mac_address, last_seen
        FROM devices
        WHERE status = 'online'
          AND ip_address IS NOT NULL
          AND TRIM(ip_address) != ''
          AND mac_address IS NOT NULL
          AND TRIM(mac_address) != ''
        ORDER BY last_seen DESC
        """
    )

    result: dict[str, str] = {}
    for row in cursor.fetchall():
        ip_address = row["ip_address"]
        if ip_address not in result:
            result[ip_address] = _normalize_mac(row["mac_address"])
    conn.close()
    return result


def load_mac_history(db_path: str, ip_address: str) -> MacHistoryState | None:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT known_mac, last_verified, candidate_mac, candidate_count,
               recent_macs, suppressed_until, last_alert_at
        FROM mac_history
        WHERE ip_address = ?
        """,
        (ip_address,),
    )
    row = cursor.fetchone()
    conn.close()
    if row is None:
        return None

    known_mac = _normalize_mac(row[0]) if row[0] else None
    candidate_mac = _normalize_mac(row[2]) if row[2] else None
    return MacHistoryState(
        ip_address=ip_address,
        known_mac=known_mac,
        last_verified=row[1],
        candidate_mac=candidate_mac,
        candidate_count=int(row[3] or 0),
        recent_macs=_parse_recent_macs(row[4]),
        suppressed_until=row[5],
        last_alert_at=row[6],
    )


def save_mac_history(db_path: str, state: MacHistoryState) -> None:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO mac_history (
            ip_address, known_mac, last_verified, candidate_mac, candidate_count,
            recent_macs, suppressed_until, last_alert_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip_address) DO UPDATE SET
            known_mac = excluded.known_mac,
            last_verified = excluded.last_verified,
            candidate_mac = excluded.candidate_mac,
            candidate_count = excluded.candidate_count,
            recent_macs = excluded.recent_macs,
            suppressed_until = excluded.suppressed_until,
            last_alert_at = excluded.last_alert_at
        """,
        (
            state.ip_address,
            state.known_mac,
            state.last_verified,
            state.candidate_mac,
            state.candidate_count,
            _serialize_recent_macs(state.recent_macs),
            state.suppressed_until,
            state.last_alert_at,
        ),
    )
    conn.commit()
    conn.close()


def insert_alert(
    db_path: str,
    timestamp: str,
    severity: str,
    device_ip: str,
    description: str,
) -> None:
    """Record an ARP spoof alert in the alerts table."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO alerts (timestamp, severity, alert_type, device_ip, description)
        VALUES (?, ?, 'arp_spoof', ?, ?)
        """,
        (timestamp, severity, device_ip, description),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

def push_recent_mac(recent_macs: list[str], mac_address: str) -> list[str]:
    mac = _normalize_mac(mac_address)
    updated = recent_macs + [mac]
    if len(updated) > RECENT_MACS_LIMIT:
        return updated[-RECENT_MACS_LIMIT:]
    return updated


def is_mac_oscillation(recent_macs: list[str]) -> bool:
    """
    Detect A↔B MAC flip-flop patterns common on mesh Wi-Fi.

    Requires at least four readings, exactly two unique MACs, and frequent
    alternation between them.
    """
    if len(recent_macs) < 4:
        return False

    unique_macs = set(recent_macs)
    if len(unique_macs) != 2:
        return False

    alternations = sum(
        1 for index in range(1, len(recent_macs))
        if recent_macs[index] != recent_macs[index - 1]
    )
    return alternations >= len(recent_macs) - 1


def _parse_iso_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _is_active_until(timestamp: str | None, now: datetime) -> bool:
    parsed = _parse_iso_timestamp(timestamp)
    return parsed is not None and parsed > now


def _stability_threshold(ip_address: str) -> int:
    return GATEWAY_STABILITY_CYCLES if ip_address == GATEWAY_IP else STABILITY_CYCLES


def evaluate_mac_change(
    state: MacHistoryState,
    current_mac: str,
    timestamp: str,
    now: datetime,
) -> tuple[MacHistoryState, EvaluationResult]:
    """
    Update MAC history for one IP and decide whether to raise an alert.

    Returns the updated state and evaluation metadata.
    """
    current_mac = _normalize_mac(current_mac)
    state.recent_macs = push_recent_mac(state.recent_macs, current_mac)
    state.last_verified = timestamp

    if state.known_mac is None:
        state.known_mac = current_mac
        state.candidate_mac = None
        state.candidate_count = 0
        return state, EvaluationResult(alerted=False)

    if _is_active_until(state.suppressed_until, now):
        if is_mac_oscillation(state.recent_macs):
            suppress_until = now + timedelta(seconds=OSCILLATION_SUPPRESS_SECONDS)
            state.suppressed_until = suppress_until.isoformat()
        if current_mac == state.known_mac:
            state.candidate_mac = None
            state.candidate_count = 0
        return state, EvaluationResult(alerted=False, suppressed_oscillation=True)

    if is_mac_oscillation(state.recent_macs):
        suppress_until = now + timedelta(seconds=OSCILLATION_SUPPRESS_SECONDS)
        state.suppressed_until = suppress_until.isoformat()
        state.candidate_mac = None
        state.candidate_count = 0
        return state, EvaluationResult(alerted=False, suppressed_oscillation=True)

    if current_mac == state.known_mac:
        state.candidate_mac = None
        state.candidate_count = 0
        return state, EvaluationResult(alerted=False)

    if state.candidate_mac != current_mac:
        state.candidate_mac = current_mac
        state.candidate_count = 1
        return state, EvaluationResult(alerted=False, tracking_candidate=True)

    state.candidate_count += 1
    threshold = _stability_threshold(state.ip_address)
    if state.candidate_count < threshold:
        return state, EvaluationResult(alerted=False, tracking_candidate=True)

    last_alert = _parse_iso_timestamp(state.last_alert_at)
    if (
        last_alert is not None
        and (now - last_alert).total_seconds() < ALERT_COOLDOWN_SECONDS
    ):
        state.known_mac = current_mac
        state.candidate_mac = None
        state.candidate_count = 0
        return state, EvaluationResult(alerted=False, tracking_candidate=True)

    return state, EvaluationResult(alerted=True)


# ---------------------------------------------------------------------------
# Detection logic
# ---------------------------------------------------------------------------

def check_for_spoofing(db_path: str) -> bool:
    """
    Compare current online device MACs against stored baselines.

    Returns True if at least one alert was raised this cycle.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    now = datetime.now(timezone.utc)
    device_macs = get_online_device_macs(db_path)
    alerts_raised = False
    suppressed_ips: list[str] = []

    for ip_address, current_mac in device_macs.items():
        state = load_mac_history(db_path, ip_address)
        if state is None:
            state = MacHistoryState(
                ip_address=ip_address,
                known_mac=None,
                last_verified=None,
                candidate_mac=None,
                candidate_count=0,
                recent_macs=[],
                suppressed_until=None,
                last_alert_at=None,
            )

        state, result = evaluate_mac_change(state, current_mac, timestamp, now)

        if result.suppressed_oscillation and ip_address not in suppressed_ips:
            suppressed_ips.append(ip_address)

        if result.alerted:
            alerts_raised = True
            known_mac = state.known_mac
            severity = "Critical" if ip_address == GATEWAY_IP else "High"
            description = (
                f"Possible ARP spoofing on {ip_address}: "
                f"MAC changed from {known_mac} to {current_mac}"
            )
            insert_alert(db_path, timestamp, severity, ip_address, description)
            state.known_mac = current_mac
            state.candidate_mac = None
            state.candidate_count = 0
            state.last_alert_at = timestamp

            print()
            print("=" * 70)
            print(f"  [!] ARP SPOOF ALERT — {severity}")
            print(f"  IP:       {ip_address}")
            print(f"  Old MAC:  {known_mac}")
            print(f"  New MAC:  {current_mac}")
            print(f"  Time:     {timestamp}")
            print("=" * 70)
            print()

        save_mac_history(db_path, state)

    if suppressed_ips:
        print(
            f"[{timestamp}] Suppressed mesh MAC flip-flop on: "
            + ", ".join(suppressed_ips)
        )

    return alerts_raised


def run_check_cycle(db_path: str) -> None:
    """Run one detection cycle and print a status line if the network is clean."""
    alerts = check_for_spoofing(db_path)
    if not alerts:
        timestamp = datetime.now(timezone.utc).isoformat()
        print(f"[{timestamp}] Network clean — no MAC address changes detected.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    print("NetGuard ARP Spoof Detector starting...")
    print(f"Database: {DB_PATH}")
    print(f"Check interval: {CHECK_INTERVAL_SECONDS}s")
    print(f"Stability cycles: {STABILITY_CYCLES} (gateway: {GATEWAY_STABILITY_CYCLES})")
    print(f"Gateway IP (Critical severity): {GATEWAY_IP}")
    print("Press Ctrl+C to stop.\n")

    init_database(DB_PATH)

    try:
        while True:
            run_check_cycle(DB_PATH)
            time.sleep(CHECK_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\n[*] ARP spoof detector stopped by user.")


if __name__ == "__main__":
    main()
