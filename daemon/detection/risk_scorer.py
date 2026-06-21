#!/usr/bin/env python3
"""
NetGuard Device Risk Scorer
Periodically computes composite security risk scores for every device
using existing database data and the curated risk_rules.json knowledge base.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCAN_INTERVAL_SECONDS = 300
NEW_DEVICE_WINDOW_HOURS = 24
TRUSTED_SCORE_MULTIPLIER = 0.7
MAX_RISK_SCORE = 100
UNKNOWN_VENDOR = "Unknown"
UNKNOWN_VENDOR_ONLY_INFO_REASON = (
    "No other risk indicators found - likely a privacy-mode phone or low-risk device"
)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

if getattr(sys, "frozen", False):
    _daemon_dir = os.path.join(sys._MEIPASS, "daemon")
    _bundle_root = sys._MEIPASS
else:
    _daemon_dir = os.path.join(PROJECT_ROOT, "daemon")
    _bundle_root = PROJECT_ROOT

if os.path.isdir(_daemon_dir) and _daemon_dir not in sys.path:
    sys.path.insert(0, _daemon_dir)

from db_path import resolve_db_path

DB_PATH = resolve_db_path(PROJECT_ROOT)
RISK_RULES_PATH = os.path.join(_bundle_root, "daemon", "data", "risk_rules.json")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def is_unknown_vendor(vendor: str | None) -> bool:
    if vendor is None:
        return True
    return not vendor.strip() or vendor.strip().lower() == UNKNOWN_VENDOR.lower()


def is_recently_added(first_seen: str, hours: int = NEW_DEVICE_WINDOW_HOURS) -> bool:
    first_seen_dt = parse_timestamp(first_seen)
    if first_seen_dt is None:
        return False
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    if first_seen_dt.tzinfo is None:
        first_seen_dt = first_seen_dt.replace(tzinfo=timezone.utc)
    return first_seen_dt >= cutoff


def was_new_device_at(first_seen: str, reference_time: datetime) -> bool:
    """Return True if the device was within the new-device window at reference_time."""
    first_seen_dt = parse_timestamp(first_seen)
    if first_seen_dt is None:
        return False
    if first_seen_dt.tzinfo is None:
        first_seen_dt = first_seen_dt.replace(tzinfo=timezone.utc)
    if reference_time.tzinfo is None:
        reference_time = reference_time.replace(tzinfo=timezone.utc)
    cutoff = reference_time - timedelta(hours=NEW_DEVICE_WINDOW_HOURS)
    return first_seen_dt >= cutoff


def new_device_status_changed(first_seen: str, risk_calculated_at: str) -> bool:
    """Return True when the 24-hour new-device modifier may have changed."""
    calc_dt = parse_timestamp(risk_calculated_at)
    if calc_dt is None:
        return True
    was_new = was_new_device_at(first_seen, calc_dt)
    is_new = is_recently_added(first_seen, NEW_DEVICE_WINDOW_HOURS)
    return was_new != is_new


# ---------------------------------------------------------------------------
# Rules loading
# ---------------------------------------------------------------------------

def load_risk_rules(path: str = RISK_RULES_PATH) -> dict:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


# ---------------------------------------------------------------------------
# Database operations
# ---------------------------------------------------------------------------

def get_db_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_database(db_path: str) -> None:
    """Ensure devices table exists with risk scoring columns."""
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
            first_seen  TEXT    NOT NULL,
            last_seen   TEXT    NOT NULL,
            status      TEXT    NOT NULL DEFAULT 'online'
        )
        """
    )
    cursor.execute("PRAGMA table_info(devices)")
    columns = {row[1] for row in cursor.fetchall()}

    risk_columns = {
        "risk_score": "INTEGER",
        "risk_level": "TEXT",
        "risk_factors": "TEXT",
        "risk_calculated_at": "TEXT",
        "os_guess": "TEXT",
        "os_confidence": "TEXT",
        "device_category": "TEXT",
        "fingerprint_source": "TEXT",
        "last_fingerprint_at": "TEXT",
        "is_trusted": "INTEGER DEFAULT 0",
    }
    changed = False
    for column_name, column_type in risk_columns.items():
        if column_name not in columns:
            cursor.execute(
                f"ALTER TABLE devices ADD COLUMN {column_name} {column_type}"
            )
            changed = True

    if changed:
        conn.commit()
    conn.close()


def get_all_devices(db_path: str) -> list[sqlite3.Row]:
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices ORDER BY ip_address")
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_open_ports_for_device(db_path: str, ip_address: str) -> list[int]:
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT port FROM open_ports WHERE device_ip = ? ORDER BY port",
            (ip_address,),
        )
        ports = [int(row[0]) for row in cursor.fetchall()]
    except sqlite3.OperationalError:
        ports = []
    finally:
        conn.close()
    return ports


def get_latest_port_scan_at(db_path: str, ip_address: str) -> str | None:
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT MAX(scanned_at) AS latest_scan
            FROM open_ports
            WHERE device_ip = ?
            """,
            (ip_address,),
        )
        row = cursor.fetchone()
        latest = row["latest_scan"] if row else None
    except sqlite3.OperationalError:
        latest = None
    finally:
        conn.close()
    return latest


def should_recalculate_device(
    device: sqlite3.Row,
    latest_port_scan_at: str | None,
) -> bool:
    risk_calculated_at = device["risk_calculated_at"]
    if not risk_calculated_at:
        return True

    calc_dt = parse_timestamp(risk_calculated_at)
    if calc_dt is None:
        return True

    fingerprint_at = device["last_fingerprint_at"]
    if fingerprint_at:
        fp_dt = parse_timestamp(fingerprint_at)
        if fp_dt and fp_dt > calc_dt:
            return True

    if latest_port_scan_at:
        port_dt = parse_timestamp(latest_port_scan_at)
        if port_dt and port_dt > calc_dt:
            return True

    if new_device_status_changed(device["first_seen"], risk_calculated_at):
        return True

    return False


def map_score_to_level(score: int, thresholds: dict) -> str:
    ordered_levels = (
        ("Critical", thresholds.get("Critical", 70)),
        ("High", thresholds.get("High", 45)),
        ("Medium", thresholds.get("Medium", 20)),
        ("Low", thresholds.get("Low", 1)),
        ("None", thresholds.get("None", 0)),
    )
    for level, minimum in ordered_levels:
        if score >= minimum:
            return level
    return "None"


def calculate_device_risk(device: sqlite3.Row, rules: dict, open_ports: list[int]) -> dict:
    factors: list[dict] = []
    score = 0

    port_rules = rules.get("port_risk_weights", {})
    for port in open_ports:
        entry = port_rules.get(str(port))
        if not entry:
            continue
        weight = int(entry.get("weight", 0))
        reason = entry.get("reason")
        if weight <= 0 or not reason:
            continue
        score += weight
        factors.append({"weight": weight, "reason": reason, "port": port})

    os_guess = device["os_guess"]
    if os_guess:
        os_entry = rules.get("os_risk_modifiers", {}).get(os_guess)
        if os_entry:
            weight = int(os_entry.get("weight", 0))
            reason = os_entry.get("reason")
            if weight > 0 and reason:
                score += weight
                factors.append({"weight": weight, "reason": reason})

    category = device["device_category"]
    if category:
        category_entry = rules.get("category_risk_modifiers", {}).get(category)
        if category_entry:
            weight = int(category_entry.get("weight", 0))
            reason = category_entry.get("reason")
            if weight > 0 and reason:
                score += weight
                factors.append({"weight": weight, "reason": reason})

    trust_rules = rules.get("trust_modifiers", {})
    unknown_vendor_entry = trust_rules.get("untrusted_unknown_vendor", {})
    unknown_vendor_reason = unknown_vendor_entry.get("reason")

    if is_unknown_vendor(device["vendor"]) and int(device["is_trusted"] or 0) != 1:
        weight = int(unknown_vendor_entry.get("weight", 0))
        if weight > 0 and unknown_vendor_reason:
            score += weight
            factors.append({"weight": weight, "reason": unknown_vendor_reason})

    if is_recently_added(device["first_seen"], NEW_DEVICE_WINDOW_HOURS):
        entry = trust_rules.get("new_device_24h", {})
        weight = int(entry.get("weight", 0))
        reason = entry.get("reason")
        if weight > 0 and reason:
            score += weight
            factors.append({"weight": weight, "reason": reason})

    if int(device["is_trusted"] or 0) == 1:
        score = max(0, int(score * TRUSTED_SCORE_MULTIPLIER))

    score = min(score, MAX_RISK_SCORE)
    factors.sort(key=lambda item: item["weight"], reverse=True)

    positive_factors = [factor for factor in factors if factor["weight"] > 0]
    unknown_vendor_only = (
        len(positive_factors) == 1
        and unknown_vendor_reason
        and positive_factors[0]["reason"] == unknown_vendor_reason
    )

    if unknown_vendor_only:
        level = "Low"
        factors.append(
            {"weight": 0, "reason": UNKNOWN_VENDOR_ONLY_INFO_REASON}
        )
    else:
        level = map_score_to_level(score, rules.get("risk_thresholds", {}))

    return {
        "risk_score": score,
        "risk_level": level,
        "risk_factors": factors,
    }


def update_device_risk(
    db_path: str,
    device_id: int,
    risk_score: int,
    risk_level: str,
    risk_factors: list[dict],
) -> None:
    timestamp = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE devices
        SET risk_score = ?,
            risk_level = ?,
            risk_factors = ?,
            risk_calculated_at = ?
        WHERE id = ?
        """,
        (
            risk_score,
            risk_level,
            json.dumps(risk_factors),
            timestamp,
            device_id,
        ),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Scoring cycle
# ---------------------------------------------------------------------------

def run_scoring_cycle(
    db_path: str,
    rules: dict,
    force_all: bool = False,
) -> tuple[int, int]:
    """
    Score devices whose underlying data changed since the last calculation.

    When force_all is True, every device is rescored regardless of timestamps.

    Returns (devices_scored, devices_skipped).
    """
    devices = get_all_devices(db_path)
    scored = 0
    skipped = 0

    for device in devices:
        ip_address = device["ip_address"]
        latest_port_scan_at = get_latest_port_scan_at(db_path, ip_address)

        if not force_all and not should_recalculate_device(device, latest_port_scan_at):
            skipped += 1
            continue

        open_ports = get_open_ports_for_device(db_path, ip_address)
        result = calculate_device_risk(device, rules, open_ports)
        update_device_risk(
            db_path,
            int(device["id"]),
            result["risk_score"],
            result["risk_level"],
            result["risk_factors"],
        )
        scored += 1
        factor_count = len(result["risk_factors"])
        print(
            f"[RISK] {ip_address} -> Score: {result['risk_score']} "
            f"({result['risk_level']}) | {factor_count} factor"
            f"{'' if factor_count == 1 else 's'}"
        )

    return scored, skipped


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="NetGuard device risk scorer")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Score all devices once and exit",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force recalculation for every device (ignore change detection)",
    )
    args = parser.parse_args()

    print("NetGuard Device Risk Scorer starting...")
    print(f"Database:       {DB_PATH}")
    print(f"Risk rules:     {RISK_RULES_PATH}")
    print(f"Scan interval:  {SCAN_INTERVAL_SECONDS}s")
    print("No admin/root privileges required (database read/compute/write only).")
    print("Press Ctrl+C to stop.\n")

    if not os.path.exists(RISK_RULES_PATH):
        print(f"[!] Risk rules file not found: {RISK_RULES_PATH}")
        sys.exit(1)

    if not os.path.exists(DB_PATH):
        print(f"[!] Database not found: {DB_PATH}")
        print("    Start the network scanner first.")
        sys.exit(1)

    try:
        rules = load_risk_rules()
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[!] Failed to load risk rules: {exc}")
        sys.exit(1)

    init_database(DB_PATH)

    force_next_cycle = True

    def run_cycle(force_all: bool) -> None:
        timestamp = datetime.now(timezone.utc).isoformat()
        print(f"\n[*] Risk scoring cycle starting at {timestamp[:19]} UTC")
        if force_all:
            print("[*] Forcing recalculation for all devices.")
        try:
            scored, skipped = run_scoring_cycle(DB_PATH, rules, force_all=force_all)
            print(
                f"[*] Risk scoring complete — {scored} updated, "
                f"{skipped} unchanged."
            )
        except sqlite3.Error as exc:
            print(f"[!] Database error during risk scoring: {exc}")
        except Exception as exc:
            print(f"[!] Risk scoring cycle failed: {exc}")

    if args.once or args.force:
        run_cycle(force_all=True)
        return

    try:
        run_cycle(force_all=True)
        force_next_cycle = False

        while True:
            run_cycle(force_all=force_next_cycle)
            print(f"\n[*] Next run in {SCAN_INTERVAL_SECONDS} seconds ...")
            time.sleep(SCAN_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\n[*] Risk scorer stopped by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()
