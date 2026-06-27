#!/usr/bin/env python3
"""Evaluate NetGuard security policies against current inventory."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DAEMON_DIR = PROJECT_ROOT / "daemon"
POLICIES_PATH = PROJECT_ROOT / "daemon" / "data" / "policies.json"


def _configure_daemon_path() -> None:
    daemon_str = str(DAEMON_DIR)
    if daemon_str not in sys.path:
        sys.path.insert(0, daemon_str)


def _load_policies(db_path: str | None = None) -> list[dict]:
    if not POLICIES_PATH.exists():
        return []
    with open(POLICIES_PATH, encoding="utf-8") as handle:
        data = json.load(handle)
    policies = list(data.get("policies", []))
    if db_path:
        conn = sqlite3.connect(db_path)
        try:
            for policy in policies:
                key = f"policy_enabled_{policy['id']}"
                row = conn.execute(
                    "SELECT value FROM notification_config WHERE key = ?",
                    (key,),
                ).fetchone()
                if row is not None:
                    policy["enabled"] = row[0] not in ("0", "false", "False")
        finally:
            conn.close()
    return [policy for policy in policies if policy.get("enabled", True)]


def _violation_exists(
    conn: sqlite3.Connection, policy_id: str, device_ip: str, window_hours: int = 24
) -> bool:
    cutoff = datetime.now(timezone.utc).timestamp() - window_hours * 3600
    row = conn.execute(
        """
        SELECT timestamp FROM policy_violations
        WHERE policy_id = ? AND device_ip = ?
        ORDER BY timestamp DESC LIMIT 1
        """,
        (policy_id, device_ip),
    ).fetchone()
    if not row:
        return False
    try:
        seen = datetime.fromisoformat(row[0].replace("Z", "+00:00")).timestamp()
    except ValueError:
        return False
    return seen >= cutoff


def _insert_violation(
    conn: sqlite3.Connection,
    policy_id: str,
    device_ip: str,
    severity: str,
    description: str,
) -> None:
    if _violation_exists(conn, policy_id, device_ip):
        return
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO policy_violations
            (site_id, policy_id, device_ip, severity, description, timestamp)
        VALUES ('default', ?, ?, ?, ?, ?)
        """,
        (policy_id, device_ip, severity, description, now),
    )
    conn.execute(
        """
        INSERT INTO alerts (timestamp, severity, alert_type, device_ip, description, recommended_action)
        VALUES (?, ?, 'policy_violation', ?, ?, ?)
        """,
        (
            now,
            severity,
            device_ip,
            description,
            f"Review policy '{policy_id}' on device {device_ip}",
        ),
    )


def evaluate_policies(db_path: str) -> int:
    """Run all enabled policies. Returns number of new violations."""
    policies = {policy["id"]: policy for policy in _load_policies(db_path)}
    if not policies:
        return 0

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    new_count = 0

    devices = conn.execute(
        "SELECT ip_address, approval_status, risk_level FROM devices WHERE status = 'online'"
    ).fetchall()
    for device in devices:
        ip = device["ip_address"]
        if policies.get("unknown_device") and device["approval_status"] == "pending":
            _insert_violation(
                conn,
                "unknown_device",
                ip,
                policies["unknown_device"]["severity"],
                policies["unknown_device"]["description"],
            )
            new_count += 1
        if policies.get("critical_risk_device") and device["risk_level"] == "Critical":
            _insert_violation(
                conn,
                "critical_risk_device",
                ip,
                policies["critical_risk_device"]["severity"],
                policies["critical_risk_device"]["description"],
            )
            new_count += 1

    if policies.get("open_rdp") or policies.get("open_ssh"):
        ports = conn.execute(
            "SELECT device_ip, port FROM open_ports"
        ).fetchall()
        for row in ports:
            if row["port"] == 3389 and policies.get("open_rdp"):
                _insert_violation(
                    conn,
                    "open_rdp",
                    row["device_ip"],
                    policies["open_rdp"]["severity"],
                    f"RDP port open on {row['device_ip']}",
                )
                new_count += 1
            if row["port"] == 22 and policies.get("open_ssh"):
                _insert_violation(
                    conn,
                    "open_ssh",
                    row["device_ip"],
                    policies["open_ssh"]["severity"],
                    f"SSH port open on {row['device_ip']}",
                )
                new_count += 1

    if policies.get("threat_intel_dns"):
        hits = conn.execute(
            """
            SELECT DISTINCT source_ip FROM dns_queries
            WHERE threat_intel_hit = 1
              AND timestamp > datetime('now', '-24 hours')
            """
        ).fetchall()
        for row in hits:
            _insert_violation(
                conn,
                "threat_intel_dns",
                row["source_ip"],
                policies["threat_intel_dns"]["severity"],
                f"Threat intel DNS hit from {row['source_ip']}",
            )
            new_count += 1

    conn.commit()
    conn.close()
    return new_count


def _load_install_env() -> None:
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


if __name__ == "__main__":
    import time

    _configure_daemon_path()
    _load_install_env()
    from database import init_netguard_database
    from db_path import resolve_db_path

    db = resolve_db_path(str(PROJECT_ROOT))
    init_netguard_database(db)

    interval = int(os.environ.get("NETGUARD_POLICY_INTERVAL_SECONDS", "300"))
    print(f"NetGuard Policy Engine — interval {interval}s")
    while True:
        count = evaluate_policies(db)
        if count:
            print(f"[*] {count} new policy violation(s)")
        time.sleep(interval)
