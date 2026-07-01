#!/usr/bin/env python3
"""Evaluate NetGuard security policies and automated-response playbooks."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DAEMON_DIR = PROJECT_ROOT / "daemon"
POLICIES_PATH = PROJECT_ROOT / "daemon" / "data" / "policies.json"

PLAYBOOK_AUTO_ISOLATE = "auto_isolate_critical"
PLAYBOOK_THREAT_DNS = "repeated_threat_dns"
PLAYBOOK_SCAN_INCIDENT = "port_scan_incident"

# Legacy policy IDs from earlier builds (DB toggle keys may still use these).
_LEGACY_POLICY_IDS = {
    PLAYBOOK_AUTO_ISOLATE: "playbook_auto_isolate_critical",
    PLAYBOOK_THREAT_DNS: "playbook_repeated_threat_dns",
    PLAYBOOK_SCAN_INCIDENT: "playbook_distributed_scan_incident",
}

PLAYBOOK_COOLDOWN_HOURS = 24
THREAT_DNS_WINDOW_MINUTES = 15
THREAT_DNS_MIN_HITS = 3
SCAN_INCIDENT_WINDOW_HOURS = 24
SCAN_INCIDENT_MIN_EVENTS = 3
CRITICAL_RISK_SCORE_MIN = 70


def _configure_daemon_path() -> None:
    daemon_str = str(DAEMON_DIR)
    if daemon_str not in sys.path:
        sys.path.insert(0, daemon_str)


def _ensure_enforcement_path() -> None:
    enforcement_dir = DAEMON_DIR / "enforcement"
    path = str(enforcement_dir)
    if path not in sys.path:
        sys.path.append(path)


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name, "").strip().lower()
    if not value:
        return default
    return value in {"1", "true", "yes", "on"}


def _policy_enabled_value(conn: sqlite3.Connection, policy_id: str) -> str | None:
    """Read enabled flag from notification_config (supports legacy playbook IDs)."""
    keys = [f"policy_enabled_{policy_id}"]
    legacy = _LEGACY_POLICY_IDS.get(policy_id)
    if legacy:
        keys.append(f"policy_enabled_{legacy}")
    for key in keys:
        row = conn.execute(
            "SELECT value FROM notification_config WHERE key = ?",
            (key,),
        ).fetchone()
        if row is not None:
            return row[0]
    return None


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
                stored = _policy_enabled_value(conn, policy["id"])
                if stored is not None:
                    policy["enabled"] = stored not in ("0", "false", "False")
        finally:
            conn.close()
    return [policy for policy in policies if policy.get("enabled", True)]


def _enabled_policy_ids(db_path: str) -> set[str]:
    return {policy["id"] for policy in _load_policies(db_path)}


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


def _playbook_recently_fired(
    conn: sqlite3.Connection,
    playbook_name: str,
    device_ip: str,
    hours: int = PLAYBOOK_COOLDOWN_HOURS,
) -> bool:
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    row = conn.execute(
        """
        SELECT 1 FROM automated_actions
        WHERE playbook_name = ? AND device_ip = ? AND timestamp >= ?
        LIMIT 1
        """,
        (playbook_name, device_ip, cutoff),
    ).fetchone()
    return row is not None


def _record_automated_action(
    conn: sqlite3.Connection,
    device_ip: str,
    playbook_name: str,
    action_taken: str,
    success: bool,
    *,
    reversible: bool = True,
    details: str | None = None,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO automated_actions (
            device_ip, playbook_name, action_taken, success, timestamp, reversible, details
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            device_ip,
            playbook_name,
            action_taken,
            1 if success else 0,
            now,
            1 if reversible else 0,
            details,
        ),
    )


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


def _notify_playbook(playbook_name: str, device_ip: str, body: str, db_path: str) -> None:
    notify_dir = str(DAEMON_DIR / "notifications")
    if notify_dir not in sys.path:
        sys.path.insert(0, notify_dir)
    from notifier import notify_playbook

    notify_playbook(playbook_name, device_ip, body, db_path)


def _run_playbook_auto_isolate_critical(
    conn: sqlite3.Connection,
    db_path: str,
    enabled: set[str],
) -> int:
    if PLAYBOOK_AUTO_ISOLATE not in enabled:
        return 0
    if not _env_bool("NETGUARD_AUTO_ISOLATE_CRITICAL", default=False):
        return 0

    _ensure_enforcement_path()
    from router_manager import RouterManager

    fired = 0
    devices = conn.execute(
        """
        SELECT ip_address, mac_address, risk_level, risk_score, is_blocked
        FROM devices
        WHERE status = 'online'
          AND risk_level = 'Critical'
          AND COALESCE(risk_score, 0) >= ?
        """,
        (CRITICAL_RISK_SCORE_MIN,),
    ).fetchall()

    mgr = RouterManager(db_path)
    for device in devices:
        device_ip = device["ip_address"]
        if device["is_blocked"]:
            continue
        if _playbook_recently_fired(conn, PLAYBOOK_AUTO_ISOLATE, device_ip):
            continue

        result = mgr.block_device(device_ip, device["mac_address"])
        if result.success:
            conn.execute(
                "UPDATE devices SET is_blocked = 1 WHERE ip_address = ?",
                (device_ip,),
            )

        action = f"router_block:{result.method}"
        details = result.detail
        _record_automated_action(
            conn,
            device_ip,
            PLAYBOOK_AUTO_ISOLATE,
            action,
            result.success,
            reversible=True,
            details=details,
        )

        body = (
            f"Critical risk auto-isolation {'succeeded' if result.success else 'failed'}.\n"
            f"Method: {result.method}\n"
            f"Detail: {result.detail}\n"
            f"Risk score: {device['risk_score']}\n"
            f"Reversible: unblock the device in the dashboard or via API."
        )
        _notify_playbook(PLAYBOOK_AUTO_ISOLATE, device_ip, body, db_path)
        fired += 1

    return fired


def _run_playbook_repeated_threat_dns(
    conn: sqlite3.Connection,
    db_path: str,
    enabled: set[str],
) -> int:
    if PLAYBOOK_THREAT_DNS not in enabled:
        return 0

    cutoff = (
        datetime.now(timezone.utc) - timedelta(minutes=THREAT_DNS_WINDOW_MINUTES)
    ).isoformat()
    fired = 0

    rows = conn.execute(
        """
        SELECT source_ip, COUNT(*) AS hit_count
        FROM dns_queries
        WHERE threat_intel_hit = 1
          AND timestamp >= ?
        GROUP BY source_ip
        HAVING hit_count >= ?
        """,
        (cutoff, THREAT_DNS_MIN_HITS),
    ).fetchall()

    for row in rows:
        device_ip = row["source_ip"]
        if not device_ip or _playbook_recently_fired(conn, PLAYBOOK_THREAT_DNS, device_ip):
            continue

        hit_count = int(row["hit_count"])
        description = (
            f"Consider isolating this device — it has contacted {hit_count} "
            f"known-malicious domains in the last {THREAT_DNS_WINDOW_MINUTES} minutes"
        )
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            INSERT INTO alerts (
                timestamp, severity, alert_type, device_ip, description, recommended_action
            )
            VALUES (?, 'HIGH', 'repeated_threat_dns', ?, ?, ?)
            """,
            (
                now,
                device_ip,
                description,
                "Review DNS activity and consider blocking this device if unintended",
            ),
        )
        _record_automated_action(
            conn,
            device_ip,
            PLAYBOOK_THREAT_DNS,
            "create_high_alert:repeated_threat_dns",
            True,
            reversible=True,
            details=description,
        )
        fired += 1

    return fired


def _format_scan_timeline(events: list[sqlite3.Row]) -> str:
    lines: list[str] = []
    for event in events:
        ts = (event["timestamp"] or "")[:19]
        source = event["source_ip"] or "unknown"
        port = event["destination_port"] or "?"
        lines.append(
            f"- {ts} UTC | source {source} -> port {port} | {event['description'] or ''}"
        )
    return "\n".join(lines) if lines else "- No scan events recorded"


def _run_playbook_distributed_scan_incident(
    conn: sqlite3.Connection,
    db_path: str,
    enabled: set[str],
) -> int:
    if PLAYBOOK_SCAN_INCIDENT not in enabled:
        return 0

    cutoff = (
        datetime.now(timezone.utc) - timedelta(hours=SCAN_INCIDENT_WINDOW_HOURS)
    ).isoformat()
    fired = 0

    candidates = conn.execute(
        """
        SELECT device_ip, COUNT(*) AS scan_events
        FROM alerts
        WHERE alert_type = 'inbound_connection'
          AND alert_pattern = 'distributed_scan'
          AND timestamp >= ?
        GROUP BY device_ip
        HAVING scan_events >= ?
        """,
        (cutoff, SCAN_INCIDENT_MIN_EVENTS),
    ).fetchall()

    notify_dir = str(DAEMON_DIR / "notifications")
    if notify_dir not in sys.path:
        sys.path.insert(0, notify_dir)
    from notifier import send_incident_report_email

    for row in candidates:
        device_ip = row["device_ip"]
        if not device_ip or _playbook_recently_fired(conn, PLAYBOOK_SCAN_INCIDENT, device_ip):
            continue

        device = conn.execute(
            """
            SELECT hostname, vendor, risk_score, risk_level, mac_address
            FROM devices WHERE ip_address = ?
            """,
            (device_ip,),
        ).fetchone()

        events = conn.execute(
            """
            SELECT timestamp, source_ip, destination_port, description
            FROM alerts
            WHERE device_ip = ?
              AND alert_type = 'inbound_connection'
              AND alert_pattern = 'distributed_scan'
              AND timestamp >= ?
            ORDER BY timestamp ASC
            """,
            (device_ip, cutoff),
        ).fetchall()

        hostname = device["hostname"] if device else None
        risk_score = device["risk_score"] if device else None
        risk_level = device["risk_level"] if device else "Unknown"
        scan_count = int(row["scan_events"])

        report = "\n".join(
            [
                "NETGUARD INCIDENT REPORT",
                "========================",
                "",
                f"Playbook:     {PLAYBOOK_SCAN_INCIDENT}",
                f"Generated:    {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
                "",
                "SUMMARY",
                "-------",
                (
                    f"Device {device_ip}"
                    + (f" ({hostname})" if hostname else "")
                    + f" received {scan_count} distributed inbound scan alert(s) "
                    f"in the last {SCAN_INCIDENT_WINDOW_HOURS} hours."
                ),
                f"Current risk: {risk_level} (score {risk_score if risk_score is not None else 'n/a'})",
                "",
                "SCAN TIMELINE",
                "-------------",
                _format_scan_timeline(events),
                "",
                "RECOMMENDED ACTIONS",
                "-------------------",
                "1. Verify whether this device should be exposed to inbound WAN traffic.",
                "2. Consider isolating the device via Settings → Block or router enforcement.",
                "3. Forward this report to your MSP ticketing system if managed.",
                "",
                "This is an automated incident summary — not a generic alert notification.",
            ]
        )

        subject = f"NetGuard Incident Report — distributed scan on {device_ip}"
        emailed = send_incident_report_email(subject, report, db_path)

        _record_automated_action(
            conn,
            device_ip,
            PLAYBOOK_SCAN_INCIDENT,
            "incident_report_email",
            emailed,
            reversible=False,
            details=f"{scan_count} distributed_scan events; email_sent={emailed}",
        )
        fired += 1

    return fired


def evaluate_playbooks(db_path: str, conn: sqlite3.Connection | None = None) -> int:
    """Run enabled automated-response playbooks. Returns actions taken."""
    enabled = _enabled_policy_ids(db_path)
    own_conn = conn is None
    if own_conn:
        conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    from schema_extensions import apply_schema_extensions

    apply_schema_extensions(conn)

    fired = 0
    fired += _run_playbook_auto_isolate_critical(conn, db_path, enabled)
    fired += _run_playbook_repeated_threat_dns(conn, db_path, enabled)
    fired += _run_playbook_distributed_scan_incident(conn, db_path, enabled)

    if own_conn:
        conn.commit()
        conn.close()
    else:
        conn.commit()

    return fired


def evaluate_policies(db_path: str) -> int:
    """Run all enabled policies and playbooks. Returns new violations + playbook actions."""
    policies = {policy["id"]: policy for policy in _load_policies(db_path)}
    if not policies:
        playbook_only = evaluate_playbooks(db_path)
        return playbook_only

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    from schema_extensions import apply_schema_extensions

    apply_schema_extensions(conn)
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
        ports = conn.execute("SELECT device_ip, port FROM open_ports").fetchall()
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

    playbook_count = evaluate_playbooks(db_path, conn=conn)

    conn.commit()
    conn.close()
    return new_count + playbook_count


def _load_install_env() -> None:
    from db_path import load_netguard_env

    load_netguard_env()


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
            print(f"[*] {count} new policy violation(s) / playbook action(s)")
        time.sleep(interval)
