"""NetGuard v1.2 API routes: alerts workflow, threat intel, policies, timeline."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel, Field

_features_daemon = os.path.join(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "daemon"))
)
if _features_daemon not in sys.path:
    sys.path.insert(0, _features_daemon)

from schema_extensions import apply_schema_extensions, is_alert_suppressed, log_device_event

router = APIRouter(tags=["features"])

_DB_PATH: str = ""
_GET_CONN = None


def configure(db_path: str, get_db_connection) -> None:
    global _DB_PATH, _GET_CONN
    _DB_PATH = db_path
    _GET_CONN = get_db_connection


def _conn() -> sqlite3.Connection:
    if _GET_CONN is None:
        raise RuntimeError("features router not configured")
    return _GET_CONN()


def _rows(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


def _optional_api_key(x_api_key: str | None = Header(default=None)) -> None:
    required = os.environ.get("NETGUARD_API_KEY", "").strip()
    if required and x_api_key != required:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


class SuppressionRequest(BaseModel):
    suppression_type: Literal["alert_type", "device_ip", "domain"]
    value: str
    reason: str | None = None
    expires_hours: int | None = None


class ProfileUpdate(BaseModel):
    profile: str | None = None
    owner: str | None = None
    criticality: str | None = None
    notes: str | None = None


class BlockDomainRequest(BaseModel):
    domain: str


class NotificationConfigUpdate(BaseModel):
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None
    smtp_host: str | None = None
    smtp_port: str | None = None
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    alert_email_to: str | None = None


@router.put("/alerts/{alert_id}/acknowledge", dependencies=[Depends(_optional_api_key)])
def acknowledge_alert(alert_id: int) -> dict:
    conn = _conn()
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE alerts
        SET is_acknowledged = 1, acknowledged_at = ?
        WHERE id = ?
        """,
        (now, alert_id),
    )
    if cursor.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Alert not found")
    conn.commit()
    conn.close()
    return {"success": True, "alert_id": alert_id}


@router.put("/alerts/{alert_id}/false-positive", dependencies=[Depends(_optional_api_key)])
def mark_false_positive(alert_id: int) -> dict:
    conn = _conn()
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE alerts
        SET is_false_positive = 1, is_acknowledged = 1, acknowledged_at = ?
        WHERE id = ?
        """,
        (now, alert_id),
    )
    if cursor.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Alert not found")
    conn.commit()
    conn.close()
    return {"success": True, "alert_id": alert_id}


@router.post("/alerts/suppressions", dependencies=[Depends(_optional_api_key)])
def create_suppression(body: SuppressionRequest) -> dict:
    conn = _conn()
    now = datetime.now(timezone.utc)
    expires_at = None
    if body.expires_hours:
        expires_at = (now + timedelta(hours=body.expires_hours)).isoformat()
    conn.execute(
        """
        INSERT INTO alert_suppressions
            (site_id, suppression_type, value, reason, created_at, expires_at)
        VALUES ('default', ?, ?, ?, ?, ?)
        """,
        (body.suppression_type, body.value, body.reason, now.isoformat(), expires_at),
    )
    conn.commit()
    conn.close()
    return {"success": True}


@router.get("/alerts/suppressions")
def list_suppressions() -> dict:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM alert_suppressions ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return {"count": len(rows), "suppressions": _rows(rows)}


@router.get("/devices/pending-approval")
def list_pending_devices() -> dict:
    conn = _conn()
    rows = conn.execute(
        """
        SELECT * FROM devices
        WHERE approval_status = 'pending'
        ORDER BY first_seen DESC
        """
    ).fetchall()
    conn.close()
    return {"count": len(rows), "devices": _rows(rows)}


@router.put("/devices/{device_ip}/approve", dependencies=[Depends(_optional_api_key)])
def approve_device(device_ip: str) -> dict:
    conn = _conn()
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE devices
        SET approval_status = 'approved', is_approved = 1, is_trusted = 1
        WHERE ip_address = ?
        """,
        (device_ip,),
    )
    if cursor.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")
    log_device_event(conn, device_ip, "approval", "Device approved by user")
    conn.close()
    return {"success": True, "device_ip": device_ip, "approval_status": "approved"}


@router.put("/devices/{device_ip}/reject", dependencies=[Depends(_optional_api_key)])
def reject_device(device_ip: str) -> dict:
    conn = _conn()
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE devices
        SET approval_status = 'rejected', is_approved = 0, is_blocked = 1
        WHERE ip_address = ?
        """,
        (device_ip,),
    )
    if cursor.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")
    log_device_event(conn, device_ip, "approval", "Device rejected and blocked")
    conn.close()
    return {"success": True, "device_ip": device_ip, "approval_status": "rejected"}


@router.put("/devices/{device_ip}/profile", dependencies=[Depends(_optional_api_key)])
def update_device_profile(device_ip: str, body: ProfileUpdate) -> dict:
    conn = _conn()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM devices WHERE ip_address = ?", (device_ip,))
    if cursor.fetchone() is None:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")
    updates: list[str] = []
    values: list[Any] = []
    for field, value in (
        ("profile", body.profile),
        ("owner", body.owner),
        ("criticality", body.criticality),
        ("notes", body.notes),
    ):
        if value is not None:
            updates.append(f"{field} = ?")
            values.append(value)
    if not updates:
        conn.close()
        return {"success": True, "device_ip": device_ip}
    values.append(device_ip)
    cursor.execute(
        f"UPDATE devices SET {', '.join(updates)} WHERE ip_address = ?",
        values,
    )
    log_device_event(conn, device_ip, "profile", "Device profile updated")
    conn.commit()
    conn.close()
    return {"success": True, "device_ip": device_ip}


@router.get("/devices/{device_ip}/timeline")
def device_timeline(device_ip: str, limit: int = 100) -> dict:
    conn = _conn()
    events: list[dict[str, Any]] = []

    for row in conn.execute(
        """
        SELECT timestamp, severity, alert_type, description, is_acknowledged
        FROM alerts WHERE device_ip = ?
        ORDER BY timestamp DESC LIMIT ?
        """,
        (device_ip, limit),
    ):
        events.append(
            {
                "timestamp": row[0],
                "event_type": "alert",
                "severity": row[1],
                "summary": f"{row[2]}: {row[3]}",
                "details": {"acknowledged": row[4]},
            }
        )

    for row in conn.execute(
        """
        SELECT timestamp, domain, is_suspicious, threat_intel_hit, reason
        FROM dns_queries WHERE source_ip = ?
        ORDER BY timestamp DESC LIMIT ?
        """,
        (device_ip, limit),
    ):
        label = "DNS query"
        if row[3]:
            label = "Threat intel DNS"
        elif row[2]:
            label = "Suspicious DNS"
        events.append(
            {
                "timestamp": row[0],
                "event_type": "dns",
                "severity": "High" if row[3] or row[2] else "Info",
                "summary": f"{label}: {row[1]}",
                "details": {"reason": row[4]},
            }
        )

    for row in conn.execute(
        """
        SELECT timestamp, event_type, summary, details
        FROM device_events WHERE device_ip = ?
        ORDER BY timestamp DESC LIMIT ?
        """,
        (device_ip, limit),
    ):
        events.append(
            {
                "timestamp": row[0],
                "event_type": row[1],
                "severity": "Info",
                "summary": row[2],
                "details": {"details": row[3]},
            }
        )

    for row in conn.execute(
        """
        SELECT scanned_at, port, service_name, is_dangerous
        FROM open_ports WHERE device_ip = ?
        ORDER BY scanned_at DESC LIMIT ?
        """,
        (device_ip, limit),
    ):
        events.append(
            {
                "timestamp": row[0],
                "event_type": "port_scan",
                "severity": "High" if row[3] else "Info",
                "summary": f"Port {row[1]} open ({row[2] or 'unknown'})",
                "details": {},
            }
        )

    conn.close()
    events.sort(key=lambda item: item["timestamp"] or "", reverse=True)
    return {"device_ip": device_ip, "count": len(events[:limit]), "events": events[:limit]}


@router.post("/domains/block", dependencies=[Depends(_optional_api_key)])
def block_domain_endpoint(body: BlockDomainRequest) -> dict:
    from detection.threat_intel import block_domain

    block_domain(_DB_PATH, body.domain, source="manual")
    return {"success": True, "domain": body.domain}


@router.get("/domains/blocked")
def list_blocked_domains() -> dict:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM blocked_domains ORDER BY blocked_at DESC"
    ).fetchall()
    conn.close()
    return {"count": len(rows), "domains": _rows(rows)}


@router.get("/threat-intel/status")
def threat_intel_status() -> dict:
    conn = _conn()
    count = conn.execute("SELECT COUNT(*) FROM threat_intel_domains").fetchone()[0]
    last = conn.execute(
        "SELECT MAX(last_seen) FROM threat_intel_domains"
    ).fetchone()[0]
    conn.close()
    return {"domain_count": count, "last_updated": last}


@router.post("/threat-intel/update", dependencies=[Depends(_optional_api_key)])
def threat_intel_update() -> dict:
    from detection.threat_intel import update_threat_intel

    total = update_threat_intel(_DB_PATH)
    return {"success": True, "domain_count": total}


@router.get("/policies/violations")
def list_policy_violations() -> dict:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM policy_violations ORDER BY timestamp DESC LIMIT 200"
    ).fetchall()
    conn.close()
    return {"count": len(rows), "violations": _rows(rows)}


@router.post("/policies/evaluate", dependencies=[Depends(_optional_api_key)])
def run_policy_evaluation() -> dict:
    from detection.policy_engine import evaluate_policies

    count = evaluate_policies(_DB_PATH)
    return {"success": True, "new_violations": count}


@router.get("/reports/summary")
def security_report_summary() -> dict:
    conn = _conn()
    now = datetime.now(timezone.utc)
    week_ago = (now - timedelta(days=7)).isoformat()
    summary = {
        "generated_at": now.isoformat(),
        "online_devices": conn.execute(
            "SELECT COUNT(*) FROM devices WHERE status = 'online'"
        ).fetchone()[0],
        "pending_approval": conn.execute(
            "SELECT COUNT(*) FROM devices WHERE approval_status = 'pending'"
        ).fetchone()[0],
        "alerts_last_7_days": conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE timestamp >= ?",
            (week_ago,),
        ).fetchone()[0],
        "critical_devices": conn.execute(
            "SELECT COUNT(*) FROM devices WHERE risk_level = 'Critical'"
        ).fetchone()[0],
        "threat_intel_domains": conn.execute(
            "SELECT COUNT(*) FROM threat_intel_domains"
        ).fetchone()[0],
        "policy_violations_last_7_days": conn.execute(
            "SELECT COUNT(*) FROM policy_violations WHERE timestamp >= ?",
            (week_ago,),
        ).fetchone()[0],
    }
    conn.close()
    return summary


@router.get("/notifications/config")
def get_notification_config() -> dict:
    conn = _conn()
    rows = conn.execute("SELECT key, value FROM notification_config").fetchall()
    conn.close()
    config = {row[0]: row[1] for row in rows}
    for key in ("smtp_password", "telegram_bot_token"):
        if key in config:
            config[key] = "***"
    return {"config": config}


@router.put("/notifications/config", dependencies=[Depends(_optional_api_key)])
def update_notification_config(body: NotificationConfigUpdate) -> dict:
    conn = _conn()
    mapping = body.model_dump(exclude_none=True)
    for key, value in mapping.items():
        conn.execute(
            """
            INSERT INTO notification_config (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )
    conn.commit()
    conn.close()
    return {"success": True, "updated_keys": list(mapping.keys())}


@router.post("/enforcement/block/{device_ip}", dependencies=[Depends(_optional_api_key)])
def enforce_block(device_ip: str) -> dict:
    conn = _conn()
    row = conn.execute(
        "SELECT mac_address FROM devices WHERE ip_address = ?",
        (device_ip,),
    ).fetchone()
    conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="Device not found")

    enforcement_dir = os.path.join(_features_daemon, "enforcement")
    if enforcement_dir not in sys.path:
        sys.path.insert(0, enforcement_dir)
    from router_manager import RouterManager

    result = RouterManager(_DB_PATH).block_device(device_ip, row[0])
    return {
        "success": result.success,
        "method": result.method,
        "detail": result.detail,
    }


def filter_visible_alerts(alerts: list[dict]) -> list[dict]:
    """Hide false positives, snoozed, and suppressed alerts for dashboard lists."""
    now = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(_DB_PATH)
    apply_schema_extensions(conn)
    visible: list[dict] = []
    for alert in alerts:
        if alert.get("is_false_positive"):
            continue
        snoozed_until = alert.get("snoozed_until")
        if snoozed_until and snoozed_until > now:
            continue
        if is_alert_suppressed(
            conn,
            alert.get("alert_type", ""),
            alert.get("device_ip"),
        ):
            continue
        visible.append(alert)
    conn.close()
    return visible
