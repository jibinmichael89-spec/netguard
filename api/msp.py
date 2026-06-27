"""MSP collector API routes for multi-site monitoring."""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel

router = APIRouter(prefix="/msp", tags=["msp"])

_DB_PATH: str = ""
_GET_CONN = None


class HeartbeatPayload(BaseModel):
    site_id: str
    timestamp: str
    online_devices: int
    alerts_24h: int
    agent_version: str = "1.2.0"


class SiteRegistration(BaseModel):
    site_id: str
    site_name: str
    token: str


def configure(db_path: str, get_db_connection) -> None:
    global _DB_PATH, _GET_CONN
    _DB_PATH = db_path
    _GET_CONN = get_db_connection


def _conn() -> sqlite3.Connection:
    if _GET_CONN is None:
        raise RuntimeError("msp router not configured")
    return _GET_CONN()


def _optional_admin_key(x_api_key: str | None = Header(default=None)) -> None:
    required = os.environ.get("NETGUARD_MSP_ADMIN_KEY", "").strip()
    if required and x_api_key != required:
        raise HTTPException(status_code=401, detail="Invalid or missing MSP admin key")


def _resolve_site_token(token: str) -> str | None:
    conn = sqlite3.connect(_DB_PATH)
    try:
        row = conn.execute(
            "SELECT site_id FROM msp_site_tokens WHERE token = ?",
            (token,),
        ).fetchone()
        if row:
            return row[0]
    finally:
        conn.close()

    env_tokens = os.environ.get("NETGUARD_MSP_SITE_TOKENS", "")
    for entry in env_tokens.split(","):
        entry = entry.strip()
        if ":" not in entry:
            continue
        site_id, site_token = entry.split(":", 1)
        if site_token.strip() == token:
            return site_id.strip()
    return None


@router.post("/api/v1/heartbeat")
def receive_heartbeat(
    body: HeartbeatPayload,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    token = authorization.split(" ", 1)[1].strip()
    registered_site = _resolve_site_token(token)
    if not registered_site or registered_site != body.site_id:
        raise HTTPException(status_code=403, detail="Invalid site token")

    conn = _conn()
    site_name = conn.execute(
        "SELECT site_name FROM msp_site_tokens WHERE site_id = ?",
        (body.site_id,),
    ).fetchone()
    name = site_name[0] if site_name else body.site_id
    conn.execute(
        """
        INSERT INTO msp_site_status
            (site_id, site_name, last_heartbeat, online_devices, alerts_24h, agent_version, status)
        VALUES (?, ?, ?, ?, ?, ?, 'online')
        ON CONFLICT(site_id) DO UPDATE SET
            site_name = excluded.site_name,
            last_heartbeat = excluded.last_heartbeat,
            online_devices = excluded.online_devices,
            alerts_24h = excluded.alerts_24h,
            agent_version = excluded.agent_version,
            status = 'online'
        """,
        (
            body.site_id,
            name,
            body.timestamp,
            body.online_devices,
            body.alerts_24h,
            body.agent_version,
        ),
    )
    conn.commit()
    conn.close()
    return {"success": True, "site_id": body.site_id}


@router.get("/sites")
def list_msp_sites() -> dict[str, Any]:
    conn = _conn()
    rows = conn.execute(
        """
        SELECT site_id, site_name, last_heartbeat, online_devices, alerts_24h,
               agent_version, status
        FROM msp_site_status
        ORDER BY site_name
        """
    ).fetchall()
    conn.close()
    sites = [dict(row) for row in rows]
    return {"count": len(sites), "sites": sites}


@router.post("/sites/register", dependencies=[Depends(_optional_admin_key)])
def register_msp_site(body: SiteRegistration) -> dict[str, Any]:
    conn = _conn()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO msp_site_tokens (site_id, site_name, token, created_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(site_id) DO UPDATE SET
            site_name = excluded.site_name,
            token = excluded.token
        """,
        (body.site_id, body.site_name, body.token, now),
    )
    conn.execute(
        """
        INSERT INTO msp_site_status (site_id, site_name, status)
        VALUES (?, ?, 'pending')
        ON CONFLICT(site_id) DO UPDATE SET site_name = excluded.site_name
        """,
        (body.site_id, body.site_name),
    )
    conn.commit()
    conn.close()
    return {"success": True, "site_id": body.site_id}
