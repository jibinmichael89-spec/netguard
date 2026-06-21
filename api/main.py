"""
NetGuard REST API
FastAPI server that exposes device data and security alerts
stored by the ARP scanner in the shared SQLite database.
"""

import json
import os
import socket
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

if getattr(sys, "frozen", False):
    PROJECT_ROOT = os.path.dirname(sys.executable)
    BUNDLE_ROOT = sys._MEIPASS
else:
    PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    BUNDLE_ROOT = PROJECT_ROOT

_vault_dir = os.path.join(BUNDLE_ROOT, "daemon", "vault")
if os.path.isdir(_vault_dir) and _vault_dir not in sys.path:
    sys.path.insert(0, _vault_dir)

from password_vault import (
    add_credential,
    calculate_strength,
    delete_credential,
    get_all_credentials,
    unlock_vault,
)
# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# How far back to look when reporting "new" devices (hours)
NEW_DEVICE_WINDOW_HOURS = 24

# Domain category keyword mappings (mirrors dns_monitor.py)
DOMAIN_CATEGORIES = {
    "Social media": ("facebook", "instagram", "twitter", "tiktok", "snapchat"),
    "Streaming": ("netflix", "youtube", "spotify", "disney", "amazon"),
    "Gaming": ("xbox", "playstation", "steam", "epicgames"),
    "IoT/Smart home": ("ring", "dreame", "xiaomi", "tuya", "alexa"),
    "Advertising": ("doubleclick", "googlesyndication", "adnxs", "tracking"),
    "Apple services": ("apple", "icloud", "itunes"),
    "Microsoft": ("microsoft", "windows", "azure"),
}

VALID_INSTRUCTION_PLATFORMS = frozenset({"windows", "linux", "pi"})

_db_module_dir = os.path.join(BUNDLE_ROOT, "daemon")
if os.path.isdir(_db_module_dir) and _db_module_dir not in sys.path:
    sys.path.insert(0, _db_module_dir)

from db_path import resolve_db_path
from database import init_netguard_database

DB_PATH = resolve_db_path(PROJECT_ROOT if not getattr(sys, "frozen", False) else None)
PORT_INSTRUCTIONS_PATH = os.path.join(
    BUNDLE_ROOT, "daemon", "data", "port_instructions.json"
)

# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="NetGuard API",
    description="Home network security monitor — device inventory and alerts",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600,
)


def get_db_connection() -> sqlite3.Connection:
    """Open a connection to the NetGuard SQLite database."""
    try:
        init_netguard_database(DB_PATH)
    except OSError as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                f"Cannot create database at {DB_PATH}: {exc}. "
                "Run ARP Scanner as your user account, or set NETGUARD_DB_PATH."
            ),
        ) from exc
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    _ensure_device_tag_column(conn)
    _ensure_device_trust_columns(conn)
    _ensure_fingerprint_columns(conn)
    _ensure_inbound_alert_columns(conn)
    return conn


def _ensure_device_tag_column(conn: sqlite3.Connection) -> None:
    """Add device_tag column to devices table if it does not already exist."""
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(devices)")
    columns = {row[1] for row in cursor.fetchall()}
    if "device_tag" not in columns:
        cursor.execute(
            "ALTER TABLE devices ADD COLUMN device_tag TEXT DEFAULT NULL"
        )
        conn.commit()


def _ensure_device_trust_columns(conn: sqlite3.Connection) -> None:
    """Add is_trusted and is_blocked columns if they do not already exist."""
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(devices)")
    columns = {row[1] for row in cursor.fetchall()}
    changed = False
    if "is_trusted" not in columns:
        cursor.execute(
            "ALTER TABLE devices ADD COLUMN is_trusted INTEGER DEFAULT 0"
        )
        changed = True
    if "is_blocked" not in columns:
        cursor.execute(
            "ALTER TABLE devices ADD COLUMN is_blocked INTEGER DEFAULT 0"
        )
        changed = True
    if changed:
        conn.commit()


def _ensure_fingerprint_columns(conn: sqlite3.Connection) -> None:
    """Add passive OS fingerprint columns to devices table if missing."""
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(devices)")
    columns = {row[1] for row in cursor.fetchall()}
    changed = False
    fingerprint_columns = {
        "os_guess": "TEXT",
        "os_confidence": "TEXT",
        "device_category": "TEXT",
        "fingerprint_source": "TEXT",
        "last_fingerprint_at": "TEXT",
    }
    for column_name, column_type in fingerprint_columns.items():
        if column_name not in columns:
            cursor.execute(
                f"ALTER TABLE devices ADD COLUMN {column_name} {column_type}"
            )
            changed = True
    if changed:
        conn.commit()


def _ensure_inbound_alert_columns(conn: sqlite3.Connection) -> None:
    """Add inbound connection columns to alerts table if missing."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'"
    )
    if cursor.fetchone() is None:
        return
    cursor.execute("PRAGMA table_info(alerts)")
    columns = {row[1] for row in cursor.fetchall()}
    changed = False
    if "source_ip" not in columns:
        cursor.execute("ALTER TABLE alerts ADD COLUMN source_ip TEXT")
        changed = True
    if "source_port" not in columns:
        cursor.execute("ALTER TABLE alerts ADD COLUMN source_port INTEGER")
        changed = True
    if "destination_port" not in columns:
        cursor.execute("ALTER TABLE alerts ADD COLUMN destination_port INTEGER")
        changed = True
    if changed:
        conn.commit()


def rows_to_dicts(rows: list[sqlite3.Row]) -> list[dict]:
    """Convert SQLite Row objects to plain Python dictionaries."""
    return [dict(row) for row in rows]


DEVICE_FINGERPRINT_FIELDS = (
    "os_guess",
    "os_confidence",
    "device_category",
    "fingerprint_source",
    "last_fingerprint_at",
)

DEVICE_SELECT_COLUMNS = (
    "id",
    "ip_address",
    "mac_address",
    "vendor",
    "hostname",
    "device_tag",
    "is_trusted",
    "is_blocked",
    "first_seen",
    "last_seen",
    "status",
    *DEVICE_FINGERPRINT_FIELDS,
)

DEVICE_SELECT_SQL = ", ".join(DEVICE_SELECT_COLUMNS)


def rows_to_device_dicts(rows: list[sqlite3.Row]) -> list[dict]:
    """
    Convert device rows to JSON-ready dicts with stable fingerprint fields.

    Unfingerprinted devices expose null for os_guess and related fields.
    """
    devices: list[dict] = []
    for row in rows:
        device = dict(row)
        for field in DEVICE_FINGERPRINT_FIELDS:
            value = device.get(field)
            if field not in device or value == "":
                device[field] = None
        devices.append(device)
    return devices


def _get_device_row(conn: sqlite3.Connection, device_id: int) -> sqlite3.Row:
    """Return a device row by primary key or raise HTTP 404."""
    cursor = conn.cursor()
    cursor.execute(
        f"SELECT {DEVICE_SELECT_SQL} FROM devices WHERE id = ?",
        (device_id,),
    )
    row = cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return row


def _get_device_by_ip(conn: sqlite3.Connection, device_ip: str) -> sqlite3.Row:
    """Return a device row by IP address or raise HTTP 404."""
    cursor = conn.cursor()
    cursor.execute(
        f"SELECT {DEVICE_SELECT_SQL} FROM devices WHERE ip_address = ?",
        (device_ip,),
    )
    row = cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return row


def _format_alert_timestamp(timestamp: str) -> str:
    """Format an ISO timestamp for inbound attempt API responses."""
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return timestamp[:19].replace("T", " ")


def _load_port_instructions() -> dict:
    """Load port remediation instructions from the JSON data file."""
    if not os.path.exists(PORT_INSTRUCTIONS_PATH):
        raise HTTPException(
            status_code=503,
            detail="Port instructions file not found.",
        )
    with open(PORT_INSTRUCTIONS_PATH, encoding="utf-8") as handle:
        return json.load(handle)


def categorize_domain(domain: str) -> str:
    """Assign a category label to a domain based on keyword matching."""
    domain_lower = domain.lower()
    for category, keywords in DOMAIN_CATEGORIES.items():
        for keyword in keywords:
            if keyword in domain_lower:
                return category
    return "Other"


class VaultUnlockRequest(BaseModel):
    master_password: str


class VaultAddRequest(BaseModel):
    master_password: str
    device_name: str
    device_ip: str
    username: str
    password: str


class DeviceTagRequest(BaseModel):
    device_tag: str


class DeviceTrustRequest(BaseModel):
    is_trusted: bool


class DeviceBlockRequest(BaseModel):
    is_blocked: bool


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/api")
def api_info() -> dict:
    """API overview and available endpoints."""
    return {
        "service": "NetGuard API",
        "endpoints": [
            "GET /system/info",
            "GET /devices",
            "GET /devices?include_blocked=true",
            "GET /devices/new",
            "GET /devices/{device_ip}",
            "PUT /devices/{device_ip}/tag",
            "PUT /devices/id/{device_id}/trust",
            "PUT /devices/id/{device_id}/block",
            "PUT /devices/{device_ip}/trust",
            "PUT /devices/{device_ip}/block",
            "GET /alerts",
            "GET /alerts/security",
            "GET /alerts/security/critical",
            "GET /inbound/{device_ip}",
            "GET /dhcp/servers",
            "GET /dns",
            "GET /dns/suspicious",
            "GET /dns/summary",
            "GET /ports",
            "GET /ports/dangerous",
            "GET /ports/{port}/instructions",
            "GET /ports/{device_ip}",
            "POST /vault/unlock",
            "POST /vault/add",
            "POST /vault/list",
            "DELETE /vault/{credential_id}",
        ],
    }


@app.get("/system/info")
def system_info() -> dict:
    """Return host OS details so the dashboard can show accurate block warnings."""
    if sys.platform == "win32":
        platform_name = "windows"
    elif sys.platform.startswith("linux"):
        platform_name = "linux"
    elif sys.platform == "darwin":
        platform_name = "darwin"
    else:
        platform_name = sys.platform

    return {
        "platform": platform_name,
        "network_block_supported": platform_name != "windows",
        "hostname": socket.gethostname(),
    }


@app.get("/devices")
def list_devices(include_blocked: bool = Query(default=False)) -> dict:
    """
    Return all devices discovered by the ARP scanner.

    Blocked devices are excluded by default. Pass include_blocked=true
    to include blocked devices for admin/recovery purposes.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    if include_blocked:
        cursor.execute(
            f"SELECT {DEVICE_SELECT_SQL} FROM devices ORDER BY ip_address"
        )
    else:
        cursor.execute(
            f"""
            SELECT {DEVICE_SELECT_SQL}
            FROM devices
            WHERE COALESCE(is_blocked, 0) = 0
            ORDER BY ip_address
            """
        )
    devices = rows_to_device_dicts(cursor.fetchall())
    conn.close()
    return {"count": len(devices), "devices": devices}


@app.put("/devices/{device_ip}/tag")
def update_device_tag(device_ip: str, request: DeviceTagRequest) -> dict:
    """
    Set or update a user-defined tag for a device by IP address.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE devices
        SET device_tag = ?
        WHERE ip_address = ?
        """,
        (request.device_tag.strip(), device_ip),
    )
    if cursor.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")

    conn.commit()
    conn.close()
    return {
        "device_ip": device_ip,
        "device_tag": request.device_tag.strip(),
        "success": True,
    }


@app.put("/devices/id/{device_id}/trust")
def update_device_trust_by_id(device_id: int, request: DeviceTrustRequest) -> dict:
    """Mark a device as trusted or remove trusted status by device id."""
    conn = get_db_connection()
    device = _get_device_row(conn, device_id)
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE devices
        SET is_trusted = ?
        WHERE id = ?
        """,
        (1 if request.is_trusted else 0, device_id),
    )
    conn.commit()
    conn.close()
    return {
        "device_ip": device["ip_address"],
        "is_trusted": request.is_trusted,
        "success": True,
    }


@app.put("/devices/id/{device_id}/block")
def update_device_block_by_id(device_id: int, request: DeviceBlockRequest) -> dict:
    """Block or unblock a device by device id."""
    conn = get_db_connection()
    device = _get_device_row(conn, device_id)
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE devices
        SET is_blocked = ?
        WHERE id = ?
        """,
        (1 if request.is_blocked else 0, device_id),
    )
    conn.commit()
    conn.close()
    return {
        "device_ip": device["ip_address"],
        "is_blocked": request.is_blocked,
        "success": True,
    }


@app.put("/devices/{device_ip}/trust")
def update_device_trust(device_ip: str, request: DeviceTrustRequest) -> dict:
    """Mark a device as trusted or remove trusted status."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id FROM devices WHERE ip_address = ?",
        (device_ip,),
    )
    row = cursor.fetchone()
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")
    conn.close()
    return update_device_trust_by_id(row[0], request)


@app.put("/devices/{device_ip}/block")
def update_device_block(device_ip: str, request: DeviceBlockRequest) -> dict:
    """Block or unblock a device on the network."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id FROM devices WHERE ip_address = ?",
        (device_ip,),
    )
    row = cursor.fetchone()
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")
    conn.close()
    return update_device_block_by_id(row[0], request)


@app.get("/devices/new")
def list_new_devices() -> dict:
    """
    Return devices first seen within the last 24 hours.

    Useful for identifying recently joined network clients.
    """
    cutoff = (
        datetime.now(timezone.utc) - timedelta(hours=NEW_DEVICE_WINDOW_HOURS)
    ).isoformat()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        f"""
        SELECT {DEVICE_SELECT_SQL}
        FROM devices
        WHERE first_seen >= ?
        ORDER BY first_seen DESC
        """,
        (cutoff,),
    )
    devices = rows_to_device_dicts(cursor.fetchall())
    conn.close()
    return {
        "window_hours": NEW_DEVICE_WINDOW_HOURS,
        "count": len(devices),
        "devices": devices,
    }


@app.get("/devices/{device_ip}")
def get_device(device_ip: str) -> dict:
    """Return a single device record by IP address."""
    conn = get_db_connection()
    device = _get_device_by_ip(conn, device_ip)
    conn.close()
    return rows_to_device_dicts([device])[0]


@app.get("/alerts")
def list_alerts() -> dict:
    """
    Return security alerts: newly discovered and offline devices.

    - new_devices: first seen in the last 24 hours
    - offline_devices: currently marked offline by the scanner
    """
    cutoff = (
        datetime.now(timezone.utc) - timedelta(hours=NEW_DEVICE_WINDOW_HOURS)
    ).isoformat()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        f"""
        SELECT {DEVICE_SELECT_SQL}
        FROM devices
        WHERE first_seen >= ?
        ORDER BY first_seen DESC
        """,
        (cutoff,),
    )
    new_devices = rows_to_device_dicts(cursor.fetchall())

    cursor.execute(
        f"""
        SELECT {DEVICE_SELECT_SQL}
        FROM devices
        WHERE status = 'offline'
        ORDER BY last_seen DESC
        """
    )
    offline_devices = rows_to_device_dicts(cursor.fetchall())

    conn.close()

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "new_devices": {
            "count": len(new_devices),
            "devices": new_devices,
        },
        "offline_devices": {
            "count": len(offline_devices),
            "devices": offline_devices,
        },
        "total_alerts": len(new_devices) + len(offline_devices),
    }


@app.get("/alerts/security")
def list_security_alerts() -> dict:
    """
    Return all ARP spoof and other security alerts from the alerts table.

    Ordered by most recent first.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT * FROM alerts
        ORDER BY timestamp DESC
        """
    )
    alerts = rows_to_dicts(cursor.fetchall())
    conn.close()
    return {"count": len(alerts), "alerts": alerts}


@app.get("/alerts/security/critical")
def list_critical_security_alerts() -> dict:
    """
    Return only Critical-severity security alerts.

    Ordered by most recent first.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT * FROM alerts
        WHERE severity = 'Critical'
        ORDER BY timestamp DESC
        """
    )
    alerts = rows_to_dicts(cursor.fetchall())
    conn.close()
    return {"count": len(alerts), "alerts": alerts}


@app.get("/inbound/{device_ip}")
def list_inbound_attempts(
    device_ip: str,
    limit: int = Query(default=100, ge=1, le=1000),
) -> dict:
    """
    Return inbound connection attempts targeting a specific device.

    Reads CRITICAL inbound_connection alerts recorded by the inbound
    connection detector. Returns an empty list when no attempts exist.
    """
    conn = get_db_connection()
    _get_device_by_ip(conn, device_ip)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT source_ip, source_port, destination_port, severity, timestamp, description
        FROM alerts
        WHERE alert_type = 'inbound_connection' AND device_ip = ?
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (device_ip, limit),
    )
    rows = rows_to_dicts(cursor.fetchall())
    conn.close()

    inbound_attempts = [
        {
            "source_ip": row["source_ip"],
            "source_port": row["source_port"],
            "destination_port": row["destination_port"],
            "severity": row["severity"],
            "timestamp": _format_alert_timestamp(row["timestamp"]),
            "description": row["description"],
        }
        for row in rows
    ]

    return {
        "device_ip": device_ip,
        "count": len(inbound_attempts),
        "inbound_attempts": inbound_attempts,
    }


@app.get("/dhcp/servers")
def list_dhcp_servers() -> dict:
    """
    Return all known DHCP servers observed by the rogue DHCP detector.

    Includes a separate count of untrusted (rogue) servers.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT * FROM dhcp_servers
        ORDER BY last_seen DESC
        """
    )
    servers = rows_to_dicts(cursor.fetchall())
    cursor.execute("SELECT COUNT(*) FROM dhcp_servers WHERE is_trusted = 0")
    untrusted_count = cursor.fetchone()[0]
    conn.close()
    return {
        "count": len(servers),
        "untrusted_count": untrusted_count,
        "servers": servers,
    }


@app.get("/dns")
def list_dns_queries() -> dict:
    """
    Return the last 100 DNS queries captured by the DNS monitor.

    Ordered by most recent first.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT * FROM dns_queries
        ORDER BY id DESC
        LIMIT 100
        """
    )
    queries = rows_to_dicts(cursor.fetchall())
    conn.close()
    return {"count": len(queries), "queries": queries}


@app.get("/dns/suspicious")
def list_suspicious_dns() -> dict:
    """
    Return all DNS queries flagged as suspicious.

    Includes the reason each query was flagged.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT * FROM dns_queries
        WHERE is_suspicious = 1
        ORDER BY id DESC
        """
    )
    queries = rows_to_dicts(cursor.fetchall())
    conn.close()
    return {"count": len(queries), "queries": queries}


@app.get("/dns/summary")
def dns_summary() -> dict:
    """
    Return query counts grouped by source device and domain category.

    Aggregates all stored DNS queries into a per-device, per-category summary.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT source_ip, domain FROM dns_queries")
    rows = cursor.fetchall()
    conn.close()

    summary: dict[str, dict[str, int]] = {}
    for row in rows:
        source_ip = row["source_ip"]
        category = categorize_domain(row["domain"])
        if source_ip not in summary:
            summary[source_ip] = {}
        summary[source_ip][category] = summary[source_ip].get(category, 0) + 1

    return {
        "devices": len(summary),
        "summary": summary,
    }

@app.get("/ports")
def list_open_ports() -> dict:
    """
    Return all open ports for all devices, grouped by device IP.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT * FROM open_ports
        ORDER BY device_ip, port
        """
    )
    rows = rows_to_dicts(cursor.fetchall())
    conn.close()

    grouped: dict[str, list[dict]] = {}
    for row in rows:
        ip = row["device_ip"]
        grouped.setdefault(ip, []).append(row)

    return {
        "devices_scanned": len(grouped),
        "total_open_ports": len(rows),
        "results": grouped,
    }


@app.get("/ports/dangerous")
def list_dangerous_ports() -> dict:
    """
    Return only ports flagged as dangerous across all devices.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT * FROM open_ports
        WHERE is_dangerous = 1
        ORDER BY device_ip, port
        """
    )
    rows = rows_to_dicts(cursor.fetchall())
    conn.close()
    return {"count": len(rows), "dangerous_ports": rows}


@app.get("/ports/{port}/instructions")
def get_port_instructions(
    port: int,
    platform: str = Query(default="linux"),
) -> dict:
    """
    Return OS-specific steps to close a dangerous port.

    Reads remediation guidance from daemon/data/port_instructions.json.
    Platform must be one of: windows, linux, pi.
    """
    platform_key = platform.lower().strip()
    if platform_key not in VALID_INSTRUCTION_PLATFORMS:
        raise HTTPException(
            status_code=400,
            detail="Platform must be one of: windows, linux, pi",
        )

    instructions = _load_port_instructions()
    port_key = str(port)
    if port_key not in instructions:
        raise HTTPException(
            status_code=404,
            detail=f"No instructions available for port {port}",
        )

    entry = instructions[port_key]
    platform_data = entry.get(platform_key)
    if not platform_data:
        raise HTTPException(
            status_code=404,
            detail=f"No {platform_key} instructions for port {port}",
        )

    return {
        "port": port,
        "service": entry.get("service"),
        "dangerous_reason": entry.get("dangerous_reason"),
        "platform": platform_key,
        "description": platform_data.get("description"),
        "steps": platform_data.get("steps", []),
    }


@app.get("/ports/{device_ip}")
def list_ports_for_device(device_ip: str) -> dict:
    """
    Return open ports for a single device by IP address.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT * FROM open_ports
        WHERE device_ip = ?
        ORDER BY port
        """,
        (device_ip,),
    )
    rows = rows_to_dicts(cursor.fetchall())
    conn.close()
    return {"device_ip": device_ip, "count": len(rows), "ports": rows}


@app.post("/vault/unlock")
def vault_unlock(request: VaultUnlockRequest) -> dict:
    """
    Verify the vault master password without returning credential data.
    """
    get_db_connection().close()
    fernet = unlock_vault(request.master_password)
    return {"unlocked": fernet is not None}


@app.post("/vault/add")
def vault_add(request: VaultAddRequest) -> dict:
    """
    Unlock the vault and store a new encrypted credential.
    """
    get_db_connection().close()
    fernet = unlock_vault(request.master_password)
    if fernet is None:
        raise HTTPException(status_code=401, detail="Incorrect master password")

    row_id = add_credential(
        fernet,
        request.device_name,
        request.device_ip,
        request.username,
        request.password,
    )
    return {
        "id": row_id,
        "strength_score": calculate_strength(request.password),
    }


@app.post("/vault/list")
def vault_list(request: VaultUnlockRequest) -> dict:
    """
    Return vault credentials with metadata only — passwords are never exposed.
    """
    get_db_connection().close()
    fernet = unlock_vault(request.master_password)
    if fernet is None:
        raise HTTPException(status_code=401, detail="Incorrect master password")

    credentials = get_all_credentials(fernet)
    masked = [
        {
            "id": cred["id"],
            "device_name": cred["device_name"],
            "device_ip": cred["device_ip"],
            "username": cred["username"],
            "strength_score": cred["strength_score"],
            "is_compromised": cred["is_compromised"],
            "last_checked": cred["last_checked"],
            "created_at": cred["created_at"],
        }
        for cred in credentials
    ]
    return {"count": len(masked), "credentials": masked}


@app.delete("/vault/{credential_id}")
def vault_delete(credential_id: int) -> dict:
    """Delete a stored credential by id."""
    get_db_connection().close()
    delete_credential(credential_id)
    return {"deleted": True}


# Serve static dashboard files (registered after API routes)
def _resolve_dashboard_path() -> str | None:
    candidates = [
        os.path.join(BUNDLE_ROOT, "api", "static"),
        os.path.join(PROJECT_ROOT, "api", "static"),
    ]
    seen: set[str] = set()
    for path in candidates:
        normalized = os.path.abspath(path)
        if normalized in seen:
            continue
        seen.add(normalized)
        if os.path.isfile(os.path.join(normalized, "index.html")):
            return normalized
    return None


dashboard_path = _resolve_dashboard_path()
assets_path = os.path.join(dashboard_path, "assets") if dashboard_path else ""

if dashboard_path:

    @app.get("/")
    async def serve_dashboard() -> FileResponse:
        return FileResponse(os.path.join(dashboard_path, "index.html"))

    if os.path.exists(assets_path):
        app.mount("/assets", StaticFiles(directory=assets_path), name="assets")

    @app.get("/favicon.svg")
    async def serve_favicon() -> FileResponse:
        return FileResponse(os.path.join(dashboard_path, "favicon.svg"))

    @app.get("/icons.svg")
    async def serve_icons() -> FileResponse:
        return FileResponse(os.path.join(dashboard_path, "icons.svg"))
else:
    print(
        "WARNING: Dashboard files not found in the application bundle. "
        "Rebuild NetGuard-API.exe with the dashboard static assets included."
    )


@app.get("/health")
def health_check() -> dict:
    """Simple health probe for troubleshooting installs."""
    return {
        "status": "ok",
        "database_path": DB_PATH,
        "database_exists": os.path.exists(DB_PATH),
        "dashboard_bundled": dashboard_path is not None,
        "dashboard_url": "http://127.0.0.1:8000/",
    }


# ---------------------------------------------------------------------------
# Direct execution (development)
# ---------------------------------------------------------------------------

DASHBOARD_URL = "http://127.0.0.1:8000"


if __name__ == "__main__":
    import uvicorn

    if getattr(sys, "frozen", False):
        if not os.path.exists(DB_PATH):
            init_netguard_database(DB_PATH)
        print(f"NetGuard API using database: {DB_PATH}")
        print("")
        print("=" * 52)
        print("  NetGuard is running!")
        print(f"  Open your browser to: {DASHBOARD_URL}")
        print("  Tip: use the NetGuard shortcut to open the dashboard.")
        print("=" * 52)
        print("")
        if dashboard_path is None:
            print("ERROR: Dashboard UI was not bundled into this executable.")
        uvicorn.run(app, host="0.0.0.0", port=8000)
    else:
        uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
