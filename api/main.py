"""
NetGuard REST API
FastAPI server that exposes device data and security alerts
stored by the ARP scanner in the shared SQLite database.
"""

import json
import os
import socket
import sqlite3
import subprocess
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
from schema_extensions import apply_schema_extensions

_api_module_dir = os.path.dirname(os.path.abspath(__file__))
if _api_module_dir not in sys.path:
    sys.path.insert(0, _api_module_dir)

import features as feature_routes
import msp as msp_routes

DB_PATH = resolve_db_path(PROJECT_ROOT if not getattr(sys, "frozen", False) else None)
PORT_INSTRUCTIONS_PATH = os.path.join(
    BUNDLE_ROOT, "daemon", "data", "port_instructions.json"
)
RISK_RULES_PATH = os.path.join(BUNDLE_ROOT, "daemon", "data", "risk_rules.json")
NVD_REFERENCE_CACHE_PATH = os.path.join(
    BUNDLE_ROOT, "daemon", "data", "nvd_reference_cache.json"
)

_RISK_RULES: dict = {}


def _ensure_stdio_for_frozen() -> None:
    """Give uvicorn writable streams when running as a windowless Windows exe."""
    if not getattr(sys, "frozen", False):
        return
    if sys.stdout is not None and sys.stderr is not None:
        return

    if sys.platform == "win32":
        log_root = os.path.join(os.environ.get("ProgramData", ""), "NetGuard", "logs")
    else:
        log_root = "/var/log/netguard"

    os.makedirs(log_root, exist_ok=True)

    if sys.stdout is None:
        sys.stdout = open(
            os.path.join(log_root, "NetGuard-API.log"),
            "a",
            encoding="utf-8",
            buffering=1,
        )
    if sys.stderr is None:
        sys.stderr = open(
            os.path.join(log_root, "NetGuard-API.err.log"),
            "a",
            encoding="utf-8",
            buffering=1,
        )


_FROZEN_UVICORN_LOG_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "()": "uvicorn.logging.DefaultFormatter",
            "fmt": "%(levelprefix)s %(message)s",
            "use_colors": False,
        },
        "access": {
            "()": "uvicorn.logging.AccessFormatter",
            "fmt": '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s',
            "use_colors": False,
        },
    },
    "handlers": {
        "default": {
            "formatter": "default",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stderr",
        },
        "access": {
            "formatter": "access",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
        },
    },
    "loggers": {
        "uvicorn": {"handlers": ["default"], "level": "INFO", "propagate": False},
        "uvicorn.error": {"level": "INFO"},
        "uvicorn.access": {"handlers": ["access"], "level": "INFO", "propagate": False},
    },
}


_ensure_stdio_for_frozen()

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


def _preload_risk_rules() -> None:
    """Load port risk weights once at startup for open-port API responses."""
    global _RISK_RULES
    if not os.path.exists(RISK_RULES_PATH):
        print(f"[!] Risk rules file not found: {RISK_RULES_PATH}")
        _RISK_RULES = {}
        return
    try:
        with open(RISK_RULES_PATH, encoding="utf-8") as handle:
            _RISK_RULES = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[!] Failed to load risk rules: {exc}")
        _RISK_RULES = {}


@app.on_event("startup")
def _startup() -> None:
    """Load risk rules and register feature routes."""
    _preload_risk_rules()
    feature_routes.configure(DB_PATH, get_db_connection)
    msp_routes.configure(DB_PATH, get_db_connection)
    app.include_router(feature_routes.router)
    app.include_router(msp_routes.router)


def get_risk_rules() -> dict:
    """Return cached risk rules loaded at startup."""
    return _RISK_RULES


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
    _ensure_risk_columns(conn)
    _ensure_inbound_alert_columns(conn)
    apply_schema_extensions(conn)
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


def _ensure_risk_columns(conn: sqlite3.Connection) -> None:
    """Add device risk scoring columns to devices table if missing."""
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(devices)")
    columns = {row[1] for row in cursor.fetchall()}
    changed = False
    risk_columns = {
        "risk_score": "INTEGER",
        "risk_level": "TEXT",
        "risk_factors": "TEXT",
        "risk_calculated_at": "TEXT",
    }
    for column_name, column_type in risk_columns.items():
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


_DNS_DEVICE_FIELDS = (
    "id",
    "mac_address",
    "hostname",
    "vendor",
    "device_tag",
    "device_category",
    "status",
    "is_blocked",
    "risk_level",
)


def _dns_query_row_to_dict(row: sqlite3.Row) -> dict:
    """Map a joined dns_queries + devices row to API shape with nested device."""
    data = dict(row)
    device_id = data.pop("device_id", None)
    device: dict | None = None
    if device_id is not None:
        device = {"id": device_id, "ip_address": data.get("source_ip")}
        for field in _DNS_DEVICE_FIELDS:
            if field == "id":
                continue
            prefixed = f"device_{field}"
            if prefixed in data:
                device[field] = data.pop(prefixed)
        device["known"] = True
    else:
        for field in _DNS_DEVICE_FIELDS:
            data.pop(f"device_{field}", None)

    data["device"] = device
    return data


def _fetch_dns_queries(
    conn: sqlite3.Connection,
    *,
    where_sql: str = "",
    params: tuple = (),
    limit: int | None = 100,
) -> list[dict]:
    """Return DNS queries with optional device details from the devices table."""
    device_select = ", ".join(
        f"d.{field} AS device_{field}" for field in _DNS_DEVICE_FIELDS
    )
    sql = f"""
        SELECT q.*, {device_select}
        FROM dns_queries q
        LEFT JOIN devices d ON d.ip_address = q.source_ip
    """
    if where_sql:
        sql += f" WHERE {where_sql}"
    sql += " ORDER BY q.id DESC"
    if limit is not None:
        sql += f" LIMIT {int(limit)}"
    cursor = conn.cursor()
    cursor.execute(sql, params)
    return [_dns_query_row_to_dict(row) for row in cursor.fetchall()]


def _parse_iso_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _safe_scalar(conn: sqlite3.Connection, query: str) -> str | int | None:
    """Run a query and return the first column of the first row, or None."""
    try:
        row = conn.execute(query).fetchone()
    except sqlite3.OperationalError:
        return None
    if row is None or row[0] is None:
        return None
    return row[0]


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    return row is not None


_DETECTOR_SERVICE_MAP: dict[str, tuple[str, str]] = {
    "arp_scanner": ("netguard-arp-scanner.service", "arp-scanner.exe"),
    "risk_scorer": ("netguard-risk-scorer.service", "risk-scorer.exe"),
    "arp_spoof": ("netguard-arp-spoof.service", "arp-spoof-detector.exe"),
    "dns_monitor": ("netguard-dns-monitor.service", "dns-monitor.exe"),
    "rogue_dhcp": ("netguard-rogue-dhcp.service", "rogue-dhcp-detector.exe"),
    "inbound": (
        "netguard-inbound-detector.service",
        "inbound-connection-detector.exe",
    ),
    "policy_engine": ("netguard-policy-engine.service", "policy-engine.exe"),
}


def _is_detector_service_running(detector_id: str) -> bool | None:
    """Return whether the detector process/service is running, or None if unknown."""
    entry = _DETECTOR_SERVICE_MAP.get(detector_id)
    if entry is None:
        return None

    systemd_unit, win_process = entry
    if sys.platform == "win32":
        try:
            result = subprocess.run(
                ["tasklist", "/FI", f"IMAGENAME eq {win_process}", "/NH"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            return win_process.lower() in result.stdout.lower()
        except (OSError, subprocess.TimeoutExpired):
            return None

    try:
        result = subprocess.run(
            ["systemctl", "is-active", "--quiet", systemd_unit],
            timeout=5,
            check=False,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return None


def _detector_runtime_status(
    last_activity: str | None,
    stale_seconds: int,
    *,
    optional: bool,
    service_running: bool | None,
) -> str:
    """
    Classify a background service using process state and DB activity.

    When the host OS reports service state, stopped services are ``stopped``
    and running services with no recent DB writes are ``idle`` (not an error).
  """
    if service_running is False:
        return "stopped"

    if service_running is True:
        parsed = _parse_iso_timestamp(
            last_activity if isinstance(last_activity, str) else None
        )
        if parsed is None:
            return "idle"
        age_seconds = (datetime.now(timezone.utc) - parsed).total_seconds()
        if age_seconds > stale_seconds:
            return "idle"
        return "active"

    parsed = _parse_iso_timestamp(
        last_activity if isinstance(last_activity, str) else None
    )
    if parsed is None:
        return "standby" if optional else "inactive"

    age_seconds = (datetime.now(timezone.utc) - parsed).total_seconds()
    if age_seconds > stale_seconds:
        return "stale"
    return "active"


def _detector_is_healthy(status: str, service_running: bool | None) -> bool:
    """True when a detector is running and not in a failed/stopped state."""
    if service_running is False or status == "stopped":
        return False
    if status in ("active", "idle"):
        return True
    if service_running is True:
        return True
    return status == "active"


MONITORING_DETECTORS: tuple[dict, ...] = (
    {
        "id": "arp_scanner",
        "name": "Device & Port Scanner",
        "description": "Discovers LAN devices and scans open ports",
        "optional": False,
        "stale_seconds": 90,
    },
    {
        "id": "risk_scorer",
        "name": "Risk Scorer",
        "description": "Calculates composite security risk scores",
        "optional": False,
        "stale_seconds": 660,
    },
    {
        "id": "arp_spoof",
        "name": "ARP Spoof Guard",
        "description": "Watches for unexpected MAC address changes",
        "optional": True,
        "stale_seconds": 45,
    },
    {
        "id": "dns_monitor",
        "name": "DNS Monitor",
        "description": "Captures DNS queries from your network",
        "optional": True,
        "stale_seconds": 600,
    },
    {
        "id": "rogue_dhcp",
        "name": "Rogue DHCP Guard",
        "description": "Detects unauthorized DHCP servers",
        "optional": True,
        "stale_seconds": 3600,
    },
    {
        "id": "inbound",
        "name": "Inbound Connection Guard",
        "description": "Alerts on unexpected incoming connections",
        "optional": True,
        "stale_seconds": 120,
    },
    {
        "id": "policy_engine",
        "name": "Policy Engine",
        "description": "Evaluates security policies against inventory",
        "optional": True,
        "stale_seconds": 660,
    },
)


def _monitoring_last_activity(
    conn: sqlite3.Connection, detector_id: str
) -> str | None:
    """Infer the most recent activity timestamp for a background detector."""
    if detector_id == "arp_scanner":
        device_scan = _safe_scalar(conn, "SELECT MAX(last_seen) FROM devices")
        port_scan = _safe_scalar(conn, "SELECT MAX(scanned_at) FROM open_ports")
        candidates = [
            ts
            for ts in (device_scan, port_scan)
            if isinstance(ts, str) and ts
        ]
        return max(candidates) if candidates else None

    if detector_id == "risk_scorer":
        value = _safe_scalar(conn, "SELECT MAX(risk_calculated_at) FROM devices")
        return value if isinstance(value, str) else None

    if detector_id == "arp_spoof":
        if not _table_exists(conn, "mac_history"):
            return None
        value = _safe_scalar(conn, "SELECT MAX(last_verified) FROM mac_history")
        return value if isinstance(value, str) else None

    if detector_id == "dns_monitor":
        value = _safe_scalar(conn, "SELECT MAX(timestamp) FROM dns_queries")
        return value if isinstance(value, str) else None

    if detector_id == "rogue_dhcp":
        if not _table_exists(conn, "dhcp_servers"):
            return None
        value = _safe_scalar(conn, "SELECT MAX(last_seen) FROM dhcp_servers")
        return value if isinstance(value, str) else None

    if detector_id == "inbound":
        value = _safe_scalar(
            conn,
            """
            SELECT MAX(timestamp) FROM alerts
            WHERE alert_type = 'inbound_connection'
            """,
        )
        return value if isinstance(value, str) else None

    if detector_id == "policy_engine":
        value = _safe_scalar(conn, "SELECT MAX(timestamp) FROM policy_violations")
        return value if isinstance(value, str) else None

    return None


def _build_monitoring_status(conn: sqlite3.Connection) -> dict:
    now = datetime.now(timezone.utc)
    last_device_scan = _safe_scalar(conn, "SELECT MAX(last_seen) FROM devices")
    online_devices = _safe_scalar(
        conn,
        "SELECT COUNT(*) FROM devices WHERE status = 'online'",
    )
    detectors: list[dict] = []

    for spec in MONITORING_DETECTORS:
        last_activity = _monitoring_last_activity(conn, spec["id"])
        service_running = _is_detector_service_running(spec["id"])
        status = _detector_runtime_status(
            last_activity if isinstance(last_activity, str) else None,
            spec["stale_seconds"],
            optional=spec["optional"],
            service_running=service_running,
        )

        parsed = _parse_iso_timestamp(
            last_activity if isinstance(last_activity, str) else None
        )
        age_seconds = (
            int((now - parsed).total_seconds()) if parsed is not None else None
        )

        detectors.append(
            {
                "id": spec["id"],
                "name": spec["name"],
                "description": spec["description"],
                "optional": spec["optional"],
                "status": status,
                "service_running": service_running,
                "last_activity": last_activity,
                "age_seconds": age_seconds,
            }
        )

    core_active = sum(
        1
        for detector in detectors
        if not detector["optional"]
        and _detector_is_healthy(detector["status"], detector["service_running"])
    )
    core_total = sum(1 for detector in detectors if not detector["optional"])

    if core_active == core_total and core_total > 0:
        overall = "watching"
    elif core_active > 0:
        overall = "degraded"
    else:
        overall = "offline"

    return {
        "timestamp": now.isoformat(),
        "overall_status": overall,
        "last_device_scan": last_device_scan,
        "online_device_count": int(online_devices or 0),
        "detectors": detectors,
    }


def _port_risk_weight(port: int, risk_rules: dict | None = None) -> int:
    """Look up per-port risk weight from risk_rules.json port_risk_weights."""
    rules = risk_rules if risk_rules is not None else get_risk_rules()
    entry = rules.get("port_risk_weights", {}).get(str(port))
    if not entry:
        return 0
    return int(entry.get("weight", 0))


def _port_risk_level(weight: int) -> str:
    """Map a single-port weight (0-35) to a port-scoped risk tier."""
    if weight >= 30:
        return "Critical"
    if weight >= 20:
        return "High"
    if weight >= 10:
        return "Medium"
    if weight >= 1:
        return "Low"
    return "Safe"


def rows_to_port_dicts(rows: list[sqlite3.Row]) -> list[dict]:
    """Convert open_ports rows to dicts with port_risk_weight and port_risk_level."""
    risk_rules = get_risk_rules()
    ports: list[dict] = []
    for row in rows:
        port_dict = dict(row)
        weight = _port_risk_weight(int(port_dict["port"]), risk_rules)
        port_dict["port_risk_weight"] = weight
        port_dict["port_risk_level"] = _port_risk_level(weight)
        ports.append(port_dict)
    return ports


DEVICE_FINGERPRINT_FIELDS = (
    "os_guess",
    "os_confidence",
    "device_category",
    "fingerprint_source",
    "last_fingerprint_at",
)

DEVICE_RISK_FIELDS = (
    "risk_score",
    "risk_level",
    "risk_factors",
    "risk_calculated_at",
)

DEVICE_PROFILE_FIELDS = (
    "owner",
    "profile",
    "criticality",
    "is_approved",
    "approval_status",
    "notes",
    "site_id",
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
    *DEVICE_RISK_FIELDS,
    *DEVICE_PROFILE_FIELDS,
)

DEVICE_SELECT_SQL = ", ".join(DEVICE_SELECT_COLUMNS)

RISK_LEVELS = ("Critical", "High", "Medium", "Low", "None")


def _parse_risk_factors(value: str | None) -> list:
    """Parse risk_factors JSON from the database into a list for API responses."""
    if not value or not str(value).strip():
        return []
    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return parsed
    except (json.JSONDecodeError, TypeError):
        pass
    return []


def rows_to_device_dicts(rows: list[sqlite3.Row]) -> list[dict]:
    """
    Convert device rows to JSON-ready dicts with stable fingerprint and risk fields.

    Unfingerprinted devices expose null for os_guess and related fields.
    Unscored devices expose null risk_score/risk_level and an empty risk_factors array.
    """
    devices: list[dict] = []
    for row in rows:
        device = dict(row)
        for field in DEVICE_FINGERPRINT_FIELDS:
            value = device.get(field)
            if field not in device or value == "":
                device[field] = None
        device["risk_factors"] = _parse_risk_factors(device.get("risk_factors"))
        for field in ("risk_score", "risk_level", "risk_calculated_at"):
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
            "GET /devices/{device_ip}/risk",
            "PUT /devices/{device_ip}/tag",
            "PUT /devices/id/{device_id}/trust",
            "PUT /devices/id/{device_id}/block",
            "PUT /devices/{device_ip}/trust",
            "PUT /devices/{device_ip}/block",
            "GET /alerts",
            "GET /alerts/security",
            "GET /alerts/security/critical",
            "GET /monitoring/status",
            "GET /inbound/{device_ip}",
            "GET /dhcp/servers",
            "GET /dns",
            "GET /dns/suspicious",
            "GET /dns/summary",
            "GET /ports",
            "GET /ports/dangerous",
            "GET /ports/{port}/instructions",
            "GET /ports/{device_ip}",
            "GET /risk/summary",
            "GET /reference/cve/{port}",
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


@app.get("/devices/{device_ip}/risk")
def get_device_risk(device_ip: str) -> dict:
    """Return full risk scoring detail for a single device."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT ip_address, risk_score, risk_level, risk_factors, risk_calculated_at
        FROM devices
        WHERE ip_address = ?
        """,
        (device_ip,),
    )
    row = cursor.fetchone()
    conn.close()

    if row is None:
        raise HTTPException(status_code=404, detail="Device not found")

    if row["risk_score"] is None:
        return {
            "device_ip": row["ip_address"],
            "risk_score": None,
            "risk_level": "Not yet assessed",
            "risk_factors": [],
            "risk_calculated_at": None,
        }

    return {
        "device_ip": row["ip_address"],
        "risk_score": row["risk_score"],
        "risk_level": row["risk_level"],
        "risk_factors": _parse_risk_factors(row["risk_factors"]),
        "risk_calculated_at": row["risk_calculated_at"] or None,
    }


@app.get("/risk/summary")
def risk_summary() -> dict:
    """Return aggregate risk statistics across all discovered devices."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) AS total FROM devices")
    total_devices = int(cursor.fetchone()["total"])

    level_counts = {level: 0 for level in RISK_LEVELS}
    cursor.execute(
        """
        SELECT risk_level, COUNT(*) AS count
        FROM devices
        GROUP BY risk_level
        """
    )
    for row in cursor.fetchall():
        level = row["risk_level"]
        if level in level_counts:
            level_counts[level] = int(row["count"])

    cursor.execute(
        """
        SELECT ip_address, hostname, risk_score, risk_level
        FROM devices
        WHERE risk_level NOT IN ('None', 'Low')
          AND risk_level IS NOT NULL
        ORDER BY risk_score DESC
        LIMIT 5
        """
    )
    highest_risk_devices = rows_to_dicts(cursor.fetchall())
    conn.close()

    return {
        "total_devices": total_devices,
        "critical_count": level_counts["Critical"],
        "high_count": level_counts["High"],
        "medium_count": level_counts["Medium"],
        "low_count": level_counts["Low"],
        "none_count": level_counts["None"],
        "highest_risk_devices": highest_risk_devices,
    }


def _load_nvd_reference_cache() -> dict:
    """Load the NVD reference cache file, returning an empty dict if unavailable."""
    if not os.path.exists(NVD_REFERENCE_CACHE_PATH):
        return {}
    try:
        with open(NVD_REFERENCE_CACHE_PATH, encoding="utf-8") as handle:
            cache = json.load(handle)
        return cache if isinstance(cache, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


@app.get("/reference/cve/{port}")
def get_cve_reference(port: int) -> dict:
    """
    Return general historical CVE examples for a port exposure category.

    These are reference illustrations only — not findings on any specific device.
    """
    cache = _load_nvd_reference_cache()
    port_key = f"port_{port}"
    entry = cache.get(port_key)

    if not entry:
        return {"port": port, "examples": [], "no_data": True}

    examples = entry.get("examples") or []
    if not isinstance(examples, list) or not examples:
        return {"port": port, "examples": [], "no_data": True}

    return {"port": port, "examples": examples, "no_data": False}


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
    alerts = feature_routes.filter_visible_alerts(alerts)
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

    Each query includes matched device details (hostname, MAC, vendor) when
    the source IP is known in the devices table.
    """
    conn = get_db_connection()
    queries = _fetch_dns_queries(conn, limit=100)
    conn.close()
    return {"count": len(queries), "queries": queries}


@app.get("/dns/suspicious")
def list_suspicious_dns() -> dict:
    """
    Return all DNS queries flagged as suspicious.

    Includes device details when the source IP matches a known device.
    """
    conn = get_db_connection()
    queries = _fetch_dns_queries(conn, where_sql="q.is_suspicious = 1", limit=None)
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
    rows = rows_to_port_dicts(cursor.fetchall())
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
    rows = rows_to_port_dicts(cursor.fetchall())
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
    rows = rows_to_port_dicts(cursor.fetchall())
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


@app.get("/monitoring/status")
def monitoring_status() -> dict:
    """
    Return health of background scanners and detectors.

    Combines systemd/process state with database activity so optional detectors
    show "running — no events" instead of appearing offline when idle.
    """
    conn = get_db_connection()
    try:
        return _build_monitoring_status(conn)
    finally:
        conn.close()


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
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8000,
            log_config=_FROZEN_UVICORN_LOG_CONFIG,
        )
    else:
        uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
