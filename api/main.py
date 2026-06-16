"""
NetGuard REST API
FastAPI server that exposes device data and security alerts
stored by the ARP scanner in the shared SQLite database.
"""

import os
import sqlite3
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Path to the shared SQLite database (project root)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.path.join(PROJECT_ROOT, "netguard.db")

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
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600,
)


def get_db_connection() -> sqlite3.Connection:
    """
    Open a read-only connection to the NetGuard SQLite database.

    Raises HTTP 503 if the database file does not exist yet (scanner
    has not run).
    """
    if not os.path.exists(DB_PATH):
        raise HTTPException(
            status_code=503,
            detail="Database not found. Start the ARP scanner first.",
        )
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def rows_to_dicts(rows: list[sqlite3.Row]) -> list[dict]:
    """Convert SQLite Row objects to plain Python dictionaries."""
    return [dict(row) for row in rows]


def categorize_domain(domain: str) -> str:
    """Assign a category label to a domain based on keyword matching."""
    domain_lower = domain.lower()
    for category, keywords in DOMAIN_CATEGORIES.items():
        for keyword in keywords:
            if keyword in domain_lower:
                return category
    return "Other"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/devices")
def list_devices() -> dict:
    """
    Return all devices discovered by the ARP scanner.

    Includes online and offline devices with full metadata.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices ORDER BY ip_address")
    devices = rows_to_dicts(cursor.fetchall())
    conn.close()
    return {"count": len(devices), "devices": devices}


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
        """
        SELECT * FROM devices
        WHERE first_seen >= ?
        ORDER BY first_seen DESC
        """,
        (cutoff,),
    )
    devices = rows_to_dicts(cursor.fetchall())
    conn.close()
    return {
        "window_hours": NEW_DEVICE_WINDOW_HOURS,
        "count": len(devices),
        "devices": devices,
    }


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
        """
        SELECT * FROM devices
        WHERE first_seen >= ?
        ORDER BY first_seen DESC
        """,
        (cutoff,),
    )
    new_devices = rows_to_dicts(cursor.fetchall())

    cursor.execute(
        """
        SELECT * FROM devices
        WHERE status = 'offline'
        ORDER BY last_seen DESC
        """
    )
    offline_devices = rows_to_dicts(cursor.fetchall())

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

@app.get("/")
def root() -> dict:
    """Health check and API overview."""
    return {
        "service": "NetGuard API",
       "endpoints": [
            "GET /devices",
            "GET /devices/new",
            "GET /alerts",
            "GET /dns",
            "GET /dns/suspicious",
            "GET /dns/summary",
            "GET /ports",
            "GET /ports/dangerous",
            "GET /ports/{device_ip}",
        ],
    }


# ---------------------------------------------------------------------------
# Direct execution (development)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
