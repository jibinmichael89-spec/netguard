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


@app.get("/")
def root() -> dict:
    """Health check and API overview."""
    return {
        "service": "NetGuard API",
        "endpoints": [
            "GET /devices",
            "GET /devices/new",
            "GET /alerts",
        ],
    }


# ---------------------------------------------------------------------------
# Direct execution (development)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
