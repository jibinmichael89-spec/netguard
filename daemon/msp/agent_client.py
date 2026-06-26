#!/usr/bin/env python3
"""
MSP agent heartbeat stub — registers this site with a central collector.

Set NETGUARD_MSP_COLLECTOR_URL and NETGUARD_SITE_TOKEN to enable.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import urllib.request
from datetime import datetime, timezone

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DAEMON_DIR = os.path.join(PROJECT_ROOT, "daemon")

if DAEMON_DIR not in sys.path:
    sys.path.insert(0, DAEMON_DIR)

from db_path import resolve_db_path


def send_heartbeat(db_path: str | None = None) -> bool:
    collector = os.environ.get("NETGUARD_MSP_COLLECTOR_URL", "").strip()
    token = os.environ.get("NETGUARD_SITE_TOKEN", "").strip()
    if not collector or not token:
        return False

    db = db_path or resolve_db_path(PROJECT_ROOT)
    conn = sqlite3.connect(db)
    online = conn.execute(
        "SELECT COUNT(*) FROM devices WHERE status = 'online'"
    ).fetchone()[0]
    alerts = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE timestamp > datetime('now', '-24 hours')"
    ).fetchone()[0]
    conn.close()

    payload = {
        "site_id": os.environ.get("NETGUARD_SITE_ID", "default"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "online_devices": online,
        "alerts_24h": alerts,
        "agent_version": "1.2.0",
    }
    request = urllib.request.Request(
        collector.rstrip("/") + "/api/v1/heartbeat",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return response.status == 200


if __name__ == "__main__":
    ok = send_heartbeat()
    print("Heartbeat sent" if ok else "Heartbeat skipped or failed")
