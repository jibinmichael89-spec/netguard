#!/usr/bin/env python3
"""Generate and email the weekly NetGuard security summary report."""

from __future__ import annotations

import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DAEMON_DIR = PROJECT_ROOT / "daemon"


def _configure_paths() -> None:
    daemon_str = str(DAEMON_DIR)
    if daemon_str not in sys.path:
        sys.path.insert(0, daemon_str)
    notify_dir = str(DAEMON_DIR / "notifications")
    if notify_dir not in sys.path:
        sys.path.insert(0, notify_dir)


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


def build_report_summary(db_path: str) -> dict:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    now = datetime.now(timezone.utc)
    week_ago = (now - timedelta(days=7)).isoformat()
    summary = {
        "generated_at": now.isoformat(),
        "online_devices": conn.execute(
            "SELECT COUNT(*) FROM devices WHERE status = 'online'"
        ).fetchone()[0],
        "total_devices": conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
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
        "top_alerts": [
            dict(row)
            for row in conn.execute(
                """
                SELECT severity, alert_type, device_ip, description, timestamp
                FROM alerts
                WHERE timestamp >= ?
                ORDER BY timestamp DESC
                LIMIT 10
                """,
                (week_ago,),
            )
        ],
    }
    conn.close()
    return summary


def render_html_report(summary: dict) -> str:
    alert_rows = ""
    for alert in summary.get("top_alerts", []):
        alert_rows += (
            f"<tr><td>{alert.get('timestamp', '')[:16]}</td>"
            f"<td>{alert.get('severity', '')}</td>"
            f"<td>{alert.get('alert_type', '')}</td>"
            f"<td>{alert.get('device_ip', '')}</td>"
            f"<td>{alert.get('description', '')}</td></tr>"
        )
    if not alert_rows:
        alert_rows = "<tr><td colspan='5'>No alerts in the last 7 days</td></tr>"

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>NetGuard Weekly Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; background: #0f1419; color: #e5e7eb; padding: 24px; }}
    h1 {{ color: #38bdf8; }}
    .card {{ background: #1a2332; border-radius: 8px; padding: 16px; margin: 16px 0; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid #334155; padding: 8px; text-align: left; }}
    th {{ color: #94a3b8; }}
  </style>
</head>
<body>
  <h1>NetGuard Weekly Security Report</h1>
  <p>Generated: {summary['generated_at'][:19]} UTC</p>
  <div class="card">
    <h2>Summary</h2>
    <ul>
      <li>Online devices: <strong>{summary['online_devices']}</strong> / {summary['total_devices']}</li>
      <li>Pending approval: <strong>{summary['pending_approval']}</strong></li>
      <li>Alerts (7 days): <strong>{summary['alerts_last_7_days']}</strong></li>
      <li>Critical risk devices: <strong>{summary['critical_devices']}</strong></li>
      <li>Threat intel domains: <strong>{summary['threat_intel_domains']}</strong></li>
      <li>Policy violations (7 days): <strong>{summary['policy_violations_last_7_days']}</strong></li>
    </ul>
  </div>
  <div class="card">
    <h2>Recent Alerts</h2>
    <table>
      <thead><tr><th>Time</th><th>Severity</th><th>Type</th><th>Device</th><th>Description</th></tr></thead>
      <tbody>{alert_rows}</tbody>
    </table>
  </div>
</body>
</html>"""


def render_text_report(summary: dict) -> str:
    lines = [
        "NetGuard Weekly Security Report",
        f"Generated: {summary['generated_at']}",
        "",
        f"Online devices: {summary['online_devices']} / {summary['total_devices']}",
        f"Pending approval: {summary['pending_approval']}",
        f"Alerts (7 days): {summary['alerts_last_7_days']}",
        f"Critical risk devices: {summary['critical_devices']}",
        f"Threat intel domains: {summary['threat_intel_domains']}",
        f"Policy violations (7 days): {summary['policy_violations_last_7_days']}",
    ]
    return "\n".join(lines)


def send_weekly_report(db_path: str | None = None) -> bool:
    _configure_paths()
    _load_install_env()
    from db_path import resolve_db_path
    from notifier import send_html_email

    db = db_path or resolve_db_path(str(PROJECT_ROOT))
    summary = build_report_summary(db)
    subject = f"NetGuard Weekly Report — {summary['alerts_last_7_days']} alerts"
    return send_html_email(
        subject,
        render_html_report(summary),
        render_text_report(summary),
        db,
    )


if __name__ == "__main__":
    ok = send_weekly_report()
    print("Weekly report sent" if ok else "Weekly report skipped — configure SMTP in Settings")
