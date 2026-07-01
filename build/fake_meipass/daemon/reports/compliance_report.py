#!/usr/bin/env python3
"""
GDPR Article 32 compliance evidence report for NetGuard.

Generates structured HTML and PDF reports demonstrating appropriate
technical measures: asset inventory, active controls, risk assessment,
incident log, and data-handling statement.
"""

from __future__ import annotations

import html
import json
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DAEMON_DIR = PROJECT_ROOT / "daemon"
PRIVACY_POLICY_PATH = DAEMON_DIR / "data" / "privacy_policy.txt"
DEFAULT_FEED_URL = os.environ.get(
    "NETGUARD_THREAT_FEED_URL",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
)
DEFAULT_FEED_NAME = "Steven Black unified hosts blocklist"

RISK_LEVELS = ("Critical", "High", "Medium", "Low", "None")


def _configure_paths() -> None:
    daemon_str = str(DAEMON_DIR)
    if daemon_str not in sys.path:
        sys.path.insert(0, daemon_str)


def _load_install_env() -> None:
    if os.environ.get("NETGUARD_DB_PATH"):
        return
    if sys.platform == "win32":
        program_data = os.environ.get("ProgramData", r"C:\ProgramData")
        env_file = os.path.join(program_data, "NetGuard", "netguard.env")
    else:
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


def _parse_date_param(value: str | None, *, end_of_day: bool = False) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if "T" in text:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    parsed = datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    if end_of_day:
        return parsed.replace(hour=23, minute=59, second=59, microsecond=999999)
    return parsed


def resolve_report_period(
    start_date: str | None = None,
    end_date: str | None = None,
) -> tuple[datetime, datetime]:
    """Default reporting window: last 30 days through now (UTC)."""
    now = datetime.now(timezone.utc)
    end = _parse_date_param(end_date, end_of_day=True) or now
    start = _parse_date_param(start_date) or (end - timedelta(days=30))
    if start > end:
        start, end = end, start
    return start, end


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    return row is not None


def _scalar(conn: sqlite3.Connection, query: str, params: tuple = ()) -> Any:
    try:
        row = conn.execute(query, params).fetchone()
    except sqlite3.OperationalError:
        return None
    return row[0] if row else None


def _rows(conn: sqlite3.Connection, query: str, params: tuple = ()) -> list[dict[str, Any]]:
    try:
        cursor = conn.execute(query, params)
        columns = [description[0] for description in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]
    except sqlite3.OperationalError:
        return []


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_ts(value: str | None) -> str:
    parsed = _parse_timestamp(value)
    if parsed is None:
        return value or "—"
    return parsed.strftime("%Y-%m-%d %H:%M UTC")


def _trust_label(is_trusted: int | None) -> str:
    return "Trusted" if is_trusted else "Untrusted"


def _approval_label(value: str | None) -> str:
    if not value:
        return "approved"
    return value


def _alert_status(alert: dict[str, Any]) -> str:
    if alert.get("is_false_positive"):
        return "false-positive"
    if alert.get("is_acknowledged"):
        return "acknowledged"
    return "open"


def _resolution_time(alert: dict[str, Any]) -> str | None:
    if not alert.get("is_acknowledged"):
        return None
    started = _parse_timestamp(alert.get("timestamp"))
    resolved = _parse_timestamp(alert.get("acknowledged_at"))
    if started is None or resolved is None:
        return None
    delta = resolved - started
    total_minutes = int(delta.total_seconds() // 60)
    if total_minutes < 60:
        return f"{total_minutes} min"
    hours = total_minutes // 60
    minutes = total_minutes % 60
    if hours < 48:
        return f"{hours}h {minutes}m"
    days = hours // 24
    return f"{days}d {hours % 24}h"


def _load_privacy_policy() -> str:
    if PRIVACY_POLICY_PATH.is_file():
        return PRIVACY_POLICY_PATH.read_text(encoding="utf-8").strip()
    return (
        "NetGuard stores device and security data locally. "
        "No cloud transmission unless MSP mode is configured."
    )


def _parse_risk_factors(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return raw
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, list) else []
    except (json.JSONDecodeError, TypeError):
        return []


def _measurement_status(last_activity: str | None, stale_seconds: int) -> str:
    parsed = _parse_timestamp(last_activity)
    if parsed is None:
        return "Deployed (no activity recorded)"
    age = (datetime.now(timezone.utc) - parsed).total_seconds()
    if age <= stale_seconds:
        return "Active"
    return "Deployed (stale — check service)"


def build_compliance_report(
    db_path: str,
    start_date: str | None = None,
    end_date: str | None = None,
) -> dict[str, Any]:
    """Collect all report sections from the NetGuard database."""
    _configure_paths()
    from schema_extensions import apply_schema_extensions

    period_start, period_end = resolve_report_period(start_date, end_date)
    start_iso = period_start.isoformat()
    end_iso = period_end.isoformat()

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    apply_schema_extensions(conn)

    devices = _rows(
        conn,
        """
        SELECT ip_address, mac_address, vendor, device_category, os_guess,
               is_trusted, approval_status, first_seen, last_seen,
               risk_score, risk_level, risk_factors
        FROM devices
        ORDER BY ip_address
        """,
    )

    trusted_count = sum(1 for device in devices if device.get("is_trusted"))
    untrusted_count = len(devices) - trusted_count

    risk_distribution = {level: 0 for level in RISK_LEVELS}
    for device in devices:
        level = device.get("risk_level") or "None"
        if level not in risk_distribution:
            level = "None"
        risk_distribution[level] += 1

    top_risk_devices = sorted(
        devices,
        key=lambda row: (row.get("risk_score") or 0, row.get("ip_address") or ""),
        reverse=True,
    )[:5]
    for device in top_risk_devices:
        device["risk_factors_parsed"] = _parse_risk_factors(device.get("risk_factors"))

    dangerous_ports = _rows(
        conn,
        """
        SELECT device_ip, port, service_name, risk_reason, scanned_at
        FROM open_ports
        WHERE is_dangerous = 1
        ORDER BY device_ip, port
        """,
    )

    threat_domain_count = int(_scalar(conn, "SELECT COUNT(*) FROM threat_intel_domains") or 0)
    threat_last_updated = _scalar(conn, "SELECT MAX(last_seen) FROM threat_intel_domains")

    fingerprinted = sum(1 for device in devices if device.get("os_guess"))
    scored = sum(1 for device in devices if device.get("risk_score") is not None)

    arp_spoof_last = (
        _scalar(conn, "SELECT MAX(last_verified) FROM mac_history")
        if _table_exists(conn, "mac_history")
        else None
    )
    rogue_dhcp_last = (
        _scalar(conn, "SELECT MAX(last_seen) FROM dhcp_servers")
        if _table_exists(conn, "dhcp_servers")
        else None
    )
    dns_last = _scalar(conn, "SELECT MAX(timestamp) FROM dns_queries")
    inbound_last = _scalar(
        conn,
        """
        SELECT MAX(timestamp) FROM alerts
        WHERE alert_type = 'inbound_connection'
        """,
    )

    technical_measures = [
        {
            "name": "ARP Spoof Detection",
            "description": "Detects unexpected MAC address changes that indicate LAN spoofing or MITM activity.",
            "status": _measurement_status(arp_spoof_last, stale_seconds=120),
            "last_activity": arp_spoof_last,
            "article_32": "Confidentiality and integrity of network communications on the LAN.",
        },
        {
            "name": "Rogue DHCP Detection",
            "description": "Identifies unauthorized DHCP servers that could redirect traffic or assign malicious gateways.",
            "status": _measurement_status(rogue_dhcp_last, stale_seconds=7200),
            "last_activity": rogue_dhcp_last,
            "article_32": "Availability and integrity of network configuration.",
        },
        {
            "name": "DNS Threat Intelligence",
            "description": (
                f"Compares observed DNS queries against the {DEFAULT_FEED_NAME} "
                f"({DEFAULT_FEED_URL}). "
                f"{threat_domain_count:,} domains loaded"
                + (f"; last updated {_format_ts(threat_last_updated)}" if threat_last_updated else "")
                + "."
            ),
            "status": "Active" if threat_domain_count > 0 else "Feed not yet loaded",
            "last_activity": threat_last_updated or dns_last,
            "article_32": "Ongoing identification of malicious or unwanted destinations.",
        },
        {
            "name": "Passive OS Fingerprinting",
            "description": "Infers operating system and device category from network behaviour without active scanning.",
            "status": f"Active — {fingerprinted} of {len(devices)} devices fingerprinted",
            "last_activity": _scalar(
                conn, "SELECT MAX(last_fingerprint_at) FROM devices"
            ),
            "article_32": "Asset identification supporting vulnerability and patch management.",
        },
        {
            "name": "Composite Risk Scoring",
            "description": "Aggregates open ports, trust status, alerts, and policy signals into per-device risk scores.",
            "status": f"Active — {scored} of {len(devices)} devices scored",
            "last_activity": _scalar(conn, "SELECT MAX(risk_calculated_at) FROM devices"),
            "article_32": "Risk-based prioritisation of security remediation.",
        },
        {
            "name": "Inbound Connection Guard",
            "description": "Alerts when external hosts attempt inbound TCP connections to monitored LAN devices.",
            "status": _measurement_status(inbound_last, stale_seconds=3600),
            "last_activity": inbound_last,
            "article_32": "Detection of unauthorised access attempts from outside the LAN.",
        },
    ]

    period_alerts = _rows(
        conn,
        """
        SELECT timestamp, severity, alert_type, device_ip, description,
               is_acknowledged, is_false_positive, acknowledged_at
        FROM alerts
        WHERE timestamp >= ? AND timestamp <= ?
        ORDER BY timestamp DESC
        """,
        (start_iso, end_iso),
    )
    for alert in period_alerts:
        alert["status"] = _alert_status(alert)
        alert["resolution_time"] = _resolution_time(alert)

    automated_actions = _rows(
        conn,
        """
        SELECT timestamp, device_ip, playbook_name, action_taken, success, reversible, details
        FROM automated_actions
        WHERE timestamp >= ? AND timestamp <= ?
        ORDER BY timestamp DESC
        """,
        (start_iso, end_iso),
    )

    msp_active = bool(os.environ.get("NETGUARD_MSP_COLLECTOR_URL", "").strip())
    privacy_policy = _load_privacy_policy()

    conn.close()

    return {
        "title": "NetGuard GDPR Article 32 Compliance Evidence Report",
        "subtitle": "Appropriate Technical and Organisational Measures",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "period_start": start_iso,
        "period_end": end_iso,
        "period_label": (
            f"{period_start.strftime('%Y-%m-%d')} to {period_end.strftime('%Y-%m-%d')} (UTC)"
        ),
        "asset_inventory": {
            "total_devices": len(devices),
            "trusted_count": trusted_count,
            "untrusted_count": untrusted_count,
            "devices": devices,
        },
        "technical_measures": technical_measures,
        "risk_assessment": {
            "distribution": risk_distribution,
            "top_risk_devices": top_risk_devices,
            "dangerous_ports": dangerous_ports,
            "dangerous_port_count": len(dangerous_ports),
        },
        "incident_log": {
            "alert_count": len(period_alerts),
            "alerts": period_alerts,
        },
        "automated_actions": {
            "action_count": len(automated_actions),
            "actions": automated_actions,
        },
        "data_handling": {
            "msp_mode_active": msp_active,
            "privacy_policy": privacy_policy,
        },
    }


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else "—"))


def render_compliance_html(report: dict[str, Any]) -> str:
    """Render auditor-friendly HTML report."""
    inventory = report["asset_inventory"]
    risk = report["risk_assessment"]
    incidents = report["incident_log"]
    automated = report.get("automated_actions", {"action_count": 0, "actions": []})
    data_handling = report["data_handling"]

    device_rows = ""
    for device in inventory["devices"]:
        device_rows += (
            "<tr>"
            f"<td>{_esc(device.get('ip_address'))}</td>"
            f"<td>{_esc(device.get('mac_address'))}</td>"
            f"<td>{_esc(device.get('vendor'))}</td>"
            f"<td>{_esc(device.get('device_category'))}</td>"
            f"<td>{_esc(device.get('os_guess'))}</td>"
            f"<td>{_esc(_trust_label(device.get('is_trusted')))}</td>"
            f"<td>{_esc(_approval_label(device.get('approval_status')))}</td>"
            f"<td>{_esc(_format_ts(device.get('first_seen')))}</td>"
            f"<td>{_esc(_format_ts(device.get('last_seen')))}</td>"
            "</tr>"
        )
    if not device_rows:
        device_rows = "<tr><td colspan='9'>No devices recorded</td></tr>"

    measure_rows = ""
    for measure in report["technical_measures"]:
        measure_rows += (
            "<tr>"
            f"<td><strong>{_esc(measure['name'])}</strong><br>"
            f"<span class='muted'>{_esc(measure['description'])}</span></td>"
            f"<td>{_esc(measure['status'])}</td>"
            f"<td>{_esc(_format_ts(measure.get('last_activity')))}</td>"
            f"<td>{_esc(measure['article_32'])}</td>"
            "</tr>"
        )

    risk_dist_items = "".join(
        f"<li><strong>{_esc(level)}</strong>: {count}</li>"
        for level, count in risk["distribution"].items()
    )

    top_risk_blocks = ""
    for device in risk["top_risk_devices"]:
        factors = device.get("risk_factors_parsed") or []
        factor_items = "".join(
            f"<li>{_esc(factor.get('reason', ''))}"
            + (f" (port {factor['port']})" if factor.get("port") else "")
            + "</li>"
            for factor in factors[:8]
        ) or "<li>No detailed factors recorded</li>"
        top_risk_blocks += (
            f"<div class='subcard'><h4>{_esc(device.get('ip_address'))} — "
            f"Risk {_esc(device.get('risk_level'))} (score {device.get('risk_score') or 0})</h4>"
            f"<ul>{factor_items}</ul></div>"
        )
    if not top_risk_blocks:
        top_risk_blocks = "<p class='muted'>No risk scores calculated yet.</p>"

    port_rows = ""
    for port in risk["dangerous_ports"]:
        port_rows += (
            "<tr>"
            f"<td>{_esc(port.get('device_ip'))}</td>"
            f"<td>{_esc(port.get('port'))}</td>"
            f"<td>{_esc(port.get('service_name'))}</td>"
            f"<td>{_esc(port.get('risk_reason'))}</td>"
            f"<td>{_esc(_format_ts(port.get('scanned_at')))}</td>"
            "</tr>"
        )
    if not port_rows:
        port_rows = "<tr><td colspan='5'>No dangerous ports detected</td></tr>"

    alert_rows = ""
    for alert in incidents["alerts"]:
        alert_rows += (
            "<tr>"
            f"<td>{_esc(_format_ts(alert.get('timestamp')))}</td>"
            f"<td>{_esc(alert.get('severity'))}</td>"
            f"<td>{_esc(alert.get('alert_type'))}</td>"
            f"<td>{_esc(alert.get('device_ip'))}</td>"
            f"<td>{_esc(alert.get('status'))}</td>"
            f"<td>{_esc(alert.get('resolution_time') or '—')}</td>"
            f"<td>{_esc(alert.get('description'))}</td>"
            "</tr>"
        )
    if not alert_rows:
        alert_rows = "<tr><td colspan='7'>No alerts in the reporting period</td></tr>"

    action_rows = ""
    for action in automated.get("actions", []):
        action_rows += (
            "<tr>"
            f"<td>{_esc(_format_ts(action.get('timestamp')))}</td>"
            f"<td>{_esc(action.get('device_ip'))}</td>"
            f"<td>{_esc(action.get('playbook_name'))}</td>"
            f"<td>{_esc(action.get('action_taken'))}</td>"
            f"<td>{'Yes' if action.get('success') else 'No'}</td>"
            f"<td>{'Yes' if action.get('reversible') else 'No'}</td>"
            f"<td>{_esc(action.get('details'))}</td>"
            "</tr>"
        )
    if not action_rows:
        action_rows = "<tr><td colspan='7'>No automated playbook actions in the reporting period</td></tr>"

    msp_note = (
        "<p class='warn'><strong>MSP mode is active.</strong> Periodic heartbeat "
        "summaries are sent to the configured MSP collector. See privacy statement below.</p>"
        if data_handling["msp_mode_active"]
        else "<p><strong>MSP mode is not active.</strong> No remote telemetry is sent "
        "from this installation.</p>"
    )

    privacy_html = "<br>".join(_esc(line) for line in data_handling["privacy_policy"].splitlines())

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{_esc(report['title'])}</title>
  <style>
    body {{ font-family: Georgia, "Times New Roman", serif; color: #1e293b; background: #f8fafc; margin: 0; padding: 32px; line-height: 1.5; }}
    .page {{ max-width: 1100px; margin: 0 auto; background: #fff; padding: 40px 48px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
    h1 {{ font-size: 1.75rem; margin: 0 0 8px; color: #0f172a; }}
    h2 {{ font-size: 1.25rem; margin: 32px 0 12px; color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 6px; }}
    h3 {{ font-size: 1.05rem; margin: 20px 0 8px; color: #334155; }}
    h4 {{ margin: 0 0 8px; font-size: 1rem; }}
    .meta {{ color: #64748b; font-size: 0.95rem; margin-bottom: 24px; }}
    .card, .subcard {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 16px; margin: 12px 0; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; margin: 12px 0; }}
    th, td {{ border: 1px solid #e2e8f0; padding: 8px 10px; text-align: left; vertical-align: top; }}
    th {{ background: #f1f5f9; color: #475569; font-weight: 600; }}
    .muted {{ color: #64748b; font-size: 0.85rem; }}
    .warn {{ background: #fffbeb; border: 1px solid #fcd34d; padding: 12px; border-radius: 6px; }}
    ul {{ margin: 8px 0; padding-left: 20px; }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }}
    .stat {{ background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 6px; padding: 12px; }}
    .stat strong {{ display: block; font-size: 1.4rem; color: #1d4ed8; }}
  </style>
</head>
<body>
  <div class="page">
    <h1>{_esc(report['title'])}</h1>
    <p class="meta">{_esc(report['subtitle'])}<br>
    Generated: {_esc(_format_ts(report['generated_at']))}<br>
    Reporting period: {_esc(report['period_label'])}</p>

    <h2>1. Network Asset Inventory</h2>
    <div class="summary-grid">
      <div class="stat"><strong>{inventory['total_devices']}</strong>Total devices</div>
      <div class="stat"><strong>{inventory['trusted_count']}</strong>Trusted</div>
      <div class="stat"><strong>{inventory['untrusted_count']}</strong>Untrusted</div>
    </div>
    <table>
      <thead>
        <tr>
          <th>IP</th><th>MAC</th><th>Vendor</th><th>Category</th><th>OS guess</th>
          <th>Trust</th><th>Approval</th><th>First seen</th><th>Last seen</th>
        </tr>
      </thead>
      <tbody>{device_rows}</tbody>
    </table>

    <h2>2. Technical Security Measures in Place</h2>
    <p>Evidence of technical measures deployed to ensure a level of security appropriate
    to the risk (GDPR Article 32(1)(b)).</p>
    <table>
      <thead>
        <tr><th>Capability</th><th>Status</th><th>Last activity</th><th>Art. 32 relevance</th></tr>
      </thead>
      <tbody>{measure_rows}</tbody>
    </table>

    <h2>3. Risk Assessment Summary</h2>
    <h3>Device risk distribution</h3>
    <ul>{risk_dist_items}</ul>
    <h3>Top 5 highest-risk devices</h3>
    {top_risk_blocks}
    <h3>Open dangerous ports ({risk['dangerous_port_count']} total)</h3>
    <table>
      <thead>
        <tr><th>Device</th><th>Port</th><th>Service</th><th>Risk reason</th><th>Scanned</th></tr>
      </thead>
      <tbody>{port_rows}</tbody>
    </table>

    <h2>4. Incident &amp; Alert Log</h2>
    <p>{incidents['alert_count']} alert(s) in the reporting period — demonstrates ability
    to detect, record, and respond to security events.</p>
    <table>
      <thead>
        <tr>
          <th>Time</th><th>Severity</th><th>Type</th><th>Device</th>
          <th>Status</th><th>Resolution</th><th>Description</th>
        </tr>
      </thead>
      <tbody>{alert_rows}</tbody>
    </table>

    <h2>5. Automated Response Actions</h2>
    <p>{automated.get('action_count', 0)} automated playbook action(s) in the reporting
    period — audit trail for opt-in response playbooks (isolation, threat DNS alerts,
    incident reports).</p>
    <table>
      <thead>
        <tr>
          <th>Time</th><th>Device</th><th>Playbook</th><th>Action</th>
          <th>Success</th><th>Reversible</th><th>Details</th>
        </tr>
      </thead>
      <tbody>{action_rows}</tbody>
    </table>

    <h2>6. Data Handling Statement</h2>
    {msp_note}
    <div class="card">{privacy_html}</div>

    <p class="muted" style="margin-top:32px;">
      This report was generated automatically by NetGuard from locally stored monitoring data.
      It is intended to support GDPR Article 32 compliance evidence and cyber-insurance questionnaires.
    </p>
  </div>
</body>
</html>"""


def _pdf_safe(text: str) -> str:
    return text.encode("latin-1", errors="replace").decode("latin-1")


def render_compliance_pdf(report: dict[str, Any]) -> bytes:
    """Render PDF using fpdf2 (lightweight, pure Python)."""
    from fpdf import FPDF
    from fpdf.enums import XPos, YPos

    class CompliancePDF(FPDF):
        def header(self) -> None:
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(100, 116, 139)
            self.cell(
                0,
                8,
                _pdf_safe("NetGuard GDPR Art. 32 Compliance Report"),
                align="R",
                new_x=XPos.LMARGIN,
                new_y=YPos.NEXT,
            )

        def footer(self) -> None:
            self.set_y(-12)
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(100, 116, 139)
            self.cell(0, 8, _pdf_safe(f"Page {self.page_no()}"), align="C")

        def section_title(self, title: str) -> None:
            self.ln(4)
            self.set_x(self.l_margin)
            self.set_font("Helvetica", "B", 12)
            self.set_text_color(15, 23, 42)
            self.multi_cell(0, 7, _pdf_safe(title))
            self.set_draw_color(226, 232, 240)
            self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
            self.ln(3)

        def body_text(self, text: str) -> None:
            self.set_x(self.l_margin)
            self.set_font("Helvetica", "", 9)
            self.set_text_color(30, 41, 59)
            self.multi_cell(0, 5, _pdf_safe(text))
            self.ln(1)

        def bullet_line(self, text: str, size: int = 8) -> None:
            self.set_x(self.l_margin)
            self.set_font("Helvetica", "", size)
            self.set_text_color(30, 41, 59)
            self.multi_cell(0, 4, _pdf_safe(f"• {text}"))

    pdf = CompliancePDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.add_page()

    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(15, 23, 42)
    pdf.multi_cell(0, 9, _pdf_safe(report["title"]))
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(100, 116, 139)
    pdf.multi_cell(
        0,
        5,
        _pdf_safe(
            f"{report['subtitle']}\n"
            f"Generated: {_format_ts(report['generated_at'])}\n"
            f"Period: {report['period_label']}"
        ),
    )

    inventory = report["asset_inventory"]
    pdf.section_title("1. Network Asset Inventory")
    pdf.body_text(
        f"Total devices: {inventory['total_devices']} | "
        f"Trusted: {inventory['trusted_count']} | "
        f"Untrusted: {inventory['untrusted_count']}"
    )
    for device in inventory["devices"]:
        pdf.bullet_line(
            f"{device.get('ip_address')} | {device.get('mac_address')} | "
            f"{device.get('vendor') or '—'} | {device.get('device_category') or '—'} | "
            f"{device.get('os_guess') or '—'} | {_trust_label(device.get('is_trusted'))} | "
            f"{_approval_label(device.get('approval_status'))} | "
            f"first {_format_ts(device.get('first_seen'))[:16]} | "
            f"last {_format_ts(device.get('last_seen'))[:16]}",
            size=7,
        )
    pdf.ln(2)

    pdf.section_title("2. Technical Security Measures in Place")
    for measure in report["technical_measures"]:
        pdf.bullet_line(f"{measure['name']} — {measure['status']}", size=9)
        pdf.body_text(
            f"{measure['description']}\n"
            f"Art. 32 relevance: {measure['article_32']}\n"
            f"Last activity: {_format_ts(measure.get('last_activity'))}"
        )

    risk = report["risk_assessment"]
    pdf.section_title("3. Risk Assessment Summary")
    dist_text = ", ".join(f"{level}: {count}" for level, count in risk["distribution"].items())
    pdf.body_text(f"Risk distribution — {dist_text}")
    pdf.body_text("Top highest-risk devices:")
    for device in risk["top_risk_devices"]:
        factors = device.get("risk_factors_parsed") or []
        factor_text = "; ".join(
            f"{factor.get('reason', '')}"
            + (f" (port {factor['port']})" if factor.get("port") else "")
            for factor in factors[:5]
        ) or "No factors recorded"
        pdf.bullet_line(
            f"{device.get('ip_address')} — {device.get('risk_level')} "
            f"(score {device.get('risk_score') or 0}): {factor_text}"
        )
    pdf.body_text(f"Dangerous open ports: {risk['dangerous_port_count']} total")
    for port in risk["dangerous_ports"]:
        pdf.bullet_line(
            f"{port.get('device_ip')}:{port.get('port')} "
            f"{port.get('service_name') or '—'} — {(port.get('risk_reason') or '—')[:100]}",
            size=7,
        )
    pdf.ln(2)

    incidents = report["incident_log"]
    pdf.section_title("4. Incident & Alert Log")
    pdf.body_text(f"{incidents['alert_count']} alert(s) in the reporting period.")
    for alert in incidents["alerts"]:
        pdf.bullet_line(
            f"{_format_ts(alert.get('timestamp'))[:16]} | {alert.get('severity')} | "
            f"{alert.get('alert_type')} | {alert.get('device_ip')} | "
            f"{alert.get('status')} | resolution {alert.get('resolution_time') or '—'}",
            size=7,
        )
        pdf.body_text((alert.get("description") or "")[:240])
    pdf.ln(2)

    automated = report.get("automated_actions", {"action_count": 0, "actions": []})
    pdf.section_title("5. Automated Response Actions")
    pdf.body_text(
        f"{automated.get('action_count', 0)} automated playbook action(s) in the reporting period."
    )
    for action in automated.get("actions", []):
        pdf.bullet_line(
            f"{_format_ts(action.get('timestamp'))[:16]} | {action.get('device_ip')} | "
            f"{action.get('playbook_name')} | {action.get('action_taken')} | "
            f"success={'yes' if action.get('success') else 'no'} | "
            f"reversible={'yes' if action.get('reversible') else 'no'}",
            size=7,
        )
        if action.get("details"):
            pdf.body_text(str(action["details"])[:240])
    pdf.ln(2)

    data_handling = report["data_handling"]
    pdf.section_title("6. Data Handling Statement")
    if data_handling["msp_mode_active"]:
        pdf.body_text(
            "MSP mode is ACTIVE. Periodic heartbeat summaries are sent to the "
            "configured MSP collector."
        )
    else:
        pdf.body_text(
            "MSP mode is NOT active. No remote telemetry is sent from this installation."
        )
    for line in data_handling["privacy_policy"].splitlines():
        if line.strip():
            pdf.body_text(line.strip())

    return bytes(pdf.output())


def generate_compliance_report(
    db_path: str,
    start_date: str | None = None,
    end_date: str | None = None,
) -> tuple[dict[str, Any], str, bytes]:
    """Return (report data, HTML string, PDF bytes)."""
    report = build_compliance_report(db_path, start_date, end_date)
    html_content = render_compliance_html(report)
    pdf_bytes = render_compliance_pdf(report)
    return report, html_content, pdf_bytes


if __name__ == "__main__":
    _configure_paths()
    _load_install_env()
    from db_path import resolve_db_path

    db = resolve_db_path(str(PROJECT_ROOT))
    _, html_out, pdf_out = generate_compliance_report(db)
    out_dir = PROJECT_ROOT / "build" / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    html_path = out_dir / f"netguard-compliance-{stamp}.html"
    pdf_path = out_dir / f"netguard-compliance-{stamp}.pdf"
    html_path.write_text(html_out, encoding="utf-8")
    pdf_path.write_bytes(pdf_out)
    print(f"Wrote {html_path}")
    print(f"Wrote {pdf_path}")
