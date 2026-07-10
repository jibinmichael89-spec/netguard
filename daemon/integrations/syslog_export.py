#!/usr/bin/env python3
"""
Forward NetGuard security alerts to external SIEM targets.

Supports:
- RFC 5424 syslog (UDP/TCP) via rsyslog, Splunk, Elastic, Wazuh, etc.
- Microsoft Sentinel / Log Analytics via the Data Collector HTTP API

Polls the alerts table every 30 seconds and forwards new rows to every
configured destination. Syslog and Sentinel can run simultaneously.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import socket
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import formatdate
from pathlib import Path

POLL_INTERVAL_SECONDS = 30
SYSLOG_FACILITY = 16  # local0
SYSLOG_ENTERPRISE_ID = 32473
APP_NAME = "NetGuard"
SENTINEL_API_VERSION = "2016-04-01"
SENTINEL_COMPUTER = "netguard-pi"
DEFAULT_SENTINEL_LOG_TYPE = "NetGuard"

PROJECT_ROOT = Path(__file__).resolve().parents[2]

if getattr(sys, "frozen", False):
    _daemon_dir = Path(sys._MEIPASS) / "daemon"
else:
    _daemon_dir = PROJECT_ROOT / "daemon"

if _daemon_dir.is_dir() and str(_daemon_dir) not in sys.path:
    sys.path.insert(0, str(_daemon_dir))


@dataclass
class SyslogConfig:
    enabled: bool
    host: str
    port: int
    protocol: str

    @property
    def is_usable(self) -> bool:
        return self.enabled and bool(self.host.strip()) and self.port > 0


@dataclass
class SentinelConfig:
    workspace_id: str
    primary_key: str
    log_type: str

    @property
    def is_usable(self) -> bool:
        return bool(self.workspace_id.strip() and self.primary_key.strip())

    @property
    def endpoint(self) -> str:
        return (
            f"https://{self.workspace_id.strip()}.ods.opinsights.azure.com"
            f"/api/logs?api-version={SENTINEL_API_VERSION}"
        )


def _state_file_path(db_path: str, channel: str) -> str:
    filename = f"{channel}_export.state"
    if sys.platform == "win32":
        program_data = os.environ.get("ProgramData", r"C:\ProgramData")
        return os.path.join(program_data, "NetGuard", filename)
    directory = os.path.dirname(os.path.abspath(db_path)) or str(PROJECT_ROOT)
    return os.path.join(directory, filename)


def load_state(path: str) -> int:
    if not os.path.isfile(path):
        return 0
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        return int(data.get("last_alert_id", 0))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return 0


def save_state(path: str, last_alert_id: int) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"last_alert_id": last_alert_id}, handle)


def load_syslog_config() -> SyslogConfig:
    from netguard_env import env_bool, load_and_apply_env_file

    load_and_apply_env_file()
    protocol = os.environ.get("NETGUARD_SYSLOG_PROTOCOL", "udp").strip().lower()
    if protocol not in {"udp", "tcp"}:
        protocol = "udp"
    try:
        port = int(os.environ.get("NETGUARD_SYSLOG_PORT", "514"))
    except ValueError:
        port = 514
    return SyslogConfig(
        enabled=env_bool(os.environ.get("NETGUARD_SYSLOG_ENABLED")),
        host=os.environ.get("NETGUARD_SYSLOG_HOST", "").strip(),
        port=port,
        protocol=protocol,
    )


def load_sentinel_config() -> SentinelConfig:
    from netguard_env import load_and_apply_env_file

    load_and_apply_env_file()
    log_type = os.environ.get("NETGUARD_SENTINEL_LOG_TYPE", DEFAULT_SENTINEL_LOG_TYPE).strip()
    return SentinelConfig(
        workspace_id=os.environ.get("NETGUARD_SENTINEL_WORKSPACE_ID", "").strip(),
        primary_key=os.environ.get("NETGUARD_SENTINEL_PRIMARY_KEY", "").strip(),
        log_type=log_type or DEFAULT_SENTINEL_LOG_TYPE,
    )


def severity_to_syslog_level(severity: str | None) -> int:
    normalized = (severity or "").strip().upper()
    if normalized == "CRITICAL":
        return 2
    if normalized == "HIGH":
        return 3
    if normalized == "MEDIUM":
        return 4
    if normalized == "LOW":
        return 6
    return 6


def _sd_escape(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("]", "\\]")
    )


def _normalize_timestamp(value: str | None) -> str:
    if not value:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def alert_to_sentinel_record(alert: dict) -> dict[str, str]:
    """Map a NetGuard alert row to Sentinel custom log fields."""
    return {
        "AlertType": str(alert.get("alert_type") or ""),
        "Severity": str(alert.get("severity") or ""),
        "DeviceIP": str(alert.get("device_ip") or ""),
        "Description": str(alert.get("description") or ""),
        "TimeGenerated": _normalize_timestamp(alert.get("timestamp")),
        "Computer": SENTINEL_COMPUTER,
    }


def build_sentinel_authorization(
    workspace_id: str,
    primary_key: str,
    content_length: int,
    date_header: str,
) -> str:
    """Build SharedKey authorization header for Log Analytics Data Collector API."""
    string_to_hash = (
        f"POST\n{content_length}\napplication/json\nx-ms-date:{date_header}\n/api/logs"
    )
    decoded_key = base64.b64decode(primary_key)
    encoded_signature = base64.b64encode(
        hmac.new(
            decoded_key,
            string_to_hash.encode("utf-8"),
            hashlib.sha256,
        ).digest()
    ).decode("ascii")
    return f"SharedKey {workspace_id}:{encoded_signature}"


def send_to_sentinel_http(alert_data: dict, config: SentinelConfig | None = None) -> bool:
    """
    POST one alert to Microsoft Sentinel via the Log Analytics Data Collector API.

    Returns True on HTTP 200, False on configuration or transport errors.
    """
    if config is None:
        config = load_sentinel_config()
    if not config.is_usable:
        return False

    body = json.dumps([alert_to_sentinel_record(alert_data)], separators=(",", ":")).encode(
        "utf-8"
    )
    date_header = formatdate(timeval=None, localtime=False, usegmt=True)
    authorization = build_sentinel_authorization(
        config.workspace_id,
        config.primary_key,
        len(body),
        date_header,
    )

    request = urllib.request.Request(
        config.endpoint,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Log-Type": config.log_type,
            "x-ms-date": date_header,
            "Authorization": authorization,
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status == 200
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        print(
            f"[!] Sentinel HTTP {exc.code} for alert id={alert_data.get('id')}: {detail}",
            flush=True,
        )
        return False
    except urllib.error.URLError as exc:
        print(
            f"[!] Sentinel HTTP failed for alert id={alert_data.get('id')}: {exc.reason}",
            flush=True,
        )
        return False
    except OSError as exc:
        print(
            f"[!] Sentinel HTTP failed for alert id={alert_data.get('id')}: {exc}",
            flush=True,
        )
        return False


def format_rfc5424_message(alert: dict, hostname: str, pid: int) -> str:
    """Build an RFC 5424 syslog line for one alert row."""
    severity = alert.get("severity")
    level = severity_to_syslog_level(severity)
    priority = SYSLOG_FACILITY * 8 + level

    timestamp_raw = alert.get("timestamp") or datetime.now(timezone.utc).isoformat()
    parsed = datetime.fromisoformat(timestamp_raw.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    timestamp = parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    alert_type = str(alert.get("alert_type") or "alert")
    device_ip = str(alert.get("device_ip") or "")
    description = str(alert.get("description") or "")
    message = description or f"NetGuard {alert_type} on {device_ip or 'unknown'}"

    structured = (
        f"[netguard@{SYSLOG_ENTERPRISE_ID} "
        f'device_ip="{_sd_escape(device_ip)}" '
        f'severity="{_sd_escape(str(severity or ""))}" '
        f'description="{_sd_escape(description)}"]'
    )

    return (
        f"<{priority}>1 {timestamp} {hostname} {APP_NAME} {pid} {alert_type} "
        f"{structured} {message}"
    )


def fetch_new_alerts(db_path: str, after_id: int) -> list[dict]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT id, timestamp, severity, alert_type, device_ip, description
        FROM alerts
        WHERE id > ?
        ORDER BY id ASC
        """,
        (after_id,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


class SyslogSender:
    """UDP or TCP syslog transport with TCP reconnect."""

    def __init__(self, config: SyslogConfig) -> None:
        self.config = config
        self._tcp_socket: socket.socket | None = None

    def close(self) -> None:
        if self._tcp_socket is not None:
            try:
                self._tcp_socket.close()
            except OSError:
                pass
            self._tcp_socket = None

    def _ensure_tcp(self) -> socket.socket:
        if self._tcp_socket is not None:
            return self._tcp_socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((self.config.host, self.config.port))
        self._tcp_socket = sock
        return sock

    def send(self, payload: str) -> None:
        data = (payload + "\n").encode("utf-8")
        if self.config.protocol == "tcp":
            try:
                sock = self._ensure_tcp()
                sock.sendall(data)
            except OSError:
                self.close()
                sock = self._ensure_tcp()
                sock.sendall(data)
            return

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)
            sock.sendto(data, (self.config.host, self.config.port))


def export_pending_alerts_syslog(db_path: str, config: SyslogConfig) -> int:
    """Send unsent alerts via syslog; return count forwarded."""
    if not config.is_usable:
        return 0

    state_path = _state_file_path(db_path, "syslog")
    last_id = load_state(state_path)
    alerts = fetch_new_alerts(db_path, last_id)
    if not alerts:
        return 0

    hostname = socket.gethostname()
    pid = os.getpid()
    sender = SyslogSender(config)
    sent = 0
    try:
        for alert in alerts:
            message = format_rfc5424_message(alert, hostname, pid)
            sender.send(message)
            last_id = int(alert["id"])
            sent += 1
        if sent:
            save_state(state_path, last_id)
    finally:
        sender.close()
    return sent


def export_pending_alerts_sentinel(db_path: str, config: SentinelConfig) -> int:
    """Send unsent alerts to Microsoft Sentinel; return count forwarded."""
    if not config.is_usable:
        return 0

    state_path = _state_file_path(db_path, "sentinel")
    last_id = load_state(state_path)
    alerts = fetch_new_alerts(db_path, last_id)
    if not alerts:
        return 0

    sent = 0
    highest_id = last_id
    for alert in alerts:
        if send_to_sentinel_http(alert, config):
            sent += 1
            highest_id = int(alert["id"])
        else:
            # Stop at first failure so unsent alerts are retried next cycle.
            break

    if sent:
        save_state(state_path, highest_id)
    return sent


def export_pending_alerts(db_path: str, config: SyslogConfig) -> int:
    """Backward-compatible alias for syslog-only export."""
    return export_pending_alerts_syslog(db_path, config)


def run_loop(db_path: str) -> None:
    print("NetGuard SIEM Export starting...")
    print(f"Database: {db_path}")
    print(f"Poll interval: {POLL_INTERVAL_SECONDS}s")
    print("Transports: syslog (RFC 5424), Microsoft Sentinel (HTTPS)")
    print("Press Ctrl+C to stop.\n")

    while True:
        from netguard_env import load_and_apply_env_file

        load_and_apply_env_file()
        syslog_config = load_syslog_config()
        sentinel_config = load_sentinel_config()

        if not syslog_config.is_usable and not sentinel_config.is_usable:
            time.sleep(POLL_INTERVAL_SECONDS)
            continue

        now = datetime.now(timezone.utc).isoformat()

        if syslog_config.is_usable:
            try:
                count = export_pending_alerts_syslog(db_path, syslog_config)
                if count:
                    print(
                        f"[{now}] Forwarded {count} alert(s) via syslog to "
                        f"{syslog_config.protocol}://{syslog_config.host}:{syslog_config.port}"
                    )
            except OSError as exc:
                print(f"[!] Syslog send failed: {exc}")

        if sentinel_config.is_usable:
            try:
                count = export_pending_alerts_sentinel(db_path, sentinel_config)
                if count:
                    print(
                        f"[{now}] Forwarded {count} alert(s) to Microsoft Sentinel "
                        f"(workspace {sentinel_config.workspace_id}, "
                        f"log type {sentinel_config.log_type})"
                    )
            except OSError as exc:
                print(f"[!] Sentinel export failed: {exc}")

        time.sleep(POLL_INTERVAL_SECONDS)


def main() -> None:
    from db_path import resolve_db_path

    db_path = resolve_db_path(str(PROJECT_ROOT))
    if not os.path.exists(db_path):
        print(f"[!] Database not found: {db_path}")
        sys.exit(1)
    try:
        run_loop(db_path)
    except KeyboardInterrupt:
        print("\n[*] SIEM export stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
