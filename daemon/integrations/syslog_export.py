#!/usr/bin/env python3
"""
Forward NetGuard security alerts to external SIEM targets.

Modes:
  python syslog_export.py          — RFC 5424 syslog export (30s poll)
  python syslog_export.py sentinel — Microsoft Sentinel HTTP API (60s poll)
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

SYSLOG_POLL_INTERVAL_SECONDS = 30
SENTINEL_POLL_INTERVAL_SECONDS = 60
SYSLOG_FACILITY = 16  # local0
SYSLOG_ENTERPRISE_ID = 32473
APP_NAME = "NetGuard"
SENTINEL_API_VERSION = "2016-04-01"
SENTINEL_COMPUTER = "netguard-pi"
SENTINEL_PROCESS_NAME = "NetGuard"
DEFAULT_SENTINEL_LOG_TYPE = "NetGuard"
SENTINEL_BATCH_MAX = 100

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


def _syslog_state_file_path(db_path: str) -> str:
    if sys.platform == "win32":
        program_data = os.environ.get("ProgramData", r"C:\ProgramData")
        return os.path.join(program_data, "NetGuard", "syslog_export.state")
    directory = os.path.dirname(os.path.abspath(db_path)) or str(PROJECT_ROOT)
    return os.path.join(directory, "syslog_export.state")


def sentinel_state_file_path() -> str:
    """Persist Sentinel cursor at /var/lib/netguard/sentinel_state.json on Pi."""
    if sys.platform == "win32":
        program_data = os.environ.get("ProgramData", r"C:\ProgramData")
        return os.path.join(program_data, "NetGuard", "sentinel_state.json")
    db_path = os.environ.get("NETGUARD_DB_PATH", "/var/lib/netguard/netguard.db")
    directory = os.path.dirname(os.path.abspath(db_path)) or "/var/lib/netguard"
    return os.path.join(directory, "sentinel_state.json")


def load_syslog_state(path: str) -> int:
    if not os.path.isfile(path):
        return 0
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        return int(data.get("last_alert_id", 0))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return 0


def save_syslog_state(path: str, last_alert_id: int) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"last_alert_id": last_alert_id}, handle)


def load_sentinel_state(path: str) -> int:
    if not os.path.isfile(path):
        return 0
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        return int(data.get("last_sent_id", 0))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return 0


def save_sentinel_state(path: str, last_sent_id: int) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"last_sent_id": last_sent_id}, handle)


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


def _normalize_timestamp(value: str | None) -> str:
    if not value:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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


class SentinelExporter:
    """Microsoft Sentinel / Log Analytics Data Collector API client."""

    def __init__(self) -> None:
        from netguard_env import load_and_apply_env_file

        load_and_apply_env_file()
        self.workspace_id = os.environ.get("NETGUARD_SENTINEL_WORKSPACE_ID", "").strip()
        self.primary_key = os.environ.get("NETGUARD_SENTINEL_PRIMARY_KEY", "").strip()
        self.log_type = (
            os.environ.get("NETGUARD_SENTINEL_LOG_TYPE", DEFAULT_SENTINEL_LOG_TYPE).strip()
            or DEFAULT_SENTINEL_LOG_TYPE
        )
        self._host_hostname = socket.gethostname()

    @property
    def is_configured(self) -> bool:
        from netguard_env import env_bool

        enabled_val = os.environ.get("NETGUARD_SENTINEL_ENABLED")
        if enabled_val is not None and not env_bool(enabled_val):
            return False
        return bool(self.workspace_id and self.primary_key)

    @property
    def endpoint(self) -> str:
        return (
            f"https://{self.workspace_id}.ods.opinsights.azure.com"
            f"/api/logs?api-version={SENTINEL_API_VERSION}"
        )

    def _map_alert(self, alert: dict) -> dict[str, str]:
        hostname = str(alert.get("hostname") or self._host_hostname)
        return {
            "DeviceIP_s": str(alert.get("device_ip") or ""),
            "Severity_s": str(alert.get("severity") or ""),
            "AlertType_s": str(alert.get("alert_type") or ""),
            "Message": str(alert.get("description") or ""),
            "TimeGenerated": _normalize_timestamp(alert.get("timestamp")),
            "Hostname_s": hostname,
            "Computer": SENTINEL_COMPUTER,
            "ProcessName_s": SENTINEL_PROCESS_NAME,
        }

    def _build_authorization(self, content_length: int, date_header: str) -> str:
        string_to_hash = (
            f"POST\n{content_length}\napplication/json\nx-ms-date:{date_header}\n/api/logs"
        )
        decoded_key = base64.b64decode(self.primary_key)
        encoded_signature = base64.b64encode(
            hmac.new(
                decoded_key,
                string_to_hash.encode("utf-8"),
                hashlib.sha256,
            ).digest()
        ).decode("ascii")
        return f"SharedKey {self.workspace_id}:{encoded_signature}"

    def _post_records(self, records: list[dict[str, str]]) -> int:
        """POST a JSON array of records. Returns HTTP status or 0 on failure."""
        body = json.dumps(records, separators=(",", ":")).encode("utf-8")
        date_header = formatdate(timeval=None, localtime=False, usegmt=True)
        authorization = self._build_authorization(len(body), date_header)

        request = urllib.request.Request(
            self.endpoint,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Log-Type": self.log_type,
                "x-ms-date": date_header,
                "Authorization": authorization,
            },
        )

        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return int(response.status)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            print(
                f"[!] Sentinel HTTP {exc.code}: {detail}",
                flush=True,
            )
            return int(exc.code)
        except urllib.error.URLError as exc:
            print(f"[!] Sentinel HTTP failed: {exc.reason}", flush=True)
            return 0
        except OSError as exc:
            print(f"[!] Sentinel HTTP failed: {exc}", flush=True)
            return 0

    def send_alert(self, alert_dict: dict) -> bool:
        """Send a single alert record to Sentinel."""
        if not self.is_configured:
            return False
        status = self._post_records([self._map_alert(alert_dict)])
        return status == 200

    def send_batch(self, alerts_list: list[dict]) -> int:
        """
        Send multiple alerts in batched API calls (max 100 per request).

        Returns the number of alerts successfully accepted (HTTP 200).
        Stops at the first failed batch so unsent alerts can be retried.
        """
        if not self.is_configured or not alerts_list:
            return 0

        sent = 0
        for offset in range(0, len(alerts_list), SENTINEL_BATCH_MAX):
            chunk = alerts_list[offset : offset + SENTINEL_BATCH_MAX]
            records = [self._map_alert(alert) for alert in chunk]
            status = self._post_records(records)
            if status != 200:
                break
            sent += len(chunk)
        return sent


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

    state_path = _syslog_state_file_path(db_path)
    last_id = load_syslog_state(state_path)
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
            save_syslog_state(state_path, last_id)
    finally:
        sender.close()
    return sent


def export_pending_alerts_sentinel(db_path: str, exporter: SentinelExporter) -> int:
    """Send unsent alerts to Sentinel via batched HTTP; return count forwarded."""
    if not exporter.is_configured:
        return 0

    state_path = sentinel_state_file_path()
    last_id = load_sentinel_state(state_path)
    alerts = fetch_new_alerts(db_path, last_id)
    if not alerts:
        return 0

    sent = exporter.send_batch(alerts)
    if sent > 0:
        save_sentinel_state(state_path, int(alerts[sent - 1]["id"]))
    return sent


def export_pending_alerts(db_path: str, config: SyslogConfig) -> int:
    """Backward-compatible alias for syslog-only export."""
    return export_pending_alerts_syslog(db_path, config)


def run_syslog_loop(db_path: str) -> None:
    print("NetGuard Syslog Export starting...")
    print(f"Database: {db_path}")
    print(f"Poll interval: {SYSLOG_POLL_INTERVAL_SECONDS}s")
    print("Press Ctrl+C to stop.\n")

    while True:
        from netguard_env import load_and_apply_env_file

        load_and_apply_env_file()
        syslog_config = load_syslog_config()

        if syslog_config.is_usable:
            try:
                count = export_pending_alerts_syslog(db_path, syslog_config)
                if count:
                    print(
                        f"[{datetime.now(timezone.utc).isoformat()}] "
                        f"Forwarded {count} alert(s) via syslog to "
                        f"{syslog_config.protocol}://{syslog_config.host}:{syslog_config.port}"
                    )
            except OSError as exc:
                print(f"[!] Syslog send failed: {exc}")

        time.sleep(SYSLOG_POLL_INTERVAL_SECONDS)


def run_sentinel_loop(db_path: str) -> None:
    print("NetGuard Sentinel Export starting...")
    print(f"Database: {db_path}")
    print(f"State file: {sentinel_state_file_path()}")
    print(f"Poll interval: {SENTINEL_POLL_INTERVAL_SECONDS}s")
    print("Press Ctrl+C to stop.\n")

    while True:
        exporter = SentinelExporter()
        if exporter.is_configured:
            try:
                count = export_pending_alerts_sentinel(db_path, exporter)
                if count:
                    print(
                        f"[SENTINEL] Sent {count} alerts to Microsoft Sentinel (HTTP 200)",
                        flush=True,
                    )
            except OSError as exc:
                print(f"[!] Sentinel export failed: {exc}", flush=True)

        time.sleep(SENTINEL_POLL_INTERVAL_SECONDS)


def run_loop(db_path: str) -> None:
    """Backward-compatible alias for syslog loop."""
    run_syslog_loop(db_path)


def main() -> None:
    from db_path import resolve_db_path

    db_path = resolve_db_path(str(PROJECT_ROOT))
    if not os.path.exists(db_path):
        print(f"[!] Database not found: {db_path}")
        sys.exit(1)

    sentinel_mode = len(sys.argv) > 1 and sys.argv[1].strip().lower() == "sentinel"

    try:
        if sentinel_mode:
            run_sentinel_loop(db_path)
        else:
            run_syslog_loop(db_path)
    except KeyboardInterrupt:
        label = "Sentinel" if sentinel_mode else "Syslog"
        print(f"\n[*] {label} export stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
