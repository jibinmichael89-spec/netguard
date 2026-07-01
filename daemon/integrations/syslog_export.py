#!/usr/bin/env python3
"""
Forward NetGuard security alerts to an external syslog server (RFC 5424).

Polls the alerts table every 30 seconds and sends new rows to a configured
UDP or TCP syslog receiver (Wazuh, Elastic, Splunk, rsyslog, etc.).
"""

from __future__ import annotations

import json
import os
import socket
import sqlite3
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

POLL_INTERVAL_SECONDS = 30
SYSLOG_FACILITY = 16  # local0
SYSLOG_ENTERPRISE_ID = 32473
APP_NAME = "NetGuard"

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


def _state_file_path(db_path: str) -> str:
    if sys.platform == "win32":
        program_data = os.environ.get("ProgramData", r"C:\ProgramData")
        return os.path.join(program_data, "NetGuard", "syslog_export.state")
    directory = os.path.dirname(os.path.abspath(db_path)) or str(PROJECT_ROOT)
    return os.path.join(directory, "syslog_export.state")


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


def export_pending_alerts(db_path: str, config: SyslogConfig) -> int:
    """Send unsent alerts; return count forwarded."""
    if not config.is_usable:
        return 0

    state_path = _state_file_path(db_path)
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


def run_loop(db_path: str) -> None:
    print("NetGuard Syslog Export starting...")
    print(f"Database: {db_path}")
    print(f"Poll interval: {POLL_INTERVAL_SECONDS}s")
    print("Press Ctrl+C to stop.\n")

    while True:
        config = load_syslog_config()
        if config.is_usable:
            try:
                count = export_pending_alerts(db_path, config)
                if count:
                    print(
                        f"[{datetime.now(timezone.utc).isoformat()}] "
                        f"Forwarded {count} alert(s) to "
                        f"{config.protocol}://{config.host}:{config.port}"
                    )
            except OSError as exc:
                print(f"[!] Syslog send failed: {exc}")
        else:
            pass  # idle until enabled via Settings or netguard.env

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
        print("\n[*] Syslog export stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
