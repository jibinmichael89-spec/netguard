#!/usr/bin/env python3
"""Notification delivery for NetGuard alerts (Telegram + SMTP email)."""

from __future__ import annotations

import os
import smtplib
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage
from typing import Any

# DB key(s) -> environment variable fallback (database values take priority).
_CONFIG_ENV_MAP: dict[str, tuple[str, ...]] = {
    "telegram_bot_token": ("NETGUARD_TELEGRAM_BOT_TOKEN",),
    "telegram_chat_id": ("NETGUARD_TELEGRAM_CHAT_ID",),
    "telegram_enabled": ("NETGUARD_TELEGRAM_ENABLED",),
    "smtp_host": ("NETGUARD_SMTP_HOST",),
    "smtp_port": ("NETGUARD_SMTP_PORT",),
    "smtp_user": ("NETGUARD_SMTP_USER",),
    "smtp_password": ("NETGUARD_SMTP_PASSWORD",),
    "smtp_from": ("NETGUARD_SMTP_FROM",),
    "alert_email_to": ("NETGUARD_ALERT_EMAIL_TO", "NETGUARD_SMTP_TO"),
    "email_enabled": ("NETGUARD_EMAIL_ENABLED", "NETGUARD_ALERT_EMAIL_ENABLED"),
}

# Alternate DB column names used by older configs or the Settings UI.
_DB_KEY_ALIASES: dict[str, tuple[str, ...]] = {
    "alert_email_to": ("alert_email_to", "smtp_to"),
}


def _parse_bool(value: str | bool | None, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def _read_db_config(db_path: str | None) -> dict[str, str]:
    if not db_path:
        return {}
    try:
        conn = sqlite3.connect(db_path)
        rows = conn.execute("SELECT key, value FROM notification_config").fetchall()
        conn.close()
        return {
            str(row[0]): str(row[1])
            for row in rows
            if row[0] is not None and row[1] is not None
        }
    except sqlite3.Error:
        return {}


def _merged_string(
    db_config: dict[str, str],
    logical_key: str,
) -> str | None:
    for db_key in _DB_KEY_ALIASES.get(logical_key, (logical_key,)):
        raw = db_config.get(db_key)
        if raw is not None:
            stripped = str(raw).strip()
            if stripped:
                return stripped

    for env_key in _CONFIG_ENV_MAP.get(logical_key, ()):
        raw = os.environ.get(env_key)
        if raw is not None:
            stripped = str(raw).strip()
            if stripped:
                return stripped
    return None


def load_notification_config(db_path: str | None = None) -> dict[str, Any]:
    """
    Load notification settings from notification_config (priority) with env fallbacks.

    Reloaded on every call so Settings UI changes apply without restarting services.
    """
    db_config = _read_db_config(db_path)

    telegram_token = _merged_string(db_config, "telegram_bot_token")
    telegram_chat_id = _merged_string(db_config, "telegram_chat_id")
    smtp_host = _merged_string(db_config, "smtp_host")
    smtp_port_raw = _merged_string(db_config, "smtp_port")
    smtp_user = _merged_string(db_config, "smtp_user")
    smtp_password = _merged_string(db_config, "smtp_password")
    smtp_from = _merged_string(db_config, "smtp_from")
    alert_email_to = _merged_string(db_config, "alert_email_to")

    try:
        smtp_port = int(smtp_port_raw or "587")
    except ValueError:
        smtp_port = 587

    telegram_enabled_raw = _merged_string(db_config, "telegram_enabled")
    if telegram_enabled_raw is not None:
        telegram_enabled = _parse_bool(telegram_enabled_raw)
    else:
        telegram_enabled = bool(telegram_token and telegram_chat_id)

    email_enabled_raw = _merged_string(db_config, "email_enabled")
    if email_enabled_raw is not None:
        email_enabled = _parse_bool(email_enabled_raw)
    else:
        email_enabled = bool(smtp_host and alert_email_to)

    return {
        "telegram_bot_token": telegram_token,
        "telegram_chat_id": telegram_chat_id,
        "telegram_enabled": telegram_enabled,
        "smtp_host": smtp_host,
        "smtp_port": smtp_port,
        "smtp_user": smtp_user,
        "smtp_password": smtp_password,
        "smtp_from": smtp_from,
        "alert_email_to": alert_email_to,
        "email_enabled": email_enabled,
    }


def send_telegram(message: str, db_path: str | None = None) -> bool:
    config = load_notification_config(db_path)
    if not config["telegram_enabled"]:
        return False

    token = config["telegram_bot_token"]
    chat_id = config["telegram_chat_id"]
    if not token or not chat_id:
        return False

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = urllib.parse.urlencode(
        {"chat_id": chat_id, "text": message[:4000]}
    ).encode("utf-8")
    request = urllib.request.Request(url, data=data, method="POST")
    with urllib.request.urlopen(request, timeout=15) as response:
        return response.status == 200


def _send_smtp_message(msg: EmailMessage, config: dict[str, Any]) -> bool:
    host = config["smtp_host"]
    recipient = config["alert_email_to"]
    if not host or not recipient:
        return False

    port = int(config["smtp_port"] or 587)
    user = config["smtp_user"]
    password = config["smtp_password"]

    with smtplib.SMTP(host, port, timeout=20) as smtp:
        if user and password:
            smtp.starttls()
            smtp.login(user, password)
        smtp.send_message(msg)
    return True


def send_email(subject: str, body: str, db_path: str | None = None) -> bool:
    config = load_notification_config(db_path)
    if not config["email_enabled"]:
        return False

    sender = config["smtp_from"] or config["smtp_user"]
    recipient = config["alert_email_to"]
    if not config["smtp_host"] or not recipient:
        return False

    msg = EmailMessage()
    msg["Subject"] = subject[:200]
    msg["From"] = sender or "netguard@localhost"
    msg["To"] = recipient
    msg.set_content(body)
    return _send_smtp_message(msg, config)


def send_html_email(
    subject: str,
    html_body: str,
    text_body: str,
    db_path: str | None = None,
) -> bool:
    config = load_notification_config(db_path)
    if not config["email_enabled"]:
        return False

    sender = config["smtp_from"] or config["smtp_user"]
    recipient = config["alert_email_to"]
    if not config["smtp_host"] or not recipient:
        return False

    msg = EmailMessage()
    msg["Subject"] = subject[:200]
    msg["From"] = sender or "netguard@localhost"
    msg["To"] = recipient
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")
    return _send_smtp_message(msg, config)


def notify_alert(
    severity: str,
    alert_type: str,
    device_ip: str,
    description: str,
    db_path: str | None = None,
) -> None:
    """Send alert notifications when configured. Failures are silent."""
    config = load_notification_config(db_path)
    message = (
        f"NetGuard {severity} alert\n"
        f"Type: {alert_type}\n"
        f"Device: {device_ip}\n"
        f"{description}"
    )
    if config["telegram_enabled"]:
        try:
            send_telegram(message, db_path)
        except OSError:
            pass
    if config["email_enabled"]:
        try:
            send_email(f"NetGuard {severity}: {alert_type}", message, db_path)
        except OSError:
            pass


def notify_playbook(
    playbook_name: str,
    device_ip: str,
    body: str,
    db_path: str | None = None,
) -> None:
    """Send playbook notifications unconditionally (bypasses severity thresholds)."""
    config = load_notification_config(db_path)
    message = (
        f"NetGuard automated playbook: {playbook_name}\n"
        f"Device: {device_ip}\n\n"
        f"{body}"
    )
    if config["telegram_enabled"]:
        try:
            send_telegram(message, db_path)
        except OSError:
            pass
    if config["email_enabled"]:
        try:
            send_email(f"NetGuard Playbook: {playbook_name}", message, db_path)
        except OSError:
            pass


def send_incident_report_email(
    subject: str,
    report_text: str,
    db_path: str | None = None,
) -> bool:
    """Deliver a structured incident report suitable for MSP ticketing workflows."""
    config = load_notification_config(db_path)
    if not config["email_enabled"]:
        return False

    sender = config["smtp_from"] or config["smtp_user"]
    recipient = config["alert_email_to"]
    if not config["smtp_host"] or not recipient:
        return False

    msg = EmailMessage()
    msg["Subject"] = subject[:200]
    msg["From"] = sender or "netguard@localhost"
    msg["To"] = recipient
    msg.set_content(report_text)
    return _send_smtp_message(msg, config)


def test_telegram(db_path: str | None = None) -> dict[str, Any]:
    """Send a Telegram test message using the current merged notification config."""
    config = load_notification_config(db_path)
    if not config["telegram_enabled"]:
        return {"success": False, "error": "Telegram notifications are disabled"}
    if not config["telegram_bot_token"] or not config["telegram_chat_id"]:
        return {
            "success": False,
            "error": "Telegram bot token or chat ID is not configured",
        }

    message = "NetGuard: Test notification from your NetGuard Pi"
    try:
        if send_telegram(message, db_path):
            return {"success": True}
        return {"success": False, "error": "Telegram API rejected the message"}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:300]
        return {
            "success": False,
            "error": f"Telegram HTTP {exc.code}: {detail or exc.reason}",
        }
    except urllib.error.URLError as exc:
        return {"success": False, "error": f"Telegram request failed: {exc.reason}"}
    except OSError as exc:
        return {"success": False, "error": str(exc)}


def test_email(db_path: str | None = None) -> dict[str, Any]:
    """Send an SMTP test message using the current merged notification config."""
    config = load_notification_config(db_path)
    if not config["email_enabled"]:
        return {"success": False, "error": "Email notifications are disabled"}
    if not config["smtp_host"] or not config["alert_email_to"]:
        return {"success": False, "error": "SMTP host or recipient is not configured"}

    try:
        if send_email(
            "NetGuard test notification",
            "NetGuard: Test notification from your NetGuard Pi",
            db_path,
        ):
            return {"success": True}
        return {"success": False, "error": "SMTP send failed"}
    except OSError as exc:
        return {"success": False, "error": str(exc)}
