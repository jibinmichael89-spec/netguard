#!/usr/bin/env python3
"""Notification delivery for NetGuard alerts (Telegram + SMTP email)."""

from __future__ import annotations

import os
import smtplib
import sqlite3
import urllib.parse
import urllib.request
from email.message import EmailMessage


def _config_value(db_path: str | None, key: str) -> str | None:
    env_key = f"NETGUARD_{key.upper()}"
    env_value = os.environ.get(env_key, "").strip()
    if env_value:
        return env_value
    if not db_path:
        return None
    try:
        conn = sqlite3.connect(db_path)
        row = conn.execute(
            "SELECT value FROM notification_config WHERE key = ?", (key,)
        ).fetchone()
        conn.close()
        return row[0] if row else None
    except sqlite3.Error:
        return None


def send_telegram(message: str, db_path: str | None = None) -> bool:
    token = _config_value(db_path, "telegram_bot_token")
    chat_id = _config_value(db_path, "telegram_chat_id")
    if not token or not chat_id:
        return False
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = urllib.parse.urlencode(
        {"chat_id": chat_id, "text": message[:4000]}
    ).encode("utf-8")
    request = urllib.request.Request(url, data=data, method="POST")
    with urllib.request.urlopen(request, timeout=15) as response:
        return response.status == 200


def send_email(subject: str, body: str, db_path: str | None = None) -> bool:
    host = _config_value(db_path, "smtp_host")
    port = int(_config_value(db_path, "smtp_port") or "587")
    user = _config_value(db_path, "smtp_user")
    password = _config_value(db_path, "smtp_password")
    sender = _config_value(db_path, "smtp_from") or user
    recipient = _config_value(db_path, "alert_email_to")
    if not host or not recipient:
        return False

    msg = EmailMessage()
    msg["Subject"] = subject[:200]
    msg["From"] = sender or "netguard@localhost"
    msg["To"] = recipient
    msg.set_content(body)

    with smtplib.SMTP(host, port, timeout=20) as smtp:
        if user and password:
            smtp.starttls()
            smtp.login(user, password)
        smtp.send_message(msg)
    return True


def send_html_email(
    subject: str,
    html_body: str,
    text_body: str,
    db_path: str | None = None,
) -> bool:
    host = _config_value(db_path, "smtp_host")
    port = int(_config_value(db_path, "smtp_port") or "587")
    user = _config_value(db_path, "smtp_user")
    password = _config_value(db_path, "smtp_password")
    sender = _config_value(db_path, "smtp_from") or user
    recipient = _config_value(db_path, "alert_email_to")
    if not host or not recipient:
        return False

    msg = EmailMessage()
    msg["Subject"] = subject[:200]
    msg["From"] = sender or "netguard@localhost"
    msg["To"] = recipient
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")

    with smtplib.SMTP(host, port, timeout=20) as smtp:
        if user and password:
            smtp.starttls()
            smtp.login(user, password)
        smtp.send_message(msg)
    return True


def notify_alert(
    severity: str,
    alert_type: str,
    device_ip: str,
    description: str,
    db_path: str | None = None,
) -> None:
    """Send alert notifications when configured. Failures are silent."""
    message = (
        f"NetGuard {severity} alert\n"
        f"Type: {alert_type}\n"
        f"Device: {device_ip}\n"
        f"{description}"
    )
    try:
        send_telegram(message, db_path)
    except OSError:
        pass
    try:
        send_email(f"NetGuard {severity}: {alert_type}", message, db_path)
    except OSError:
        pass
