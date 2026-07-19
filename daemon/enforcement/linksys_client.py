"""Linksys local JNAP client for device pause/block on supported routers."""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from typing import Any


class LinksysClient:
    """Local JNAP API used by Linksys Smart WiFi routers on the LAN."""

    def __init__(self, base_url: str, password: str, username: str = "admin") -> None:
        self.base_url = base_url.rstrip("/")
        self.password = password
        self.username = username
        self._auth_token: str | None = None

    def _jnap(self, action: str, body: dict | None = None) -> dict[str, Any]:
        headers = {
            "X-JNAP-Action": action,
            "Content-Type": "application/json; charset=utf-8",
        }
        if self._auth_token:
            headers["X-JNAP-Authorization"] = f"Basic {self._auth_token}"
        payload = json.dumps(body or {}).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/JNAP/",
            data=payload,
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))

    @staticmethod
    def _normalize_mac(mac_address: str) -> str:
        cleaned = "".join(ch for ch in mac_address.upper() if ch.isalnum())
        if len(cleaned) != 12:
            return mac_address.upper().replace("-", ":")
        return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))

    def _login_with_password(self, password_value: str) -> bool:
        result = self._jnap(
            "http://linksys.com/jnap/core/Login",
            {
                "login": {
                    "password": password_value,
                    "locale": "en-US",
                    "timezone": "UTC",
                    "rememberMe": False,
                }
            },
        )
        if result.get("result") != "OK":
            return False
        output = result.get("output", {})
        self._auth_token = output.get("token") or output.get("authToken")
        return bool(self._auth_token)

    def login(self) -> None:
        # Some models expect SHA-256; others accept the plaintext admin password.
        password_hash = hashlib.sha256(self.password.encode("utf-8")).hexdigest()
        if self._login_with_password(password_hash):
            return
        if self._login_with_password(self.password):
            return
        raise RuntimeError("Linksys JNAP login failed")

    def _find_device_id(self, mac_address: str) -> str | None:
        result = self._jnap("http://linksys.com/jnap/devicelist/GetDevices", {})
        if result.get("result") != "OK":
            return None
        target = self._normalize_mac(mac_address)
        for device in result.get("output", {}).get("devices", []):
            mac = self._normalize_mac(
                device.get("macAddress") or device.get("mac") or ""
            )
            if mac and mac == target:
                return device.get("deviceID") or device.get("id")
        return None

    def pause_device(self, mac_address: str, paused: bool = True) -> None:
        normalized_mac = self._normalize_mac(mac_address)
        device_id = self._find_device_id(normalized_mac)
        body: dict[str, Any]
        if device_id:
            body = {
                "devices": [
                    {"deviceID": device_id, "paused": paused},
                ]
            }
        else:
            body = {
                "devices": [
                    {"macAddress": normalized_mac, "paused": paused},
                ]
            }
        result = self._jnap(
            "http://linksys.com/jnap/parentalcontrol/SetDevicePause",
            body,
        )
        if result.get("result") != "OK":
            raise RuntimeError(result.get("error", "Linksys pause request failed"))

    def block_device(self, mac_address: str) -> None:
        self.pause_device(mac_address, paused=True)

    def unblock_device(self, mac_address: str) -> None:
        self.pause_device(mac_address, paused=False)
