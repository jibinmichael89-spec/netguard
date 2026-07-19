"""OpenWrt ubus HTTP client for per-device firewall block/unblock."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any


def _insecure_ssl_context() -> ssl.SSLContext:
    """Local routers almost always use self-signed HTTPS certificates."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


class OpenWrtClient:
    """Minimal ubus-over-HTTP client for OpenWrt routers with rpcd."""

    def __init__(self, base_url: str, username: str = "", password: str = "") -> None:
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.session_id = ""
        self._request_id = 0
        self._ssl_context = _insecure_ssl_context()

    def _ubus(self, namespace: str, method: str, params: dict | None = None, session: str | None = None) -> Any:
        self._request_id += 1
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": self._request_id,
                "method": "call",
                "params": [session or self.session_id, namespace, method, params or {}],
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/ubus",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(
            request,
            timeout=20,
            context=self._ssl_context,
        ) as response:
            data = json.loads(response.read().decode("utf-8"))
        if "error" in data:
            raise RuntimeError(str(data["error"]))
        return data.get("result")

    def login(self) -> None:
        result = self._ubus(
            "session",
            "login",
            {"username": self.username, "password": self.password},
            session="00000000000000000000000000000000",
        )
        if not isinstance(result, list) or len(result) < 2:
            raise RuntimeError("OpenWrt login returned unexpected response")
        self.session_id = result[1].get("ubus_rpc_session", "")
        if not self.session_id:
            raise RuntimeError("OpenWrt login failed — check username and password")

    def use_token(self, token: str) -> None:
        self.session_id = token.strip()

    def _iptables(self, command: str) -> None:
        result = self._ubus(
            "file",
            "exec",
            {"command": "/bin/sh", "params": ["-c", command]},
        )
        if not isinstance(result, list) or result[0] != 0:
            raise RuntimeError(f"OpenWrt iptables command failed: {result}")

    @staticmethod
    def _comment_tag(device_ip: str) -> str:
        return f"netguard-block-{device_ip.replace('.', '-')}"

    def block_device(self, device_ip: str, mac_address: str | None = None) -> None:
        comment = self._comment_tag(device_ip)
        if mac_address:
            rule = (
                f"iptables -C FORWARD -m mac --mac-source {mac_address.upper()} "
                f"-m comment --comment {comment} -j DROP 2>/dev/null || "
                f"iptables -I FORWARD -m mac --mac-source {mac_address.upper()} "
                f"-m comment --comment {comment} -j DROP"
            )
        else:
            rule = (
                f"iptables -C FORWARD -s {device_ip} -m comment --comment {comment} -j DROP 2>/dev/null || "
                f"iptables -I FORWARD -s {device_ip} -m comment --comment {comment} -j DROP"
            )
        self._iptables(rule)

    def unblock_device(self, device_ip: str, mac_address: str | None = None) -> None:
        comment = self._comment_tag(device_ip)
        if mac_address:
            spec = (
                f"-m mac --mac-source {mac_address.upper()} "
                f"-m comment --comment {comment} -j DROP"
            )
        else:
            spec = f"-s {device_ip} -m comment --comment {comment} -j DROP"
        command = (
            f"while iptables -C FORWARD {spec} 2>/dev/null; do "
            f"iptables -D FORWARD {spec}; done"
        )
        self._iptables(command)

    def pause_device(self, mac_address: str, minutes: int = 60) -> None:
        """Best-effort timed pause via dnsmasq deny (OpenWrt with dnsmasq)."""
        mac = mac_address.upper()
        tag = mac.replace(":", "")
        conf = f"dhcp-host={mac},ignore\n"
        command = (
            f"mkdir -p /tmp/netguard && "
            f"echo '{conf}' > /tmp/netguard/pause-{tag}.conf && "
            f"uci add_list dhcp.@dnsmasq[0].addnhosts=/tmp/netguard/pause-{tag}.conf 2>/dev/null || true && "
            f"/etc/init.d/dnsmasq reload 2>/dev/null || true"
        )
        try:
            self._iptables(command)
        except (RuntimeError, urllib.error.URLError):
            raise RuntimeError(
                f"OpenWrt pause not available — use block instead ({minutes} min requested)"
            ) from None
