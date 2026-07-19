#!/usr/bin/env python3
"""Router and local enforcement orchestration."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import urllib.error
import urllib.request

from schema_extensions import log_device_event

ROUTER_CONFIG_KEYS: tuple[str, ...] = (
    "router_type",
    "router_url",
    "router_user",
    "router_password",
    "router_token",
)

_ROUTER_ENV_KEYS: dict[str, str] = {
    "router_type": "NETGUARD_ROUTER_TYPE",
    "router_url": "NETGUARD_ROUTER_URL",
    "router_user": "NETGUARD_ROUTER_USER",
    "router_password": "NETGUARD_ROUTER_PASSWORD",
    "router_token": "NETGUARD_ROUTER_TOKEN",
}

DNS_ONLY_ROUTER_TYPES: frozenset[str] = frozenset(
    {"sky", "eir", "virgin", "bt", "asus", "netgear", "other"}
)
ROUTER_API_TYPES: frozenset[str] = frozenset(
    {"linksys", "velop", "openwrt", "custom"}
)
SUPPORTED_ROUTER_TYPES: tuple[str, ...] = (
    "linksys",
    "openwrt",
    "sky",
    "eir",
    "virgin",
    "bt",
    "asus",
    "netgear",
    "custom",
    "other",
)

ROUTER_TYPE_META: dict[str, dict[str, str | bool]] = {
    "linksys": {
        "label": "Linksys JNAP",
        "blocking_method": "router_api",
        "setup_required": False,
        "setup_instructions": "Automatic blocking via Linksys JNAP parental control API.",
        "default_url": "http://192.168.1.1",
    },
    "velop": {
        "label": "Linksys Velop",
        "blocking_method": "router_api",
        "setup_required": False,
        "setup_instructions": "Automatic blocking via Linksys JNAP parental control API.",
        "default_url": "http://192.168.1.1",
    },
    "openwrt": {
        "label": "OpenWrt",
        "blocking_method": "router_api",
        "setup_required": False,
        "setup_instructions": "Automatic blocking via OpenWrt ubus firewall rules.",
        "default_url": "http://192.168.1.1",
    },
    "sky": {
        "label": "Sky Hub",
        "blocking_method": "dns_only",
        "setup_required": True,
        "setup_instructions": (
            "Set Sky Hub primary DNS to your NetGuard Pi IP under Advanced → DNS Settings."
        ),
        "default_url": "http://192.168.0.1",
    },
    "eir": {
        "label": "Eir F3000",
        "blocking_method": "dns_only",
        "setup_required": True,
        "setup_instructions": (
            "Set Eir F3000 primary DNS to your NetGuard Pi IP under Basic → WAN → DNS."
        ),
        "default_url": "http://192.168.1.1",
    },
    "virgin": {
        "label": "Virgin Media Super Hub",
        "blocking_method": "dns_only",
        "setup_required": True,
        "setup_instructions": (
            "Set Virgin Super Hub primary DNS to your NetGuard Pi IP under "
            "Basic Settings → Network → DNS."
        ),
        "default_url": "http://192.168.100.1",
    },
    "bt": {
        "label": "BT Hub",
        "blocking_method": "dns_only",
        "setup_required": True,
        "setup_instructions": (
            "Set BT Hub primary DNS to your NetGuard Pi IP under Advanced Settings → DNS."
        ),
        "default_url": "http://192.168.1.254",
    },
    "asus": {
        "label": "ASUS Router",
        "blocking_method": "dns_only",
        "setup_required": True,
        "setup_instructions": (
            "Set ASUS DNS Server 1 to your NetGuard Pi IP under LAN → DHCP → DNS and WINS."
        ),
        "default_url": "http://192.168.1.1",
    },
    "netgear": {
        "label": "Netgear",
        "blocking_method": "dns_only",
        "setup_required": True,
        "setup_instructions": (
            "Set Netgear primary DNS to your NetGuard Pi IP under Internet → Domain Name Server."
        ),
        "default_url": "http://192.168.1.1",
    },
    "custom": {
        "label": "Custom webhook",
        "blocking_method": "router_api",
        "setup_required": False,
        "setup_instructions": "POST block/unblock events to your webhook URL.",
        "default_url": "",
    },
    "other": {
        "label": "Generic router",
        "blocking_method": "dns_only",
        "setup_required": True,
        "setup_instructions": (
            "Point your router's primary DNS to your NetGuard Pi IP in WAN or Advanced DNS settings."
        ),
        "default_url": "http://192.168.1.1",
    },
}


def _detect_host_ip() -> str | None:
    import socket

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return None


def is_dns_only_router(router_type: str | None) -> bool:
    return bool(router_type) and router_type.lower() in DNS_ONLY_ROUTER_TYPES


def _run_quiet(command: list[str]) -> bool:
    try:
        result = subprocess.run(
            command,
            check=False,
            timeout=5,
            capture_output=True,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _network_blocker_active() -> bool:
    """True when netguard-network-blocker is running or enabled (Pi ARP isolation)."""
    if sys.platform == "win32":
        return False

    unit = "netguard-network-blocker.service"
    for systemctl in ("systemctl", "/bin/systemctl", "/usr/bin/systemctl"):
        if _run_quiet([systemctl, "is-active", "--quiet", unit]):
            return True
        # Enabled-but-restarting still enforces blocked devices after is_blocked=1.
        if _run_quiet([systemctl, "is-enabled", "--quiet", unit]):
            return True

    for pgrep in ("pgrep", "/usr/bin/pgrep"):
        if _run_quiet([pgrep, "-f", "network_blocker.py"]):
            return True

    # Pi home installs expect ARP enforcement even if systemctl is unavailable
    # to the API user (e.g. restricted PATH / container quirks).
    profile = os.environ.get("NETGUARD_PROFILE", "").strip().lower()
    return profile == "home"


def router_type_metadata(router_type: str | None) -> dict[str, str | bool]:
    if not router_type:
        return {
            "label": "",
            "blocking_method": "",
            "setup_required": False,
            "setup_instructions": "",
            "default_url": "",
        }
    return ROUTER_TYPE_META.get(router_type.lower(), ROUTER_TYPE_META["other"])


def _router_setting(db_path: str | None, key: str, *, default: str = "") -> str:
    """Read a router setting from environment (preferred) or notification_config."""
    env_name = _ROUTER_ENV_KEYS.get(key)
    if env_name:
        env_value = os.environ.get(env_name, "").strip()
        if env_value:
            return env_value.lower() if key == "router_type" else env_value

    if not db_path:
        return default

    try:
        conn = sqlite3.connect(db_path)
        row = conn.execute(
            "SELECT value FROM notification_config WHERE key = ?",
            (key,),
        ).fetchone()
        conn.close()
        if row and row[0]:
            value = str(row[0]).strip()
            return value.lower() if key == "router_type" else value
    except sqlite3.Error:
        pass

    return default


def _router_env_overrides(db_path: str | None) -> list[str]:
    """Return config keys currently overridden by environment variables."""
    overrides: list[str] = []
    for key, env_name in _ROUTER_ENV_KEYS.items():
        if os.environ.get(env_name, "").strip():
            overrides.append(key)
    return overrides


class EnforcementResult:
    """Outcome of a block/unblock/pause enforcement action."""

    __slots__ = ("method", "success", "detail")

    def __init__(self, method: str, success: bool, detail: str) -> None:
        self.method = method
        self.success = success
        self.detail = detail


class RouterManager:
    """
    Coordinate device blocking across available methods.

    Priority: router API (when configured) → DNS block on Pi → ARP network blocker → visibility flag.
    """

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.router_type = _router_setting(db_path, "router_type")
        self.router_url = _router_setting(db_path, "router_url")
        self.router_token = _router_setting(db_path, "router_token")
        default_user = (
            "admin" if self.router_type in ("linksys", "velop") else "root"
        )
        self.router_user = (
            _router_setting(db_path, "router_user", default=default_user) or default_user
        )
        self.router_password = _router_setting(db_path, "router_password")

    def _router_credentials_ready(self) -> bool:
        if not self.router_type or not self.router_url:
            return False
        if self.router_type in ("linksys", "velop"):
            return bool(self.router_password or self.router_token)
        if self.router_type == "openwrt":
            return bool(self.router_password or self.router_token)
        if self.router_type == "custom":
            return True
        return False

    def _arp_isolation_result(self) -> EnforcementResult | None:
        if not _network_blocker_active():
            return None
        return EnforcementResult(
            method="arp_isolation",
            success=True,
            detail="Device blocked via NetGuard network blocker (ARP isolation).",
        )

    def block_device(self, device_ip: str, mac_address: str | None = None) -> EnforcementResult:
        if is_dns_only_router(self.router_type):
            return self._block_dns_only(device_ip)

        router_failure: EnforcementResult | None = None
        if self.router_type and self.router_url:
            result = self._block_via_router(device_ip, mac_address)
            if result.success:
                self._log_enforcement(device_ip, result)
                return result
            router_failure = result

        dns_result = self._block_via_dns(device_ip)
        if dns_result.success:
            self._log_enforcement(device_ip, dns_result)
            return dns_result

        arp_result = self._arp_isolation_result()
        if arp_result is not None:
            # Dashboard already set is_blocked=1; network blocker will enforce it.
            if router_failure and self._router_credentials_ready():
                arp_result = EnforcementResult(
                    method="arp_isolation",
                    success=True,
                    detail=(
                        "Device blocked via NetGuard network blocker (ARP isolation). "
                        f"Router API note: {router_failure.detail}"
                    ),
                )
            self._log_enforcement(device_ip, arp_result)
            return arp_result

        if router_failure and self._router_credentials_ready():
            return EnforcementResult(
                method=router_failure.method,
                success=False,
                detail=(
                    f"Router enforcement failed: {router_failure.detail}. "
                    "Device is marked blocked in NetGuard only."
                ),
            )

        return EnforcementResult(
            method="visibility_only",
            success=False,
            detail=(
                "Device marked blocked in NetGuard only. Configure router enforcement "
                "in Settings → Router (Linksys: http://192.168.1.1, user admin). "
                "On Pi without router API, enable netguard-network-blocker for ARP isolation."
            ),
        )

    def unblock_device(self, device_ip: str, mac_address: str | None = None) -> EnforcementResult:
        if is_dns_only_router(self.router_type):
            return self._unblock_dns_only(device_ip)

        if self.router_type and self.router_url:
            result = self._unblock_via_router(device_ip, mac_address)
            if result.success:
                self._log_enforcement(device_ip, result)
                return result

        dns_result = self._unblock_via_dns(device_ip)
        if dns_result.success:
            self._log_enforcement(device_ip, dns_result)
            return dns_result

        if _network_blocker_active():
            result = EnforcementResult(
                method="arp_isolation",
                success=True,
                detail="Device unblocked in NetGuard; network blocker will release ARP isolation.",
            )
            self._log_enforcement(device_ip, result)
            return result

        return EnforcementResult(
            method="database",
            success=True,
            detail="Device unblocked in NetGuard database.",
        )

    def pause_device(
        self,
        device_ip: str,
        mac_address: str | None = None,
        minutes: int = 60,
    ) -> EnforcementResult:
        if not mac_address:
            return EnforcementResult(
                method="pause",
                success=False,
                detail="MAC address required for router pause.",
            )
        if self.router_type in ("linksys", "velop"):
            try:
                from linksys_client import LinksysClient

                password = self.router_password or self.router_token
                if not password:
                    raise RuntimeError("Set NETGUARD_ROUTER_PASSWORD for Linksys JNAP login")
                client = LinksysClient(self.router_url, password, self.router_user)
                client.login()
                client.pause_device(mac_address, paused=True)
                return EnforcementResult(
                    method="router_pause",
                    success=True,
                    detail=f"Device paused on Linksys router ({minutes} min requested — resume via unblock).",
                )
            except Exception as exc:
                return EnforcementResult(method="router_pause", success=False, detail=str(exc))

        if self.router_type == "openwrt":
            try:
                from openwrt_client import OpenWrtClient

                client = OpenWrtClient(self.router_url, self.router_user, self.router_password)
                if self.router_token:
                    client.use_token(self.router_token)
                else:
                    client.login()
                client.pause_device(mac_address, minutes=minutes)
                return EnforcementResult(
                    method="router_pause",
                    success=True,
                    detail=f"Device paused on OpenWrt for ~{minutes} minutes.",
                )
            except Exception as exc:
                block_result = self.block_device(device_ip, mac_address)
                if block_result.success:
                    return EnforcementResult(
                        method="router_block",
                        success=True,
                        detail=f"Pause unavailable; device blocked instead: {block_result.detail}",
                    )
                return EnforcementResult(method="router_pause", success=False, detail=str(exc))

        return EnforcementResult(
            method="pause",
            success=False,
            detail="Router pause requires NETGUARD_ROUTER_TYPE=linksys or openwrt.",
        )

    def _block_dns_only(self, device_ip: str) -> EnforcementResult:
        dns_result = self._block_via_dns(device_ip)
        if dns_result.success:
            result = EnforcementResult(
                method="dns_fallback",
                success=True,
                detail=(
                    "Blocked via DNS — ensure Pi is set as DNS server in your router settings"
                ),
            )
            self._log_enforcement(device_ip, result)
            return result
        arp_result = self._arp_isolation_result()
        if arp_result is not None:
            self._log_enforcement(device_ip, arp_result)
            return arp_result
        return EnforcementResult(
            method="dns_fallback",
            success=False,
            detail=dns_result.detail,
        )

    def _unblock_dns_only(self, device_ip: str) -> EnforcementResult:
        dns_result = self._unblock_via_dns(device_ip)
        if dns_result.success:
            result = EnforcementResult(
                method="dns_fallback",
                success=True,
                detail="DNS block removed on Pi.",
            )
            self._log_enforcement(device_ip, result)
            return result
        return EnforcementResult(
            method="dns_fallback",
            success=False,
            detail=dns_result.detail,
        )

    def _block_via_router(
        self, device_ip: str, mac_address: str | None
    ) -> EnforcementResult:
        if self.router_type in ("linksys", "velop"):
            return self._linksys_block(device_ip, mac_address)
        if self.router_type == "openwrt":
            return self._openwrt_block(device_ip, mac_address, pause=False)
        if self.router_type == "custom":
            return self._custom_webhook(device_ip, mac_address, action="block")
        return EnforcementResult(
            method="router_api",
            success=False,
            detail=f"Unknown router type: {self.router_type}",
        )

    def _unblock_via_router(
        self, device_ip: str, mac_address: str | None
    ) -> EnforcementResult:
        if self.router_type in ("linksys", "velop"):
            return self._linksys_unblock(mac_address)
        if self.router_type == "openwrt":
            return self._openwrt_block(device_ip, mac_address, pause=False, unblock=True)
        if self.router_type == "custom":
            return self._custom_webhook(device_ip, mac_address, action="unblock")
        return EnforcementResult(
            method="router_api",
            success=False,
            detail=f"Unknown router type: {self.router_type}",
        )

    def _linksys_block(self, device_ip: str, mac_address: str | None) -> EnforcementResult:
        if not mac_address:
            return EnforcementResult(
                method="router_api",
                success=False,
                detail="MAC address required for Linksys pause/block.",
            )
        try:
            from linksys_client import LinksysClient

            password = self.router_password or self.router_token
            if not password:
                raise RuntimeError("Set NETGUARD_ROUTER_PASSWORD for Linksys JNAP login")
            client = LinksysClient(self.router_url, password, self.router_user)
            client.login()
            client.block_device(mac_address)
            return EnforcementResult(
                method="router_api",
                success=True,
                detail="Device paused on Linksys router via JNAP parental control.",
            )
        except Exception as exc:
            return EnforcementResult(method="router_api", success=False, detail=str(exc))

    def _linksys_unblock(self, mac_address: str | None) -> EnforcementResult:
        if not mac_address:
            return EnforcementResult(
                method="router_api",
                success=False,
                detail="MAC address required for Linksys unblock.",
            )
        try:
            from linksys_client import LinksysClient

            password = self.router_password or self.router_token
            if not password:
                raise RuntimeError("Set NETGUARD_ROUTER_PASSWORD for Linksys JNAP login")
            client = LinksysClient(self.router_url, password, self.router_user)
            client.login()
            client.unblock_device(mac_address)
            return EnforcementResult(
                method="router_api",
                success=True,
                detail="Device resumed on Linksys router.",
            )
        except Exception as exc:
            return EnforcementResult(method="router_api", success=False, detail=str(exc))

    def _openwrt_block(
        self,
        device_ip: str,
        mac_address: str | None,
        *,
        pause: bool,
        unblock: bool = False,
    ) -> EnforcementResult:
        try:
            from openwrt_client import OpenWrtClient

            client = OpenWrtClient(self.router_url, self.router_user, self.router_password)
            if self.router_token:
                client.use_token(self.router_token)
            else:
                client.login()
            if unblock:
                client.unblock_device(device_ip, mac_address)
                detail = "OpenWrt firewall rule removed."
            else:
                client.block_device(device_ip, mac_address)
                detail = "OpenWrt FORWARD rule added (iptables)."
            return EnforcementResult(method="router_api", success=True, detail=detail)
        except Exception as exc:
            return EnforcementResult(method="router_api", success=False, detail=str(exc))

    def _custom_webhook(
        self,
        device_ip: str,
        mac_address: str | None,
        *,
        action: str,
    ) -> EnforcementResult:
        payload = json.dumps(
            {"action": action, "ip": device_ip, "mac": mac_address}
        ).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.router_token:
            headers["Authorization"] = f"Bearer {self.router_token}"
        request = urllib.request.Request(
            self.router_url,
            data=payload,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                if response.status != 200:
                    raise RuntimeError(f"Webhook returned HTTP {response.status}")
        except urllib.error.URLError as exc:
            return EnforcementResult(method="custom_webhook", success=False, detail=str(exc))
        return EnforcementResult(
            method="custom_webhook",
            success=True,
            detail=f"Webhook {action} sent to {self.router_url}.",
        )

    def _block_via_dns(self, device_ip: str) -> EnforcementResult:
        enforcement_dir = os.path.dirname(__file__)
        if enforcement_dir not in sys.path:
            sys.path.insert(0, enforcement_dir)
        try:
            from dns_blocker import apply_dns_block

            applied = apply_dns_block(device_ip)
            if not applied:
                return EnforcementResult(
                    method="dns_block",
                    success=False,
                    detail="DNS block rule could not be applied (requires root on Pi).",
                )
            return EnforcementResult(
                method="dns_block",
                success=True,
                detail="DNS queries from device dropped on Pi (port 53).",
            )
        except Exception as exc:
            return EnforcementResult(method="dns_block", success=False, detail=str(exc))

    def _unblock_via_dns(self, device_ip: str) -> EnforcementResult:
        enforcement_dir = os.path.dirname(__file__)
        if enforcement_dir not in sys.path:
            sys.path.insert(0, enforcement_dir)
        try:
            from dns_blocker import remove_dns_block

            remove_dns_block(device_ip)
            return EnforcementResult(
                method="dns_block",
                success=True,
                detail="DNS block rules removed on Pi.",
            )
        except Exception as exc:
            return EnforcementResult(method="dns_block", success=False, detail=str(exc))

    def _log_enforcement(self, device_ip: str, result: EnforcementResult) -> None:
        conn = sqlite3.connect(self.db_path)
        try:
            log_device_event(
                conn,
                device_ip,
                "enforcement",
                result.detail,
                details=result.method,
            )
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def router_config_summary(db_path: str | None = None) -> dict:
        router_type = _router_setting(db_path, "router_type")
        router_url = _router_setting(db_path, "router_url")
        meta = router_type_metadata(router_type)
        default_user = "admin" if router_type in ("linksys", "velop") else "root"
        router_user = (
            _router_setting(db_path, "router_user", default=default_user) or default_user
        )
        router_password = _router_setting(db_path, "router_password")
        router_token = _router_setting(db_path, "router_token")
        env_overrides = _router_env_overrides(db_path)
        blocking_method = str(meta.get("blocking_method") or "")
        setup_required = bool(meta.get("setup_required"))
        setup_instructions = str(meta.get("setup_instructions") or "")

        if is_dns_only_router(router_type):
            configured = bool(router_type)
        else:
            configured = bool(router_type and router_url)

        return {
            "router_type": router_type or None,
            "router_url": router_url or None,
            "router_user": router_user or None,
            "router_password": "***" if router_password else None,
            "router_token": "***" if router_token else None,
            "configured": configured,
            "supported_types": list(SUPPORTED_ROUTER_TYPES),
            "blocking_method": blocking_method or None,
            "setup_required": setup_required,
            "setup_instructions": setup_instructions,
            "netguard_host_ip": _detect_host_ip(),
            "env_overrides": env_overrides,
            "env_keys": list(_ROUTER_ENV_KEYS.values()),
        }
