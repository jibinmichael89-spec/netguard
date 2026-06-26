#!/usr/bin/env python3
"""Router and local enforcement orchestration."""

from __future__ import annotations

import os
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime, timezone

from schema_extensions import log_device_event


@dataclass
class EnforcementResult:
    method: str
    success: bool
    detail: str


class RouterManager:
    """
    Coordinate device blocking across available methods.

    Priority: router API (when configured) → DNS block on Pi → ARP isolation.
    """

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.router_type = os.environ.get("NETGUARD_ROUTER_TYPE", "").strip().lower()
        self.router_url = os.environ.get("NETGUARD_ROUTER_URL", "").strip()
        self.router_token = os.environ.get("NETGUARD_ROUTER_TOKEN", "").strip()

    def block_device(self, device_ip: str, mac_address: str | None = None) -> EnforcementResult:
        if self.router_type and self.router_url:
            result = self._block_via_router(device_ip, mac_address)
            if result.success:
                return result

        dns_result = self._block_via_dns(device_ip)
        if dns_result.success:
            return dns_result

        return EnforcementResult(
            method="visibility_only",
            success=False,
            detail=(
                "Device marked blocked in NetGuard. Configure NETGUARD_ROUTER_TYPE "
                "or use Pi DNS blocking / network_blocker for network enforcement."
            ),
        )

    def _block_via_router(
        self, device_ip: str, mac_address: str | None
    ) -> EnforcementResult:
        # Router-specific APIs vary; Linksys cloud often has no local API.
        # Hook point for future UniFi / OpenWrt integrations.
        if self.router_type in ("linksys", "velop"):
            return EnforcementResult(
                method="router_api",
                success=False,
                detail=(
                    "Linksys Velop mesh has no reliable local block API. "
                    "Use the Linksys app to pause the device, or set NETGUARD_ROUTER_TYPE=openwrt."
                ),
            )
        if self.router_type == "openwrt":
            return EnforcementResult(
                method="router_api",
                success=False,
                detail="OpenWrt integration stub — set NETGUARD_ROUTER_URL and token.",
            )
        return EnforcementResult(
            method="router_api",
            success=False,
            detail=f"Unknown router type: {self.router_type}",
        )

    def _block_via_dns(self, device_ip: str) -> EnforcementResult:
        enforcement_dir = os.path.join(os.path.dirname(__file__))
        if enforcement_dir not in sys.path:
            sys.path.insert(0, enforcement_dir)
        try:
            from dns_blocker import apply_dns_block

            applied = apply_dns_block(device_ip)
            conn = sqlite3.connect(self.db_path)
            log_device_event(
                conn,
                device_ip,
                "enforcement",
                "DNS traffic blocked via iptables",
                details="dns_blocker",
            )
            conn.close()
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
            return EnforcementResult(
                method="dns_block",
                success=False,
                detail=str(exc),
            )
