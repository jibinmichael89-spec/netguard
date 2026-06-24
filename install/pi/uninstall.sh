#!/usr/bin/env bash
#
# NetGuard Raspberry Pi uninstaller
#
set -euo pipefail

INSTALL_DIR="${NETGUARD_INSTALL_DIR:-/opt/netguard}"
DATA_DIR="/var/lib/netguard"
LOG_DIR="/var/log/netguard"
ENV_FILE="/etc/netguard/netguard.env"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { printf '[*] %s\n' "$*"; }

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "[!] Run as root: sudo $0"
    exit 1
fi

KEEP_DATA=0
if [[ "${1:-}" == "--keep-data" ]]; then
    KEEP_DATA=1
fi

log "Stopping NetGuard services ..."
for unit in netguard-network-blocker netguard-dns-monitor netguard-risk-scorer \
    netguard-arp-scanner netguard-api netguard.target; do
    systemctl disable --now "$unit.service" 2>/dev/null || true
done

log "Removing systemd units ..."
for unit in netguard.target netguard-api.service netguard-arp-scanner.service \
    netguard-risk-scorer.service netguard-dns-monitor.service \
    netguard-network-blocker.service; do
    rm -f "/etc/systemd/system/$unit"
done
systemctl daemon-reload

if [[ -d "$INSTALL_DIR" ]]; then
    log "Removing $INSTALL_DIR ..."
    rm -rf "$INSTALL_DIR"
fi

if [[ -f "$ENV_FILE" ]]; then
    rm -f "$ENV_FILE"
    rmdir /etc/netguard 2>/dev/null || true
fi

if [[ "$KEEP_DATA" -eq 0 ]]; then
    log "Removing data in $DATA_DIR and $LOG_DIR ..."
    rm -rf "$DATA_DIR" "$LOG_DIR"
else
    log "Keeping database and logs (--keep-data)"
fi

log "NetGuard uninstalled."
