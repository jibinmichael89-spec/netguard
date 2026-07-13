#!/usr/bin/env bash
#
# Enable Microsoft Sentinel auto-export on this Pi.
#
# Usage:
#   sudo bash install/pi/setup-sentinel-export.sh <workspace_id> <primary_key>
#
# Or with environment variables:
#   sudo NETGUARD_SENTINEL_WORKSPACE_ID=... NETGUARD_SENTINEL_PRIMARY_KEY=... \
#     bash install/pi/setup-sentinel-export.sh
#
# Get workspace ID and primary key from Azure Portal:
#   Log Analytics workspace → Agents → Log Analytics agent instructions →
#   "Primary Key" and workspace ID (GUID).
#
set -euo pipefail

INSTALL_DIR="${NETGUARD_INSTALL_DIR:-/opt/netguard}"
ENV_FILE="/etc/netguard/netguard.env"
DATA_DIR="/var/lib/netguard"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_TYPE="${NETGUARD_SENTINEL_LOG_TYPE:-NetGuard}"

log() { printf '[*] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*"; }

require_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        echo "[!] Run as root: sudo $0"
        exit 1
    fi
}

upsert_env() {
    local key="$1"
    local value="$2"
    mkdir -p "$(dirname "$ENV_FILE")"
    touch "$ENV_FILE"
    chmod 640 "$ENV_FILE"
    if grep -q "^${key}=" "$ENV_FILE"; then
        sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
    else
        printf '\n%s=%s\n' "$key" "$value" >> "$ENV_FILE"
    fi
}

install_systemd_unit() {
    local unit_src="$SCRIPT_DIR/systemd/netguard-sentinel-export.service"
    if [[ ! -f "$unit_src" ]]; then
        unit_src="$INSTALL_DIR/install/pi/systemd/netguard-sentinel-export.service"
    fi
    if [[ ! -f "$unit_src" ]]; then
        echo "[!] Cannot find netguard-sentinel-export.service"
        exit 1
    fi
    install -m 644 "$unit_src" /etc/systemd/system/netguard-sentinel-export.service
    systemctl daemon-reload
}

main() {
    require_root

    local workspace_id="${1:-${NETGUARD_SENTINEL_WORKSPACE_ID:-}}"
    local primary_key="${2:-${NETGUARD_SENTINEL_PRIMARY_KEY:-}}"

    if [[ -z "$workspace_id" || -z "$primary_key" ]]; then
        echo "Usage: sudo $0 <workspace_id> <primary_key>"
        echo ""
        echo "Example:"
        echo "  sudo $0 a1b2c3d4-e5f6-7890-abcd-ef1234567890 YOUR_BASE64_PRIMARY_KEY"
        exit 1
    fi

    if [[ ! -d "$INSTALL_DIR" ]]; then
        echo "[!] NetGuard not found at $INSTALL_DIR — run install.sh first"
        exit 1
    fi

    if [[ ! -f "$INSTALL_DIR/daemon/integrations/syslog_export.py" ]]; then
        echo "[!] syslog_export.py missing — git pull or reinstall NetGuard first"
        exit 1
    fi

    log "Writing Sentinel credentials to $ENV_FILE"
    upsert_env "NETGUARD_SENTINEL_WORKSPACE_ID" "$workspace_id"
    upsert_env "NETGUARD_SENTINEL_PRIMARY_KEY" "$primary_key"
    upsert_env "NETGUARD_SENTINEL_LOG_TYPE" "$LOG_TYPE"
    chown root:netguard "$ENV_FILE" 2>/dev/null || chown root:root "$ENV_FILE"

    mkdir -p "$DATA_DIR"
    chown netguard:netguard "$DATA_DIR" 2>/dev/null || true

    log "Installing systemd unit ..."
    install_systemd_unit

    log "Enabling and starting netguard-sentinel-export.service ..."
    systemctl enable netguard-sentinel-export.service
    systemctl restart netguard-sentinel-export.service

    sleep 2
    if systemctl is-active --quiet netguard-sentinel-export.service; then
        log "Sentinel export is running"
    else
        warn "Service did not start — check: journalctl -u netguard-sentinel-export -n 30"
        exit 1
    fi

    log "Done. New NetGuard alerts will export every 60 seconds."
    log "Watch logs: journalctl -u netguard-sentinel-export -f"
    log "State file: $DATA_DIR/sentinel_state.json"
}

main "$@"
