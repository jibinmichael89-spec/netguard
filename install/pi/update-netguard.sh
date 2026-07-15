#!/usr/bin/env bash
#
# Update an existing NetGuard Pi installation from a release tarball.
# Preserves /etc/netguard/netguard.env (including Sentinel credentials).
#
# Usage (after extracting a new release tarball on the Pi):
#   tar xzf NetGuard-pi-YYYY.MM.DD.tar.gz
#   cd NetGuard-pi
#   sudo ./install/pi/update-netguard.sh
#
set -euo pipefail

INSTALL_DIR="${NETGUARD_INSTALL_DIR:-/opt/netguard}"
NETGUARD_USER="${NETGUARD_USER:-netguard}"
NETGUARD_GROUP="${NETGUARD_GROUP:-netguard}"
ENV_FILE="/etc/netguard/netguard.env"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "$SCRIPT_DIR/../../api/main.py" ]]; then
    SOURCE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
elif [[ -f "$SCRIPT_DIR/../api/main.py" ]]; then
    SOURCE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
else
    echo "[!] Cannot locate NetGuard source files next to update-netguard.sh"
    exit 1
fi

log() { printf '[*] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*"; }

require_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        echo "[!] Run as root: sudo $0"
        exit 1
    fi
}

sync_application_files() {
    log "Updating application in $INSTALL_DIR ..."
    mkdir -p "$INSTALL_DIR"
    rsync -a --delete \
        --exclude 'venv/' \
        --exclude 'node_modules/' \
        --exclude '.git/' \
        --exclude 'build/' \
        --exclude 'dist/' \
        --exclude 'dashboard/dist/' \
        --exclude '__pycache__/' \
        --exclude '*.pyc' \
        --exclude 'netguard.db' \
        "$SOURCE_DIR/" "$INSTALL_DIR/"
    chown -R "$NETGUARD_USER:$NETGUARD_GROUP" "$INSTALL_DIR"
}

setup_python_venv() {
    log "Updating Python dependencies ..."
    if [[ ! -d "$INSTALL_DIR/venv" ]]; then
        python3 -m venv "$INSTALL_DIR/venv"
    fi
    "$INSTALL_DIR/venv/bin/python" -m pip install --upgrade pip -q
    "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q
    chown -R "$NETGUARD_USER:$NETGUARD_GROUP" "$INSTALL_DIR/venv"
}

install_systemd_units() {
    log "Installing systemd units ..."
    local systemd_dir="$SOURCE_DIR/install/pi/systemd"
    if [[ ! -d "$systemd_dir" ]]; then
        systemd_dir="$SCRIPT_DIR/systemd"
    fi
    for unit in netguard.target netguard-api.service netguard-arp-scanner.service \
        netguard-risk-scorer.service netguard-dns-monitor.service \
        netguard-arp-spoof.service netguard-rogue-dhcp.service \
        netguard-inbound-detector.service netguard-policy-engine.service \
        netguard-syslog-export.service netguard-sentinel-export.service \
        netguard-threat-intel.service netguard-threat-intel.timer \
        netguard-weekly-report.service netguard-weekly-report.timer \
        netguard-msp-agent.service netguard-msp-agent.timer \
        netguard-network-blocker.service; do
        if [[ -f "$systemd_dir/$unit" ]]; then
            install -m 644 "$systemd_dir/$unit" "/etc/systemd/system/$unit"
        fi
    done
    systemctl daemon-reload
}

configure_sentinel_export() {
    systemctl enable netguard-sentinel-export.service 2>/dev/null || true
    if [[ -f "$ENV_FILE" ]] && grep -qE '^\s*NETGUARD_SENTINEL_ENABLED=(0|false|no|off)\s*$' "$ENV_FILE" 2>/dev/null; then
        warn "Sentinel disabled in $ENV_FILE"
        systemctl stop netguard-sentinel-export.service 2>/dev/null || true
    elif [[ -f "$ENV_FILE" ]] && grep -qE '^\s*NETGUARD_SENTINEL_WORKSPACE_ID=.+$' "$ENV_FILE" 2>/dev/null; then
        log "Microsoft Sentinel export: configured — starting service"
        systemctl restart netguard-sentinel-export.service 2>/dev/null || true
        if systemctl is-active --quiet netguard-sentinel-export.service; then
            log "Sentinel export is active"
        else
            warn "Sentinel service failed to start — check: journalctl -u netguard-sentinel-export -n 30"
        fi
    else
        warn "Sentinel not configured in $ENV_FILE"
        log "  Enable with: sudo $INSTALL_DIR/install/pi/setup-sentinel-export.sh <workspace_id> <primary_key>"
        systemctl stop netguard-sentinel-export.service 2>/dev/null || true
    fi
}

configure_syslog_export() {
    systemctl enable netguard-syslog-export.service 2>/dev/null || true
    if [[ -f "$ENV_FILE" ]] && grep -qE '^\s*NETGUARD_SYSLOG_ENABLED=(1|true|yes)\s*$' "$ENV_FILE" 2>/dev/null; then
        log "Syslog export: configured — starting service"
        systemctl restart netguard-syslog-export.service 2>/dev/null || true
    fi
}

restart_services() {
    log "Restarting NetGuard services ..."
    for unit in netguard-arp-scanner netguard-risk-scorer netguard-dns-monitor \
        netguard-arp-spoof netguard-rogue-dhcp netguard-inbound-detector \
        netguard-policy-engine netguard-api; do
        systemctl restart "$unit.service" 2>/dev/null || true
    done
    systemctl restart netguard.target 2>/dev/null || true
}

print_summary() {
    local ip sentinel_status="not configured"
    ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    if [[ -f "$ENV_FILE" ]] && grep -qE '^\s*NETGUARD_SENTINEL_WORKSPACE_ID=.+$' "$ENV_FILE" 2>/dev/null; then
        if systemctl is-active --quiet netguard-sentinel-export.service; then
            sentinel_status="active"
        else
            sentinel_status="configured but not running"
        fi
    fi
    cat <<EOF

================================================================
 NetGuard update complete
================================================================
 Install dir:  $INSTALL_DIR
 Dashboard:    http://${ip:-<pi-ip>}:8000
 Env file:     $ENV_FILE (unchanged)
 Sentinel:     $sentinel_status

 Commands:
   sudo systemctl status netguard-sentinel-export
   sudo journalctl -u netguard-sentinel-export -f
================================================================
EOF
}

main() {
    require_root
    log "NetGuard Pi updater"
    log "Source:  $SOURCE_DIR"
    log "Target:  $INSTALL_DIR"

    if [[ ! -d "$INSTALL_DIR" ]]; then
        warn "$INSTALL_DIR not found — run install.sh for a fresh install instead"
        exit 1
    fi

    sync_application_files
    setup_python_venv
    bash "$SCRIPT_DIR/build-dashboard.sh" "$INSTALL_DIR"
    install_systemd_units
    configure_syslog_export
    configure_sentinel_export
    restart_services
    print_summary
}

main "$@"
