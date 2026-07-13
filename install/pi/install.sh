#!/usr/bin/env bash
#
# NetGuard Raspberry Pi installer
# Installs to /opt/netguard, configures systemd, and starts all core services.
#
# Usage (from extracted release tarball or git clone):
#   chmod +x install.sh
#   sudo ./install.sh
#
set -euo pipefail

INSTALL_DIR="${NETGUARD_INSTALL_DIR:-/opt/netguard}"
NETGUARD_USER="${NETGUARD_USER:-netguard}"
NETGUARD_GROUP="${NETGUARD_GROUP:-netguard}"
DATA_DIR="/var/lib/netguard"
LOG_DIR="/var/log/netguard"
ENV_FILE="/etc/netguard/netguard.env"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETGUARD_PROFILE="${NETGUARD_PROFILE:-home}"

# Source tree: install/pi/install.sh -> repo root is ../..
if [[ -f "$SCRIPT_DIR/../../api/main.py" ]]; then
    SOURCE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
elif [[ -f "$SCRIPT_DIR/api/main.py" ]]; then
    SOURCE_DIR="$SCRIPT_DIR"
else
    echo "[!] Cannot locate NetGuard source files next to install.sh"
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

install_apt_packages() {
    log "Installing system packages ..."
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        python3 \
        python3-venv \
        python3-pip \
        python3-dev \
        python3-scapy \
        libpcap-dev \
        iptables \
        iproute2 \
        curl
}

ensure_user() {
    if ! id "$NETGUARD_USER" &>/dev/null; then
        log "Creating system user: $NETGUARD_USER"
        useradd --system --create-home --home-dir "/home/$NETGUARD_USER" \
            --shell /bin/bash "$NETGUARD_USER"
    fi
    if ! getent group "$NETGUARD_GROUP" &>/dev/null; then
        groupadd --system "$NETGUARD_GROUP"
    fi
    usermod -a -G "$NETGUARD_GROUP" "$NETGUARD_USER" 2>/dev/null || true
}

sync_application_files() {
    log "Installing application to $INSTALL_DIR ..."
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
    log "Creating Python virtual environment ..."
    if [[ ! -d "$INSTALL_DIR/venv" ]]; then
        python3 -m venv "$INSTALL_DIR/venv"
    fi
    "$INSTALL_DIR/venv/bin/python" -m pip install --upgrade pip
    "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"
    chown -R "$NETGUARD_USER:$NETGUARD_GROUP" "$INSTALL_DIR/venv"
}

dashboard_assets_ok() {
    local html="$INSTALL_DIR/api/static/index.html"
    local asset

    [[ -f "$html" ]] || return 1
    grep -q 'assets/' "$html" 2>/dev/null || return 1

    while IFS= read -r asset; do
        [[ -n "$asset" ]] || continue
        asset="${asset#/}"
        if [[ ! -f "$INSTALL_DIR/api/static/$asset" ]]; then
            warn "Missing dashboard asset: api/static/$asset"
            return 1
        fi
    done < <(grep -oE '/assets/[^"'"'"' ]+' "$html" | sort -u)

    return 0
}

build_dashboard() {
    if dashboard_assets_ok; then
        log "Dashboard static assets verified — skipping npm build"
        return
    fi

    if ! command -v npm &>/dev/null; then
        warn "npm not found — installing nodejs for dashboard build"
        apt-get install -y --no-install-recommends nodejs npm || true
    fi

    if ! command -v npm &>/dev/null; then
        warn "Dashboard not built — install nodejs/npm and re-run, or copy api/static/ manually"
        return
    fi

    log "Building dashboard ..."
    cd "$INSTALL_DIR/dashboard"
    npm install --no-fund --no-audit
    npm run build
    mkdir -p "$INSTALL_DIR/api/static"
    cp -r dist/* "$INSTALL_DIR/api/static/"
    chown -R "$NETGUARD_USER:$NETGUARD_GROUP" "$INSTALL_DIR/api/static"
}

setup_data_directories() {
    log "Creating data and log directories ..."
    mkdir -p "$DATA_DIR" "$LOG_DIR" /etc/netguard
    touch "$LOG_DIR/dnsmasq.log"
    chown "$NETGUARD_USER:$NETGUARD_GROUP" "$DATA_DIR" "$LOG_DIR"
    chmod 2775 "$DATA_DIR" "$LOG_DIR"
    chmod 664 "$LOG_DIR/dnsmasq.log"
}

install_env_file() {
    log "Installing $ENV_FILE (profile: $NETGUARD_PROFILE) ..."
    mkdir -p /etc/netguard

    if [[ -n "${NETGUARD_PROFILE_ENV:-}" && -f "$NETGUARD_PROFILE_ENV" ]]; then
        cp "$NETGUARD_PROFILE_ENV" "$ENV_FILE"
        chmod 644 "$ENV_FILE"
        return
    fi

    local profile_template="$SOURCE_DIR/install/profiles/pi-${NETGUARD_PROFILE}/netguard.env"
    if [[ -f "$profile_template" ]]; then
        cp "$profile_template" "$ENV_FILE"
        chmod 644 "$ENV_FILE"
        return
    fi

    cat >"$ENV_FILE" <<EOF
# NetGuard environment — managed by install.sh
NETGUARD_DB_PATH=$DATA_DIR/netguard.db
NETGUARD_LOG_DIR=$LOG_DIR
DNSMASQ_LOG_PATH=$LOG_DIR/dnsmasq.log
# Uncomment and set if gateway auto-detection is wrong:
# NETGUARD_GATEWAY_IP=192.168.1.1
# Require approval for newly discovered devices (1=yes, 0=no)
NETGUARD_REQUIRE_DEVICE_APPROVAL=1
# Optional notifications (or configure via dashboard /notifications/config)
# NETGUARD_TELEGRAM_BOT_TOKEN=
# NETGUARD_TELEGRAM_CHAT_ID=
# NETGUARD_ALERT_EMAIL_TO=
# Optional API key for write endpoints
# NETGUARD_API_KEY=
# Router enforcement (openwrt | linksys | velop | custom)
# NETGUARD_ROUTER_TYPE=openwrt
# NETGUARD_ROUTER_URL=http://192.168.1.1
# NETGUARD_ROUTER_USER=root
# NETGUARD_ROUTER_PASSWORD=
# NETGUARD_ROUTER_TOKEN=
# MSP collector (central server URL + site token)
# NETGUARD_MSP_COLLECTOR_URL=https://msp.example.com
# NETGUARD_SITE_TOKEN=
# NETGUARD_SITE_ID=default
# MSP admin key for POST /msp/sites/register
# NETGUARD_MSP_ADMIN_KEY=
# Syslog / SIEM export (optional)
# NETGUARD_SYSLOG_ENABLED=false
# NETGUARD_SYSLOG_HOST=192.168.1.10
# NETGUARD_SYSLOG_PORT=514
# NETGUARD_SYSLOG_PROTOCOL=udp
# Microsoft Sentinel HTTPS export (optional — auto-starts when workspace ID is set)
# NETGUARD_SENTINEL_WORKSPACE_ID=
# NETGUARD_SENTINEL_PRIMARY_KEY=
# NETGUARD_SENTINEL_LOG_TYPE=NetGuard
EOF
    chmod 644 "$ENV_FILE"
}

migrate_existing_database() {
  local legacy_db=""
  for candidate in \
      "$SOURCE_DIR/netguard.db" \
      "/home/$NETGUARD_USER/netguard/netguard.db" \
      "/home/$NETGUARD_USER/netguard.db"; do
      if [[ -f "$candidate" ]]; then
          legacy_db="$candidate"
          break
      fi
  done

  if [[ -n "$legacy_db" && ! -f "$DATA_DIR/netguard.db" ]]; then
      log "Migrating existing database from $legacy_db"
      cp "$legacy_db" "$DATA_DIR/netguard.db"
      chown "$NETGUARD_USER:$NETGUARD_GROUP" "$DATA_DIR/netguard.db"
      chmod 664 "$DATA_DIR/netguard.db"
  fi
}

install_systemd_units() {
    log "Installing systemd services ..."
    local systemd_dir=""
    if [[ -d "$SOURCE_DIR/install/pi/systemd" ]]; then
        systemd_dir="$SOURCE_DIR/install/pi/systemd"
    elif [[ -d "$SCRIPT_DIR/systemd" ]]; then
        systemd_dir="$SCRIPT_DIR/systemd"
    else
        echo "[!] Cannot find systemd unit files"
        exit 1
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
        install -m 644 "$systemd_dir/$unit" "/etc/systemd/system/$unit"
    done
    systemctl daemon-reload
}

configure_dns_relay() {
    local enabled=""
    if [[ -f "$ENV_FILE" ]]; then
        enabled="$(grep -E '^\s*NETGUARD_DNS_RELAY=' "$ENV_FILE" | tail -1 | cut -d= -f2 | tr -d ' \r' || true)"
    fi
    if [[ "$enabled" != "1" ]]; then
        log "DNS relay disabled (set NETGUARD_DNS_RELAY=1 in $ENV_FILE to log all LAN DNS)"
        return
    fi

    local relay_script=""
    if [[ -f "$SOURCE_DIR/install/pi/setup-dns-relay.sh" ]]; then
        relay_script="$SOURCE_DIR/install/pi/setup-dns-relay.sh"
    elif [[ -f "$SCRIPT_DIR/setup-dns-relay.sh" ]]; then
        relay_script="$SCRIPT_DIR/setup-dns-relay.sh"
    fi

    if [[ -z "$relay_script" ]]; then
        warn "setup-dns-relay.sh not found — skipping DNS relay setup"
        return
    fi

    chmod +x "$relay_script"
    log "Enabling Pi DNS relay (dnsmasq) for full-network DNS logging ..."
    bash "$relay_script" "$ENV_FILE" || warn "DNS relay setup failed — DNS page may only show Pi/router traffic"
}

configure_firewall() {
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qi "Status: active"; then
        log "Opening firewall port 8000 for dashboard access ..."
        ufw allow 8000/tcp comment 'NetGuard dashboard' >/dev/null 2>&1 || true
    fi
}

configure_api_restart() {
    local restart_script="$INSTALL_DIR/scripts/restart-api.sh"
    if [[ ! -f "$restart_script" ]]; then
        warn "Missing $restart_script — Settings API restart button will not work"
        return
    fi
    log "Configuring passwordless API restart for dashboard Settings ..."
    chmod 755 "$restart_script"
    chown root:root "$restart_script"
    local sudoers_file="/etc/sudoers.d/netguard-api-restart"
    printf '%s\n' "netguard ALL=(root) NOPASSWD: $restart_script" > "$sudoers_file"
    chmod 440 "$sudoers_file"
    if ! visudo -cf "$sudoers_file" >/dev/null 2>&1; then
        warn "sudoers validation failed for $sudoers_file"
    fi
}

configure_detector_restart() {
    local restart_script="$INSTALL_DIR/scripts/restart-detector.sh"
    if [[ ! -f "$restart_script" ]]; then
        warn "Missing $restart_script — Monitoring restart buttons will not work"
        return
    fi
    log "Configuring passwordless detector restart for dashboard Monitoring ..."
    chmod 755 "$restart_script"
    chown root:root "$restart_script"
    local sudoers_file="/etc/sudoers.d/netguard-detector-restart"
    printf '%s\n' "netguard ALL=(root) NOPASSWD: $restart_script" > "$sudoers_file"
    chmod 440 "$sudoers_file"
    if ! visudo -cf "$sudoers_file" >/dev/null 2>&1; then
        warn "sudoers validation failed for $sudoers_file"
    fi
}

configure_sentinel_export() {
    systemctl enable netguard-sentinel-export.service 2>/dev/null || true
    if grep -qE '^\s*NETGUARD_SENTINEL_ENABLED=(0|false|no|off)\s*$' "$ENV_FILE" 2>/dev/null; then
        log "Sentinel export disabled in $ENV_FILE"
        systemctl stop netguard-sentinel-export.service 2>/dev/null || true
        return
    fi
    if grep -qE '^\s*NETGUARD_SENTINEL_WORKSPACE_ID=.+$' "$ENV_FILE" 2>/dev/null; then
        log "Microsoft Sentinel export: configured — starting service"
        systemctl restart netguard-sentinel-export.service 2>/dev/null || true
    else
        log "Sentinel export not configured (set NETGUARD_SENTINEL_* in $ENV_FILE)"
        log "  Or run: sudo $INSTALL_DIR/install/pi/setup-sentinel-export.sh <workspace_id> <primary_key>"
    fi
}

configure_syslog_export() {
    systemctl enable netguard-syslog-export.service 2>/dev/null || true
    if grep -qE '^\s*NETGUARD_SYSLOG_ENABLED=(1|true|yes)\s*$' "$ENV_FILE" 2>/dev/null; then
        systemctl restart netguard-syslog-export.service 2>/dev/null || true
        log "Syslog export enabled"
    fi
}

enable_services() {
    log "Enabling NetGuard services (start on boot) ..."
    systemctl enable netguard.target
    systemctl enable netguard-network-blocker.service || true
    for unit in netguard-api.service netguard-arp-scanner.service \
        netguard-risk-scorer.service netguard-dns-monitor.service \
        netguard-arp-spoof.service netguard-rogue-dhcp.service \
        netguard-inbound-detector.service netguard-policy-engine.service; do
        systemctl enable "$unit" 2>/dev/null || true
    done

    log "Starting NetGuard services ..."
    systemctl restart netguard-arp-scanner.service
    systemctl restart netguard-risk-scorer.service
    systemctl restart netguard-dns-monitor.service
    systemctl restart netguard-arp-spoof.service
    systemctl restart netguard-rogue-dhcp.service
    systemctl restart netguard-inbound-detector.service
    systemctl restart netguard-policy-engine.service
    systemctl enable --now netguard-threat-intel.timer 2>/dev/null || true
    systemctl enable --now netguard-weekly-report.timer 2>/dev/null || true

    if [[ "$NETGUARD_PROFILE" == "msp" ]]; then
        systemctl enable --now netguard-msp-agent.timer 2>/dev/null || true
        log "MSP heartbeat timer enabled (profile: msp)"
    else
        systemctl disable --now netguard-msp-agent.timer 2>/dev/null || true
        systemctl disable --now netguard-msp-agent.service 2>/dev/null || true
    fi

    systemctl restart netguard-api.service
    systemctl restart netguard.target

    configure_syslog_export
    configure_sentinel_export

    # Pi home: ARP network blocker enforces dashboard blocks on typical ISP routers.
    if [[ "$NETGUARD_PROFILE" == "home" ]]; then
        systemctl enable --now netguard-network-blocker.service 2>/dev/null || true
        log "Network blocker enabled (ARP isolation for blocked devices)"
    else
        systemctl disable --now netguard-network-blocker.service 2>/dev/null || true
    fi
}

verify_installation() {
    log "Verifying API and dashboard ..."
    sleep 2

    if ! systemctl is-active --quiet netguard-api.service; then
        warn "netguard-api.service is not running — check: sudo journalctl -u netguard-api -n 40 --no-pager"
        return 1
    fi

    local health
    health="$(curl -fsS --max-time 5 http://127.0.0.1:8000/health 2>/dev/null || true)"
    if [[ -z "$health" ]]; then
        warn "API not responding on port 8000 — check: sudo systemctl status netguard-api"
        return 1
    fi

    if ! grep -q '"dashboard_bundled": true' <<<"$health"; then
        warn "API is up but dashboard files are missing — re-run install.sh to rebuild the UI"
        return 1
    fi

    log "Dashboard ready at http://$(hostname -I 2>/dev/null | awk '{print $1}'):8000"
    return 0
}

print_summary() {
    local ip
    ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    cat <<EOF

================================================================
 NetGuard installation complete (profile: $NETGUARD_PROFILE)
================================================================
 Install dir:  $INSTALL_DIR
 Database:     $DATA_DIR/netguard.db
 Logs:         $LOG_DIR
 Dashboard:    http://${ip:-<pi-ip>}:8000

 Core services (enabled on boot):
   netguard-api.service
   netguard-arp-scanner.service
   netguard-risk-scorer.service
   netguard-dns-monitor.service
   netguard-arp-spoof.service
   netguard-sentinel-export.service (if NETGUARD_SENTINEL_* configured)

 Documentation:
   install/pi/NetGuard-Pi-Install-Guide.pdf

 Useful commands:
   sudo systemctl status netguard.target
   sudo systemctl restart netguard.target
   sudo journalctl -u netguard-api -f
   sudo journalctl -u netguard-sentinel-export -f

 Update in-place (from a new release tarball):
   sudo ./install/pi/update-netguard.sh

 Enable Sentinel (one-time, after setting Azure credentials):
   sudo ./install/pi/setup-sentinel-export.sh <workspace_id> <primary_key>

 Optional (disabled by default — limited on mesh WiFi):
   sudo systemctl enable --now netguard-network-blocker.service

 Uninstall:
   sudo ./uninstall.sh
================================================================
EOF
}

main() {
    require_root
    log "NetGuard Pi installer (profile: $NETGUARD_PROFILE)"
    log "Source:  $SOURCE_DIR"
    log "Target:  $INSTALL_DIR"

    install_apt_packages
    ensure_user
    sync_application_files
    setup_python_venv
    build_dashboard
    setup_data_directories
    install_env_file
    migrate_existing_database
    install_systemd_units
    configure_dns_relay
    configure_firewall
    configure_api_restart
    configure_detector_restart
    enable_services
    verify_installation || true
    print_summary
}

main "$@"
