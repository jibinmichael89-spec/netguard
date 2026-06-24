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

build_dashboard() {
    if [[ -f "$INSTALL_DIR/api/static/index.html" ]] \
        && grep -q 'assets/' "$INSTALL_DIR/api/static/index.html" 2>/dev/null; then
        log "Dashboard static assets already present — skipping npm build"
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
    log "Installing $ENV_FILE ..."
    cat >"$ENV_FILE" <<EOF
# NetGuard environment — managed by install.sh
NETGUARD_DB_PATH=$DATA_DIR/netguard.db
NETGUARD_LOG_DIR=$LOG_DIR
DNSMASQ_LOG_PATH=$LOG_DIR/dnsmasq.log
# Uncomment and set if gateway auto-detection is wrong:
# NETGUARD_GATEWAY_IP=192.168.1.1
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
        netguard-arp-spoof.service netguard-network-blocker.service; do
        install -m 644 "$systemd_dir/$unit" "/etc/systemd/system/$unit"
    done
    systemctl daemon-reload
}

enable_services() {
    log "Enabling NetGuard services (start on boot) ..."
    systemctl enable netguard.target
    systemctl enable netguard-network-blocker.service || true

    log "Starting NetGuard services ..."
    systemctl restart netguard-arp-scanner.service
    systemctl restart netguard-risk-scorer.service
    systemctl restart netguard-dns-monitor.service
    systemctl restart netguard-arp-spoof.service
    systemctl restart netguard-api.service
    systemctl restart netguard.target

    # Optional — mesh networks may limit effectiveness
    systemctl disable --now netguard-network-blocker.service 2>/dev/null || true
}

print_summary() {
    local ip
    ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    cat <<EOF

================================================================
 NetGuard installation complete
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

 Documentation:
   install/pi/NetGuard-Pi-Install-Guide.pdf

 Useful commands:
   sudo systemctl status netguard.target
   sudo systemctl restart netguard.target
   sudo journalctl -u netguard-api -f

 Optional (disabled by default — limited on mesh WiFi):
   sudo systemctl enable --now netguard-network-blocker.service

 Uninstall:
   sudo ./uninstall.sh
================================================================
EOF
}

main() {
    require_root
    log "NetGuard Pi installer"
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
    enable_services
    print_summary
}

main "$@"
