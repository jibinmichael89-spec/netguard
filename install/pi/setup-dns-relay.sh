#!/usr/bin/env bash
# Configure dnsmasq on the Pi so LAN DNS queries are logged for NetGuard.
# Requires router DHCP to hand out this Pi's IP as the DNS server.
set -euo pipefail

ENV_FILE="${1:-/etc/netguard/netguard.env}"
LOG_DIR="/var/log/netguard"
GATEWAY=""

if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    source <(grep -E '^(NETGUARD_LOG_DIR|DNSMASQ_LOG_PATH|NETGUARD_GATEWAY_IP)=' "$ENV_FILE" | sed 's/^/export /')
fi

LOG_DIR="${NETGUARD_LOG_DIR:-$LOG_DIR}"
DNSMASQ_LOG_PATH="${DNSMASQ_LOG_PATH:-$LOG_DIR/dnsmasq.log}"
GATEWAY="${NETGUARD_GATEWAY_IP:-}"

LAN_IP="$(ip -4 route get 8.8.8.8 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')"
IFACE="$(ip -4 route get 8.8.8.8 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"

if [[ -z "$LAN_IP" || -z "$IFACE" ]]; then
    echo "[!] Could not detect LAN IP/interface for DNS relay"
    exit 1
fi

if [[ -z "$GATEWAY" ]]; then
    GATEWAY="$(ip -4 route show default dev "$IFACE" 2>/dev/null | awk '{print $3; exit}')"
fi
if [[ -z "$GATEWAY" ]]; then
    GATEWAY="1.1.1.1"
fi

mkdir -p "$(dirname "$DNSMASQ_LOG_PATH")"
touch "$DNSMASQ_LOG_PATH"
chmod 666 "$DNSMASQ_LOG_PATH"

apt-get install -y --no-install-recommends dnsmasq

if ss -lun 2>/dev/null | grep -q ':53 '; then
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        mkdir -p /etc/systemd/resolved.conf.d
        cat >/etc/systemd/resolved.conf.d/netguard-no-stub.conf <<'EOF'
[Resolve]
DNSStubListener=no
EOF
        systemctl restart systemd-resolved
    fi
fi

# Avoid "illegal repeated keyword" — stock dnsmasq.conf often duplicates bind/listen options.
if [[ ! -f /etc/dnsmasq.conf.netguard-backup ]]; then
    cp /etc/dnsmasq.conf /etc/dnsmasq.conf.netguard-backup
fi

cat >/etc/dnsmasq.conf <<'EOF'
# NetGuard DNS relay — settings live in /etc/dnsmasq.d/netguard.conf only.
conf-dir=/etc/dnsmasq.d/,*.conf
EOF

mkdir -p /etc/dnsmasq.d
for dropin in /etc/dnsmasq.d/*; do
  [[ -e "$dropin" ]] || continue
  base="$(basename "$dropin")"
  [[ "$base" == "netguard.conf" || "$base" == "README" ]] && continue
  mv -f "$dropin" "${dropin}.netguard-disabled"
done

cat >/etc/dnsmasq.d/netguard.conf <<EOF
# NetGuard LAN DNS relay — logs queries for the dashboard DNS page.
# Set your router DHCP DNS server to: $LAN_IP
interface=$IFACE
bind-interfaces
listen-address=$LAN_IP
port=53
log-queries
log-facility=$DNSMASQ_LOG_PATH
server=$GATEWAY
no-resolv
cache-size=1000
EOF

if ! dnsmasq --test 2>/tmp/dnsmasq-test.err; then
    echo "[!] dnsmasq configuration test failed:"
    cat /tmp/dnsmasq-test.err
    echo "[*] Restored backup is at /etc/dnsmasq.conf.netguard-backup"
    exit 1
fi

systemctl enable dnsmasq
systemctl restart dnsmasq

cat <<EOF

================================================================
 NetGuard DNS relay enabled on $LAN_IP ($IFACE)
================================================================
 1. Open your Linksys router admin (http://192.168.1.1)
 2. Set DHCP DNS server to:  $LAN_IP
    (Connectivity → Local Network → DHCP Settings → DNS)
 3. On phones/laptops: turn Wi-Fi off and on (renew DHCP)
 4. Browse a website — DNS Activity should show each device

 Upstream DNS forwarder: $GATEWAY
 Query log file:          $DNSMASQ_LOG_PATH
================================================================
EOF
