#!/usr/bin/env bash
# Restart a NetGuard detector systemd unit (invoked via passwordless sudo).
set -euo pipefail

DETECTOR_ID="${1:-}"
case "$DETECTOR_ID" in
    arp_scanner) UNIT="netguard-arp-scanner.service" ;;
    risk_scorer) UNIT="netguard-risk-scorer.service" ;;
    arp_spoof) UNIT="netguard-arp-spoof.service" ;;
    dns_monitor) UNIT="netguard-dns-monitor.service" ;;
    rogue_dhcp) UNIT="netguard-rogue-dhcp.service" ;;
    inbound) UNIT="netguard-inbound-detector.service" ;;
    policy_engine) UNIT="netguard-policy-engine.service" ;;
    *)
        echo "Unknown detector: $DETECTOR_ID" >&2
        exit 1
        ;;
esac

exec /bin/systemctl restart "$UNIT"
