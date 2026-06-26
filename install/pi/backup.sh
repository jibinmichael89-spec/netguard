#!/usr/bin/env bash
# Backup NetGuard database and configuration.
set -euo pipefail

DATA_DIR="${NETGUARD_DATA_DIR:-/var/lib/netguard}"
BACKUP_DIR="${NETGUARD_BACKUP_DIR:-/var/lib/netguard/backups}"
STAMP="$(date +%Y%m%d-%H%M%S)"
DEST="$BACKUP_DIR/netguard-$STAMP.tar.gz"

mkdir -p "$BACKUP_DIR"
tar -czf "$DEST" \
    -C "$DATA_DIR" netguard.db 2>/dev/null || true
if [[ -f /etc/netguard/netguard.env ]]; then
    tar -rf "$DEST" -C / etc/netguard/netguard.env 2>/dev/null || \
        tar -czf "$DEST" -C / etc/netguard/netguard.env
fi
echo "Backup created: $DEST"
