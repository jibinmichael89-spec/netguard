#!/usr/bin/env bash
#
# Build a self-contained Pi release tarball with pre-built dashboard.
#
# Usage:
#   ./install/pi/build-release.sh
#
# Output:
#   dist/NetGuard-pi-<version>.tar.gz
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="$(date +%Y.%m.%d)"
OUTPUT="$ROOT/dist/NetGuard-pi-${VERSION}.tar.gz"
STAGING="$ROOT/build/pi-release/NetGuard-pi"

log() { printf '[*] %s\n' "$*"; }

log "Building dashboard ..."
cd "$ROOT/dashboard"
if command -v npm &>/dev/null; then
    npm install --no-fund --no-audit
    npm run build
    mkdir -p "$ROOT/api/static"
    cp -r dist/* "$ROOT/api/static/"
else
    log "npm not found — using existing api/static if present"
fi

log "Staging release files ..."
rm -rf "$STAGING"
mkdir -p "$STAGING"
rsync -a \
    --exclude 'venv/' \
    --exclude 'node_modules/' \
    --exclude '.git/' \
    --exclude 'build/' \
    --exclude 'dist/' \
    --exclude 'dashboard/node_modules/' \
    --exclude 'dashboard/dist/' \
    --exclude '__pycache__/' \
    --exclude '*.pyc' \
    --exclude 'netguard.db' \
    "$ROOT/" "$STAGING/"

# Top-level install scripts for convenience after extract
cp "$ROOT/install/pi/install.sh" "$STAGING/install.sh"
cp "$ROOT/install/pi/uninstall.sh" "$STAGING/uninstall.sh"
chmod +x "$STAGING/install.sh" "$STAGING/uninstall.sh"
chmod +x "$STAGING/install/pi/update-netguard.sh" 2>/dev/null || true
chmod +x "$STAGING/install/pi/setup-sentinel-export.sh" 2>/dev/null || true

# Include PDF install guide when present
if [[ -f "$ROOT/install/pi/NetGuard-Pi-Install-Guide.pdf" ]]; then
    mkdir -p "$STAGING/install/pi"
    cp "$ROOT/install/pi/NetGuard-Pi-Install-Guide.pdf" "$STAGING/install/pi/"
    cp "$ROOT/install/pi/NetGuard-Pi-Install-Guide.md" "$STAGING/install/pi/" 2>/dev/null || true
fi

mkdir -p "$ROOT/dist"
tar -czf "$OUTPUT" -C "$STAGING/.." "NetGuard-pi"
log "Created: $OUTPUT"
log ""
log "Deploy on Pi:"
log "  scp $OUTPUT netguard@<pi-ip>:~/"
log "  ssh netguard@<pi-ip>"
log "  tar xzf NetGuard-pi-${VERSION}.tar.gz"
log "  cd NetGuard-pi && sudo ./install/pi/update-netguard.sh   # existing install"
log "  cd NetGuard-pi && sudo ./install.sh                      # fresh install"
log ""
log "Enable Sentinel (one-time, on Pi):"
log "  sudo ./install/pi/setup-sentinel-export.sh <workspace_id> <primary_key>"
