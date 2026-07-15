#!/usr/bin/env bash
#
# Build the NetGuard dashboard and copy output into api/static/.
# Used by install.sh and update-netguard.sh on Raspberry Pi.
#
set -euo pipefail

INSTALL_DIR="${1:-${NETGUARD_INSTALL_DIR:-/opt/netguard}}"
NETGUARD_USER="${NETGUARD_USER:-netguard}"
NETGUARD_GROUP="${NETGUARD_GROUP:-netguard}"

log() { printf '[*] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*"; }

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

dashboard_source_newer_than_static() {
    local html="$INSTALL_DIR/api/static/index.html"
    [[ -f "$html" ]] || return 0
    find "$INSTALL_DIR/dashboard/src" -type f -newer "$html" -print -quit | grep -q .
}

clean_stale_static_assets() {
    local html="$INSTALL_DIR/api/static/index.html"
    local assets_dir="$INSTALL_DIR/api/static/assets"
    local referenced asset path

    [[ -d "$assets_dir" ]] || return

    mapfile -t referenced < <(
        grep -oE '/assets/[^"'"'"' ]+' "$html" 2>/dev/null \
            | sed 's|^/assets/||' \
            | sort -u
    )

    for asset in "$assets_dir"/*; do
        [[ -f "$asset" ]] || continue
        path="$(basename "$asset")"
        local found=0
        for ref in "${referenced[@]}"; do
            if [[ "$path" == "$ref" ]]; then
                found=1
                break
            fi
        done
        if [[ "$found" -eq 0 ]]; then
            rm -f "$asset"
        fi
    done
}

main() {
    if [[ "${NETGUARD_FORCE_DASHBOARD_BUILD:-}" != "1" ]] \
        && dashboard_assets_ok \
        && ! dashboard_source_newer_than_static; then
        log "Dashboard static assets up to date — skipping npm build"
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
    clean_stale_static_assets
    chown -R "$NETGUARD_USER:$NETGUARD_GROUP" "$INSTALL_DIR/api/static"
    log "Dashboard built into $INSTALL_DIR/api/static"
}

main "$@"
