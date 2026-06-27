#!/usr/bin/env bash
# NetGuard Pi MSP profile installer wrapper
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export NETGUARD_PROFILE=msp
export NETGUARD_PROFILE_ENV="$SCRIPT_DIR/netguard.env"
MAIN_INSTALL="$SCRIPT_DIR/../../pi/install.sh"
if [[ ! -f "$MAIN_INSTALL" ]]; then
    echo "[!] Cannot find installer: $MAIN_INSTALL" >&2
    exit 1
fi
exec bash "$MAIN_INSTALL" "$@"
