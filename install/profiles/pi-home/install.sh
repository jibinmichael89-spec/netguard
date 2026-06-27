#!/usr/bin/env bash
# NetGuard Pi Home profile installer wrapper
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export NETGUARD_PROFILE=home
export NETGUARD_PROFILE_ENV="$SCRIPT_DIR/netguard.env"
exec "$SCRIPT_DIR/../../pi/install.sh" "$@"
