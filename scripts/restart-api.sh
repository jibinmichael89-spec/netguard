#!/usr/bin/env bash
# Restart NetGuard API (invoked via passwordless sudo from the netguard user).
set -euo pipefail
exec /bin/systemctl restart netguard-api.service
