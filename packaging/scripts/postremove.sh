#!/bin/sh
# Refresh systemd after removal. Host key + config are intentionally left
# in place (removed only on a deb purge) so reinstalls keep server identity.
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload 2>/dev/null || true
fi
