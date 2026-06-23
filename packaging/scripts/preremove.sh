#!/bin/sh
# Stop the service before files are removed.
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop esesaetsch.service 2>/dev/null || true
fi
