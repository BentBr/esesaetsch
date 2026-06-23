#!/bin/sh
# Generate a host key if absent, refresh systemd, print next steps.
# Does NOT enable or start the service — operator does that explicitly.
set -e

KEY=/etc/esesaetsch/host_key
if [ ! -e "$KEY" ]; then
    /usr/bin/esesaetsch gen-key --host-key "$KEY"
    chmod 600 "$KEY"
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

echo "esesätsch installed. Add your keys to /etc/esesaetsch/config.toml, then:"
echo "    systemctl enable --now esesaetsch.service"
