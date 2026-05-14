#!/usr/bin/env bash
# Install cross-toolchain + PAM headers for aarch64-unknown-linux-gnu builds
# on GitHub Actions' ubuntu-latest runners.
#
# Why this is needed: enabling `dpkg --add-architecture arm64` on a stock
# noble runner causes apt to try fetching arm64 Packages from
# security.ubuntu.com, which only serves amd64/i386 and returns 404. We
# fix this by:
#   1. Restricting the default sources to amd64 only.
#   2. Adding a separate sources file pointing arm64 at ports.ubuntu.com
#      (the canonical mirror for non-x86 Ubuntu).
#   3. Enabling the arm64 dpkg architecture and updating apt.
#
# Idempotent — safe to run more than once.

set -euxo pipefail

# 1. Restrict existing sources to amd64.
if [[ -f /etc/apt/sources.list ]]; then
    sudo sed -i -E 's|^deb http|deb [arch=amd64] http|; s|^deb https|deb [arch=amd64] https|' /etc/apt/sources.list
fi
if [[ -f /etc/apt/sources.list.d/ubuntu.sources ]]; then
    # DEB822 format: ensure each stanza has `Architectures: amd64`.
    sudo awk '
        /^Types:/                  { print; print "Architectures: amd64"; next }
        /^Architectures:/          { next }
        { print }
    ' /etc/apt/sources.list.d/ubuntu.sources | sudo tee /etc/apt/sources.list.d/ubuntu.sources.tmp >/dev/null
    sudo mv /etc/apt/sources.list.d/ubuntu.sources.tmp /etc/apt/sources.list.d/ubuntu.sources
fi

# 2. Add arm64 sources pointing at ports.ubuntu.com.
codename="$(lsb_release -cs)"
sudo tee /etc/apt/sources.list.d/arm64-ports.list >/dev/null <<EOF
deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports/ ${codename} main restricted universe multiverse
deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports/ ${codename}-updates main restricted universe multiverse
deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports/ ${codename}-security main restricted universe multiverse
EOF

# 3. Enable arm64 + install.
sudo dpkg --add-architecture arm64
sudo apt-get update
sudo apt-get install -y \
    gcc-aarch64-linux-gnu \
    libclang-dev \
    libpam0g-dev:arm64
