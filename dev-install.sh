#!/bin/sh

set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "dev-install.sh: must be run as root (sudo)" >&2
    exit 1
fi

if systemctl list-unit-files mitmwall.service >/dev/null 2>&1; then
    systemctl stop mitmwall.service
fi

./install.sh
install -o mitmwall -m 0600 ./example-rules.toml /opt/mitmwall/rules.d/examples.toml
systemctl restart mitmwall.service
