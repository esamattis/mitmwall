#!/bin/sh

set -eu

if sudo systemctl list-unit-files mitmwall.service >/dev/null 2>&1; then
    sudo systemctl stop mitmwall.service
fi

sudo ./install.sh
sudo install -m 0644 ./rules.toml /opt/mitmwall/rules.toml
sudo systemctl restart mitmwall.service
