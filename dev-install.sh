#!/bin/sh

set -eu

if sudo systemctl list-unit-files mitmwall.service >/dev/null 2>&1; then
    sudo systemctl stop mitmwall.service
fi

sudo ./install.sh
sudo install -o mitmwall -m 0600 ./example-rules.toml /opt/mitmwall/rules.d/examples.toml
sudo systemctl restart mitmwall.service
