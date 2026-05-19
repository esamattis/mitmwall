#!/bin/sh

set -eu

sudo systemctl stop mitmwall.service
sudo ./install.sh
sudo install -m 0644 ./rules.toml /opt/mitmwall/rules.toml
sudo systemctl restart mitmwall.service
