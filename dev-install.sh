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
user_group=$(id -gn mitmwall)
rm -f /etc/mitmwall/rules.d/5-examples.toml
install -o root -g "$user_group" -m 0640 ./integration-test-rules.toml /etc/mitmwall/rules.d/5-integration-tests.toml
install -o root -g "$user_group" -m 0640 ./integration-test-config.toml /etc/mitmwall/config.toml
systemctl restart mitmwall.service
