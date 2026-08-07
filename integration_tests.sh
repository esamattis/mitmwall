#!/bin/sh

set -eu

# The test suite exercises Linux-specific firewall and system integration.
if [ "$(uname -s)" != "Linux" ]; then
    echo "integration_tests.sh: Linux is required to run all tests" >&2
    exit 1
fi

if systemctl list-unit-files mitmwall.service >/dev/null 2>&1; then
    sudo systemctl stop mitmwall.service
fi

original_ipv4_forwarding=$(sysctl -n net.ipv4.ip_forward)
original_ipv6_forwarding=$(sysctl -n net.ipv6.conf.all.forwarding)
original_ipv4_send_redirects=$(sysctl -n net.ipv4.conf.all.send_redirects)

bypass_test_user=mitmwall-integration-bypass
if ! id "$bypass_test_user" >/dev/null 2>&1; then
    sudo useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$bypass_test_user"
fi

sudo ./dev-install.sh

# The suite stops and restarts mitmwall to verify forwarding-state restoration.
# On otherwise-empty nftables hosts, removing the last rule can discard a table
# and make an immediate iptables-nft probe of the deleted chain fail as
# "incompatible" instead of simply absent. Keep one unrelated loopback rule in
# each exercised table so the restart tests cover mitmwall's lifecycle rather
# than that empty-table frontend edge case. Add these only after installation so
# install.sh still exercises stale-rule cleanup against the host's original state.
keepalive_comment=mitmwall-integration-table-keepalive
for table_command in iptables ip6tables; do
    sudo "$table_command" -w 10 -t filter -A OUTPUT -o lo -m comment --comment "$keepalive_comment" -j ACCEPT
    sudo "$table_command" -w 10 -t nat -A OUTPUT -o lo -m comment --comment "$keepalive_comment" -j ACCEPT
done

state_dir=/run/mitmwall
state_file=$state_dir/forwarding-state.json
failure_output=$(mktemp)
corrupt_state=0
cleanup() {
    if [ "$corrupt_state" -eq 1 ]; then
        sudo rm -f "$state_file"
    fi
    sudo systemctl start mitmwall.service >/dev/null 2>&1 || true
    # Remove the temporary rules after restoring the service. Its managed rules
    # now keep the tables initialized, so deleting the keepalives cannot recreate
    # the empty-table condition during cleanup.
    for table_command in iptables ip6tables; do
        sudo "$table_command" -w 10 -t filter -D OUTPUT -o lo -m comment --comment "$keepalive_comment" -j ACCEPT >/dev/null 2>&1 || true
        sudo "$table_command" -w 10 -t nat -D OUTPUT -o lo -m comment --comment "$keepalive_comment" -j ACCEPT >/dev/null 2>&1 || true
    done
    rm -f "$failure_output"
}
trap cleanup EXIT

test "$(sudo stat -c %U:%G "$state_dir")" = root:root
test "$(sudo stat -c %a "$state_dir")" = 700
test "$(sudo stat -c %U:%G "$state_file")" = root:root
test "$(sudo stat -c %a "$state_file")" = 600

snapshot_checksum=$(sudo sha256sum "$state_file")
sudo /opt/mitmwall/hook.py start
test "$(sudo sha256sum "$state_file")" = "$snapshot_checksum"
test "$(sysctl -n net.ipv4.ip_forward)" = 1
test "$(sysctl -n net.ipv6.conf.all.forwarding)" = 1
test "$(sysctl -n net.ipv4.conf.all.send_redirects)" = 0
if [ "$original_ipv4_forwarding" -eq 0 ]; then
    sudo iptables -w 10 -t filter -C FORWARD -m comment --comment mitmwall-forwarding-guard -j DROP
fi
if [ "$original_ipv6_forwarding" -eq 0 ]; then
    sudo ip6tables -w 10 -t filter -C FORWARD -m comment --comment mitmwall-forwarding-guard -j DROP
fi

sudo systemctl stop mitmwall.service
test "$(sysctl -n net.ipv4.ip_forward)" = "$original_ipv4_forwarding"
test "$(sysctl -n net.ipv6.conf.all.forwarding)" = "$original_ipv6_forwarding"
test "$(sysctl -n net.ipv4.conf.all.send_redirects)" = "$original_ipv4_send_redirects"
if sudo iptables -w 10 -t filter -C FORWARD -m comment --comment mitmwall-forwarding-guard -j DROP 2>/dev/null; then
    echo "integration_tests.sh: IPv4 forwarding guard remained after stop" >&2
    exit 1
fi
if sudo ip6tables -w 10 -t filter -C FORWARD -m comment --comment mitmwall-forwarding-guard -j DROP 2>/dev/null; then
    echo "integration_tests.sh: IPv6 forwarding guard remained after stop" >&2
    exit 1
fi

sudo install -d -o root -g root -m 0700 "$state_dir"
printf '%s\n' 'not json' | sudo tee "$state_file" >/dev/null
sudo chmod 0600 "$state_file"
corrupt_state=1
if sudo /opt/mitmwall/hook.py start >"$failure_output" 2>&1; then
    echo "integration_tests.sh: corrupt forwarding state unexpectedly allowed startup" >&2
    exit 1
fi
if ! grep -q "saved forwarding state is corrupt" "$failure_output"; then
    echo "integration_tests.sh: corrupt forwarding state failure was not clear" >&2
    exit 1
fi
test "$(sysctl -n net.ipv4.ip_forward)" = "$original_ipv4_forwarding"
test "$(sysctl -n net.ipv6.conf.all.forwarding)" = "$original_ipv6_forwarding"
test "$(sysctl -n net.ipv4.conf.all.send_redirects)" = "$original_ipv4_send_redirects"

sudo rm -f "$state_file"
corrupt_state=0
sudo systemctl start mitmwall.service

python3 "$(dirname "$0")/tests/integration/integration_tests.py"
