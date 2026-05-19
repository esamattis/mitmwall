#!/bin/sh

set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "clear-iptables.sh: must be run as root" >&2
    exit 1
fi

user=mitmwall
proxy_port=58080

# Remove the transparent HTTP/HTTPS redirects installed by add-iptables.sh.
# These redirects capture direct outbound web traffic from non-proxy users and
# send it to the local proxy port.
remove_redirect_rule() {
    table_cmd=$1
    dport=$2

    while "$table_cmd" -t nat -C OUTPUT -p tcp -m owner ! --uid-owner "$user" --dport "$dport" -j REDIRECT --to-port "$proxy_port" >/dev/null 2>&1; do
        "$table_cmd" -t nat -D OUTPUT -p tcp -m owner ! --uid-owner "$user" --dport "$dport" -j REDIRECT --to-port "$proxy_port"
    done
}

# Remove the outbound allowlist/blocklist chain installed by add-iptables.sh.
# That chain allows established/related packets so inbound services such as SSH
# keep working, allows the proxy user to reach upstream hosts, allows other
# users to connect to the local proxy port on this host and DNS, and blocks all
# other new outbound traffic.
remove_output_filter() {
    table_cmd=$1
    chain=MITMWALL_OUTPUT

    while "$table_cmd" -t filter -C OUTPUT -j "$chain" >/dev/null 2>&1; do
        "$table_cmd" -t filter -D OUTPUT -j "$chain"
    done

    if "$table_cmd" -t filter -L "$chain" >/dev/null 2>&1; then
        "$table_cmd" -t filter -F "$chain"
        "$table_cmd" -t filter -X "$chain"
    fi
}

remove_redirect_rule iptables 80
remove_redirect_rule iptables 443
remove_redirect_rule ip6tables 80
remove_redirect_rule ip6tables 443

remove_output_filter iptables
remove_output_filter ip6tables
