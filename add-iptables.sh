#!/bin/sh

set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "add-iptables.sh: must be run as root" >&2
    exit 1
fi

user=mitmwall
proxy_port=58080
web_port=58081

# https://docs.mitmproxy.org/stable/howto/transparent/
#
# Policy installed by this script:
# - Redirect outbound HTTP/HTTPS from non-proxy users to the local proxy.
# - Allow established/related packets so inbound services such as SSH keep working.
# - Allow the proxy user to make outbound upstream connections.
# - Allow the system DNS resolver (systemd-resolve) to reach upstream DNS.
# - Allow other users to connect only to the local proxy and web UI ports on this host.
# - Allow DNS only to local resolvers so clients can resolve hostnames.
# - Drop all other new outbound traffic so applications cannot bypass the proxy.

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
sysctl -w net.ipv4.conf.all.send_redirects=0

# Capture direct outbound HTTP/HTTPS attempts from non-proxy users and
# transparently redirect them to the local proxy.
add_redirect_rule() {
    table_cmd=$1
    dport=$2

    if ! "$table_cmd" -t nat -C OUTPUT -p tcp -m owner ! --uid-owner "$user" --dport "$dport" -j REDIRECT --to-port "$proxy_port" >/dev/null 2>&1; then
        "$table_cmd" -t nat -A OUTPUT -p tcp -m owner ! --uid-owner "$user" --dport "$dport" -j REDIRECT --to-port "$proxy_port"
    fi
}

# Enforce the outbound allowlist. Established/related packets are allowed so
# replies from inbound connections (for example SSH) are not broken. The proxy
# user is allowed to reach the network, clients are allowed to reach the local
# proxy and web UI on this host and DNS, and every other new outbound connection
# is blocked.
add_output_filter() {
    table_cmd=$1
    chain=MITMWALL_OUTPUT

    if ! "$table_cmd" -t filter -L "$chain" >/dev/null 2>&1; then
        "$table_cmd" -t filter -N "$chain"
    fi

    "$table_cmd" -t filter -F "$chain"
    "$table_cmd" -t filter -A "$chain" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    "$table_cmd" -t filter -A "$chain" -m owner --uid-owner "$user" -j ACCEPT
    "$table_cmd" -t filter -A "$chain" -m owner --uid-owner systemd-resolve -j ACCEPT
    "$table_cmd" -t filter -A "$chain" -p tcp --dport "$proxy_port" -m addrtype --dst-type LOCAL -j ACCEPT
    "$table_cmd" -t filter -A "$chain" -p tcp --dport "$web_port" -m addrtype --dst-type LOCAL -j ACCEPT
    "$table_cmd" -t filter -A "$chain" -p udp --dport 53 -m addrtype --dst-type LOCAL -j ACCEPT
    "$table_cmd" -t filter -A "$chain" -p tcp --dport 53 -m addrtype --dst-type LOCAL -j ACCEPT
    "$table_cmd" -t filter -A "$chain" -j DROP

    if ! "$table_cmd" -t filter -C OUTPUT -j "$chain" >/dev/null 2>&1; then
        "$table_cmd" -t filter -A OUTPUT -j "$chain"
    fi
}

add_redirect_rule iptables 80
add_redirect_rule iptables 443
add_redirect_rule ip6tables 80
add_redirect_rule ip6tables 443

add_output_filter iptables
add_output_filter ip6tables
