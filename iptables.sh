#!/bin/sh

set -eu

program=$(basename -- "$0")

usage() {
    echo "usage: $program {add|clear}" >&2
}

if [ "$#" -ne 1 ]; then
    usage
    exit 2
fi

action=$1
case "$action" in
    add|clear)
        ;;
    *)
        usage
        exit 2
        ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    echo "$program: must be run as root" >&2
    exit 1
fi

user=mitmwall
proxy_port=58080
web_port=58081
chain=MITMWALL_OUTPUT

# https://docs.mitmproxy.org/stable/howto/transparent/
#
# Policy installed by the "add" action:
# - Redirect outbound HTTP/HTTPS from non-proxy users to the local proxy.
# - Allow established/related packets so inbound services such as SSH keep working.
# - Allow the proxy user to make outbound upstream connections.
# - Allow the system DNS resolver (systemd-resolve) to reach upstream DNS.
# - Allow other users to connect only to the local proxy and web UI ports on this host.
# - Allow DNS only to local resolvers so clients can resolve hostnames.
# - Drop all other new outbound traffic so applications cannot bypass the proxy.

enable_forwarding() {
    # Enable IPv4 and IPv6 forwarding so the kernel will route packets that are
    # transparently intercepted by mitmproxy back out to their original upstream
    # destinations.
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv6.conf.all.forwarding=1

    # Disable IPv4 ICMP redirects. This host is intentionally acting as the gateway
    # for intercepted traffic, and redirects could teach clients a bypass path that
    # avoids the transparent proxy/firewall policy.
    sysctl -w net.ipv4.conf.all.send_redirects=0
}

# Capture direct outbound HTTP/HTTPS attempts from non-proxy users and
# transparently redirect them to the local proxy.
add_redirect_rule() {
    table_cmd=$1
    dport=$2

    # Install the NAT redirect idempotently. `-C` checks whether the exact rule
    # already exists so restarting the systemd service does not append duplicate
    # redirects to the OUTPUT chain.
    #
    # The owner match excludes the dedicated proxy user. mitmproxy itself runs as
    # `$user` and must be able to open the real upstream HTTP/HTTPS connection;
    # redirecting the proxy's own traffic back into the proxy would create a loop.
    #
    # All other local users trying to connect directly to TCP port 80 or 443 are
    # transparently redirected to `$proxy_port`, where mitmproxy can inspect the
    # HTTP(S) hostname and enforce `/opt/mitmwall/rules.toml`.
    if ! "$table_cmd" -t nat -C OUTPUT -p tcp -m owner ! --uid-owner "$user" --dport "$dport" -j REDIRECT --to-port "$proxy_port" >/dev/null 2>&1; then
        "$table_cmd" -t nat -A OUTPUT -p tcp -m owner ! --uid-owner "$user" --dport "$dport" -j REDIRECT --to-port "$proxy_port"
    fi
}

# Remove the transparent HTTP/HTTPS redirects installed by the "add" action.
# These redirects capture direct outbound web traffic from non-proxy users and
# send it to the local proxy port.
remove_redirect_rule() {
    table_cmd=$1
    dport=$2

    while "$table_cmd" -t nat -C OUTPUT -p tcp -m owner ! --uid-owner "$user" --dport "$dport" -j REDIRECT --to-port "$proxy_port" >/dev/null 2>&1; do
        "$table_cmd" -t nat -D OUTPUT -p tcp -m owner ! --uid-owner "$user" --dport "$dport" -j REDIRECT --to-port "$proxy_port"
    done
}

# Enforce the outbound allowlist. Established/related packets are allowed so
# replies from inbound connections (for example SSH) are not broken. The proxy
# user is allowed to reach the network, clients are allowed to reach the local
# proxy and web UI on this host and DNS, and every other new outbound connection
# is blocked.
add_output_filter() {
    table_cmd=$1

    if ! "$table_cmd" -t filter -L "$chain" >/dev/null 2>&1; then
        "$table_cmd" -t filter -N "$chain"
    fi

    # Rebuild the managed chain on every service start. Flushing only this
    # project-specific chain keeps the rules deterministic without disturbing
    # unrelated administrator-managed firewall rules in other chains.
    "$table_cmd" -t filter -F "$chain"

    # Always allow packets that belong to connections the kernel already knows
    # about, plus related helper traffic. This prevents the outbound policy from
    # breaking replies for existing/inbound sessions such as SSH.
    "$table_cmd" -t filter -A "$chain" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # mitmproxy runs as the dedicated mitmwall user. It needs unrestricted
    # outbound access so, after accepting a client flow, it can create the real
    # upstream connection to the destination server.
    "$table_cmd" -t filter -A "$chain" -m owner --uid-owner "$user" -j ACCEPT

    # systemd-resolved runs as systemd-resolve on Ubuntu. Let only that resolver
    # process make upstream DNS queries; regular applications are limited below
    # to talking to local resolver addresses only.
    "$table_cmd" -t filter -A "$chain" -m owner --uid-owner systemd-resolve -j ACCEPT

    # Permit local clients to reach the transparent mitmproxy listener. The
    # destination must be LOCAL so this does not become a general allow rule for
    # remote hosts that happen to use the same TCP port.
    "$table_cmd" -t filter -A "$chain" -p tcp --dport "$proxy_port" -m addrtype --dst-type LOCAL -j ACCEPT

    # Permit access to the mitmweb UI only on this machine. As above, requiring a
    # LOCAL destination avoids allowing arbitrary outbound connections to remote
    # services listening on the web UI port number.
    "$table_cmd" -t filter -A "$chain" -p tcp --dport "$web_port" -m addrtype --dst-type LOCAL -j ACCEPT

    # Allow applications to ask the local resolver for names over UDP, which is
    # the normal DNS transport. Remote DNS servers remain blocked for ordinary
    # users so DNS traffic cannot bypass the local resolver policy.
    "$table_cmd" -t filter -A "$chain" -p udp --dport 53 -m addrtype --dst-type LOCAL -j ACCEPT

    # Also allow DNS-over-TCP to the local resolver for large responses, retries,
    # and standards-compliant fallback. This is still restricted to LOCAL
    # destinations and therefore does not permit direct remote DNS access.
    "$table_cmd" -t filter -A "$chain" -p tcp --dport 53 -m addrtype --dst-type LOCAL -j ACCEPT

    # Fail closed: anything not explicitly allowed above is a new outbound
    # connection attempt that would bypass the transparent proxy, so drop it.
    "$table_cmd" -t filter -A "$chain" -j DROP

    # Attach the managed chain to OUTPUT once. `-C` keeps service restarts
    # idempotent while preserving the rule order after the first installation.
    if ! "$table_cmd" -t filter -C OUTPUT -j "$chain" >/dev/null 2>&1; then
        "$table_cmd" -t filter -A OUTPUT -j "$chain"
    fi
}

# Remove the outbound allowlist/blocklist chain installed by the "add" action.
# That chain allows established/related packets so inbound services such as SSH
# keep working, allows the proxy user to reach upstream hosts, allows other
# users to connect to the local proxy and web UI ports on this host and DNS, and
# blocks all other new outbound traffic.
remove_output_filter() {
    table_cmd=$1

    while "$table_cmd" -t filter -C OUTPUT -j "$chain" >/dev/null 2>&1; do
        "$table_cmd" -t filter -D OUTPUT -j "$chain"
    done

    if "$table_cmd" -t filter -L "$chain" >/dev/null 2>&1; then
        "$table_cmd" -t filter -F "$chain"
        "$table_cmd" -t filter -X "$chain"
    fi
}

add_rules() {
    enable_forwarding

    add_redirect_rule iptables 80
    add_redirect_rule iptables 443
    add_redirect_rule ip6tables 80
    add_redirect_rule ip6tables 443

    add_output_filter iptables
    add_output_filter ip6tables
}

clear_rules() {
    remove_redirect_rule iptables 80
    remove_redirect_rule iptables 443
    remove_redirect_rule ip6tables 80
    remove_redirect_rule ip6tables 443

    remove_output_filter iptables
    remove_output_filter ip6tables
}

case "$action" in
    add)
        add_rules
        ;;
    clear)
        clear_rules
        ;;
esac
