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
dns_port=58053
web_port=58081
chain=MITMWALL_OUTPUT

# https://docs.mitmproxy.org/stable/howto/transparent/
#
# Policy installed by the "add" action:
# - Redirect outbound HTTP/HTTPS from non-proxy users to the local proxy.
# - Allow established/related packets so inbound services such as SSH keep working.
# - Allow root and the proxy user to make outbound upstream connections.
# - Redirect outbound DNS from non-proxy users to the local DNS proxy.
# - Allow the system DNS resolver (systemd-resolve) to reach upstream DNS.
# - Allow all loopback traffic so localhost services remain reachable.
# - Allow other users to connect only to the local proxy, DNS proxy, and web UI ports on this host.
# - Drop all other new outbound traffic so applications cannot bypass the proxies.

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

# Capture direct outbound HTTP/HTTPS attempts from users other than root and
# the proxy user, then transparently redirect them to the local proxy.
add_redirect_rule() {
    table_cmd=$1
    dport=$2

    # Install the NAT redirect idempotently. `-C` checks whether the exact rule
    # already exists so restarting the systemd service does not append duplicate
    # redirects to the OUTPUT chain.
    #
    # The owner matches exclude root and the dedicated proxy user. mitmproxy
    # itself runs as `$user` and must be able to open the real upstream HTTP/HTTPS
    # connection; redirecting the proxy's own traffic back into the proxy would
    # create a loop. Root is also allowed to administer the host and troubleshoot
    # networking without being captured by the transparent proxy.
    #
    # All other local users trying to connect directly to TCP port 80 or 443 are
    # transparently redirected to `$proxy_port`, where mitmproxy can inspect the
    # HTTP(S) hostname and enforce TOML rules from `/etc/mitmwall/rules.d`.
    #
    # Exclude loopback traffic from the redirect so localhost services remain
    # reachable on their real ports instead of being captured by mitmproxy.
    if ! "$table_cmd" -t nat -C OUTPUT -p tcp ! -o lo -m owner ! --uid-owner 0 -m owner ! --uid-owner "$user" --dport "$dport" -j REDIRECT --to-port "$proxy_port" >/dev/null 2>&1; then
        "$table_cmd" -t nat -A OUTPUT -p tcp ! -o lo -m owner ! --uid-owner 0 -m owner ! --uid-owner "$user" --dport "$dport" -j REDIRECT --to-port "$proxy_port"
    fi
}

# Remove the transparent HTTP/HTTPS redirects installed by the "add" action.
# These redirects capture direct outbound web traffic from non-proxy users and
# send it to the local proxy port.
remove_redirect_rule() {
    table_cmd=$1
    dport=$2

    while "$table_cmd" -t nat -C OUTPUT -p tcp ! -o lo -m owner ! --uid-owner 0 -m owner ! --uid-owner "$user" --dport "$dport" -j REDIRECT --to-port "$proxy_port" >/dev/null 2>&1; do
        "$table_cmd" -t nat -D OUTPUT -p tcp ! -o lo -m owner ! --uid-owner 0 -m owner ! --uid-owner "$user" --dport "$dport" -j REDIRECT --to-port "$proxy_port"
    done

}

# Capture DNS attempts from ordinary users, including queries aimed at local
# resolvers such as 127.0.0.53, and send them to mitmproxy's DNS mode listener.
# Exclude root, mitmproxy, and systemd-resolved so administration, DNS proxy
# upstream resolution, and resolver recursion do not loop back into the proxy.
add_dns_redirect_rule() {
    table_cmd=$1
    protocol=$2

    if ! "$table_cmd" -t nat -C OUTPUT -p "$protocol" -m owner ! --uid-owner 0 -m owner ! --uid-owner "$user" -m owner ! --uid-owner systemd-resolve --dport 53 -j REDIRECT --to-port "$dns_port" >/dev/null 2>&1; then
        "$table_cmd" -t nat -A OUTPUT -p "$protocol" -m owner ! --uid-owner 0 -m owner ! --uid-owner "$user" -m owner ! --uid-owner systemd-resolve --dport 53 -j REDIRECT --to-port "$dns_port"
    fi
}

# Remove the DNS redirects installed by the "add" action.
remove_dns_redirect_rule() {
    table_cmd=$1
    protocol=$2

    while "$table_cmd" -t nat -C OUTPUT -p "$protocol" -m owner ! --uid-owner 0 -m owner ! --uid-owner "$user" -m owner ! --uid-owner systemd-resolve --dport 53 -j REDIRECT --to-port "$dns_port" >/dev/null 2>&1; do
        "$table_cmd" -t nat -D OUTPUT -p "$protocol" -m owner ! --uid-owner 0 -m owner ! --uid-owner "$user" -m owner ! --uid-owner systemd-resolve --dport 53 -j REDIRECT --to-port "$dns_port"
    done
}

# Enforce the outbound allowlist. Established/related packets are allowed so
# replies from inbound connections (for example SSH) are not broken. The proxy
# user and root are allowed to reach the network, loopback traffic is allowed so
# localhost services remain reachable, clients are allowed to reach the local
# HTTP proxy, DNS proxy, and web UI on this host, and every other new outbound
# connection is blocked.
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

    # Root needs unrestricted outbound access for host administration and
    # troubleshooting, matching the bypass behavior of the proxy user.
    "$table_cmd" -t filter -A "$chain" -m owner --uid-owner 0 -j ACCEPT

    # mitmproxy runs as the dedicated mitmwall user. It needs unrestricted
    # outbound access so, after accepting a client flow, it can create the real
    # upstream connection to the destination server.
    "$table_cmd" -t filter -A "$chain" -m owner --uid-owner "$user" -j ACCEPT

    # systemd-resolved runs as systemd-resolve on Ubuntu. Let only that resolver
    # process make upstream DNS queries; regular applications are redirected to
    # mitmproxy's local DNS listener before this filter runs.
    "$table_cmd" -t filter -A "$chain" -m owner --uid-owner systemd-resolve -j ACCEPT

    # Permit connections to services on this machine. This keeps localhost and
    # other loopback traffic working while the default policy below still blocks
    # outbound bypass attempts to remote hosts.
    "$table_cmd" -t filter -A "$chain" -o lo -j ACCEPT

    # Permit local clients to reach the transparent mitmproxy listener. The
    # destination must be LOCAL so this does not become a general allow rule for
    # remote hosts that happen to use the same TCP port.
    "$table_cmd" -t filter -A "$chain" -p tcp --dport "$proxy_port" -m addrtype --dst-type LOCAL -j ACCEPT

    # Permit DNS queries to mitmproxy's DNS mode listener. Direct queries to
    # remote DNS servers are redirected here by NAT before this filter runs.
    "$table_cmd" -t filter -A "$chain" -p udp --dport "$dns_port" -m addrtype --dst-type LOCAL -j ACCEPT
    "$table_cmd" -t filter -A "$chain" -p tcp --dport "$dns_port" -m addrtype --dst-type LOCAL -j ACCEPT

    # Permit access to the mitmweb UI only on this machine. As above, requiring a
    # LOCAL destination avoids allowing arbitrary outbound connections to remote
    # services listening on the web UI port number.
    "$table_cmd" -t filter -A "$chain" -p tcp --dport "$web_port" -m addrtype --dst-type LOCAL -j ACCEPT

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
# keep working, allows root and the proxy user to reach upstream hosts, allows
# loopback traffic, allows other users to connect to the local HTTP proxy, DNS
# proxy, and web UI ports on this host, and blocks all other new outbound traffic.
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
    add_dns_redirect_rule iptables udp
    add_dns_redirect_rule iptables tcp
    add_dns_redirect_rule ip6tables udp
    add_dns_redirect_rule ip6tables tcp

    add_output_filter iptables
    add_output_filter ip6tables
}

clear_rules() {
    remove_redirect_rule iptables 80
    remove_redirect_rule iptables 443
    remove_redirect_rule ip6tables 80
    remove_redirect_rule ip6tables 443
    remove_dns_redirect_rule iptables udp
    remove_dns_redirect_rule iptables tcp
    remove_dns_redirect_rule ip6tables udp
    remove_dns_redirect_rule ip6tables tcp

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
