#!/usr/bin/env python3
"""
mitmwall iptables hook for systemd.

Manages the transparent proxy firewall rules and optional custom egress
bypass rules.  Called by the systemd unit as ExecStartPre (start) and
ExecStopPost (stop).
"""

import ipaddress
import subprocess
import sys
from pathlib import Path
from typing import cast

import tomllib

from src.addon.constants import ADDON_CONFIG_FILE, WEB_RULES_FILE
from src.systemd.resolv_conf import configure_system_resolver, restore_system_resolver
from src.utils.toml_helpers import is_toml_table

USER = "mitmwall"
APT_USER = "_apt"
PROXY_PORT = 58080
DNS_PORT = 58053
WEB_PORT = 58081
CHAIN = "MITMWALL_OUTPUT"
COMMENT = "mitmwall-custom"
# https://docs.mitmproxy.org/stable/howto/transparent/
#
# Policy installed by the "start" action:
# - Redirect outbound HTTP/HTTPS from non-proxy users to the local proxy.
# - Allow established/related packets so inbound services such as SSH keep working.
# - Allow root, APT's sandbox user, and the proxy user to make outbound upstream
#   connections.
# - Redirect outbound DNS from non-proxy users to the local DNS proxy.
# - Allow the system DNS resolver (systemd-resolve) to reach upstream DNS.
# - Allow installed system time synchronizers to reach upstream NTP and DNS.
# - Allow all loopback traffic so localhost services remain reachable.
# - Allow other users to connect only to the local proxy, DNS proxy, and web UI ports on this host.
# - Drop all other new outbound traffic so applications cannot bypass the proxies.


def place_rule_first(
    table_cmd: str, table: str, chain: str, rule_args: list[str]
) -> None:
    """
    Place exactly one copy of a managed rule at the head of a built-in chain.

    Removing all matching copies before insertion repairs rules left behind an
    unrelated terminal rule and keeps repeated service starts idempotent.
    """

    while True:
        check = subprocess.run(
            [table_cmd, "-t", table, "-C", chain, *rule_args],
            capture_output=True,
        )
        if check.returncode != 0:
            break
        _ = subprocess.run(
            [table_cmd, "-t", table, "-D", chain, *rule_args],
            capture_output=True,
            check=True,
        )

    _ = subprocess.run(
        [table_cmd, "-t", table, "-I", chain, "1", *rule_args],
        capture_output=True,
        check=True,
    )


def enable_forwarding() -> None:
    """
    Enable IPv4 and IPv6 forwarding so the kernel will route packets that are
    transparently intercepted by mitmproxy back out to their original upstream
    destinations.
    """

    # Enable IPv4 and IPv6 forwarding so the kernel will route packets that are
    # transparently intercepted by mitmproxy back out to their original upstream
    # destinations.
    _ = subprocess.run(
        ["sysctl", "-w", "net.ipv4.ip_forward=1"],
        capture_output=True,
        check=True,
    )
    _ = subprocess.run(
        ["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"],
        capture_output=True,
        check=True,
    )

    # Disable IPv4 ICMP redirects. This host is intentionally acting as the gateway
    # for intercepted traffic, and redirects could teach clients a bypass path that
    # avoids the transparent proxy/firewall policy.
    _ = subprocess.run(
        ["sysctl", "-w", "net.ipv4.conf.all.send_redirects=0"],
        capture_output=True,
        check=True,
    )


def add_redirect_rule(table_cmd: str, dport: int) -> None:
    """
    Capture direct outbound HTTP/HTTPS attempts from users other than root, the
    proxy user, and APT's sandbox user, then redirect them to the local proxy.

    Install the NAT redirect idempotently.  The owner matches exclude root,
    APT's sandbox user, and the dedicated proxy user.  mitmproxy itself runs as
    ``USER`` and must be able to open the real upstream HTTP/HTTPS connection;
    redirecting the proxy's own traffic back into the proxy would create a loop.
    Root is also
    allowed to administer the host and troubleshoot networking without being
    captured by the transparent proxy.

    All other local users trying to connect directly to TCP port 80 or 443 are
    transparently redirected to ``PROXY_PORT``, where mitmproxy can inspect the
    HTTP(S) hostname and enforce TOML rules from ``/etc/mitmwall/rules.d``.

    Exclude loopback traffic from the redirect so localhost services remain
    reachable on their real ports instead of being captured by mitmproxy.
    """

    place_rule_first(
        table_cmd,
        "nat",
        "OUTPUT",
        [
            "-p",
            "tcp",
            "!",
            "-o",
            "lo",
            "-m",
            "owner",
            "!",
            "--uid-owner",
            "0",
            "-m",
            "owner",
            "!",
            "--uid-owner",
            USER,
            "-m",
            "owner",
            "!",
            "--uid-owner",
            APT_USER,
            "--dport",
            str(dport),
            "-j",
            "REDIRECT",
            "--to-port",
            str(PROXY_PORT),
        ],
    )


def remove_redirect_rule(table_cmd: str, dport: int) -> None:
    """
    Remove the transparent HTTP/HTTPS redirects installed by the "start" action.
    These redirects capture direct outbound web traffic from non-proxy users and
    send it to the local proxy port.
    """

    while True:
        check = subprocess.run(
            [
                table_cmd,
                "-t",
                "nat",
                "-C",
                "OUTPUT",
                "-p",
                "tcp",
                "!",
                "-o",
                "lo",
                "-m",
                "owner",
                "!",
                "--uid-owner",
                "0",
                "-m",
                "owner",
                "!",
                "--uid-owner",
                USER,
                "-m",
                "owner",
                "!",
                "--uid-owner",
                APT_USER,
                "--dport",
                str(dport),
                "-j",
                "REDIRECT",
                "--to-port",
                str(PROXY_PORT),
            ],
            capture_output=True,
        )
        if check.returncode != 0:
            break
        _ = subprocess.run(
            [
                table_cmd,
                "-t",
                "nat",
                "-D",
                "OUTPUT",
                "-p",
                "tcp",
                "!",
                "-o",
                "lo",
                "-m",
                "owner",
                "!",
                "--uid-owner",
                "0",
                "-m",
                "owner",
                "!",
                "--uid-owner",
                USER,
                "-m",
                "owner",
                "!",
                "--uid-owner",
                APT_USER,
                "--dport",
                str(dport),
                "-j",
                "REDIRECT",
                "--to-port",
                str(PROXY_PORT),
            ],
            capture_output=True,
            check=True,
        )


def add_dns_redirect_rule(table_cmd: str, protocol: str) -> None:
    """
    Capture DNS attempts from ordinary users, including queries aimed at local
    resolvers such as 127.0.0.53, and send them to mitmproxy's DNS mode listener.
    Exclude root, APT's sandbox user, mitmproxy, and systemd-resolved so package
    administration, DNS proxy upstream resolution, and resolver recursion do not
    loop back into the proxy.
    """

    place_rule_first(
        table_cmd,
        "nat",
        "OUTPUT",
        [
            "-p",
            protocol,
            "-m",
            "owner",
            "!",
            "--uid-owner",
            "0",
            "-m",
            "owner",
            "!",
            "--uid-owner",
            USER,
            "-m",
            "owner",
            "!",
            "--uid-owner",
            "systemd-resolve",
            "-m",
            "owner",
            "!",
            "--uid-owner",
            APT_USER,
            "--dport",
            "53",
            "-j",
            "REDIRECT",
            "--to-port",
            str(DNS_PORT),
        ],
    )


def remove_dns_redirect_rule(table_cmd: str, protocol: str) -> None:
    """
    Remove the DNS redirects installed by the "start" action.
    """

    while True:
        check = subprocess.run(
            [
                table_cmd,
                "-t",
                "nat",
                "-C",
                "OUTPUT",
                "-p",
                protocol,
                "-m",
                "owner",
                "!",
                "--uid-owner",
                "0",
                "-m",
                "owner",
                "!",
                "--uid-owner",
                USER,
                "-m",
                "owner",
                "!",
                "--uid-owner",
                "systemd-resolve",
                "-m",
                "owner",
                "!",
                "--uid-owner",
                APT_USER,
                "--dport",
                "53",
                "-j",
                "REDIRECT",
                "--to-port",
                str(DNS_PORT),
            ],
            capture_output=True,
        )
        if check.returncode != 0:
            break
        _ = subprocess.run(
            [
                table_cmd,
                "-t",
                "nat",
                "-D",
                "OUTPUT",
                "-p",
                protocol,
                "-m",
                "owner",
                "!",
                "--uid-owner",
                "0",
                "-m",
                "owner",
                "!",
                "--uid-owner",
                USER,
                "-m",
                "owner",
                "!",
                "--uid-owner",
                "systemd-resolve",
                "-m",
                "owner",
                "!",
                "--uid-owner",
                APT_USER,
                "--dport",
                "53",
                "-j",
                "REDIRECT",
                "--to-port",
                str(DNS_PORT),
            ],
            capture_output=True,
            check=True,
        )


def legacy_redirect_rule_args(
    protocol: str,
    dport: int,
    target_port: int,
    excluded_users: tuple[str, ...],
    *,
    exclude_loopback: bool = False,
) -> list[str]:
    """
    Reconstruct an exact untagged redirect signature from an older helper.
    """

    rule_args = ["-p", protocol]
    if exclude_loopback:
        rule_args.extend(["!", "-o", "lo"])
    for excluded_user in excluded_users:
        rule_args.extend(["-m", "owner", "!", "--uid-owner", excluded_user])
    rule_args.extend(
        [
            "--dport",
            str(dport),
            "-j",
            "REDIRECT",
            "--to-port",
            str(target_port),
        ]
    )
    return rule_args


def remove_legacy_rule_copies(table_cmd: str, rule_args: list[str]) -> None:
    """
    Remove every exact copy of a historical rule from the NAT OUTPUT chain.
    """

    while True:
        check = subprocess.run(
            [table_cmd, "-t", "nat", "-C", "OUTPUT", *rule_args],
            capture_output=True,
        )
        if check.returncode != 0:
            break
        _ = subprocess.run(
            [table_cmd, "-t", "nat", "-D", "OUTPUT", *rule_args],
            capture_output=True,
            check=True,
        )


def clear_legacy_redirect_rules() -> None:
    """
    Remove untagged redirect forms installed by historical mitmwall helpers.

    These exact signatures cover web rules before loopback, root, and APT
    exclusions were added, plus DNS rules from before the APT exclusion.
    """

    for table_cmd in ("iptables", "ip6tables"):
        for dport in (80, 443):
            for excluded_users, exclude_loopback in (
                ((USER,), False),
                ((USER,), True),
                (("0", USER), True),
            ):
                remove_legacy_rule_copies(
                    table_cmd,
                    legacy_redirect_rule_args(
                        "tcp",
                        dport,
                        PROXY_PORT,
                        excluded_users,
                        exclude_loopback=exclude_loopback,
                    ),
                )

        for protocol in ("udp", "tcp"):
            remove_legacy_rule_copies(
                table_cmd,
                legacy_redirect_rule_args(
                    protocol,
                    53,
                    DNS_PORT,
                    ("0", USER, "systemd-resolve"),
                ),
            )


def add_ntp_filter_rules(table_cmd: str) -> None:
    """
    Allow installed Ubuntu time synchronization services to reach upstream NTP.
    This runs in the filter table, so it decides whether a packet may leave the
    machine after any NAT rewriting has already happened.  Two things are needed:

    1. NTP traffic on UDP/123 must be allowed out.
    2. DNS traffic on UDP/TCP 53 must be allowed out.  This is required even
       though a separate nat-table rule (add_ntp_dns_bypass_rule) prevents the
       NTP user's DNS from being redirected to the local proxy, because without
       this filter rule the OUTPUT chain would still drop the direct query.
    """

    for ntp_user in ("systemd-timesync", "_chrony", "ntp"):
        result = subprocess.run(
            ["id", "-u", ntp_user],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            continue
        ntp_uid = result.stdout.strip()
        # Allow NTP synchronization traffic.
        _ = subprocess.run(
            [
                table_cmd,
                "-t",
                "filter",
                "-A",
                CHAIN,
                "-p",
                "udp",
                "--dport",
                "123",
                "-m",
                "owner",
                "--uid-owner",
                ntp_uid,
                "-j",
                "ACCEPT",
            ],
            capture_output=True,
            check=True,
        )
        # Allow direct DNS queries (bypassed from the proxy by
        # add_ntp_dns_bypass_rule) to actually leave the host.
        _ = subprocess.run(
            [
                table_cmd,
                "-t",
                "filter",
                "-A",
                CHAIN,
                "-p",
                "udp",
                "--dport",
                "53",
                "-m",
                "owner",
                "--uid-owner",
                ntp_uid,
                "-j",
                "ACCEPT",
            ],
            capture_output=True,
            check=True,
        )
        _ = subprocess.run(
            [
                table_cmd,
                "-t",
                "filter",
                "-A",
                CHAIN,
                "-p",
                "tcp",
                "--dport",
                "53",
                "-m",
                "owner",
                "--uid-owner",
                ntp_uid,
                "-j",
                "ACCEPT",
            ],
            capture_output=True,
            check=True,
        )


def add_ntp_dns_bypass_rule(table_cmd: str, protocol: str) -> None:
    """
    NTP clients need to resolve server hostnames (e.g. pool.ntp.org) before
    syncing time.  This runs in the nat table and stops the generic DNS REDIRECT
    rule from rewriting their queries to the local mitmproxy DNS listener.  Without
    this bypass, NTP users' DNS would be redirected to 127.0.0.1:58053, and the
    mitmproxy addon (which only knows about web allow rules) would REFUSE NTP
    pool domains.  ACCEPT in nat means "leave the destination unchanged" so the
    query goes directly to the real upstream resolver.
    """

    for ntp_user in ("systemd-timesync", "_chrony", "ntp"):
        result = subprocess.run(
            ["id", "-u", ntp_user],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            continue
        ntp_uid = result.stdout.strip()
        # Move the bypass to the top on every start so it remains ahead of both
        # generic redirects and unrelated rules.
        place_rule_first(
            table_cmd,
            "nat",
            "OUTPUT",
            [
                "-p",
                protocol,
                "-m",
                "owner",
                "--uid-owner",
                ntp_uid,
                "--dport",
                "53",
                "-j",
                "ACCEPT",
            ],
        )


def remove_ntp_dns_bypass_rule(table_cmd: str, protocol: str) -> None:
    """
    Remove the NTP DNS bypass rules installed by the "start" action.
    """

    for ntp_user in ("systemd-timesync", "_chrony", "ntp"):
        result = subprocess.run(
            ["id", "-u", ntp_user],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            continue
        ntp_uid = result.stdout.strip()
        while True:
            check = subprocess.run(
                [
                    table_cmd,
                    "-t",
                    "nat",
                    "-C",
                    "OUTPUT",
                    "-p",
                    protocol,
                    "-m",
                    "owner",
                    "--uid-owner",
                    ntp_uid,
                    "--dport",
                    "53",
                    "-j",
                    "ACCEPT",
                ],
                capture_output=True,
            )
            if check.returncode != 0:
                break
            _ = subprocess.run(
                [
                    table_cmd,
                    "-t",
                    "nat",
                    "-D",
                    "OUTPUT",
                    "-p",
                    protocol,
                    "-m",
                    "owner",
                    "--uid-owner",
                    ntp_uid,
                    "--dport",
                    "53",
                    "-j",
                    "ACCEPT",
                ],
                capture_output=True,
                check=True,
            )


def add_output_filter(table_cmd: str) -> None:
    """
    Enforce the outbound allowlist.  Reply-direction established/related packets
    are allowed so inbound connections (for example SSH) are not broken.  The
    proxy user, root, and APT's sandbox user are allowed to reach the network,
    loopback traffic is allowed so localhost services remain reachable, clients
    are allowed to reach the local HTTP proxy, DNS proxy, and web UI on this host,
    and every other outbound packet is blocked.
    """

    check = subprocess.run(
        [table_cmd, "-t", "filter", "-L", CHAIN],
        capture_output=True,
    )
    if check.returncode != 0:
        _ = subprocess.run(
            [table_cmd, "-t", "filter", "-N", CHAIN],
            capture_output=True,
            check=True,
        )

    # Rebuild the managed chain on every service start.  Flushing only this
    # project-specific chain keeps the rules deterministic without disturbing
    # unrelated administrator-managed firewall rules in other chains.
    _ = subprocess.run(
        [table_cmd, "-t", "filter", "-F", CHAIN],
        capture_output=True,
        check=True,
    )

    # For inbound sessions, locally generated responses flow in conntrack's REPLY
    # direction.  Restricting this exception to REPLY preserves sessions such as
    # SSH without accepting ORIGINAL-direction packets from outbound connections
    # that ordinary users established before this chain was installed or rebuilt.
    _ = subprocess.run(
        [
            table_cmd,
            "-t",
            "filter",
            "-A",
            CHAIN,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "--ctdir",
            "REPLY",
            "-j",
            "ACCEPT",
        ],
        capture_output=True,
        check=True,
    )

    # Root needs unrestricted outbound access for host administration and
    # troubleshooting, matching the bypass behavior of the proxy user.
    _ = subprocess.run(
        [
            table_cmd,
            "-t",
            "filter",
            "-A",
            CHAIN,
            "-m",
            "owner",
            "--uid-owner",
            "0",
            "-j",
            "ACCEPT",
        ],
        capture_output=True,
        check=True,
    )

    # APT intentionally drops its download workers from root to _apt.  Preserve
    # that sandbox while retaining the unrestricted package-management behavior
    # expected when an administrator invokes APT as root.
    _ = subprocess.run(
        [
            table_cmd,
            "-t",
            "filter",
            "-A",
            CHAIN,
            "-m",
            "owner",
            "--uid-owner",
            APT_USER,
            "-j",
            "ACCEPT",
        ],
        capture_output=True,
        check=True,
    )

    # mitmproxy runs as the dedicated mitmwall user.  It needs unrestricted
    # outbound access so, after accepting a client flow, it can create the real
    # upstream connection to the destination server.
    _ = subprocess.run(
        [
            table_cmd,
            "-t",
            "filter",
            "-A",
            CHAIN,
            "-m",
            "owner",
            "--uid-owner",
            USER,
            "-j",
            "ACCEPT",
        ],
        capture_output=True,
        check=True,
    )

    # systemd-resolved runs as systemd-resolve on Ubuntu.  Let only that resolver
    # process make upstream DNS queries; regular applications are redirected to
    # mitmproxy's local DNS listener before this filter runs.
    _ = subprocess.run(
        [
            table_cmd,
            "-t",
            "filter",
            "-A",
            CHAIN,
            "-m",
            "owner",
            "--uid-owner",
            "systemd-resolve",
            "-j",
            "ACCEPT",
        ],
        capture_output=True,
        check=True,
    )

    # Time synchronization clients run as unprivileged service users.  The filter
    # rules here allow their outbound NTP (UDP/123) and direct DNS (UDP/TCP 53)
    # traffic.  Note: the DNS bypass itself happens in the nat table earlier
    # (add_ntp_dns_bypass_rule); this only grants permission for the already-
    # bypassed packets to leave the host.
    add_ntp_filter_rules(table_cmd)

    # Permit connections to services on this machine.  This keeps localhost and
    # other loopback traffic working while the default policy below still blocks
    # outbound bypass attempts to remote hosts.
    _ = subprocess.run(
        [table_cmd, "-t", "filter", "-A", CHAIN, "-o", "lo", "-j", "ACCEPT"],
        capture_output=True,
        check=True,
    )

    # Permit local clients to reach the transparent mitmproxy listener.  The
    # destination must be LOCAL so this does not become a general allow rule for
    # remote hosts that happen to use the same TCP port.
    _ = subprocess.run(
        [
            table_cmd,
            "-t",
            "filter",
            "-A",
            CHAIN,
            "-p",
            "tcp",
            "--dport",
            str(PROXY_PORT),
            "-m",
            "addrtype",
            "--dst-type",
            "LOCAL",
            "-j",
            "ACCEPT",
        ],
        capture_output=True,
        check=True,
    )

    # Permit DNS queries to mitmproxy's DNS mode listener.  Direct queries to
    # remote DNS servers are redirected here by NAT before this filter runs.
    _ = subprocess.run(
        [
            table_cmd,
            "-t",
            "filter",
            "-A",
            CHAIN,
            "-p",
            "udp",
            "--dport",
            str(DNS_PORT),
            "-m",
            "addrtype",
            "--dst-type",
            "LOCAL",
            "-j",
            "ACCEPT",
        ],
        capture_output=True,
        check=True,
    )
    _ = subprocess.run(
        [
            table_cmd,
            "-t",
            "filter",
            "-A",
            CHAIN,
            "-p",
            "tcp",
            "--dport",
            str(DNS_PORT),
            "-m",
            "addrtype",
            "--dst-type",
            "LOCAL",
            "-j",
            "ACCEPT",
        ],
        capture_output=True,
        check=True,
    )

    # Permit access to the mitmweb UI only on this machine.  As above, requiring a
    # LOCAL destination avoids allowing arbitrary outbound connections to remote
    # services listening on the web UI port number.
    _ = subprocess.run(
        [
            table_cmd,
            "-t",
            "filter",
            "-A",
            CHAIN,
            "-p",
            "tcp",
            "--dport",
            str(WEB_PORT),
            "-m",
            "addrtype",
            "--dst-type",
            "LOCAL",
            "-j",
            "ACCEPT",
        ],
        capture_output=True,
        check=True,
    )

    # Fail closed: anything not explicitly allowed above is a new outbound
    # connection attempt that would bypass the transparent proxy, so drop it.
    _ = subprocess.run(
        [table_cmd, "-t", "filter", "-A", CHAIN, "-j", "DROP"],
        capture_output=True,
        check=True,
    )

    # Reattach at the head on every start.  An earlier terminal rule in OUTPUT
    # would otherwise bypass the fail-closed managed chain.
    place_rule_first(table_cmd, "filter", "OUTPUT", ["-j", CHAIN])


def remove_output_filter(table_cmd: str) -> None:
    """
    Remove the outbound allowlist/blocklist chain installed by the "start" action.
    That chain allows reply-direction established/related packets so inbound
    services such as SSH keep working, allows root, APT's sandbox user, and the
    proxy user to reach upstream hosts, allows loopback traffic, allows other users
    to connect to the local HTTP proxy, DNS proxy, and web UI ports on this host,
    and blocks all other outbound traffic.
    """

    while True:
        check = subprocess.run(
            [table_cmd, "-t", "filter", "-C", "OUTPUT", "-j", CHAIN],
            capture_output=True,
        )
        if check.returncode != 0:
            break
        _ = subprocess.run(
            [table_cmd, "-t", "filter", "-D", "OUTPUT", "-j", CHAIN],
            capture_output=True,
            check=True,
        )

    check = subprocess.run(
        [table_cmd, "-t", "filter", "-L", CHAIN],
        capture_output=True,
    )
    if check.returncode == 0:
        _ = subprocess.run(
            [table_cmd, "-t", "filter", "-F", CHAIN],
            capture_output=True,
            check=True,
        )
        _ = subprocess.run(
            [table_cmd, "-t", "filter", "-X", CHAIN],
            capture_output=True,
            check=True,
        )


def ensure_web_rules_file() -> None:
    """
    Ensure the web-managed rules file exists and is writable by the mitmwall user.

    The mitmweb UI sets the rules_text option at runtime; the addon persists
    changes to this file.  Because the rules directory is owned by root with
    group mitmwall and mode 0750, the unprivileged addon process cannot create
    new files there, so the hook (running as root) pre-creates the file and
    sets permissions so the mitmwall user can rewrite it.
    """

    if not WEB_RULES_FILE.exists():
        _ = WEB_RULES_FILE.write_text(
            "# no custom rules from mitmweb\n", encoding="utf-8"
        )

    _ = subprocess.run(
        ["chown", "root:mitmwall", str(WEB_RULES_FILE)],
        capture_output=True,
        check=True,
    )
    _ = subprocess.run(
        ["chmod", "660", str(WEB_RULES_FILE)],
        capture_output=True,
        check=True,
    )


def add_rules() -> None:
    """
    Install the full transparent proxy firewall policy.
    """

    clear_legacy_redirect_rules()
    enable_forwarding()

    # Every managed NAT rule is moved to the head.  Install generic redirects
    # first, then bypasses, so bypasses retain their required higher precedence.
    add_dns_redirect_rule("iptables", "udp")
    add_dns_redirect_rule("iptables", "tcp")
    add_dns_redirect_rule("ip6tables", "udp")
    add_dns_redirect_rule("ip6tables", "tcp")

    add_redirect_rule("iptables", 80)
    add_redirect_rule("iptables", 443)
    add_redirect_rule("ip6tables", 80)
    add_redirect_rule("ip6tables", 443)

    add_ntp_dns_bypass_rule("iptables", "udp")
    add_ntp_dns_bypass_rule("iptables", "tcp")
    add_ntp_dns_bypass_rule("ip6tables", "udp")
    add_ntp_dns_bypass_rule("ip6tables", "tcp")

    add_output_filter("iptables")
    add_output_filter("ip6tables")

    add_custom_rules()


def clear_rules() -> None:
    """
    Remove all firewall rules installed by the "start" action.
    """

    clear_legacy_redirect_rules()
    clear_custom_rules()

    remove_redirect_rule("iptables", 80)
    remove_redirect_rule("iptables", 443)
    remove_redirect_rule("ip6tables", 80)
    remove_redirect_rule("ip6tables", 443)

    remove_ntp_dns_bypass_rule("iptables", "udp")
    remove_ntp_dns_bypass_rule("iptables", "tcp")
    remove_ntp_dns_bypass_rule("ip6tables", "udp")
    remove_ntp_dns_bypass_rule("ip6tables", "tcp")

    remove_dns_redirect_rule("iptables", "udp")
    remove_dns_redirect_rule("iptables", "tcp")
    remove_dns_redirect_rule("ip6tables", "udp")
    remove_dns_redirect_rule("ip6tables", "tcp")

    remove_output_filter("iptables")
    remove_output_filter("ip6tables")


# ---------------------------------------------------------------------------
# Custom iptables bypass rules (ported from custom_iptables.py)
# ---------------------------------------------------------------------------


def parse_custom_rules(config_path: Path = ADDON_CONFIG_FILE) -> list[tuple[str, int]]:
    """
    Parse custom iptables bypass rules from a TOML config file.

    Returns a list of (network, port) tuples for each [[iptables.bypass]]
    entry.  If the file does not exist, the iptables key is missing, or
    the bypass table is malformed, an empty list is returned.
    """

    if not config_path.exists():
        return []

    with config_path.open("rb") as file:
        config_value = cast(object, tomllib.load(file))

    if not is_toml_table(config_value):
        return []

    iptables_value = config_value.get("iptables")
    if not is_toml_table(iptables_value):
        return []

    bypass_value = iptables_value.get("bypass")
    if not isinstance(bypass_value, list):
        return []

    bypass_rules = cast(list[object], bypass_value)
    rules: list[tuple[str, int]] = []
    for rule in bypass_rules:
        if not is_toml_table(rule):
            continue
        network = rule.get("network")
        port = rule.get("port")
        if not isinstance(network, str) or not isinstance(port, int):
            continue
        rules.append((network, port))

    return rules


def is_ipv4_network(network: str) -> bool:
    """
    Return whether a network string represents an IPv4 network.

    Uses ``ipaddress.ip_network`` to parse and classify the address so that
    malformed strings are rejected rather than silently forwarded to iptables.
    """

    try:
        return ipaddress.ip_network(network, strict=False).version == 4
    except ValueError:
        return False


def find_drop_line_number(result: subprocess.CompletedProcess[str]) -> str | None:
    """
    Find the line number of the DROP rule in iptables --line-numbers output.

    Returns the line number as a string, or None if no DROP rule is found.
    """

    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "DROP":
            return parts[0]
    return None


def add_rule(table_cmd: str, chain: str, network: str, port: int) -> None:
    """
    Insert a single custom ACCEPT rule into the given chain before the DROP rule.

    The rule is tagged with a comment so it can be identified and removed later.
    If the chain does not exist or has no DROP rule, the rule is appended.
    """

    rule_args = [
        "-t",
        "filter",
        "-L",
        chain,
        "--line-numbers",
    ]
    result = subprocess.run([table_cmd, *rule_args], capture_output=True, text=True)
    if result.returncode != 0:
        return

    drop_line = find_drop_line_number(result)

    custom_rule = [
        "-p",
        "tcp",
        "-d",
        network,
        "--dport",
        str(port),
        "-m",
        "comment",
        "--comment",
        COMMENT,
        "-j",
        "ACCEPT",
    ]

    if drop_line is not None:
        _ = subprocess.run(
            [table_cmd, "-t", "filter", "-I", chain, drop_line, *custom_rule],
            capture_output=True,
            check=True,
        )
    else:
        _ = subprocess.run(
            [table_cmd, "-t", "filter", "-A", chain, *custom_rule],
            capture_output=True,
            check=True,
        )


def add_nat_bypass_rule(table_cmd: str, network: str, port: int) -> None:
    """
    Insert a NAT bypass rule at the top of the OUTPUT chain so traffic to the
    specified network and port is not redirected to the transparent proxy.
    """

    place_rule_first(
        table_cmd,
        "nat",
        "OUTPUT",
        [
            "-p",
            "tcp",
            "-d",
            network,
            "--dport",
            str(port),
            "-m",
            "comment",
            "--comment",
            COMMENT,
            "-j",
            "ACCEPT",
        ],
    )


def add_custom_rules() -> None:
    """
    Read the config and insert all custom bypass rules into MITMWALL_OUTPUT.

    Existing custom rules are cleared first so repeated runs are idempotent.
    """

    rules = parse_custom_rules()
    if not rules:
        return

    clear_custom_rules()

    for network, port in rules:
        if is_ipv4_network(network):
            add_nat_bypass_rule("iptables", network, port)
            add_rule("iptables", CHAIN, network, port)
        else:
            add_nat_bypass_rule("ip6tables", network, port)
            add_rule("ip6tables", CHAIN, network, port)


def remove_comment_rules(table_cmd: str, table: str, chain: str) -> None:
    """
    Remove all rules tagged with the mitmwall-custom comment from a chain.

    Rules are removed one at a time by line number because deleting a rule
    shifts the line numbers of the remaining rules.
    """

    while True:
        result = subprocess.run(
            [table_cmd, "-t", table, "-L", chain, "--line-numbers"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            break

        removed = False
        for line in result.stdout.splitlines():
            if COMMENT in line:
                parts = line.split()
                if parts and parts[0].isdigit():
                    _ = subprocess.run(
                        [table_cmd, "-t", table, "-D", chain, parts[0]],
                        capture_output=True,
                        check=True,
                    )
                    removed = True
                    break

        if not removed:
            break


def remove_custom_rules_from_chain(table_cmd: str, chain: str) -> None:
    """
    Remove all rules tagged with the mitmwall-custom comment from a filter chain.
    """

    remove_comment_rules(table_cmd, "filter", chain)


def clear_custom_rules() -> None:
    """
    Remove all custom bypass rules previously inserted by add_custom_rules().
    """

    remove_comment_rules("iptables", "filter", CHAIN)
    remove_comment_rules("ip6tables", "filter", CHAIN)
    remove_comment_rules("iptables", "nat", "OUTPUT")
    remove_comment_rules("ip6tables", "nat", "OUTPUT")


def usage() -> None:
    """
    Print usage information to stderr.
    """

    print(f"usage: {sys.argv[0]} {{start|stop}}", file=sys.stderr)


def main() -> None:
    """
    Entry point for the mitmwall iptables hook.
    """

    if len(sys.argv) != 2:
        usage()
        sys.exit(2)

    action = sys.argv[1]
    if action == "start":
        try:
            configure_system_resolver()
            ensure_web_rules_file()
            add_rules()
        except BaseException:
            restore_system_resolver()
            raise
    elif action == "stop":
        try:
            clear_rules()
        finally:
            restore_system_resolver()
    else:
        usage()
        sys.exit(2)


if __name__ == "__main__":
    main()
