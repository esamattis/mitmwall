#!/usr/bin/env python3
"""
mitmwall iptables hook for systemd.

Manages the transparent proxy firewall rules and optional custom egress
bypass rules.  Called by the systemd unit as ExecStartPre (start) and
ExecStopPost (stop).
"""

import grp
import ipaddress
import json
import logging
import os
import pwd
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import tomllib

from src.addon.constants import ADDON_CONFIG_FILE, WEB_RULES_FILE
from src.systemd.iptables import Iptables, IptablesCommand, Rule, Table
from src.systemd.migrations import clear_legacy_redirect_rules, run_startup_migrations
from src.systemd.resolv_conf import configure_system_resolver, restore_system_resolver
from src.utils.toml_helpers import is_toml_array, is_toml_table

USER = "mitmwall"
APT_USER = "_apt"
REQUIRED_BYPASS_USERS = (USER,)
PROXY_PORT = 58080
DNS_PORT = 58053
WEB_PORT = 58081
CHAIN = "MITMWALL_OUTPUT"
COMMENT = "mitmwall-custom"
REDIRECT_COMMENT = "mitmwall-redirect"
FORWARDING_STATE_DIR = Path("/run/mitmwall")
FORWARDING_STATE_FILE = FORWARDING_STATE_DIR / "forwarding-state.json"
IPV4_FORWARDING = "net.ipv4.ip_forward"
IPV6_FORWARDING = "net.ipv6.conf.all.forwarding"
IPV4_SEND_REDIRECTS = "net.ipv4.conf.all.send_redirects"
FORWARD_GUARD_COMMENT = "mitmwall-forwarding-guard"
# https://docs.mitmproxy.org/stable/howto/transparent/
#
# Policy installed by the "start" action:
# - Redirect outbound HTTP/HTTPS from non-proxy users to the local proxy.
# - Allow established/related packets so inbound services such as SSH keep working.
# - Allow configured bypass users and the proxy user to make outbound upstream
#   connections.
# - Redirect outbound DNS from non-proxy users to the local DNS proxy.
# - Allow the system DNS resolver (systemd-resolve) to reach upstream DNS.
# - Allow installed system time synchronizers to reach upstream NTP and DNS.
# - Allow ICMPv6 so the kernel can maintain IPv6 connectivity.
# - Allow all loopback traffic so localhost services remain reachable.
# - Allow other users to connect only to the local proxy, DNS proxy, and web UI ports on this host.
# - Drop all other new outbound traffic so applications cannot bypass the proxies.

IPV4 = Iptables("iptables")
IPV6 = Iptables("ip6tables")
FIREWALLS = (IPV4, IPV6)


def firewall_for(command: IptablesCommand) -> Iptables:
    """Return the shared firewall client for an iptables command."""

    return IPV4 if command == "iptables" else IPV6


@dataclass(frozen=True)
class ForwardingState:
    """
    Exact forwarding-related sysctl values from before mitmwall started.
    """

    ipv4_forwarding: int
    ipv6_forwarding: int
    ipv4_send_redirects: int


@dataclass(frozen=True)
class CustomRule:
    """
    A validated custom firewall bypass rule and its address family command.
    """

    table_cmd: IptablesCommand
    network: str
    port: int


def read_sysctl(name: str) -> int:
    """
    Read an integer sysctl value.
    """

    result = subprocess.run(
        ["sysctl", "-n", name],
        capture_output=True,
        text=True,
        check=True,
    )
    try:
        return int(result.stdout.strip())
    except ValueError as error:
        raise RuntimeError(f"sysctl {name} returned a non-integer value") from error


def write_sysctl(name: str, value: int) -> None:
    """
    Set an integer sysctl value.
    """

    _ = subprocess.run(
        ["sysctl", "-w", f"{name}={value}"],
        capture_output=True,
        text=True,
        check=True,
    )


def validate_forwarding_state_directory() -> None:
    """
    Create or validate the root-only forwarding state directory.
    """

    try:
        metadata = FORWARDING_STATE_DIR.lstat()
    except FileNotFoundError:
        FORWARDING_STATE_DIR.mkdir(mode=0o700, parents=True)
        metadata = FORWARDING_STATE_DIR.lstat()

    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
        raise RuntimeError(
            f"forwarding state directory is not owned by root: {FORWARDING_STATE_DIR}"
        )
    FORWARDING_STATE_DIR.chmod(0o700)


def write_forwarding_state(state: ForwardingState) -> None:
    """
    Persist the original forwarding sysctls atomically with root-only access.
    """

    validate_forwarding_state_directory()
    payload = {
        "ipv4_forwarding": state.ipv4_forwarding,
        "ipv6_forwarding": state.ipv6_forwarding,
        "ipv4_send_redirects": state.ipv4_send_redirects,
    }
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".forwarding-state-", dir=FORWARDING_STATE_DIR
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as file:
            descriptor = -1
            json.dump(payload, file, sort_keys=True)
            _ = file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.link(temporary_path, FORWARDING_STATE_FILE)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary_path.unlink(missing_ok=True)


def read_forwarding_state() -> ForwardingState:
    """
    Read and strictly validate the saved forwarding sysctls.
    """

    validate_forwarding_state_directory()
    try:
        metadata = FORWARDING_STATE_FILE.lstat()
    except FileNotFoundError as error:
        raise RuntimeError("saved forwarding state is absent") from error

    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise RuntimeError("saved forwarding state is not a root-only regular file")

    try:
        value: object = json.loads(  # pyright: ignore[reportAny]
            FORWARDING_STATE_FILE.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError("saved forwarding state is corrupt") from error
    if not is_toml_table(value):
        raise RuntimeError("saved forwarding state is not a JSON object")

    expected_fields = {
        "ipv4_forwarding",
        "ipv6_forwarding",
        "ipv4_send_redirects",
    }
    if set(value) != expected_fields:
        raise RuntimeError("saved forwarding state has invalid fields")
    ipv4_forwarding = value["ipv4_forwarding"]
    ipv6_forwarding = value["ipv6_forwarding"]
    ipv4_send_redirects = value["ipv4_send_redirects"]
    if not all(
        type(field) is int
        for field in (ipv4_forwarding, ipv6_forwarding, ipv4_send_redirects)
    ):
        raise RuntimeError("saved forwarding state has non-integer values")
    if (
        ipv4_forwarding not in (0, 1)
        or ipv6_forwarding not in (0, 1)
        or ipv4_send_redirects not in (0, 1)
    ):
        raise RuntimeError("saved forwarding state has invalid values")

    return ForwardingState(
        ipv4_forwarding,
        ipv6_forwarding,
        ipv4_send_redirects,
    )


def load_or_create_forwarding_state() -> ForwardingState:
    """
    Return the original snapshot, creating it once before changing sysctls.
    """

    try:
        _metadata = FORWARDING_STATE_FILE.lstat()
    except FileNotFoundError:
        state = ForwardingState(
            read_sysctl(IPV4_FORWARDING),
            read_sysctl(IPV6_FORWARDING),
            read_sysctl(IPV4_SEND_REDIRECTS),
        )
        try:
            write_forwarding_state(state)
            return state
        except FileExistsError:
            return read_forwarding_state()
    return read_forwarding_state()


def forward_guard_rule() -> list[str]:
    """
    Return the managed rule that blocks transit traffic enabled by mitmwall.
    """

    return [
        "-m",
        "comment",
        "--comment",
        FORWARD_GUARD_COMMENT,
        "-j",
        "DROP",
    ]


def add_forwarding_guards(state: ForwardingState) -> None:
    """
    Block transit only for address families mitmwall newly enables.

    A pre-existing enabled value is administrator policy and is not guarded or
    otherwise changed beyond being preserved for exact restoration.
    """

    if state.ipv4_forwarding == 0:
        IPV4.ensure_first(
            Rule(
                table="filter",
                chain="FORWARD",
                args=tuple(forward_guard_rule()),
            )
        )
    if state.ipv6_forwarding == 0:
        IPV6.ensure_first(
            Rule(
                table="filter",
                chain="FORWARD",
                args=tuple(forward_guard_rule()),
            )
        )


def remove_forwarding_guard(firewall: Iptables) -> None:
    """
    Remove every copy of mitmwall's transit forwarding guard.
    """

    firewall.remove_all(
        Rule(
            table="filter",
            chain="FORWARD",
            args=tuple(forward_guard_rule()),
        )
    )


def remove_forwarding_guards(state: ForwardingState) -> None:
    """
    Remove transit guards after forwarding has returned to its original state.
    """

    if state.ipv4_forwarding == 0:
        remove_forwarding_guard(IPV4)
    if state.ipv6_forwarding == 0:
        remove_forwarding_guard(IPV6)


def restore_forwarding() -> bool:
    """
    Restore all saved sysctls exactly and remove the snapshot on full success.

    Missing state means this invocation did not manage forwarding and is a safe
    no-op. Invalid state and failed writes leave both the state and any transit
    guards in place so the operator can repair and retry without guessing.
    """

    try:
        _metadata = FORWARDING_STATE_FILE.lstat()
    except FileNotFoundError:
        return False

    state = read_forwarding_state()
    failures: list[str] = []
    for name, value in (
        (IPV4_FORWARDING, state.ipv4_forwarding),
        (IPV6_FORWARDING, state.ipv6_forwarding),
        (IPV4_SEND_REDIRECTS, state.ipv4_send_redirects),
    ):
        try:
            write_sysctl(name, value)
        except (OSError, subprocess.SubprocessError, RuntimeError) as error:
            failures.append(f"{name}: {error}")

    if failures:
        raise RuntimeError(
            "failed to restore saved forwarding state: " + "; ".join(failures)
        )

    remove_forwarding_guards(state)
    FORWARDING_STATE_FILE.unlink()
    try:
        FORWARDING_STATE_DIR.rmdir()
    except OSError:
        pass
    return True


def enable_forwarding() -> None:
    """
    Save, guard, and enable forwarding-related settings for mitmwall startup.
    """

    state = load_or_create_forwarding_state()
    try:
        add_forwarding_guards(state)
        write_sysctl(IPV4_FORWARDING, 1)
        write_sysctl(IPV6_FORWARDING, 1)
        write_sysctl(IPV4_SEND_REDIRECTS, 0)
    except BaseException as start_error:
        try:
            _restored = restore_forwarding()
        except BaseException as restore_error:
            raise RuntimeError(
                "failed to enable forwarding and restore its saved state"
            ) from BaseExceptionGroup(
                "forwarding setup and restoration failures",
                [start_error, restore_error],
            )
        raise


def owner_exclusion_args(users: tuple[str, ...]) -> list[str]:
    """
    Build negated owner matches for users excluded from a redirect rule.
    """

    args: list[str] = []
    for user in users:
        args.extend(["-m", "owner", "!", "--uid-owner", user])
    return args


def add_redirect_rule(
    firewall: Iptables, dport: int, bypass_users: tuple[str, ...] = ()
) -> None:
    """
    Capture direct outbound HTTP/HTTPS attempts from users other than the proxy
    user and configured bypass users, then redirect them to the local proxy.

    Install the NAT redirect idempotently.  mitmproxy itself runs as ``USER``
    and must be able to open the real upstream HTTP/HTTPS connection;
    redirecting the proxy's own traffic back into the proxy would create a loop.

    All other local users trying to connect directly to TCP port 80 or 443 are
    transparently redirected to ``PROXY_PORT``, where mitmproxy can inspect the
    HTTP(S) hostname and enforce TOML rules from ``/etc/mitmwall/rules.d``.

    Exclude loopback traffic from the redirect so localhost services remain
    reachable on their real ports instead of being captured by mitmproxy.
    """

    firewall.ensure_first(
        Rule(
            table="nat",
            chain="OUTPUT",
            args=(
                "-p",
                "tcp",
                "!",
                "-o",
                "lo",
                *owner_exclusion_args((*REQUIRED_BYPASS_USERS, *bypass_users)),
                "--dport",
                str(dport),
                "-m",
                "comment",
                "--comment",
                REDIRECT_COMMENT,
                "-j",
                "REDIRECT",
                "--to-port",
                str(PROXY_PORT),
            ),
        )
    )


def remove_redirect_rule(firewall: Iptables, dport: int) -> None:
    """
    Remove the transparent HTTP/HTTPS redirects installed by the "start" action.
    These redirects capture direct outbound web traffic from non-proxy users and
    send it to the local proxy port.
    """

    firewall.remove_all(
        Rule(
            table="nat",
            chain="OUTPUT",
            args=(
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
            ),
        )
    )


def add_dns_redirect_rule(
    firewall: Iptables, protocol: str, bypass_users: tuple[str, ...] = ()
) -> None:
    """
    Capture DNS attempts from ordinary users, including queries aimed at local
    resolvers such as 127.0.0.53, and send them to mitmproxy's DNS mode listener.
    Exclude mitmproxy, configured bypass users, and systemd-resolved so DNS proxy
    upstream resolution and resolver recursion do not loop back into the proxy.
    """

    firewall.ensure_first(
        Rule(
            table="nat",
            chain="OUTPUT",
            args=(
                "-p",
                protocol,
                *owner_exclusion_args(
                    (*REQUIRED_BYPASS_USERS, "systemd-resolve", *bypass_users)
                ),
                "--dport",
                "53",
                "-m",
                "comment",
                "--comment",
                REDIRECT_COMMENT,
                "-j",
                "REDIRECT",
                "--to-port",
                str(DNS_PORT),
            ),
        )
    )


def remove_dns_redirect_rule(firewall: Iptables, protocol: str) -> None:
    """
    Remove the DNS redirects installed by the "start" action.
    """

    firewall.remove_all(
        Rule(
            table="nat",
            chain="OUTPUT",
            args=(
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
            ),
        )
    )


def add_ntp_filter_rules(firewall: Iptables) -> None:
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
        try:
            ntp_uid = str(pwd.getpwnam(ntp_user).pw_uid)
        except KeyError:
            continue
        # Allow NTP synchronization traffic.
        firewall.append(
            Rule(
                table="filter",
                chain=CHAIN,
                args=(
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
                ),
            )
        )
        # Allow direct DNS queries (bypassed from the proxy by
        # add_ntp_dns_bypass_rule) to actually leave the host.
        firewall.append(
            Rule(
                table="filter",
                chain=CHAIN,
                args=(
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
                ),
            )
        )
        firewall.append(
            Rule(
                table="filter",
                chain=CHAIN,
                args=(
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
                ),
            )
        )


def add_ntp_dns_bypass_rule(firewall: Iptables, protocol: str) -> None:
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
        try:
            ntp_uid = str(pwd.getpwnam(ntp_user).pw_uid)
        except KeyError:
            continue
        # Move the bypass to the top on every start so it remains ahead of both
        # generic redirects and unrelated rules.
        firewall.ensure_first(
            Rule(
                table="nat",
                chain="OUTPUT",
                args=(
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
                ),
            )
        )


def remove_ntp_dns_bypass_rule(firewall: Iptables, protocol: str) -> None:
    """
    Remove the NTP DNS bypass rules installed by the "start" action.
    """

    for ntp_user in ("systemd-timesync", "_chrony", "ntp"):
        try:
            ntp_uid = str(pwd.getpwnam(ntp_user).pw_uid)
        except KeyError:
            continue
        firewall.remove_all(
            Rule(
                table="nat",
                chain="OUTPUT",
                args=(
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
                ),
            )
        )


def add_output_filter(
    firewall: Iptables, bypass_users: tuple[str, ...] = ()
) -> None:
    """
    Enforce the outbound allowlist.  Reply-direction established/related packets
    are allowed so inbound connections (for example SSH) are not broken.  The
    proxy user and configured bypass users are allowed to reach the network,
    ICMPv6 control traffic is allowed for the IPv6 stack, loopback traffic is
    allowed so localhost services remain reachable, clients are allowed to reach
    the local HTTP proxy, DNS proxy, and web UI on this host, and every other
    outbound packet is blocked.
    """

    def append_output(*args: str) -> None:
        """Append one rule to the managed output chain."""

        firewall.append(Rule(table="filter", chain=CHAIN, args=args))

    firewall.ensure_chain("filter", CHAIN)

    # Rebuild the managed chain on every service start.  Flushing only this
    # project-specific chain keeps the rules deterministic without disturbing
    # unrelated administrator-managed firewall rules in other chains.
    firewall.flush_chain("filter", CHAIN)

    # For inbound sessions, locally generated responses flow in conntrack's REPLY
    # direction.  Restricting this exception to REPLY preserves sessions such as
    # SSH without accepting ORIGINAL-direction packets from outbound connections
    # that ordinary users established before this chain was installed or rebuilt.
    append_output(
        "-m",
        "conntrack",
        "--ctstate",
        "ESTABLISHED,RELATED",
        "--ctdir",
        "REPLY",
        "-j",
        "ACCEPT",
    )

    # Operator-configured users and the required proxy account bypass the proxy
    # and fail-closed output policy.
    for bypass_user in (*bypass_users, *REQUIRED_BYPASS_USERS):
        append_output(
            "-m",
            "owner",
            "--uid-owner",
            bypass_user,
            "-j",
            "ACCEPT",
        )

    # systemd-resolved runs as systemd-resolve on Ubuntu.  Let only that resolver
    # process make upstream DNS queries; regular applications are redirected to
    # mitmproxy's local DNS listener before this filter runs.
    append_output(
        "-m",
        "owner",
        "--uid-owner",
        "systemd-resolve",
        "-j",
        "ACCEPT",
    )

    # Time synchronization clients run as unprivileged service users.  The filter
    # rules here allow their outbound NTP (UDP/123) and direct DNS (UDP/TCP 53)
    # traffic.  Note: the DNS bypass itself happens in the nat table earlier
    # (add_ntp_dns_bypass_rule); this only grants permission for the already-
    # bypassed packets to leave the host.
    add_ntp_filter_rules(firewall)

    if firewall.is_ipv6:
        # ICMPv6 is part of the IPv6 control plane, including Neighbor Discovery,
        # router discovery, address configuration, and Path MTU Discovery. RFC
        # 4890's required and recommended messages extend beyond the familiar
        # error and ND types, and a fixed type list is prone to breaking current
        # or future Linux IPv6 behavior. Allow the complete protocol instead.
        # Under mitmwall's threat model, unprivileged processes lack CAP_NET_RAW;
        # Linux ping sockets can emit only echo requests, not arbitrary ICMPv6.
        append_output(
            "-p",
            "ipv6-icmp",
            "-j",
            "ACCEPT",
        )

    # Permit connections to services on this machine.  This keeps localhost and
    # other loopback traffic working while the default policy below still blocks
    # outbound bypass attempts to remote hosts.
    append_output("-o", "lo", "-j", "ACCEPT")

    # Permit local clients to reach the transparent mitmproxy listener.  The
    # destination must be LOCAL so this does not become a general allow rule for
    # remote hosts that happen to use the same TCP port.
    append_output(
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
    )

    # Permit DNS queries to mitmproxy's DNS mode listener.  Direct queries to
    # remote DNS servers are redirected here by NAT before this filter runs.
    append_output(
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
    )
    append_output(
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
    )

    # Permit access to the mitmweb UI only on this machine.  As above, requiring a
    # LOCAL destination avoids allowing arbitrary outbound connections to remote
    # services listening on the web UI port number.
    append_output(
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
    )

    # Fail closed: anything not explicitly allowed above is a new outbound
    # connection attempt that would bypass the transparent proxy, so drop it.
    append_output("-j", "DROP")

    # Reattach at the head on every start.  An earlier terminal rule in OUTPUT
    # would otherwise bypass the fail-closed managed chain.
    firewall.ensure_first(
        Rule(table="filter", chain="OUTPUT", args=("-j", CHAIN))
    )


def remove_output_filter(firewall: Iptables) -> None:
    """
    Remove the outbound allowlist/blocklist chain installed by the "start" action.
    That chain allows reply-direction established/related packets so inbound
    services such as SSH keep working, allows configured bypass users and the
    proxy user to reach upstream hosts, allows loopback traffic, allows other
    users to connect to the local HTTP proxy, DNS proxy, and web UI ports on this
    host, and blocks all other outbound traffic.
    """

    if not firewall.chain_exists("filter", CHAIN):
        return

    firewall.remove_all(
        Rule(table="filter", chain="OUTPUT", args=("-j", CHAIN))
    )
    firewall.flush_chain("filter", CHAIN)
    firewall.delete_chain("filter", CHAIN)


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

    group_id = grp.getgrnam(USER).gr_gid
    os.chown(WEB_RULES_FILE, 0, group_id)
    WEB_RULES_FILE.chmod(0o660)


def add_rules(
    custom_rules: list[CustomRule] | None = None,
    bypass_users: tuple[str, ...] | None = None,
) -> None:
    """
    Install the full transparent proxy firewall policy.
    """

    if custom_rules is None:
        custom_rules = parse_custom_rules()
    if bypass_users is None:
        bypass_users = parse_bypass_users()

    clear_managed_redirect_rules()
    enable_forwarding()

    # Every managed NAT rule is moved to the head.  Install generic redirects
    # first, then bypasses, so bypasses retain their required higher precedence.
    for firewall in FIREWALLS:
        for protocol in ("udp", "tcp"):
            add_dns_redirect_rule(firewall, protocol, bypass_users)

    for firewall in FIREWALLS:
        for port in (80, 443):
            add_redirect_rule(firewall, port, bypass_users)

    for firewall in FIREWALLS:
        for protocol in ("udp", "tcp"):
            add_ntp_dns_bypass_rule(firewall, protocol)

    for firewall in FIREWALLS:
        add_output_filter(firewall, bypass_users)

    add_custom_rules(custom_rules)


def clear_rules() -> None:
    """
    Remove all firewall rules installed by the "start" action.
    """

    clear_managed_redirect_rules()
    clear_legacy_redirect_rules(FIREWALLS)
    clear_custom_rules()

    for firewall in FIREWALLS:
        for port in (80, 443):
            remove_redirect_rule(firewall, port)
        for protocol in ("udp", "tcp"):
            remove_ntp_dns_bypass_rule(firewall, protocol)
            remove_dns_redirect_rule(firewall, protocol)
        remove_output_filter(firewall)


# ---------------------------------------------------------------------------
# Custom iptables bypass rules (ported from custom_iptables.py)
# ---------------------------------------------------------------------------


def load_config(config_path: Path) -> dict[str, object]:
    """
    Load a TOML configuration file as a string-keyed table.
    """

    if not config_path.exists():
        return {}
    with config_path.open("rb") as file:
        config_value: object = tomllib.load(file)
    if not is_toml_table(config_value):
        return {}
    return config_value


def parse_bypass_users(config_path: Path = ADDON_CONFIG_FILE) -> tuple[str, ...]:
    """
    Parse and validate users with unrestricted outbound access.
    """

    config_value = load_config(config_path)
    value = config_value.get("bypass_users", [])
    error_prefix = f"invalid bypass user configuration in {config_path}: "
    if not is_toml_array(value):
        raise ValueError(error_prefix + "'bypass_users' must be an array of strings")

    users: list[str] = []
    for index, user_value in enumerate(value, start=1):
        if not isinstance(user_value, str) or not user_value:
            raise ValueError(
                error_prefix + f"'bypass_users' entry {index} must be a non-empty string"
            )
        try:
            _ = pwd.getpwnam(user_value)
        except KeyError as error:
            raise ValueError(
                error_prefix
                + f"'bypass_users' entry {index} names unknown user {user_value!r}"
            ) from error
        if user_value not in users and user_value not in REQUIRED_BYPASS_USERS:
            users.append(user_value)
    return tuple(users)


def parse_custom_rules(config_path: Path = ADDON_CONFIG_FILE) -> list[CustomRule]:
    """
    Parse and validate custom iptables bypass rules from a TOML config file.

    Networks are normalized with host bits cleared. Missing optional sections
    yield no rules, while every present bypass entry must be fully valid.
    """

    config_value = load_config(config_path)

    if "iptables" not in config_value:
        return []

    error_prefix = f"invalid custom firewall configuration in {config_path}: "
    iptables_value = config_value["iptables"]
    if not is_toml_table(iptables_value):
        raise ValueError(error_prefix + "'iptables' must be a table")

    if "bypass" not in iptables_value:
        return []

    bypass_value = iptables_value["bypass"]
    if not is_toml_array(bypass_value):
        raise ValueError(
            error_prefix + "'iptables.bypass' must be an array of tables"
        )

    rules: list[CustomRule] = []
    for index, rule in enumerate(bypass_value, start=1):
        entry = f"[[iptables.bypass]] entry {index}"
        if not is_toml_table(rule):
            raise ValueError(error_prefix + f"{entry} must be a table")
        network = rule.get("network")
        port = rule.get("port")
        if not isinstance(network, str):
            raise ValueError(
                error_prefix
                + f"{entry} 'network' must be a valid IPv4 or IPv6 address or network"
            )
        try:
            parsed_network = ipaddress.ip_network(network, strict=False)
        except ValueError as error:
            raise ValueError(
                error_prefix + f"{entry} has invalid network {network!r}"
            ) from error
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError(
                error_prefix
                + f"{entry} 'port' must be an integer from 1 to 65535"
            )

        table_cmd: IptablesCommand
        table_cmd = "iptables" if parsed_network.version == 4 else "ip6tables"
        rules.append(CustomRule(table_cmd, str(parsed_network), port))

    return rules


def find_drop_line_number(lines: tuple[str, ...]) -> int | None:
    """
    Find the line number of the DROP rule in iptables --line-numbers output.

    Returns the line number, or None if no DROP rule is found.
    """

    for line in lines:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "DROP":
            return int(parts[0])
    return None


def add_rule(firewall: Iptables, chain: str, network: str, port: int) -> None:
    """
    Insert a single custom ACCEPT rule into the given chain before the DROP rule.

    The rule is tagged with a comment so it can be identified and removed later.
    A missing chain is left absent; if the chain has no DROP rule, the custom
    rule is appended.
    """

    lines = firewall.list_rules("filter", chain, line_numbers=True)
    if lines is None:
        return

    drop_line = find_drop_line_number(lines)

    custom_rule = Rule(
        table="filter",
        chain=chain,
        args=(
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
        ),
    )

    if drop_line is not None:
        firewall.insert(custom_rule, drop_line)
    else:
        firewall.append(custom_rule)


def add_nat_bypass_rule(firewall: Iptables, network: str, port: int) -> None:
    """
    Insert a NAT bypass rule at the top of the OUTPUT chain so traffic to the
    specified network and port is not redirected to the transparent proxy.
    """

    firewall.ensure_first(
        Rule(
            table="nat",
            chain="OUTPUT",
            args=(
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
            ),
        )
    )


def add_custom_rules(rules: list[CustomRule] | None = None) -> None:
    """
    Read the config and insert all custom bypass rules into MITMWALL_OUTPUT.

    Existing custom rules are cleared first so repeated runs are idempotent.
    """

    if rules is None:
        rules = parse_custom_rules()

    clear_custom_rules()

    if not rules:
        return

    for rule in rules:
        firewall = firewall_for(rule.table_cmd)
        add_nat_bypass_rule(firewall, rule.network, rule.port)
        add_rule(firewall, CHAIN, rule.network, rule.port)


def remove_comment_rules(firewall: Iptables, table: Table, chain: str) -> None:
    """
    Remove all rules tagged with the mitmwall-custom comment from a chain.

    Rules are removed one at a time by line number because deleting a rule
    shifts the line numbers of the remaining rules.
    """

    firewall.remove_by_comment(table, chain, COMMENT)


def clear_managed_redirect_rules() -> None:
    """
    Remove all tagged web and DNS redirects, including stale user combinations.
    """

    for firewall in FIREWALLS:
        firewall.remove_by_comment("nat", "OUTPUT", REDIRECT_COMMENT)


def remove_custom_rules_from_chain(firewall: Iptables, chain: str) -> None:
    """
    Remove all rules tagged with the mitmwall-custom comment from a filter chain.
    """

    remove_comment_rules(firewall, "filter", chain)


def clear_custom_rules() -> None:
    """
    Remove all custom bypass rules previously inserted by add_custom_rules().
    """

    for firewall in FIREWALLS:
        remove_comment_rules(firewall, "filter", CHAIN)
        remove_comment_rules(firewall, "nat", "OUTPUT")


def usage() -> None:
    """
    Print usage information to stderr.
    """

    print(f"usage: {sys.argv[0]} {{start|stop}}", file=sys.stderr)


def main() -> None:
    """
    Entry point for the mitmwall iptables hook.
    """

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if len(sys.argv) != 2:
        usage()
        sys.exit(2)

    action = sys.argv[1]
    if action == "start":
        custom_rules = parse_custom_rules()
        bypass_users = parse_bypass_users()
        try:
            run_startup_migrations(FIREWALLS)
            configure_system_resolver()
            ensure_web_rules_file()
            add_rules(custom_rules, bypass_users)
        except BaseException as start_error:
            try:
                _restored = restore_forwarding()
                restore_system_resolver()
            except BaseException as restore_error:
                raise RuntimeError(
                    "mitmwall startup failed and runtime state restoration failed"
                ) from BaseExceptionGroup(
                    "startup and restoration failures",
                    [start_error, restore_error],
                )
            raise
    elif action == "stop":
        try:
            restored = restore_forwarding()
            if not restored:
                print(
                    "hook.py: no saved forwarding state; sysctls left unchanged",
                    file=sys.stderr,
                )
            clear_rules()
        finally:
            restore_system_resolver()
    else:
        usage()
        sys.exit(2)


if __name__ == "__main__":
    main()
