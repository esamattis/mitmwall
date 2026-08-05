#!/usr/bin/env python3
"""
mitmwall iptables hook for systemd.

Manages the transparent proxy firewall rules and optional custom egress
bypass rules.  Called by the systemd unit as ExecStartPre (start) and
ExecStopPost (stop).
"""

import ipaddress
import json
import os
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

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
XTABLES_WAIT_SECONDS = 10
RULE_ABSENT_ERROR = "Bad rule (does a matching rule exist in that chain?)."
CHAIN_ABSENT_ERROR = "No chain/target/match by that name."
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
# - Allow root, APT's sandbox user, and the proxy user to make outbound upstream
#   connections.
# - Redirect outbound DNS from non-proxy users to the local DNS proxy.
# - Allow the system DNS resolver (systemd-resolve) to reach upstream DNS.
# - Allow installed system time synchronizers to reach upstream NTP and DNS.
# - Allow ICMPv6 so the kernel can maintain IPv6 connectivity.
# - Allow all loopback traffic so localhost services remain reachable.
# - Allow other users to connect only to the local proxy, DNS proxy, and web UI ports on this host.
# - Drop all other new outbound traffic so applications cannot bypass the proxies.


def run_xtables(
    table_cmd: str, args: list[str], *, check: bool = True
) -> subprocess.CompletedProcess[str]:
    """
    Run an iptables-family command after waiting for the shared xtables lock.

    A bounded wait prevents transient concurrent firewall updates from failing
    immediately while still making a persistent lock problem visible.
    """

    command = [table_cmd, "-w", str(XTABLES_WAIT_SECONDS), *args]
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=check,
        env={**os.environ, "LC_ALL": "C"},
    )


def probe_xtables(
    table_cmd: str, args: list[str], expected_absence: str
) -> subprocess.CompletedProcess[str] | None:
    """
    Run an xtables existence/list probe and distinguish absence from failure.

    Only exit status 1 with the diagnostic specific to the requested absent
    state is idempotent. Lock timeouts, permission failures, unsupported
    features, and malformed commands are raised to the caller.
    """

    result = run_xtables(table_cmd, args, check=False)
    if result.returncode == 0:
        return result
    if result.returncode == 1 and result.stderr.rstrip().endswith(expected_absence):
        return None
    raise subprocess.CalledProcessError(
        result.returncode,
        [table_cmd, "-w", str(XTABLES_WAIT_SECONDS), *args],
        output=result.stdout,
        stderr=result.stderr,
    )


def place_rule_first(
    table_cmd: str, table: str, chain: str, rule_args: list[str]
) -> None:
    """
    Place exactly one copy of a managed rule at the head of a built-in chain.

    Removing all matching copies before insertion repairs rules left behind an
    unrelated terminal rule and keeps repeated service starts idempotent.
    """

    while True:
        existing = probe_xtables(
            table_cmd,
            ["-t", table, "-C", chain, *rule_args],
            RULE_ABSENT_ERROR,
        )
        if existing is None:
            break
        _ = run_xtables(
            table_cmd, ["-t", table, "-D", chain, *rule_args]
        )

    _ = run_xtables(
        table_cmd, ["-t", table, "-I", chain, "1", *rule_args]
    )


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

    table_cmd: Literal["iptables", "ip6tables"]
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
        value = cast(
            object, json.loads(FORWARDING_STATE_FILE.read_text(encoding="utf-8"))
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError("saved forwarding state is corrupt") from error
    if not isinstance(value, dict):
        raise RuntimeError("saved forwarding state is not a JSON object")

    fields = cast(dict[object, object], value)
    expected_fields = {
        "ipv4_forwarding",
        "ipv6_forwarding",
        "ipv4_send_redirects",
    }
    if set(fields) != expected_fields:
        raise RuntimeError("saved forwarding state has invalid fields")
    if any(type(fields[field]) is not int for field in expected_fields):
        raise RuntimeError("saved forwarding state has non-integer values")
    if any(fields[field] not in (0, 1) for field in expected_fields):
        raise RuntimeError("saved forwarding state has invalid values")

    return ForwardingState(
        cast(int, fields["ipv4_forwarding"]),
        cast(int, fields["ipv6_forwarding"]),
        cast(int, fields["ipv4_send_redirects"]),
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
        place_rule_first("iptables", "filter", "FORWARD", forward_guard_rule())
    if state.ipv6_forwarding == 0:
        place_rule_first("ip6tables", "filter", "FORWARD", forward_guard_rule())


def remove_forwarding_guard(table_cmd: str) -> None:
    """
    Remove every copy of mitmwall's transit forwarding guard.
    """

    rule = forward_guard_rule()
    while probe_xtables(
        table_cmd,
        ["-t", "filter", "-C", "FORWARD", *rule],
        RULE_ABSENT_ERROR,
    ) is not None:
        _ = run_xtables(
            table_cmd, ["-t", "filter", "-D", "FORWARD", *rule]
        )


def remove_forwarding_guards(state: ForwardingState) -> None:
    """
    Remove transit guards after forwarding has returned to its original state.
    """

    if state.ipv4_forwarding == 0:
        remove_forwarding_guard("iptables")
    if state.ipv6_forwarding == 0:
        remove_forwarding_guard("ip6tables")


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
        existing = probe_xtables(
            table_cmd,
            [
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
            RULE_ABSENT_ERROR,
        )
        if existing is None:
            break
        _ = run_xtables(
            table_cmd,
            [
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
        existing = probe_xtables(
            table_cmd,
            [
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
            RULE_ABSENT_ERROR,
        )
        if existing is None:
            break
        _ = run_xtables(
            table_cmd,
            [
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
        existing = probe_xtables(
            table_cmd,
            ["-t", "nat", "-C", "OUTPUT", *rule_args],
            RULE_ABSENT_ERROR,
        )
        if existing is None:
            break
        _ = run_xtables(
            table_cmd, ["-t", "nat", "-D", "OUTPUT", *rule_args]
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
        _ = run_xtables(
            table_cmd,
            [
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
        )
        # Allow direct DNS queries (bypassed from the proxy by
        # add_ntp_dns_bypass_rule) to actually leave the host.
        _ = run_xtables(
            table_cmd,
            [
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
        )
        _ = run_xtables(
            table_cmd,
            [
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
            existing = probe_xtables(
                table_cmd,
                [
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
                RULE_ABSENT_ERROR,
            )
            if existing is None:
                break
            _ = run_xtables(
                table_cmd,
                [
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
            )


def add_output_filter(table_cmd: str) -> None:
    """
    Enforce the outbound allowlist.  Reply-direction established/related packets
    are allowed so inbound connections (for example SSH) are not broken.  The
    proxy user, root, and APT's sandbox user are allowed to reach the network,
    ICMPv6 control traffic is allowed for the IPv6 stack, loopback traffic is
    allowed so localhost services remain reachable, clients are allowed to reach
    the local HTTP proxy, DNS proxy, and web UI on this host, and every other
    outbound packet is blocked.
    """

    existing_chain = probe_xtables(
        table_cmd,
        ["-t", "filter", "-L", CHAIN],
        CHAIN_ABSENT_ERROR,
    )
    if existing_chain is None:
        _ = run_xtables(
            table_cmd, ["-t", "filter", "-N", CHAIN]
        )

    # Rebuild the managed chain on every service start.  Flushing only this
    # project-specific chain keeps the rules deterministic without disturbing
    # unrelated administrator-managed firewall rules in other chains.
    _ = run_xtables(
        table_cmd, ["-t", "filter", "-F", CHAIN]
    )

    # For inbound sessions, locally generated responses flow in conntrack's REPLY
    # direction.  Restricting this exception to REPLY preserves sessions such as
    # SSH without accepting ORIGINAL-direction packets from outbound connections
    # that ordinary users established before this chain was installed or rebuilt.
    _ = run_xtables(
        table_cmd,
        [
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
    )

    # Root needs unrestricted outbound access for host administration and
    # troubleshooting, matching the bypass behavior of the proxy user.
    _ = run_xtables(
        table_cmd,
        [
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
    )

    # APT intentionally drops its download workers from root to _apt.  Preserve
    # that sandbox while retaining the unrestricted package-management behavior
    # expected when an administrator invokes APT as root.
    _ = run_xtables(
        table_cmd,
        [
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
    )

    # mitmproxy runs as the dedicated mitmwall user.  It needs unrestricted
    # outbound access so, after accepting a client flow, it can create the real
    # upstream connection to the destination server.
    _ = run_xtables(
        table_cmd,
        [
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
    )

    # systemd-resolved runs as systemd-resolve on Ubuntu.  Let only that resolver
    # process make upstream DNS queries; regular applications are redirected to
    # mitmproxy's local DNS listener before this filter runs.
    _ = run_xtables(
        table_cmd,
        [
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
    )

    # Time synchronization clients run as unprivileged service users.  The filter
    # rules here allow their outbound NTP (UDP/123) and direct DNS (UDP/TCP 53)
    # traffic.  Note: the DNS bypass itself happens in the nat table earlier
    # (add_ntp_dns_bypass_rule); this only grants permission for the already-
    # bypassed packets to leave the host.
    add_ntp_filter_rules(table_cmd)

    if table_cmd == "ip6tables":
        # ICMPv6 is part of the IPv6 control plane, including Neighbor Discovery,
        # router discovery, address configuration, and Path MTU Discovery. RFC
        # 4890's required and recommended messages extend beyond the familiar
        # error and ND types, and a fixed type list is prone to breaking current
        # or future Linux IPv6 behavior. Allow the complete protocol instead.
        # Under mitmwall's threat model, unprivileged processes lack CAP_NET_RAW;
        # Linux ping sockets can emit only echo requests, not arbitrary ICMPv6.
        _ = run_xtables(
            table_cmd,
            [
                "-t",
                "filter",
                "-A",
                CHAIN,
                "-p",
                "ipv6-icmp",
                "-j",
                "ACCEPT",
            ],
        )

    # Permit connections to services on this machine.  This keeps localhost and
    # other loopback traffic working while the default policy below still blocks
    # outbound bypass attempts to remote hosts.
    _ = run_xtables(
        table_cmd,
        ["-t", "filter", "-A", CHAIN, "-o", "lo", "-j", "ACCEPT"],
    )

    # Permit local clients to reach the transparent mitmproxy listener.  The
    # destination must be LOCAL so this does not become a general allow rule for
    # remote hosts that happen to use the same TCP port.
    _ = run_xtables(
        table_cmd,
        [
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
    )

    # Permit DNS queries to mitmproxy's DNS mode listener.  Direct queries to
    # remote DNS servers are redirected here by NAT before this filter runs.
    _ = run_xtables(
        table_cmd,
        [
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
    )
    _ = run_xtables(
        table_cmd,
        [
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
    )

    # Permit access to the mitmweb UI only on this machine.  As above, requiring a
    # LOCAL destination avoids allowing arbitrary outbound connections to remote
    # services listening on the web UI port number.
    _ = run_xtables(
        table_cmd,
        [
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
    )

    # Fail closed: anything not explicitly allowed above is a new outbound
    # connection attempt that would bypass the transparent proxy, so drop it.
    _ = run_xtables(
        table_cmd, ["-t", "filter", "-A", CHAIN, "-j", "DROP"]
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

    existing_chain = probe_xtables(
        table_cmd,
        ["-t", "filter", "-L", CHAIN],
        CHAIN_ABSENT_ERROR,
    )
    if existing_chain is None:
        return

    while True:
        existing_jump = probe_xtables(
            table_cmd,
            ["-t", "filter", "-C", "OUTPUT", "-j", CHAIN],
            RULE_ABSENT_ERROR,
        )
        if existing_jump is None:
            break
        _ = run_xtables(
            table_cmd, ["-t", "filter", "-D", "OUTPUT", "-j", CHAIN]
        )

    _ = run_xtables(table_cmd, ["-t", "filter", "-F", CHAIN])
    _ = run_xtables(table_cmd, ["-t", "filter", "-X", CHAIN])


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


def add_rules(custom_rules: list[CustomRule] | None = None) -> None:
    """
    Install the full transparent proxy firewall policy.
    """

    if custom_rules is None:
        custom_rules = parse_custom_rules()

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

    add_custom_rules(custom_rules)


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


def parse_custom_rules(config_path: Path = ADDON_CONFIG_FILE) -> list[CustomRule]:
    """
    Parse and validate custom iptables bypass rules from a TOML config file.

    Networks are normalized with host bits cleared. Missing optional sections
    yield no rules, while every present bypass entry must be fully valid.
    """

    if not config_path.exists():
        return []

    with config_path.open("rb") as file:
        config_value = cast(object, tomllib.load(file))

    if not is_toml_table(config_value):
        return []

    if "iptables" not in config_value:
        return []

    error_prefix = f"invalid custom firewall configuration in {config_path}: "
    iptables_value = config_value["iptables"]
    if not is_toml_table(iptables_value):
        raise ValueError(error_prefix + "'iptables' must be a table")

    if "bypass" not in iptables_value:
        return []

    bypass_value = iptables_value["bypass"]
    if not isinstance(bypass_value, list):
        raise ValueError(
            error_prefix + "'iptables.bypass' must be an array of tables"
        )

    bypass_rules = cast(list[object], bypass_value)
    rules: list[CustomRule] = []
    for index, rule in enumerate(bypass_rules, start=1):
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

        table_cmd: Literal["iptables", "ip6tables"]
        table_cmd = "iptables" if parsed_network.version == 4 else "ip6tables"
        rules.append(CustomRule(table_cmd, str(parsed_network), port))

    return rules


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
    A missing chain is left absent; if the chain has no DROP rule, the custom
    rule is appended.
    """

    rule_args = [
        "-t",
        "filter",
        "-L",
        chain,
        "--line-numbers",
    ]
    result = probe_xtables(table_cmd, rule_args, CHAIN_ABSENT_ERROR)
    if result is None:
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
        _ = run_xtables(
            table_cmd,
            ["-t", "filter", "-I", chain, drop_line, *custom_rule],
        )
    else:
        _ = run_xtables(
            table_cmd, ["-t", "filter", "-A", chain, *custom_rule]
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
        add_nat_bypass_rule(rule.table_cmd, rule.network, rule.port)
        add_rule(rule.table_cmd, CHAIN, rule.network, rule.port)


def remove_comment_rules(table_cmd: str, table: str, chain: str) -> None:
    """
    Remove all rules tagged with the mitmwall-custom comment from a chain.

    Rules are removed one at a time by line number because deleting a rule
    shifts the line numbers of the remaining rules.
    """

    while True:
        result = probe_xtables(
            table_cmd,
            ["-t", table, "-L", chain, "--line-numbers"],
            CHAIN_ABSENT_ERROR,
        )
        if result is None:
            break

        removed = False
        for line in result.stdout.splitlines():
            if COMMENT in line:
                parts = line.split()
                if parts and parts[0].isdigit():
                    _ = run_xtables(
                        table_cmd, ["-t", table, "-D", chain, parts[0]]
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
        custom_rules = parse_custom_rules()
        try:
            configure_system_resolver()
            ensure_web_rules_file()
            add_rules(custom_rules)
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
