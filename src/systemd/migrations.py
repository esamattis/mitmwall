"""
Startup migrations for state left by historical mitmwall releases.

Migrations in this module must be safe to run repeatedly. Runtime
reconciliation for the current release belongs in the normal hook lifecycle,
not here.
"""

import os
import tempfile
from collections.abc import Sequence
from pathlib import Path

from src.systemd.iptables import Iptables, Rule


USER = "mitmwall"
APT_USER = "_apt"
PROXY_PORT = 58080
DNS_PORT = 58053
RESOLVER_STATE_DIR = Path("/var/lib/mitmwall")
RESOLVER_STATE_FILE = RESOLVER_STATE_DIR / "resolv-conf-state.json"
LEGACY_RESOLVER_STATE_DIR = Path("/run/mitmwall")
LEGACY_RESOLVER_STATE_FILE = LEGACY_RESOLVER_STATE_DIR / "resolv-conf-state.json"


def legacy_redirect_rule_args(
    protocol: str,
    dport: int,
    target_port: int,
    excluded_users: tuple[str, ...],
    *,
    exclude_loopback: bool = False,
) -> list[str]:
    """Reconstruct an exact untagged redirect signature from an older helper."""

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


def remove_legacy_rule_copies(
    firewall: Iptables,
    rule_args: list[str],
) -> None:
    """Remove every exact copy of a historical rule from the NAT OUTPUT chain."""

    firewall.remove_all(
        Rule(table="nat", chain="OUTPUT", args=tuple(rule_args))
    )


def clear_legacy_redirect_rules(firewalls: Sequence[Iptables]) -> None:
    """Remove untagged redirect forms installed by historical helpers."""

    for firewall in firewalls:
        for dport in (80, 443):
            for excluded_users, exclude_loopback in (
                ((USER,), False),
                ((USER,), True),
                (("0", USER), True),
                (("0", USER, APT_USER), True),
            ):
                remove_legacy_rule_copies(
                    firewall,
                    legacy_redirect_rule_args(
                        "tcp",
                        dport,
                        PROXY_PORT,
                        excluded_users,
                        exclude_loopback=exclude_loopback,
                    ),
                )

        for protocol in ("udp", "tcp"):
            for excluded_users in (
                ("0", USER, "systemd-resolve"),
                ("0", USER, "systemd-resolve", APT_USER),
            ):
                remove_legacy_rule_copies(
                    firewall,
                    legacy_redirect_rule_args(
                        protocol,
                        53,
                        DNS_PORT,
                        excluded_users,
                    ),
                )


def migrate_legacy_resolver_state() -> None:
    """Move an old runtime resolver snapshot into persistent private state."""

    if not LEGACY_RESOLVER_STATE_FILE.exists():
        return

    if RESOLVER_STATE_FILE.exists():
        LEGACY_RESOLVER_STATE_FILE.unlink()
    else:
        RESOLVER_STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        RESOLVER_STATE_DIR.chmod(0o700)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".resolv-conf-state-migration-", dir=RESOLVER_STATE_DIR
        )
        temporary_path = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with (
                LEGACY_RESOLVER_STATE_FILE.open("rb") as source,
                os.fdopen(descriptor, "wb") as destination,
            ):
                descriptor = -1
                while chunk := source.read(64 * 1024):
                    _ = destination.write(chunk)
                destination.flush()
                os.fsync(destination.fileno())
            os.replace(temporary_path, RESOLVER_STATE_FILE)
            LEGACY_RESOLVER_STATE_FILE.unlink()
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            temporary_path.unlink(missing_ok=True)

    try:
        LEGACY_RESOLVER_STATE_DIR.rmdir()
    except OSError:
        pass


def run_startup_migrations(firewalls: Sequence[Iptables]) -> None:
    """Migrate state left by older mitmwall versions before current-state setup."""

    migrate_legacy_resolver_state()
    clear_legacy_redirect_rules(firewalls)
