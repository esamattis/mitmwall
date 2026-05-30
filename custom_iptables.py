#!/usr/bin/env python3
"""
Custom iptables rule manager for mitmwall.

Reads /etc/mitmwall/config.toml and manages additional egress allow rules
in the MITMWALL_OUTPUT chain so operators can permit traffic to specific
networks and ports without maintaining a separate firewall script.
"""

import subprocess
import sys
import tomllib
from pathlib import Path
from typing import cast

from mitmproxy_addon.toml_helpers import is_toml_table

CONFIG_PATH = Path("/etc/mitmwall/config.toml")
CHAIN = "MITMWALL_OUTPUT"
COMMENT = "mitmwall-custom"


def run_iptables(*args: str) -> subprocess.CompletedProcess[str]:
    """
    Run iptables with the given arguments and return the completed process.
    """

    return subprocess.run(["iptables", *args], capture_output=True, text=True)


def run_ip6tables(*args: str) -> subprocess.CompletedProcess[str]:
    """
    Run ip6tables with the given arguments and return the completed process.
    """

    return subprocess.run(["ip6tables", *args], capture_output=True, text=True)


def parse_custom_rules(config_path: Path = CONFIG_PATH) -> list[tuple[str, int]]:
    """
    Parse custom iptables allow rules from a TOML config file.

    Returns a list of (network, port) tuples for each [[iptables.allow]]
    entry.  If the file does not exist, the iptables key is missing, or
    the allow table is malformed, an empty list is returned.
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

    allow_value = iptables_value.get("allow")
    if not isinstance(allow_value, list):
        return []

    allow_rules = cast(list[object], allow_value)
    rules: list[tuple[str, int]] = []
    for rule in allow_rules:
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

    IPv6 networks contain at least one colon; all others are treated as IPv4.
    """

    return ":" not in network


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


def add_rule(
    table_cmd: list[str], chain: str, network: str, port: int
) -> None:
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
    result = subprocess.run([*table_cmd, *rule_args], capture_output=True, text=True)
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
            [*table_cmd, "-t", "filter", "-I", chain, drop_line, *custom_rule]
        )
    else:
        _ = subprocess.run([*table_cmd, "-t", "filter", "-A", chain, *custom_rule])


def add_rules() -> None:
    """
    Read the config and insert all custom allow rules into MITMWALL_OUTPUT.

    Existing custom rules are cleared first so repeated runs are idempotent.
    """

    rules = parse_custom_rules()
    if not rules:
        return

    clear_rules()

    for network, port in rules:
        if is_ipv4_network(network):
            add_rule(["iptables"], CHAIN, network, port)
        else:
            add_rule(["ip6tables"], CHAIN, network, port)


def remove_custom_rules_from_chain(table_cmd: list[str], chain: str) -> None:
    """
    Remove all rules tagged with the mitmwall-custom comment from a chain.

    Rules are removed one at a time by line number because deleting a rule
    shifts the line numbers of the remaining rules.
    """

    while True:
        result = subprocess.run(
            [*table_cmd, "-t", "filter", "-L", chain, "--line-numbers"],
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
                    delete_result = subprocess.run(
                        [*table_cmd, "-t", "filter", "-D", chain, parts[0]],
                        capture_output=True,
                    )
                    if delete_result.returncode == 0:
                        removed = True
                        break

        if not removed:
            break


def clear_rules() -> None:
    """
    Remove all custom allow rules previously inserted by add_rules().
    """

    remove_custom_rules_from_chain(["iptables"], CHAIN)
    remove_custom_rules_from_chain(["ip6tables"], CHAIN)


def usage() -> None:
    """
    Print usage information to stderr.
    """

    print(f"usage: {sys.argv[0]} {{add|clear}}", file=sys.stderr)


def main() -> None:
    """
    Entry point for the custom iptables rule manager.
    """

    if len(sys.argv) != 2:
        usage()
        sys.exit(2)

    action = sys.argv[1]
    if action == "add":
        add_rules()
    elif action == "clear":
        clear_rules()
    else:
        usage()
        sys.exit(2)


if __name__ == "__main__":
    main()
