"""Typed, idempotent management of iptables and ip6tables rules."""

import os
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal


IptablesCommand = Literal["iptables", "ip6tables"]
Table = Literal["filter", "nat", "mangle", "raw", "security"]

XTABLES_WAIT_SECONDS = 10
RULE_ABSENT_ERROR = "Bad rule (does a matching rule exist in that chain?)."
CHAIN_ABSENT_ERROR = "No chain/target/match by that name."


@dataclass(frozen=True, kw_only=True)
class Rule:
    """Describe an exact rule in an iptables chain."""

    table: Table
    chain: str
    args: tuple[str, ...]


class Iptables:
    """Manage rules for one iptables address family."""

    def __init__(
        self, command: IptablesCommand, *, wait_seconds: int = XTABLES_WAIT_SECONDS
    ) -> None:
        """Create a client backed by iptables or ip6tables."""

        self.command: IptablesCommand = command
        self.wait_seconds: int = wait_seconds

    @property
    def is_ipv6(self) -> bool:
        """Return whether this client manages the IPv6 ruleset."""

        return self.command == "ip6tables"

    def run(
        self, args: Sequence[str], *, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        """Run a command after waiting for the shared xtables lock."""

        command = [self.command, "-w", str(self.wait_seconds), *args]
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=check,
            env={**os.environ, "LC_ALL": "C"},
        )

    def probe(
        self, args: Sequence[str], expected_absence: str
    ) -> subprocess.CompletedProcess[str] | None:
        """Return a successful probe or None for one expected absent state."""

        result = self.run(args, check=False)
        if result.returncode == 0:
            return result
        if result.returncode == 1 and result.stderr.rstrip().endswith(
            expected_absence
        ):
            return None
        raise subprocess.CalledProcessError(
            result.returncode,
            [self.command, "-w", str(self.wait_seconds), *args],
            output=result.stdout,
            stderr=result.stderr,
        )

    def rule_exists(self, rule: Rule) -> bool:
        """Return whether an exact rule exists."""

        return (
            self.probe(
                ["-t", rule.table, "-C", rule.chain, *rule.args],
                RULE_ABSENT_ERROR,
            )
            is not None
        )

    def append(self, rule: Rule) -> None:
        """Append a rule without checking for an existing copy."""

        _ = self.run(["-t", rule.table, "-A", rule.chain, *rule.args])

    def insert(self, rule: Rule, position: int = 1) -> None:
        """Insert a rule at a given chain position."""

        _ = self.run(
            ["-t", rule.table, "-I", rule.chain, str(position), *rule.args]
        )

    def delete(self, rule: Rule) -> None:
        """Delete one exact copy of a rule."""

        _ = self.run(["-t", rule.table, "-D", rule.chain, *rule.args])

    def remove_all(self, rule: Rule) -> None:
        """Remove every exact copy of a rule."""

        while self.rule_exists(rule):
            self.delete(rule)

    def ensure_first(self, rule: Rule) -> None:
        """Ensure exactly one copy of a rule is at the chain head."""

        self.remove_all(rule)
        self.insert(rule)

    def chain_exists(self, table: Table, chain: str) -> bool:
        """Return whether a chain exists."""

        return (
            self.probe(["-t", table, "-S", chain], CHAIN_ABSENT_ERROR)
            is not None
        )

    def ensure_chain(self, table: Table, chain: str) -> None:
        """Create a chain if it does not exist."""

        if not self.chain_exists(table, chain):
            _ = self.run(["-t", table, "-N", chain])

    def flush_chain(self, table: Table, chain: str) -> None:
        """Remove every rule from an existing chain."""

        _ = self.run(["-t", table, "-F", chain])

    def delete_chain(self, table: Table, chain: str) -> None:
        """Delete an empty chain if it exists."""

        if self.chain_exists(table, chain):
            _ = self.run(["-t", table, "-X", chain])

    def list_rules(
        self, table: Table, chain: str, *, line_numbers: bool = False
    ) -> tuple[str, ...] | None:
        """List rendered rules, or return None when the chain is absent."""

        if not self.chain_exists(table, chain):
            return None

        args = ["-t", table, "-L", chain]
        if line_numbers:
            args.append("--line-numbers")
        result = self.run(args)
        return tuple(result.stdout.splitlines())

    def remove_by_comment(self, table: Table, chain: str, comment: str) -> None:
        """Remove every rule in a chain carrying an exact comment token."""

        while True:
            lines = self.list_rules(table, chain, line_numbers=True)
            if lines is None:
                return
            for line in lines:
                parts = line.split()
                if comment in parts and parts and parts[0].isdigit():
                    _ = self.run(["-t", table, "-D", chain, parts[0]])
                    break
            else:
                return
