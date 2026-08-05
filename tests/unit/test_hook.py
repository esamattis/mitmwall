"""
Unit tests for the mitmwall iptables hook.
"""

import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock, call, patch

from src.systemd import hook, resolv_conf as resolver


class ParseCustomRulesTests(unittest.TestCase):
    """
    Verify parsing of custom iptables rules from TOML config.
    """

    def test_missing_config_file_returns_empty_list(self) -> None:
        """
        A missing config file yields no custom rules.
        """

        rules = hook.parse_custom_rules(Path("/nonexistent/config.toml"))
        self.assertEqual(rules, [])

    def test_valid_iptables_bypass_rules(self) -> None:
        """
        IPv4, IPv6, host bits, and boundary ports are parsed and normalized.
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as file:
            _ = file.write("""
[[iptables.bypass]]
network = "192.168.5.129/24"
port = 1

[[iptables.bypass]]
network = "2001:0db8::1"
port = 65535
""")
            path = Path(file.name)

        try:
            rules = hook.parse_custom_rules(path)
            self.assertEqual(
                rules,
                [
                    hook.CustomRule("iptables", "192.168.5.0/24", 1),
                    hook.CustomRule("ip6tables", "2001:db8::1/128", 65535),
                ],
            )
        finally:
            path.unlink()

    def test_missing_iptables_key_returns_empty_list(self) -> None:
        """
        A config file without an iptables section yields no rules.
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as file:
            _ = file.write('log_level = "info"\n')
            path = Path(file.name)

        try:
            rules = hook.parse_custom_rules(path)
            self.assertEqual(rules, [])
        finally:
            path.unlink()

    def test_malformed_network_is_rejected(self) -> None:
        """
        A value that is neither an IPv4 nor IPv6 network is a configuration error.
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as file:
            _ = file.write("""
[[iptables.bypass]]
network = "not-a-network"
port = 8080
""")
            path = Path(file.name)

        try:
            with self.assertRaisesRegex(
                ValueError,
                r"invalid custom firewall configuration.*entry 1 has invalid network 'not-a-network'",
            ):
                _ = hook.parse_custom_rules(path)
        finally:
            path.unlink()

    def test_invalid_ports_are_rejected(self) -> None:
        """
        Booleans, zero, negatives, and values above 65535 are invalid ports.
        """

        for port in ("true", "0", "-1", "65536"):
            with self.subTest(port=port):
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".toml", delete=False
                ) as file:
                    config_text = (
                        f'[[iptables.bypass]]\nnetwork = "192.0.2.1"\nport = {port}\n'
                    )
                    _ = file.write(config_text)
                    path = Path(file.name)

                try:
                    with self.assertRaisesRegex(
                        ValueError, r"'port' must be an integer from 1 to 65535"
                    ):
                        _ = hook.parse_custom_rules(path)
                finally:
                    path.unlink()

    def test_incomplete_entry_is_rejected_instead_of_skipped(self) -> None:
        """
        One invalid entry rejects the configuration even when another is valid.
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as file:
            _ = file.write("""
[[iptables.bypass]]
network = "192.0.2.1"

[[iptables.bypass]]
network = "2001:db8::/32"
port = 443
""")
            path = Path(file.name)

        try:
            with self.assertRaisesRegex(ValueError, r"entry 1 'port' must be"):
                _ = hook.parse_custom_rules(path)
        finally:
            path.unlink()


class FindDropLineNumberTests(unittest.TestCase):
    """
    Verify extraction of the DROP rule line number from iptables output.
    """

    def test_finds_drop_line(self) -> None:
        """
        The DROP rule line number is extracted from iptables --line-numbers output.
        """

        stdout = """Chain MITMWALL_OUTPUT (1 references)
num  target     prot opt source               destination
1    ACCEPT     all  --  anywhere             anywhere             ctstate ESTABLISHED,RELATED
2    ACCEPT     all  --  anywhere             anywhere             owner UID match root
3    DROP       all  --  anywhere             anywhere
"""
        result = subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout)
        self.assertEqual(hook.find_drop_line_number(result), "3")

    def test_returns_none_when_no_drop(self) -> None:
        """
        None is returned when no DROP rule is present.
        """

        stdout = """Chain MITMWALL_OUTPUT (1 references)
num  target     prot opt source               destination
1    ACCEPT     all  --  anywhere             anywhere
"""
        result = subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout)
        self.assertIsNone(hook.find_drop_line_number(result))


class XtablesCommandTests(unittest.TestCase):
    """
    Verify centralized xtables locking and probe error classification.
    """

    @patch("src.systemd.hook.subprocess.run")
    def test_ipv4_and_ipv6_commands_wait_for_xtables_lock(
        self, mock_run: MagicMock
    ) -> None:
        """
        Every iptables-family invocation includes the bounded lock wait flags.
        """

        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )

        for table_cmd in ("iptables", "ip6tables"):
            _ = hook.run_xtables(table_cmd, ["-t", "filter", "-L", "OUTPUT"])

        commands = [invocation.args[0] for invocation in mock_run.call_args_list]
        self.assertEqual(
            commands,
            [
                ["iptables", "-w", "10", "-t", "filter", "-L", "OUTPUT"],
                ["ip6tables", "-w", "10", "-t", "filter", "-L", "OUTPUT"],
            ],
        )
        self.assertTrue(
            all(
                invocation.kwargs["env"]["LC_ALL"] == "C"
                for invocation in mock_run.call_args_list
            )
        )

    @patch("src.systemd.hook.run_xtables")
    def test_expected_rule_and_chain_absence_is_idempotent(
        self, mock_run: MagicMock
    ) -> None:
        """
        Canonical missing-rule and missing-chain probe results return None.
        """

        for absence_error in (hook.RULE_ABSENT_ERROR, hook.CHAIN_ABSENT_ERROR):
            with self.subTest(absence_error=absence_error):
                mock_run.return_value = subprocess.CompletedProcess(
                    args=["iptables"],
                    returncode=1,
                    stdout="",
                    stderr=f"iptables: {absence_error}\n",
                )

                self.assertIsNone(
                    hook.probe_xtables("iptables", ["probe"], absence_error)
                )

    @patch("src.systemd.hook.run_xtables")
    def test_probe_raises_unexpected_operational_errors(
        self, mock_run: MagicMock
    ) -> None:
        """
        Lock, permission, unsupported-feature, and syntax errors remain visible.
        """

        errors = (
            (4, "Another app is currently holding the xtables lock"),
            (4, "Permission denied (you must be root)"),
            (3, "can't initialize iptables table `security': Table does not exist"),
            (1, "Couldn't load match `owner':No such file or directory"),
            (2, "unknown option --malformed"),
        )
        for returncode, stderr in errors:
            with self.subTest(stderr=stderr):
                mock_run.return_value = subprocess.CompletedProcess(
                    args=["iptables"],
                    returncode=returncode,
                    stdout="",
                    stderr=stderr,
                )

                with self.assertRaises(subprocess.CalledProcessError):
                    _ = hook.probe_xtables(
                        "iptables",
                        ["-t", "filter", "-C", "OUTPUT"],
                        hook.RULE_ABSENT_ERROR,
                    )

    @patch("src.systemd.hook.subprocess.run")
    def test_cleanup_probe_error_propagates(self, mock_run: MagicMock) -> None:
        """
        Cleanup raises instead of reporting success after an operational error.
        """

        mock_run.return_value = subprocess.CompletedProcess(
            args=["iptables"],
            returncode=4,
            stdout="",
            stderr="Another app is currently holding the xtables lock",
        )

        with self.assertRaises(subprocess.CalledProcessError):
            hook.remove_redirect_rule("iptables", 443)


class ForwardingStateTests(unittest.TestCase):
    """
    Verify forwarding sysctl snapshots, guards, and exact restoration.
    """

    def test_repeated_enable_preserves_snapshot_and_restores_exact_values(self) -> None:
        """
        Repeated starts retain the first values and stop restores all of them.
        """

        with tempfile.TemporaryDirectory() as temp_dir:
            state_dir = Path(temp_dir) / "run" / "mitmwall"
            state_file = state_dir / "forwarding-state.json"
            values = {
                hook.IPV4_FORWARDING: 0,
                hook.IPV6_FORWARDING: 1,
                hook.IPV4_SEND_REDIRECTS: 1,
            }

            def write_value(name: str, value: int) -> None:
                """Record a simulated sysctl write."""

                values[name] = value

            def read_value(name: str) -> int:
                """Return a simulated sysctl value."""

                return values[name]

            with (
                patch("src.systemd.hook.FORWARDING_STATE_DIR", state_dir),
                patch("src.systemd.hook.FORWARDING_STATE_FILE", state_file),
                patch(
                    "src.systemd.hook.read_sysctl",
                    side_effect=read_value,
                ) as mock_read,
                patch("src.systemd.hook.write_sysctl", side_effect=write_value),
                patch("src.systemd.hook.add_forwarding_guards") as mock_add_guards,
                patch(
                    "src.systemd.hook.remove_forwarding_guards"
                ) as mock_remove_guards,
            ):
                hook.enable_forwarding()
                original_snapshot = state_file.read_bytes()
                hook.enable_forwarding()

                self.assertEqual(state_file.read_bytes(), original_snapshot)
                self.assertEqual(mock_read.call_count, 3)
                self.assertEqual(
                    values,
                    {
                        hook.IPV4_FORWARDING: 1,
                        hook.IPV6_FORWARDING: 1,
                        hook.IPV4_SEND_REDIRECTS: 0,
                    },
                )

                self.assertTrue(hook.restore_forwarding())

            expected_state = hook.ForwardingState(0, 1, 1)
            self.assertEqual(values[hook.IPV4_FORWARDING], 0)
            self.assertEqual(values[hook.IPV6_FORWARDING], 1)
            self.assertEqual(values[hook.IPV4_SEND_REDIRECTS], 1)
            self.assertEqual(
                mock_add_guards.call_args_list,
                [call(expected_state), call(expected_state)],
            )
            mock_remove_guards.assert_called_once_with(expected_state)
            self.assertFalse(state_file.exists())

    def test_enable_failure_restores_snapshot_and_removes_state(self) -> None:
        """
        A partial sysctl setup failure restores every exact original value.
        """

        with tempfile.TemporaryDirectory() as temp_dir:
            state_dir = Path(temp_dir) / "run" / "mitmwall"
            state_file = state_dir / "forwarding-state.json"
            values = {
                hook.IPV4_FORWARDING: 0,
                hook.IPV6_FORWARDING: 0,
                hook.IPV4_SEND_REDIRECTS: 1,
            }
            failed = False

            def write_value(name: str, value: int) -> None:
                """Fail the first IPv6 enable write and record all others."""

                nonlocal failed
                if name == hook.IPV6_FORWARDING and value == 1 and not failed:
                    failed = True
                    raise subprocess.CalledProcessError(1, ["sysctl"])
                values[name] = value

            def read_value(name: str) -> int:
                """Return a simulated sysctl value."""

                return values[name]

            with (
                patch("src.systemd.hook.FORWARDING_STATE_DIR", state_dir),
                patch("src.systemd.hook.FORWARDING_STATE_FILE", state_file),
                patch(
                    "src.systemd.hook.read_sysctl",
                    side_effect=read_value,
                ),
                patch("src.systemd.hook.write_sysctl", side_effect=write_value),
                patch("src.systemd.hook.add_forwarding_guards"),
                patch("src.systemd.hook.remove_forwarding_guards"),
            ):
                with self.assertRaises(subprocess.CalledProcessError):
                    hook.enable_forwarding()

            self.assertEqual(
                values,
                {
                    hook.IPV4_FORWARDING: 0,
                    hook.IPV6_FORWARDING: 0,
                    hook.IPV4_SEND_REDIRECTS: 1,
                },
            )
            self.assertFalse(state_file.exists())

    def test_corrupt_existing_state_fails_before_any_sysctl_change(self) -> None:
        """
        Corrupt state is preserved and prevents a start from guessing values.
        """

        with tempfile.TemporaryDirectory() as temp_dir:
            state_dir = Path(temp_dir) / "run" / "mitmwall"
            state_file = state_dir / "forwarding-state.json"
            state_dir.mkdir(mode=0o700, parents=True)
            _ = state_file.write_text("not json\n", encoding="utf-8")
            state_file.chmod(0o600)

            with (
                patch("src.systemd.hook.FORWARDING_STATE_DIR", state_dir),
                patch("src.systemd.hook.FORWARDING_STATE_FILE", state_file),
                patch("src.systemd.hook.read_sysctl") as mock_read,
                patch("src.systemd.hook.write_sysctl") as mock_write,
                patch("src.systemd.hook.add_forwarding_guards") as mock_guards,
            ):
                with self.assertRaisesRegex(RuntimeError, "state is corrupt"):
                    hook.enable_forwarding()

            mock_read.assert_not_called()
            mock_write.assert_not_called()
            mock_guards.assert_not_called()
            self.assertTrue(state_file.exists())

    def test_missing_state_is_a_safe_restore_no_op(self) -> None:
        """
        Stop does not invent values when no forwarding snapshot exists.
        """

        with tempfile.TemporaryDirectory() as temp_dir:
            state_dir = Path(temp_dir) / "run" / "mitmwall"
            state_file = state_dir / "forwarding-state.json"
            with (
                patch("src.systemd.hook.FORWARDING_STATE_DIR", state_dir),
                patch("src.systemd.hook.FORWARDING_STATE_FILE", state_file),
                patch("src.systemd.hook.write_sysctl") as mock_write,
            ):
                self.assertFalse(hook.restore_forwarding())

            mock_write.assert_not_called()

    def test_restore_failure_preserves_state_and_transit_guard(self) -> None:
        """
        Failed restoration remains retryable and does not expose forwarding.
        """

        with tempfile.TemporaryDirectory() as temp_dir:
            state_dir = Path(temp_dir) / "run" / "mitmwall"
            state_file = state_dir / "forwarding-state.json"
            state = hook.ForwardingState(0, 0, 1)
            with (
                patch("src.systemd.hook.FORWARDING_STATE_DIR", state_dir),
                patch("src.systemd.hook.FORWARDING_STATE_FILE", state_file),
            ):
                hook.write_forwarding_state(state)

                def fail_ipv6(name: str, _value: int) -> None:
                    """Simulate one sysctl that cannot be restored."""

                    if name == hook.IPV6_FORWARDING:
                        raise subprocess.CalledProcessError(1, ["sysctl"])

                with (
                    patch("src.systemd.hook.write_sysctl", side_effect=fail_ipv6),
                    patch(
                        "src.systemd.hook.remove_forwarding_guards"
                    ) as mock_remove,
                ):
                    with self.assertRaisesRegex(
                        RuntimeError, "failed to restore saved forwarding state"
                    ):
                        _restored = hook.restore_forwarding()

                self.assertTrue(state_file.exists())
                mock_remove.assert_not_called()

    @patch("src.systemd.hook.place_rule_first")
    def test_guards_only_newly_enabled_address_families(
        self, mock_place: MagicMock
    ) -> None:
        """
        Existing administrator forwarding remains outside mitmwall policy.
        """

        hook.add_forwarding_guards(hook.ForwardingState(0, 1, 1))

        mock_place.assert_called_once_with(
            "iptables", "filter", "FORWARD", hook.forward_guard_rule()
        )

    def test_snapshot_permissions_are_root_only(self) -> None:
        """
        The runtime directory and state file exclude group and other users.
        """

        with tempfile.TemporaryDirectory() as temp_dir:
            state_dir = Path(temp_dir) / "run" / "mitmwall"
            state_file = state_dir / "forwarding-state.json"
            with (
                patch("src.systemd.hook.FORWARDING_STATE_DIR", state_dir),
                patch("src.systemd.hook.FORWARDING_STATE_FILE", state_file),
            ):
                hook.write_forwarding_state(hook.ForwardingState(0, 1, 1))

            self.assertEqual(state_dir.stat().st_mode & 0o777, 0o700)
            self.assertEqual(state_file.stat().st_mode & 0o777, 0o600)


class PlaceRuleFirstTests(unittest.TestCase):
    """
    Verify managed entry points are repaired at the head of built-in chains.
    """

    @patch("src.systemd.hook.subprocess.run")
    def test_repositions_existing_ipv4_and_ipv6_rules(
        self, mock_run: MagicMock
    ) -> None:
        """
        Existing rules are deleted and reinserted at position one for both families.
        """

        rule = ["-j", hook.CHAIN]
        for table_cmd in ("iptables", "ip6tables"):
            with self.subTest(table_cmd=table_cmd):
                mock_run.reset_mock()
                mock_run.side_effect = [
                    subprocess.CompletedProcess(args=[], returncode=0),
                    subprocess.CompletedProcess(args=[], returncode=0),
                    subprocess.CompletedProcess(
                        args=[], returncode=1, stderr=hook.RULE_ABSENT_ERROR
                    ),
                    subprocess.CompletedProcess(args=[], returncode=0),
                ]

                hook.place_rule_first(table_cmd, "filter", "OUTPUT", rule)

                self.assertEqual(
                    [item.args[0] for item in mock_run.call_args_list],
                    [
                        [
                            table_cmd,
                            "-w",
                            "10",
                            "-t",
                            "filter",
                            "-C",
                            "OUTPUT",
                            *rule,
                        ],
                        [
                            table_cmd,
                            "-w",
                            "10",
                            "-t",
                            "filter",
                            "-D",
                            "OUTPUT",
                            *rule,
                        ],
                        [
                            table_cmd,
                            "-w",
                            "10",
                            "-t",
                            "filter",
                            "-C",
                            "OUTPUT",
                            *rule,
                        ],
                        [
                            table_cmd,
                            "-w",
                            "10",
                            "-t",
                            "filter",
                            "-I",
                            "OUTPUT",
                            "1",
                            *rule,
                        ],
                    ],
                )

    @patch("src.systemd.hook.subprocess.run")
    def test_removes_duplicate_rules_before_inserting_one(
        self, mock_run: MagicMock
    ) -> None:
        """
        Repeated starts converge duplicate managed rules to one head rule.
        """

        mock_run.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=0),
            subprocess.CompletedProcess(args=[], returncode=0),
            subprocess.CompletedProcess(args=[], returncode=0),
            subprocess.CompletedProcess(args=[], returncode=0),
            subprocess.CompletedProcess(
                args=[], returncode=1, stderr=hook.RULE_ABSENT_ERROR
            ),
            subprocess.CompletedProcess(args=[], returncode=0),
        ]

        hook.place_rule_first("iptables", "nat", "OUTPUT", ["-j", "REDIRECT"])

        commands = [
            cast(list[str], item.args[0]) for item in mock_run.call_args_list
        ]
        self.assertEqual(sum("-D" in command for command in commands), 2)
        self.assertEqual(sum("-I" in command for command in commands), 1)
        self.assertEqual(commands[-1][7:9], ["1", "-j"])


class LegacyRedirectCleanupTests(unittest.TestCase):
    """
    Verify cleanup recognizes exact untagged redirect forms from old helpers.
    """

    @patch("src.systemd.hook.remove_legacy_rule_copies")
    def test_removes_all_shipped_legacy_redirect_forms(
        self, mock_remove: MagicMock
    ) -> None:
        """
        IPv4 and IPv6 web and DNS signatures from prior releases are removed.
        """

        hook.clear_legacy_redirect_rules()

        self.assertEqual(mock_remove.call_count, 16)
        for table_cmd in ("iptables", "ip6tables"):
            mock_remove.assert_any_call(
                table_cmd,
                hook.legacy_redirect_rule_args(
                    "tcp", 80, hook.PROXY_PORT, (hook.USER,)
                ),
            )
            mock_remove.assert_any_call(
                table_cmd,
                hook.legacy_redirect_rule_args(
                    "tcp",
                    443,
                    hook.PROXY_PORT,
                    ("0", hook.USER),
                    exclude_loopback=True,
                ),
            )
            for protocol in ("udp", "tcp"):
                mock_remove.assert_any_call(
                    table_cmd,
                    hook.legacy_redirect_rule_args(
                        protocol,
                        53,
                        hook.DNS_PORT,
                        ("0", hook.USER, "systemd-resolve"),
                    ),
                )

    @patch("src.systemd.hook.remove_legacy_rule_copies")
    def test_does_not_treat_current_redirects_as_legacy(
        self, mock_remove: MagicMock
    ) -> None:
        """
        Legacy migration leaves current APT-excluding forms to normal cleanup.
        """

        hook.clear_legacy_redirect_rules()

        removed_rules = [
            cast(list[str], invocation.args[1])
            for invocation in mock_remove.call_args_list
        ]
        self.assertTrue(removed_rules)
        self.assertTrue(all(hook.APT_USER not in rule for rule in removed_rules))

    @patch("src.systemd.hook.subprocess.run")
    def test_removes_every_copy_by_exact_rule_syntax(
        self, mock_run: MagicMock
    ) -> None:
        """
        Duplicate legacy rules are checked and deleted until none remain.
        """

        mock_run.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=0),
            subprocess.CompletedProcess(args=[], returncode=0),
            subprocess.CompletedProcess(args=[], returncode=0),
            subprocess.CompletedProcess(args=[], returncode=0),
            subprocess.CompletedProcess(
                args=[], returncode=1, stderr=hook.RULE_ABSENT_ERROR
            ),
        ]
        rule = hook.legacy_redirect_rule_args(
            "tcp", 443, hook.PROXY_PORT, ("0", hook.USER), exclude_loopback=True
        )

        hook.remove_legacy_rule_copies("iptables", rule)

        commands = [invocation.args[0] for invocation in mock_run.call_args_list]
        delete_command = [
            "iptables",
            "-w",
            "10",
            "-t",
            "nat",
            "-D",
            "OUTPUT",
            *rule,
        ]
        check_command = [
            "iptables",
            "-w",
            "10",
            "-t",
            "nat",
            "-C",
            "OUTPUT",
            *rule,
        ]
        self.assertEqual(commands.count(delete_command), 2)
        self.assertEqual(commands[-1], check_command)


class OutputFilterConntrackTests(unittest.TestCase):
    """
    Verify the OUTPUT filter's conntrack direction restriction.
    """

    @patch("src.systemd.hook.place_rule_first")
    @patch("src.systemd.hook.add_ntp_filter_rules")
    @patch("src.systemd.hook.subprocess.run")
    def test_first_accept_rule_only_allows_reply_direction(
        self, mock_run: MagicMock, _mock_ntp: MagicMock, mock_place: MagicMock
    ) -> None:
        """
        Established outbound flows do not bypass policy after a chain rebuild.
        """

        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)

        hook.add_output_filter("iptables")

        commands = [call[0][0] for call in mock_run.call_args_list]
        self.assertEqual(commands[2], [
            "iptables",
            "-w",
            "10",
            "-t",
            "filter",
            "-A",
            hook.CHAIN,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "--ctdir",
            "REPLY",
            "-j",
            "ACCEPT",
        ])
        self.assertNotIn(
            [
                "iptables",
                "-w",
                "10",
                "-t",
                "filter",
                "-A",
                hook.CHAIN,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ],
            commands,
        )
        mock_place.assert_called_once_with(
            "iptables", "filter", "OUTPUT", ["-j", hook.CHAIN]
        )


class OutputFilterIPv6ControlPlaneTests(unittest.TestCase):
    """
    Verify that only IPv6 receives the control-plane protocol allowance.
    """

    @patch("src.systemd.hook.place_rule_first")
    @patch("src.systemd.hook.add_ntp_filter_rules")
    @patch("src.systemd.hook.subprocess.run")
    def test_allows_icmpv6_before_drop(
        self, mock_run: MagicMock, _mock_ntp: MagicMock, _mock_place: MagicMock
    ) -> None:
        """
        The IPv6 chain accepts the complete ICMPv6 protocol before failing closed.
        """

        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)

        hook.add_output_filter("ip6tables")

        commands = [
            cast(list[str], invocation.args[0])
            for invocation in mock_run.call_args_list
        ]
        icmpv6_rule = [
            "ip6tables",
            "-w",
            "10",
            "-t",
            "filter",
            "-A",
            hook.CHAIN,
            "-p",
            "ipv6-icmp",
            "-j",
            "ACCEPT",
        ]
        drop_rule = [
            "ip6tables",
            "-w",
            "10",
            "-t",
            "filter",
            "-A",
            hook.CHAIN,
            "-j",
            "DROP",
        ]
        self.assertEqual(commands.count(icmpv6_rule), 1)
        self.assertLess(commands.index(icmpv6_rule), commands.index(drop_rule))

    @patch("src.systemd.hook.place_rule_first")
    @patch("src.systemd.hook.add_ntp_filter_rules")
    @patch("src.systemd.hook.subprocess.run")
    def test_ipv4_has_no_corresponding_protocol_allowance(
        self, mock_run: MagicMock, _mock_ntp: MagicMock, _mock_place: MagicMock
    ) -> None:
        """
        The IPv4 chain retains its policy without a protocol-wide allowance.
        """

        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)

        hook.add_output_filter("iptables")

        commands = [
            cast(list[str], invocation.args[0])
            for invocation in mock_run.call_args_list
        ]
        appended_rules = [
            command[7:]
            for command in commands
            if command[5:7] == ["-A", hook.CHAIN]
        ]
        self.assertNotIn(["-p", "icmp", "-j", "ACCEPT"], appended_rules)
        self.assertNotIn(["-p", "tcp", "-j", "ACCEPT"], appended_rules)
        self.assertNotIn(["-p", "udp", "-j", "ACCEPT"], appended_rules)


class AddRuleTests(unittest.TestCase):
    """
    Verify add_rule inserts custom rules into an iptables chain.
    """

    @patch("src.systemd.hook.subprocess.run")
    def test_inserts_before_drop(self, mock_run: MagicMock) -> None:
        """
        The rule is inserted before the DROP rule when one exists.
        """

        list_result = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="1 ACCEPT\n2 DROP",
        )
        mock_run.return_value = list_result

        hook.add_rule("iptables", "MITMWALL_OUTPUT", "10.0.0.0/8", 9090)

        calls = mock_run.call_args_list
        self.assertEqual(calls[-1][0][0], [
            "iptables",
            "-w",
            "10",
            "-t",
            "filter",
            "-I",
            "MITMWALL_OUTPUT",
            "2",
            "-p",
            "tcp",
            "-d",
            "10.0.0.0/8",
            "--dport",
            "9090",
            "-m",
            "comment",
            "--comment",
            "mitmwall-custom",
            "-j",
            "ACCEPT",
        ])

    @patch("src.systemd.hook.subprocess.run")
    def test_appends_when_no_drop(self, mock_run: MagicMock) -> None:
        """
        The rule is appended when no DROP rule is found.
        """

        list_result = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="1 ACCEPT",
        )
        mock_run.return_value = list_result

        hook.add_rule("iptables", "MITMWALL_OUTPUT", "10.0.0.0/8", 9090)

        calls = mock_run.call_args_list
        self.assertEqual(calls[-1][0][0], [
            "iptables",
            "-w",
            "10",
            "-t",
            "filter",
            "-A",
            "MITMWALL_OUTPUT",
            "-p",
            "tcp",
            "-d",
            "10.0.0.0/8",
            "--dport",
            "9090",
            "-m",
            "comment",
            "--comment",
            "mitmwall-custom",
            "-j",
            "ACCEPT",
        ])


class RemoveCustomRulesTests(unittest.TestCase):
    """
    Verify removal of custom rules from an iptables chain.
    """

    @patch("src.systemd.hook.subprocess.run")
    def test_removes_rules_with_comment(self, mock_run: MagicMock) -> None:
        """
        Rules tagged with the mitmwall-custom comment are removed by line number.
        """

        list_result = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="1 ACCEPT all -- anywhere anywhere /* mitmwall-custom */\n2 DROP",
        )
        delete_result = subprocess.CompletedProcess(args=[], returncode=0, stdout="")
        empty_list = subprocess.CompletedProcess(args=[], returncode=0, stdout="1 DROP")

        mock_run.side_effect = [list_result, delete_result, empty_list]

        hook.remove_custom_rules_from_chain("iptables", "MITMWALL_OUTPUT")

        delete_call = mock_run.call_args_list[1]
        self.assertEqual(delete_call[0][0], [
            "iptables",
            "-w",
            "10",
            "-t",
            "filter",
            "-D",
            "MITMWALL_OUTPUT",
            "1",
        ])

    @patch("src.systemd.hook.subprocess.run")
    def test_handles_missing_chain(self, mock_run: MagicMock) -> None:
        """
        Removal stops gracefully when the chain does not exist.
        """

        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stderr=hook.CHAIN_ABSENT_ERROR,
        )

        hook.remove_custom_rules_from_chain("iptables", "MITMWALL_OUTPUT")

        self.assertEqual(mock_run.call_count, 1)


class AddNatBypassRuleTests(unittest.TestCase):
    """
    Verify add_nat_bypass_rule inserts NAT bypass rules into the OUTPUT chain.
    """

    @patch("src.systemd.hook.place_rule_first")
    def test_places_rule_at_top(self, mock_place: MagicMock) -> None:
        """
        The NAT bypass uses the managed head-placement operation.
        """

        hook.add_nat_bypass_rule("iptables", "10.0.0.0/8", 443)

        mock_place.assert_called_once_with(
            "iptables",
            "nat",
            "OUTPUT",
            [
                "-p",
                "tcp",
                "-d",
                "10.0.0.0/8",
                "--dport",
                "443",
                "-m",
                "comment",
                "--comment",
                "mitmwall-custom",
                "-j",
                "ACCEPT",
            ],
        )


class ManagedNatOrderingTests(unittest.TestCase):
    """
    Verify core redirects and bypasses use the required NAT precedence.
    """

    @patch("src.systemd.hook.place_rule_first")
    def test_core_redirects_are_placed_first_for_ipv4_and_ipv6(
        self, mock_place: MagicMock
    ) -> None:
        """
        IPv4 and IPv6 HTTP and DNS redirects are managed at the OUTPUT head.
        """

        for table_cmd in ("iptables", "ip6tables"):
            hook.add_redirect_rule(table_cmd, 443)
            hook.add_dns_redirect_rule(table_cmd, "udp")

        self.assertEqual(mock_place.call_count, 4)
        for invocation in mock_place.call_args_list:
            self.assertEqual(invocation.args[1:3], ("nat", "OUTPUT"))
        self.assertEqual(
            [invocation.args[0] for invocation in mock_place.call_args_list],
            ["iptables", "iptables", "ip6tables", "ip6tables"],
        )

    def test_bypasses_are_installed_after_generic_redirects(self) -> None:
        """
        Head insertion leaves NTP and custom bypasses above generic redirects.
        """

        manager = MagicMock()
        with (
            patch("src.systemd.hook.clear_legacy_redirect_rules"),
            patch("src.systemd.hook.enable_forwarding") as mock_forwarding,
            patch("src.systemd.hook.add_dns_redirect_rule") as mock_dns,
            patch("src.systemd.hook.add_redirect_rule") as mock_web,
            patch("src.systemd.hook.add_ntp_dns_bypass_rule") as mock_ntp,
            patch("src.systemd.hook.add_output_filter") as mock_filter,
            patch("src.systemd.hook.add_custom_rules") as mock_custom,
            patch("src.systemd.hook.parse_custom_rules", return_value=[]),
        ):
            manager.attach_mock(mock_forwarding, "forwarding")
            manager.attach_mock(mock_dns, "dns")
            manager.attach_mock(mock_web, "web")
            manager.attach_mock(mock_ntp, "ntp")
            manager.attach_mock(mock_filter, "filter")
            manager.attach_mock(mock_custom, "custom")

            hook.add_rules()

        self.assertEqual(
            manager.mock_calls,
            [
                call.forwarding(),
                call.dns("iptables", "udp"),
                call.dns("iptables", "tcp"),
                call.dns("ip6tables", "udp"),
                call.dns("ip6tables", "tcp"),
                call.web("iptables", 80),
                call.web("iptables", 443),
                call.web("ip6tables", 80),
                call.web("ip6tables", 443),
                call.ntp("iptables", "udp"),
                call.ntp("iptables", "tcp"),
                call.ntp("ip6tables", "udp"),
                call.ntp("ip6tables", "tcp"),
                call.filter("iptables"),
                call.filter("ip6tables"),
                call.custom([]),
            ],
        )

    def test_custom_rules_are_validated_before_firewall_mutation(self) -> None:
        """
        Invalid custom configuration fails before legacy cleanup or setup begins.
        """

        with (
            patch(
                "src.systemd.hook.parse_custom_rules",
                side_effect=ValueError("invalid custom firewall configuration"),
            ),
            patch("src.systemd.hook.clear_legacy_redirect_rules") as mock_legacy,
            patch("src.systemd.hook.enable_forwarding") as mock_forwarding,
            patch("src.systemd.hook.run_xtables") as mock_xtables,
        ):
            with self.assertRaisesRegex(ValueError, "invalid custom firewall"):
                hook.add_rules()

        mock_legacy.assert_not_called()
        mock_forwarding.assert_not_called()
        mock_xtables.assert_not_called()


class AptSandboxBypassTests(unittest.TestCase):
    """
    Verify that APT's sandbox user retains root-invoked network access.
    """

    @patch("src.systemd.hook.subprocess.run")
    def test_http_redirect_excludes_apt_user(self, mock_run: MagicMock) -> None:
        """
        HTTP traffic owned by _apt is not redirected into the proxy.
        """

        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stderr=hook.RULE_ABSENT_ERROR
        )

        hook.add_redirect_rule("iptables", 80)

        command = cast(list[str], mock_run.call_args_list[-1][0][0])
        apt_index = command.index(hook.APT_USER)
        self.assertEqual(
            command[apt_index - 4 : apt_index + 1],
            ["-m", "owner", "!", "--uid-owner", hook.APT_USER],
        )

    @patch("src.systemd.hook.subprocess.run")
    def test_dns_redirect_excludes_apt_user(self, mock_run: MagicMock) -> None:
        """
        DNS traffic owned by _apt is not redirected into the DNS proxy.
        """

        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stderr=hook.RULE_ABSENT_ERROR
        )

        hook.add_dns_redirect_rule("iptables", "udp")

        command = cast(list[str], mock_run.call_args_list[-1][0][0])
        apt_index = command.index(hook.APT_USER)
        self.assertEqual(
            command[apt_index - 4 : apt_index + 1],
            ["-m", "owner", "!", "--uid-owner", hook.APT_USER],
        )

    @patch("src.systemd.hook.place_rule_first")
    @patch("src.systemd.hook.add_ntp_filter_rules")
    @patch("src.systemd.hook.subprocess.run")
    def test_output_filter_allows_apt_user(
        self, mock_run: MagicMock, _mock_ntp: MagicMock, _mock_place: MagicMock
    ) -> None:
        """
        The fail-closed OUTPUT chain accepts sockets owned by _apt.
        """

        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)

        hook.add_output_filter("iptables")

        commands = [call[0][0] for call in mock_run.call_args_list]
        self.assertIn(
            [
                "iptables",
                "-w",
                "10",
                "-t",
                "filter",
                "-A",
                hook.CHAIN,
                "-m",
                "owner",
                "--uid-owner",
                hook.APT_USER,
                "-j",
                "ACCEPT",
            ],
            commands,
        )


class AddCustomRulesTests(unittest.TestCase):
    """
    Verify add_custom_rules orchestrates config parsing and iptables insertion.
    """

    @patch("src.systemd.hook.clear_custom_rules")
    @patch("src.systemd.hook.add_rule")
    @patch("src.systemd.hook.add_nat_bypass_rule")
    @patch("src.systemd.hook.parse_custom_rules")
    def test_adds_ipv4_and_ipv6_rules(
        self,
        mock_parse: MagicMock,
        mock_nat: MagicMock,
        mock_add: MagicMock,
        mock_clear: MagicMock,
    ) -> None:
        """
        IPv4 rules use iptables and IPv6 rules use ip6tables, both for NAT
        bypass and filter ACCEPT.
        """

        mock_parse.return_value = [
            hook.CustomRule("iptables", "192.168.0.0/16", 80),
            hook.CustomRule("ip6tables", "2001:db8::/32", 443),
        ]

        hook.add_custom_rules()

        mock_clear.assert_called_once()
        self.assertEqual(mock_nat.call_count, 2)
        self.assertEqual(mock_add.call_count, 2)
        mock_nat.assert_any_call("iptables", "192.168.0.0/16", 80)
        mock_nat.assert_any_call("ip6tables", "2001:db8::/32", 443)
        mock_add.assert_any_call("iptables", "MITMWALL_OUTPUT", "192.168.0.0/16", 80)
        mock_add.assert_any_call("ip6tables", "MITMWALL_OUTPUT", "2001:db8::/32", 443)

    @patch("src.systemd.hook.clear_custom_rules")
    @patch("src.systemd.hook.add_rule")
    @patch("src.systemd.hook.add_nat_bypass_rule")
    @patch("src.systemd.hook.parse_custom_rules")
    def test_empty_config_clears_stale_rules(
        self,
        mock_parse: MagicMock,
        mock_nat: MagicMock,
        mock_add: MagicMock,
        mock_clear: MagicMock,
    ) -> None:
        """
        An empty parsed config removes stale rules without adding replacements.
        """

        mock_parse.return_value = []

        hook.add_custom_rules()

        mock_clear.assert_called_once()
        mock_nat.assert_not_called()
        mock_add.assert_not_called()

    @patch("src.systemd.hook.clear_custom_rules")
    @patch("src.systemd.hook.add_rule")
    @patch("src.systemd.hook.add_nat_bypass_rule")
    @patch("src.systemd.hook.parse_custom_rules")
    def test_empty_validated_rules_clear_without_reparsing(
        self,
        mock_parse: MagicMock,
        mock_nat: MagicMock,
        mock_add: MagicMock,
        mock_clear: MagicMock,
    ) -> None:
        """
        A typed empty rule list from startup still removes stale installed rules.
        """

        hook.add_custom_rules([])

        mock_parse.assert_not_called()
        mock_clear.assert_called_once()
        mock_nat.assert_not_called()
        mock_add.assert_not_called()


class ClearCustomRulesTests(unittest.TestCase):
    """
    Verify clear_custom_rules orchestrates removal from both iptables and ip6tables.
    """

    @patch("src.systemd.hook.remove_comment_rules")
    def test_clears_filter_and_nat_chains(self, mock_remove: MagicMock) -> None:
        """
        clear_custom_rules removes custom rules from IPv4 and IPv6 filter and
        NAT OUTPUT chains.
        """

        hook.clear_custom_rules()

        self.assertEqual(mock_remove.call_count, 4)
        mock_remove.assert_any_call("iptables", "filter", "MITMWALL_OUTPUT")
        mock_remove.assert_any_call("ip6tables", "filter", "MITMWALL_OUTPUT")
        mock_remove.assert_any_call("iptables", "nat", "OUTPUT")
        mock_remove.assert_any_call("ip6tables", "nat", "OUTPUT")


class EnsureWebRulesFileTests(unittest.TestCase):
    """
    Verify ensure_web_rules_file creates the file and sets permissions.
    """

    @patch("src.systemd.hook.subprocess.run")
    def test_creates_file_when_missing(self, _mock_run: MagicMock) -> None:
        """
        The web rules file is created with an empty allow list when missing.
        """

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "2-web.toml"
            with patch("src.systemd.hook.WEB_RULES_FILE", path):
                hook.ensure_web_rules_file()

            self.assertTrue(path.exists())
            self.assertEqual(path.read_text(encoding="utf-8"), "# no custom rules from mitmweb\n")

    @patch("src.systemd.hook.subprocess.run")
    def test_does_not_overwrite_existing_file(self, _mock_run: MagicMock) -> None:
        """
        An existing web rules file is left untouched.
        """

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "2-web.toml"
            _ = path.write_text("existing content", encoding="utf-8")
            with patch("src.systemd.hook.WEB_RULES_FILE", path):
                hook.ensure_web_rules_file()

            self.assertEqual(path.read_text(encoding="utf-8"), "existing content")

    @patch("src.systemd.hook.subprocess.run")
    def test_runs_chown_and_chmod(self, mock_run: MagicMock) -> None:
        """
        Ownership and permissions are set so the mitmwall user can write the file.
        """

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "2-web.toml"
            with patch("src.systemd.hook.WEB_RULES_FILE", path):
                hook.ensure_web_rules_file()

            commands = [call[0][0] for call in mock_run.call_args_list]
            self.assertIn(["chown", "root:mitmwall", str(path)], commands)
            self.assertIn(["chmod", "660", str(path)], commands)


class SystemResolverTests(unittest.TestCase):
    """
    Verify temporary use and exact restoration of systemd-resolved's stub.
    """

    def test_external_nameserver_is_detected(self) -> None:
        """
        A non-loopback nameserver requires the systemd-resolved stub.
        """

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "resolv.conf"
            _ = path.write_text(
                "nameserver 127.0.0.53\nnameserver 192.0.2.53\n",
                encoding="utf-8",
            )

            self.assertTrue(resolver.resolv_conf_uses_external_nameserver(path))

    def test_loopback_nameservers_do_not_require_reconfiguration(self) -> None:
        """
        IPv4 and IPv6 loopback resolvers avoid the LXC UDP hairpin.
        """

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "resolv.conf"
            _ = path.write_text(
                "nameserver 127.0.0.53\nnameserver ::1\n", encoding="utf-8"
            )

            self.assertFalse(resolver.resolv_conf_uses_external_nameserver(path))

    @patch("src.systemd.resolv_conf.subprocess.run")
    def test_regular_resolv_conf_is_switched_and_restored(
        self, mock_run: MagicMock
    ) -> None:
        """
        An external regular file is replaced by the stub and restored exactly.
        """

        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            resolv_conf = root / "resolv.conf"
            stub = root / "stub-resolv.conf"
            state_dir = root / "state"
            state_file = state_dir / "resolv-conf-state.json"
            legacy_state_dir = root / "legacy-state"
            legacy_state_file = legacy_state_dir / "resolv-conf-state.json"
            original = b"search example.test\nnameserver 192.0.2.53\n"
            _ = resolv_conf.write_bytes(original)
            resolv_conf.chmod(0o640)
            _ = stub.write_text("nameserver 127.0.0.53\n", encoding="utf-8")

            with (
                patch("src.systemd.resolv_conf.RESOLV_CONF", resolv_conf),
                patch("src.systemd.resolv_conf.SYSTEMD_RESOLVED_STUB", stub),
                patch("src.systemd.resolv_conf.RESOLVER_STATE_DIR", state_dir),
                patch("src.systemd.resolv_conf.RESOLVER_STATE_FILE", state_file),
                patch("src.systemd.resolv_conf.LEGACY_RESOLVER_STATE_DIR", legacy_state_dir),
                patch("src.systemd.resolv_conf.LEGACY_RESOLVER_STATE_FILE", legacy_state_file),
            ):
                resolver.configure_system_resolver(Path("/nonexistent/config.toml"))
                self.assertTrue(resolv_conf.is_symlink())
                self.assertEqual(resolv_conf.resolve(), stub)

                # A repeated start must retain the first saved configuration.
                resolver.configure_system_resolver(Path("/nonexistent/config.toml"))
                resolver.restore_system_resolver()

            self.assertFalse(resolv_conf.is_symlink())
            self.assertEqual(resolv_conf.read_bytes(), original)
            self.assertEqual(resolv_conf.stat().st_mode & 0o777, 0o640)
            self.assertFalse(state_file.exists())

    @patch("src.systemd.resolv_conf.subprocess.run")
    def test_symlink_resolv_conf_is_restored(self, mock_run: MagicMock) -> None:
        """
        An original symlink is restored with its exact relative target.
        """

        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            upstream = root / "upstream-resolv.conf"
            stub = root / "stub-resolv.conf"
            resolv_conf = root / "resolv.conf"
            state_dir = root / "state"
            state_file = state_dir / "resolv-conf-state.json"
            legacy_state_dir = root / "legacy-state"
            legacy_state_file = legacy_state_dir / "resolv-conf-state.json"
            _ = upstream.write_text("nameserver 192.0.2.53\n", encoding="utf-8")
            _ = stub.write_text("nameserver 127.0.0.53\n", encoding="utf-8")
            resolv_conf.symlink_to(upstream.name)

            with (
                patch("src.systemd.resolv_conf.RESOLV_CONF", resolv_conf),
                patch("src.systemd.resolv_conf.SYSTEMD_RESOLVED_STUB", stub),
                patch("src.systemd.resolv_conf.RESOLVER_STATE_DIR", state_dir),
                patch("src.systemd.resolv_conf.RESOLVER_STATE_FILE", state_file),
                patch("src.systemd.resolv_conf.LEGACY_RESOLVER_STATE_DIR", legacy_state_dir),
                patch("src.systemd.resolv_conf.LEGACY_RESOLVER_STATE_FILE", legacy_state_file),
            ):
                resolver.configure_system_resolver(Path("/nonexistent/config.toml"))
                resolver.restore_system_resolver()

            self.assertTrue(resolv_conf.is_symlink())
            self.assertEqual(resolv_conf.readlink(), Path(upstream.name))

    @patch("src.systemd.resolv_conf.subprocess.run")
    def test_inactive_systemd_resolved_fails_without_modifying_file(
        self, mock_run: MagicMock
    ) -> None:
        """
        External DNS fails visibly when no safe local stub is active.
        """

        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=3)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            resolv_conf = root / "resolv.conf"
            stub = root / "stub-resolv.conf"
            state_dir = root / "state"
            state_file = state_dir / "resolv-conf-state.json"
            legacy_state_dir = root / "legacy-state"
            legacy_state_file = legacy_state_dir / "resolv-conf-state.json"
            original = "nameserver 192.0.2.53\n"
            _ = resolv_conf.write_text(original, encoding="utf-8")
            _ = stub.write_text("nameserver 127.0.0.53\n", encoding="utf-8")

            with (
                patch("src.systemd.resolv_conf.RESOLV_CONF", resolv_conf),
                patch("src.systemd.resolv_conf.SYSTEMD_RESOLVED_STUB", stub),
                patch("src.systemd.resolv_conf.RESOLVER_STATE_DIR", state_dir),
                patch("src.systemd.resolv_conf.RESOLVER_STATE_FILE", state_file),
                patch("src.systemd.resolv_conf.LEGACY_RESOLVER_STATE_DIR", legacy_state_dir),
                patch("src.systemd.resolv_conf.LEGACY_RESOLVER_STATE_FILE", legacy_state_file),
            ):
                with self.assertRaisesRegex(RuntimeError, "systemd-resolved is not active"):
                    resolver.configure_system_resolver(
                        Path("/nonexistent/config.toml")
                    )

            self.assertEqual(resolv_conf.read_text("utf-8"), original)
            self.assertFalse(state_file.exists())

    @patch("src.systemd.resolv_conf.subprocess.run")
    def test_external_resolver_update_is_not_overwritten(
        self, mock_run: MagicMock
    ) -> None:
        """
        A resolver manager update made while mitmwall runs remains authoritative.
        """

        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            resolv_conf = root / "resolv.conf"
            stub = root / "stub-resolv.conf"
            state_dir = root / "state"
            state_file = state_dir / "resolv-conf-state.json"
            legacy_state_dir = root / "legacy-state"
            legacy_state_file = legacy_state_dir / "resolv-conf-state.json"
            _ = resolv_conf.write_text("nameserver 192.0.2.53\n", encoding="utf-8")
            _ = stub.write_text("nameserver 127.0.0.53\n", encoding="utf-8")

            with (
                patch("src.systemd.resolv_conf.RESOLV_CONF", resolv_conf),
                patch("src.systemd.resolv_conf.SYSTEMD_RESOLVED_STUB", stub),
                patch("src.systemd.resolv_conf.RESOLVER_STATE_DIR", state_dir),
                patch("src.systemd.resolv_conf.RESOLVER_STATE_FILE", state_file),
                patch("src.systemd.resolv_conf.LEGACY_RESOLVER_STATE_DIR", legacy_state_dir),
                patch("src.systemd.resolv_conf.LEGACY_RESOLVER_STATE_FILE", legacy_state_file),
                patch("sys.stderr"),
            ):
                resolver.configure_system_resolver(Path("/nonexistent/config.toml"))
                resolv_conf.unlink()
                updated = "search updated.test\nnameserver 198.51.100.53\n"
                _ = resolv_conf.write_text(updated, encoding="utf-8")
                resolver.restore_system_resolver()

            self.assertEqual(resolv_conf.read_text("utf-8"), updated)
            self.assertFalse(state_file.exists())

    def test_legacy_runtime_state_is_restored_after_upgrade(self) -> None:
        """
        State written under /run by the previous hook remains recoverable.
        """

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            resolv_conf = root / "resolv.conf"
            stub = root / "stub-resolv.conf"
            state_dir = root / "state"
            state_file = state_dir / "resolv-conf-state.json"
            legacy_state_dir = root / "legacy-state"
            legacy_state_file = legacy_state_dir / "resolv-conf-state.json"
            original = b"search legacy.test\nnameserver 192.0.2.53\n"
            _ = stub.write_text("nameserver 127.0.0.53\n", encoding="utf-8")
            resolv_conf.symlink_to(stub)

            with (
                patch("src.systemd.resolv_conf.RESOLVER_STATE_DIR", legacy_state_dir),
                patch("src.systemd.resolv_conf.RESOLVER_STATE_FILE", legacy_state_file),
            ):
                resolver.write_resolver_state(
                    resolver.ResolverState(
                        "file",
                        resolv_conf.lstat().st_uid,
                        resolv_conf.lstat().st_gid,
                        0o644,
                        content=original,
                    )
                )

            with (
                patch("src.systemd.resolv_conf.RESOLV_CONF", resolv_conf),
                patch("src.systemd.resolv_conf.SYSTEMD_RESOLVED_STUB", stub),
                patch("src.systemd.resolv_conf.RESOLVER_STATE_DIR", state_dir),
                patch("src.systemd.resolv_conf.RESOLVER_STATE_FILE", state_file),
                patch("src.systemd.resolv_conf.LEGACY_RESOLVER_STATE_DIR", legacy_state_dir),
                patch("src.systemd.resolv_conf.LEGACY_RESOLVER_STATE_FILE", legacy_state_file),
            ):
                resolver.restore_system_resolver()

            self.assertFalse(resolv_conf.is_symlink())
            self.assertEqual(resolv_conf.read_bytes(), original)
            self.assertFalse(legacy_state_file.exists())

    @patch("src.systemd.resolv_conf.subprocess.run")
    def test_resolver_handling_can_be_disabled(self, mock_run: MagicMock) -> None:
        """
        manage_resolv_conf=false leaves an external resolver file unchanged.
        """

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = root / "config.toml"
            system_resolv_conf = root / "resolv.conf"
            _ = config.write_text("manage_resolv_conf = false\n", encoding="utf-8")
            original = "nameserver 192.0.2.53\n"
            _ = system_resolv_conf.write_text(original, encoding="utf-8")

            with patch("src.systemd.resolv_conf.RESOLV_CONF", system_resolv_conf):
                resolver.configure_system_resolver(config)

            self.assertEqual(system_resolv_conf.read_text("utf-8"), original)
            mock_run.assert_not_called()

    def test_resolver_handling_defaults_to_enabled(self) -> None:
        """
        A missing configuration file retains the enabled default.
        """

        self.assertTrue(
            resolver.resolv_conf_handling_enabled(
                Path("/nonexistent/config.toml")
            )
        )

    def test_resolver_handling_rejects_non_boolean_value(self) -> None:
        """
        manage_resolv_conf must be a TOML boolean.
        """

        with tempfile.TemporaryDirectory() as temp_dir:
            config = Path(temp_dir) / "config.toml"
            _ = config.write_text(
                'manage_resolv_conf = "false"\n', encoding="utf-8"
            )

            with self.assertRaisesRegex(
                ValueError, "'manage_resolv_conf' must be a boolean"
            ):
                _enabled = resolver.resolv_conf_handling_enabled(config)


class MainTests(unittest.TestCase):
    """
    Verify the script entry point dispatches to the correct actions.
    """

    @patch("src.systemd.hook.ensure_web_rules_file")
    @patch("src.systemd.hook.add_rules")
    def test_main_start(self, mock_add: MagicMock, _mock_ensure: MagicMock) -> None:
        """
        The 'start' argument triggers add_rules.
        """

        with (
            patch("src.systemd.hook.configure_system_resolver") as mock_configure,
            patch("src.systemd.hook.parse_custom_rules", return_value=[]) as mock_parse,
            patch("sys.argv", ["hook.py", "start"]),
        ):
            hook.main()

        mock_parse.assert_called_once()
        mock_configure.assert_called_once()
        mock_add.assert_called_once_with([])

    def test_main_rejects_custom_rules_before_startup_mutation(self) -> None:
        """
        Startup configuration validation precedes setup and rollback mutations.
        """

        with (
            patch(
                "src.systemd.hook.parse_custom_rules",
                side_effect=ValueError("invalid custom firewall configuration"),
            ),
            patch("src.systemd.hook.configure_system_resolver") as mock_configure,
            patch("src.systemd.hook.ensure_web_rules_file") as mock_ensure,
            patch("src.systemd.hook.add_rules") as mock_add,
            patch("src.systemd.hook.restore_forwarding") as mock_restore,
            patch("sys.argv", ["hook.py", "start"]),
        ):
            with self.assertRaisesRegex(ValueError, "invalid custom firewall"):
                hook.main()

        mock_configure.assert_not_called()
        mock_ensure.assert_not_called()
        mock_add.assert_not_called()
        mock_restore.assert_not_called()

    @patch("src.systemd.hook.ensure_web_rules_file")
    @patch("src.systemd.hook.add_rules")
    def test_main_start_restores_resolver_when_configuration_fails(
        self, mock_add: MagicMock, mock_ensure: MagicMock
    ) -> None:
        """
        Resolver restoration runs when start-time resolver setup raises an error.
        """

        with (
            patch("src.systemd.hook.configure_system_resolver") as mock_configure,
            patch("src.systemd.hook.restore_forwarding") as mock_forward_restore,
            patch("src.systemd.hook.restore_system_resolver") as mock_restore,
            patch("sys.argv", ["hook.py", "start"]),
        ):
            mock_configure.side_effect = RuntimeError("resolver failed")
            with self.assertRaisesRegex(RuntimeError, "resolver failed"):
                hook.main()

        mock_forward_restore.assert_called_once()
        mock_restore.assert_called_once()
        mock_ensure.assert_not_called()
        mock_add.assert_not_called()

    @patch("src.systemd.hook.clear_rules")
    def test_main_stop(self, mock_clear: MagicMock) -> None:
        """
        The 'stop' argument triggers clear_rules.
        """

        with (
            patch("src.systemd.hook.restore_forwarding") as mock_forward_restore,
            patch("src.systemd.hook.restore_system_resolver") as mock_restore,
            patch("sys.argv", ["hook.py", "stop"]),
        ):
            hook.main()

        mock_forward_restore.assert_called_once()
        mock_clear.assert_called_once()
        mock_restore.assert_called_once()

    @patch("src.systemd.hook.clear_rules")
    def test_main_stop_restores_resolver_when_rule_cleanup_fails(
        self, mock_clear: MagicMock
    ) -> None:
        """
        Resolver restoration still runs when firewall cleanup raises an error.
        """

        mock_clear.side_effect = RuntimeError("cleanup failed")
        with (
            patch("src.systemd.hook.restore_forwarding") as mock_forward_restore,
            patch("src.systemd.hook.restore_system_resolver") as mock_restore,
            patch("sys.argv", ["hook.py", "stop"]),
        ):
            with self.assertRaisesRegex(RuntimeError, "cleanup failed"):
                hook.main()

        mock_forward_restore.assert_called_once()
        mock_restore.assert_called_once()

    @patch("src.systemd.hook.ensure_web_rules_file")
    @patch("src.systemd.hook.add_rules")
    def test_main_start_restores_forwarding_when_rule_setup_fails(
        self, mock_add: MagicMock, _mock_ensure: MagicMock
    ) -> None:
        """
        A failure after forwarding setup invokes runtime state restoration.
        """

        mock_add.side_effect = RuntimeError("rule setup failed")
        with (
            patch("src.systemd.hook.configure_system_resolver"),
            patch("src.systemd.hook.restore_forwarding") as mock_forward_restore,
            patch("src.systemd.hook.restore_system_resolver") as mock_resolver_restore,
            patch("sys.argv", ["hook.py", "start"]),
        ):
            with self.assertRaisesRegex(RuntimeError, "rule setup failed"):
                hook.main()

        mock_forward_restore.assert_called_once()
        mock_resolver_restore.assert_called_once()

    def test_main_missing_argument(self) -> None:
        """
        Missing argument causes exit code 2.
        """

        with patch("sys.argv", ["hook.py"]):
            with self.assertRaises(SystemExit) as context:
                hook.main()

        self.assertEqual(context.exception.code, 2)

    def test_main_invalid_argument(self) -> None:
        """
        An invalid argument causes exit code 2.
        """

        with patch("sys.argv", ["hook.py", "invalid"]):
            with self.assertRaises(SystemExit) as context:
                hook.main()

        self.assertEqual(context.exception.code, 2)


if __name__ == "__main__":
    _test_program = unittest.main(verbosity=2)
