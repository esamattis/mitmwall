"""
Unit tests for the mitmwall iptables hook.
"""

import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock, patch

from src.systemd import hook


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
        Parse IPv4 and IPv6 bypass rules from a well-formed config file.
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as file:
            _ = file.write("""
[[iptables.bypass]]
network = "192.168.5.0/24"
port = 1234

[[iptables.bypass]]
network = "2001:db8::/32"
port = 443
""")
            path = Path(file.name)

        try:
            rules = hook.parse_custom_rules(path)
            self.assertEqual(rules, [("192.168.5.0/24", 1234), ("2001:db8::/32", 443)])
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

    def test_malformed_bypass_entries_are_skipped(self) -> None:
        """
        Entries missing network or port are ignored.
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as file:
            _ = file.write("""
[[iptables.bypass]]
network = "192.168.1.0/24"
port = "not-an-int"

[[iptables.bypass]]
network = "192.168.2.0/24"
port = 8080
""")
            path = Path(file.name)

        try:
            rules = hook.parse_custom_rules(path)
            self.assertEqual(rules, [("192.168.2.0/24", 8080)])
        finally:
            path.unlink()


class IsIPv4NetworkTests(unittest.TestCase):
    """
    Verify IPv4/IPv6 network detection.
    """

    def test_ipv4_network(self) -> None:
        """
        A dotted-decimal network is identified as IPv4.
        """

        self.assertTrue(hook.is_ipv4_network("192.168.0.0/16"))

    def test_ipv6_network(self) -> None:
        """
        A colon-containing network is identified as IPv6.
        """

        self.assertFalse(hook.is_ipv4_network("2001:db8::/32"))

    def test_ipv4_mapped_ipv6(self) -> None:
        """
        An IPv4-mapped IPv6 address is identified as IPv6.
        """

        self.assertFalse(hook.is_ipv4_network("::ffff:192.168.1.0/24"))

    def test_garbage_string(self) -> None:
        """
        A malformed string that is neither IPv4 nor IPv6 returns False.
        """

        self.assertFalse(hook.is_ipv4_network("not-a-network"))


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
            stderr="No chain/target/match by that name",
        )

        hook.remove_custom_rules_from_chain("iptables", "MITMWALL_OUTPUT")

        self.assertEqual(mock_run.call_count, 1)


class AddNatBypassRuleTests(unittest.TestCase):
    """
    Verify add_nat_bypass_rule inserts NAT bypass rules into the OUTPUT chain.
    """

    @patch("src.systemd.hook.subprocess.run")
    def test_inserts_at_top_when_not_exists(self, mock_run: MagicMock) -> None:
        """
        The NAT bypass rule is inserted at the top of OUTPUT when not present.
        """

        check_result = subprocess.CompletedProcess(args=[], returncode=1, stdout="")
        mock_run.return_value = check_result

        hook.add_nat_bypass_rule("iptables", "10.0.0.0/8", 443)

        calls = mock_run.call_args_list
        self.assertEqual(calls[-1][0][0], [
            "iptables",
            "-t",
            "nat",
            "-I",
            "OUTPUT",
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
        ])

    @patch("src.systemd.hook.subprocess.run")
    def test_skips_when_already_exists(self, mock_run: MagicMock) -> None:
        """
        The NAT bypass rule is skipped when it already exists.
        """

        check_result = subprocess.CompletedProcess(args=[], returncode=0, stdout="")
        mock_run.return_value = check_result

        hook.add_nat_bypass_rule("iptables", "10.0.0.0/8", 443)

        self.assertEqual(mock_run.call_count, 1)


class AptSandboxBypassTests(unittest.TestCase):
    """
    Verify that APT's sandbox user retains root-invoked network access.
    """

    @patch("src.systemd.hook.subprocess.run")
    def test_http_redirect_excludes_apt_user(self, mock_run: MagicMock) -> None:
        """
        HTTP traffic owned by _apt is not redirected into the proxy.
        """

        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=1)

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

        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=1)

        hook.add_dns_redirect_rule("iptables", "udp")

        command = cast(list[str], mock_run.call_args_list[-1][0][0])
        apt_index = command.index(hook.APT_USER)
        self.assertEqual(
            command[apt_index - 4 : apt_index + 1],
            ["-m", "owner", "!", "--uid-owner", hook.APT_USER],
        )

    @patch("src.systemd.hook.add_ntp_filter_rules")
    @patch("src.systemd.hook.subprocess.run")
    def test_output_filter_allows_apt_user(
        self, mock_run: MagicMock, _mock_ntp: MagicMock
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
            ("192.168.0.0/16", 80),
            ("2001:db8::/32", 443),
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
    def test_no_rules_when_config_empty(
        self,
        mock_parse: MagicMock,
        mock_nat: MagicMock,
        mock_add: MagicMock,
        mock_clear: MagicMock,
    ) -> None:
        """
        Nothing is added when the config contains no custom rules.
        """

        mock_parse.return_value = []

        hook.add_custom_rules()

        mock_clear.assert_not_called()
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

        with patch("sys.argv", ["hook.py", "start"]):
            hook.main()

        mock_add.assert_called_once()

    @patch("src.systemd.hook.clear_rules")
    def test_main_stop(self, mock_clear: MagicMock) -> None:
        """
        The 'stop' argument triggers clear_rules.
        """

        with patch("sys.argv", ["hook.py", "stop"]):
            hook.main()

        mock_clear.assert_called_once()

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
