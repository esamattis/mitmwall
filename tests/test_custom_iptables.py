"""
Unit tests for the custom iptables rule manager.
"""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import custom_iptables


class ParseCustomRulesTests(unittest.TestCase):
    """
    Verify parsing of custom iptables rules from TOML config.
    """

    def test_missing_config_file_returns_empty_list(self) -> None:
        """
        A missing config file yields no custom rules.
        """

        rules = custom_iptables.parse_custom_rules(Path("/nonexistent/config.toml"))
        self.assertEqual(rules, [])

    def test_valid_iptables_allow_rules(self) -> None:
        """
        Parse IPv4 and IPv6 allow rules from a well-formed config file.
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as file:
            _ = file.write("""
[[iptables.allow]]
network = "192.168.5.0/24"
port = 1234

[[iptables.allow]]
network = "2001:db8::/32"
port = 443
""")
            path = Path(file.name)

        try:
            rules = custom_iptables.parse_custom_rules(path)
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
            rules = custom_iptables.parse_custom_rules(path)
            self.assertEqual(rules, [])
        finally:
            path.unlink()

    def test_malformed_allow_entries_are_skipped(self) -> None:
        """
        Entries missing network or port are ignored.
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as file:
            _ = file.write("""
[[iptables.allow]]
network = "192.168.1.0/24"
port = "not-an-int"

[[iptables.allow]]
network = "192.168.2.0/24"
port = 8080
""")
            path = Path(file.name)

        try:
            rules = custom_iptables.parse_custom_rules(path)
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

        self.assertTrue(custom_iptables.is_ipv4_network("192.168.0.0/16"))

    def test_ipv6_network(self) -> None:
        """
        A colon-containing network is identified as IPv6.
        """

        self.assertFalse(custom_iptables.is_ipv4_network("2001:db8::/32"))


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
        self.assertEqual(custom_iptables.find_drop_line_number(result), "3")

    def test_returns_none_when_no_drop(self) -> None:
        """
        None is returned when no DROP rule is present.
        """

        stdout = """Chain MITMWALL_OUTPUT (1 references)
num  target     prot opt source               destination
1    ACCEPT     all  --  anywhere             anywhere
"""
        result = subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout)
        self.assertIsNone(custom_iptables.find_drop_line_number(result))


class AddRuleTests(unittest.TestCase):
    """
    Verify add_rule inserts custom rules into an iptables chain.
    """

    @patch("custom_iptables.subprocess.run")
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

        custom_iptables.add_rule(["iptables"], "MITMWALL_OUTPUT", "10.0.0.0/8", 9090)

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

    @patch("custom_iptables.subprocess.run")
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

        custom_iptables.add_rule(["iptables"], "MITMWALL_OUTPUT", "10.0.0.0/8", 9090)

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

    @patch("custom_iptables.subprocess.run")
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

        custom_iptables.remove_custom_rules_from_chain(["iptables"], "MITMWALL_OUTPUT")

        delete_call = mock_run.call_args_list[1]
        self.assertEqual(delete_call[0][0], [
            "iptables",
            "-t",
            "filter",
            "-D",
            "MITMWALL_OUTPUT",
            "1",
        ])

    @patch("custom_iptables.subprocess.run")
    def test_handles_missing_chain(self, mock_run: MagicMock) -> None:
        """
        Removal stops gracefully when the chain does not exist.
        """

        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stderr="No chain/target/match by that name",
        )

        custom_iptables.remove_custom_rules_from_chain(["iptables"], "MITMWALL_OUTPUT")

        self.assertEqual(mock_run.call_count, 1)


class AddRulesTests(unittest.TestCase):
    """
    Verify add_rules orchestrates config parsing and iptables insertion.
    """

    @patch("custom_iptables.clear_rules")
    @patch("custom_iptables.add_rule")
    @patch("custom_iptables.parse_custom_rules")
    def test_adds_ipv4_and_ipv6_rules(
        self,
        mock_parse: MagicMock,
        mock_add: MagicMock,
        mock_clear: MagicMock,
    ) -> None:
        """
        IPv4 rules use iptables and IPv6 rules use ip6tables.
        """

        mock_parse.return_value = [
            ("192.168.0.0/16", 80),
            ("2001:db8::/32", 443),
        ]

        custom_iptables.add_rules()

        mock_clear.assert_called_once()
        self.assertEqual(mock_add.call_count, 2)
        mock_add.assert_any_call(["iptables"], "MITMWALL_OUTPUT", "192.168.0.0/16", 80)
        mock_add.assert_any_call(["ip6tables"], "MITMWALL_OUTPUT", "2001:db8::/32", 443)

    @patch("custom_iptables.clear_rules")
    @patch("custom_iptables.add_rule")
    @patch("custom_iptables.parse_custom_rules")
    def test_no_rules_when_config_empty(
        self,
        mock_parse: MagicMock,
        mock_add: MagicMock,
        mock_clear: MagicMock,
    ) -> None:
        """
        Nothing is added when the config contains no custom rules.
        """

        mock_parse.return_value = []

        custom_iptables.add_rules()

        mock_clear.assert_not_called()
        mock_add.assert_not_called()


class ClearRulesTests(unittest.TestCase):
    """
    Verify clear_rules orchestrates removal from both iptables and ip6tables.
    """

    @patch("custom_iptables.remove_custom_rules_from_chain")
    def test_clears_both_chains(self, mock_remove: MagicMock) -> None:
        """
        clear_rules removes custom rules from IPv4 and IPv6 chains.
        """

        custom_iptables.clear_rules()

        self.assertEqual(mock_remove.call_count, 2)
        mock_remove.assert_any_call(["iptables"], "MITMWALL_OUTPUT")
        mock_remove.assert_any_call(["ip6tables"], "MITMWALL_OUTPUT")


class MainTests(unittest.TestCase):
    """
    Verify the script entry point dispatches to the correct actions.
    """

    @patch("custom_iptables.add_rules")
    def test_main_add(self, mock_add: MagicMock) -> None:
        """
        The 'add' argument triggers add_rules.
        """

        with patch("sys.argv", ["custom_iptables.py", "add"]):
            custom_iptables.main()

        mock_add.assert_called_once()

    @patch("custom_iptables.clear_rules")
    def test_main_clear(self, mock_clear: MagicMock) -> None:
        """
        The 'clear' argument triggers clear_rules.
        """

        with patch("sys.argv", ["custom_iptables.py", "clear"]):
            custom_iptables.main()

        mock_clear.assert_called_once()

    def test_main_missing_argument(self) -> None:
        """
        Missing argument causes exit code 2.
        """

        with patch("sys.argv", ["custom_iptables.py"]):
            with self.assertRaises(SystemExit) as context:
                custom_iptables.main()

        self.assertEqual(context.exception.code, 2)

    def test_main_invalid_argument(self) -> None:
        """
        An invalid argument causes exit code 2.
        """

        with patch("sys.argv", ["custom_iptables.py", "invalid"]):
            with self.assertRaises(SystemExit) as context:
                custom_iptables.main()

        self.assertEqual(context.exception.code, 2)


if __name__ == "__main__":
    _test_program = unittest.main(verbosity=2)
