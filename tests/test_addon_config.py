"""
Unit tests for addon configuration parsing.
"""

import unittest

from mitmproxy_addon.addon_config import default_addon_config, parse_addon_config
from mitmproxy_addon.constants import (
    DEFAULT_BLOCK_DNS,
    DEFAULT_FLOW_HISTORY_CLEAR_INTERVAL,
)


class AddonConfigTests(unittest.TestCase):
    """
    Verify addon config defaults and validation.
    """

    def test_default_addon_config_blocks_dns(self) -> None:
        """
        Default addon configuration enables DNS blocking.
        """

        addon_config = default_addon_config()

        self.assertIs(addon_config.block_dns, DEFAULT_BLOCK_DNS)
        self.assertTrue(addon_config.block_dns)
        self.assertEqual(
            addon_config.flow_history_clear_interval,
            DEFAULT_FLOW_HISTORY_CLEAR_INTERVAL,
        )

    def test_parse_addon_config_accepts_block_dns_false(self) -> None:
        """
        Parse block_dns=false from config.toml contents.
        """

        addon_config = parse_addon_config(
            {
                "log_level": "debug",
                "block_dns": False,
                "flow_history_clear_interval": 500,
            }
        )

        self.assertEqual(addon_config.log_level_name, "debug")
        self.assertFalse(addon_config.block_dns)
        self.assertEqual(addon_config.flow_history_clear_interval, 500)

    def test_parse_addon_config_rejects_non_boolean_block_dns(self) -> None:
        """
        Reject block_dns values that are not TOML booleans.
        """

        with self.assertRaisesRegex(ValueError, "'block_dns' must be a boolean"):
            _addon_config = parse_addon_config({"block_dns": "false"})

    def test_parse_addon_config_rejects_invalid_flow_history_interval(self) -> None:
        """
        Reject flow history clear intervals that are not positive integers.
        """

        with self.assertRaisesRegex(
            ValueError,
            "'flow_history_clear_interval' must be a positive integer",
        ):
            _addon_config = parse_addon_config({"flow_history_clear_interval": 0})

    def test_parse_addon_config_rejects_unknown_keys(self) -> None:
        """
        Reject unsupported top-level keys while allowing block_dns.
        """

        with self.assertRaisesRegex(ValueError, "unsupported top-level key"):
            _addon_config = parse_addon_config(
                {
                    "block_dns": True,
                    "unsupported": True,
                }
            )


if __name__ == "__main__":
    _test_program = unittest.main(verbosity=2)
