"""
Unit tests for addon configuration parsing.
"""

import unittest

from mitmproxy_addon.addon_config import default_addon_config, parse_addon_config
from mitmproxy_addon.constants import DEFAULT_BLOCK_DNS


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

    def test_parse_addon_config_accepts_block_dns_false(self) -> None:
        """
        Parse block_dns=false from config.toml contents.
        """

        addon_config = parse_addon_config(
            {
                "log_level": "debug",
                "block_dns": False,
            }
        )

        self.assertEqual(addon_config.log_level_name, "debug")
        self.assertFalse(addon_config.block_dns)

    def test_parse_addon_config_rejects_non_boolean_block_dns(self) -> None:
        """
        Reject block_dns values that are not TOML booleans.
        """

        with self.assertRaisesRegex(ValueError, "'block_dns' must be a boolean"):
            _addon_config = parse_addon_config({"block_dns": "false"})

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
