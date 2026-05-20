"""
Shared constants for the mitmwall mitmproxy addon.
"""

import logging
from pathlib import Path

RULES_DIR = Path("/opt/mitmwall/rules.d")
ADDON_CONFIG_FILE = Path("/opt/mitmwall/addon_config.toml")
DEFAULT_LOG_LEVEL_NAME = "info"
LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}
DEFAULT_ALLOWED_METHODS = ("GET", "HEAD")
ANY_METHOD = "ANY"
ALLOW_RULE_KEYS = {
    "domain",
    "domain_regex",
    "include_subdomains",
    "methods",
    "pathname_regex",
    "pathname_pattern",
}
