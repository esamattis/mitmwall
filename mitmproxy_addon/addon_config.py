"""
Addon configuration parsing for the mitmwall addon.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import TypeGuard

import tomllib

from .constants import (
    ADDON_CONFIG_FILE,
    DEFAULT_BLOCK_DNS,
    DEFAULT_FLOW_HISTORY_CLEAR_INTERVAL,
    DEFAULT_FLOW_HISTORY_KEEP_ENTRIES,
    DEFAULT_LOG_LEVEL_NAME,
    LOG_LEVELS,
)


@dataclass(frozen=True)
class AddonConfig:
    """
    Runtime addon settings loaded from config.toml.
    """

    log_level_name: str
    log_level: int
    block_dns: bool
    flow_history_clear_interval: int
    flow_history_keep_entries: int


def default_addon_config() -> AddonConfig:
    """
    Return the built-in addon configuration defaults.
    """

    return AddonConfig(
        log_level_name=DEFAULT_LOG_LEVEL_NAME,
        log_level=LOG_LEVELS[DEFAULT_LOG_LEVEL_NAME],
        block_dns=DEFAULT_BLOCK_DNS,
        flow_history_clear_interval=DEFAULT_FLOW_HISTORY_CLEAR_INTERVAL,
        flow_history_keep_entries=DEFAULT_FLOW_HISTORY_KEEP_ENTRIES,
    )


def parse_log_level(value: object) -> tuple[str, int]:
    """
    Parse and validate a plugin log level value.
    """

    if not isinstance(value, str) or not value.strip():
        raise ValueError("'log_level' must be a non-empty string")

    normalized = value.strip().lower()
    if normalized not in LOG_LEVELS:
        allowed = ", ".join(sorted(LOG_LEVELS))
        raise ValueError(f"'log_level' must be one of: {allowed}")

    return normalized, LOG_LEVELS[normalized]


def parse_block_dns(value: object) -> bool:
    """
    Parse and validate whether DNS queries should be filtered by rules.
    """

    if not isinstance(value, bool):
        raise ValueError("'block_dns' must be a boolean")

    return value


def parse_flow_history_clear_interval(value: object) -> int:
    """
    Parse and validate the request interval for clearing mitmproxy flow history.
    """

    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError("'flow_history_clear_interval' must be a positive integer")

    return value


def parse_flow_history_keep_entries(value: object) -> int:
    """
    Parse and validate how many recent mitmproxy flows should be retained.
    """

    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError("'flow_history_keep_entries' must be a positive integer")

    return value


def is_toml_table(value: object) -> TypeGuard[dict[str, object]]:
    """
    Return whether a TOML value is a table.
    """

    return isinstance(value, dict)


def parse_addon_config(config_value: object) -> AddonConfig:
    """
    Parse and validate config.toml contents.
    """

    if not is_toml_table(config_value):
        raise ValueError("top-level TOML value must be a table")

    extra_top_level_keys = set(config_value) - {
        "block_dns",
        "flow_history_clear_interval",
        "flow_history_keep_entries",
        "log_level",
    }
    if extra_top_level_keys:
        keys = ", ".join(sorted(repr(key) for key in extra_top_level_keys))
        raise ValueError(f"unsupported top-level key(s): {keys}")

    log_level_name, log_level = parse_log_level(
        config_value.get("log_level", DEFAULT_LOG_LEVEL_NAME)
    )
    block_dns = parse_block_dns(config_value.get("block_dns", DEFAULT_BLOCK_DNS))
    flow_history_clear_interval = parse_flow_history_clear_interval(
        config_value.get(
            "flow_history_clear_interval",
            DEFAULT_FLOW_HISTORY_CLEAR_INTERVAL,
        )
    )
    flow_history_keep_entries = parse_flow_history_keep_entries(
        config_value.get(
            "flow_history_keep_entries",
            DEFAULT_FLOW_HISTORY_KEEP_ENTRIES,
        )
    )
    return AddonConfig(
        log_level_name=log_level_name,
        log_level=log_level,
        block_dns=block_dns,
        flow_history_clear_interval=flow_history_clear_interval,
        flow_history_keep_entries=flow_history_keep_entries,
    )


def load_addon_config(path: Path = ADDON_CONFIG_FILE) -> AddonConfig:
    """
    Load addon runtime configuration from a TOML file.
    """

    if not path.exists():
        return default_addon_config()

    with path.open("rb") as file:
        config_value = tomllib.load(file)

    return parse_addon_config(config_value)
