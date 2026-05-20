"""
Logging setup for the mitmwall addon.
"""

import logging

from .addon_config import default_addon_config, load_addon_config
from .constants import ADDON_CONFIG_FILE

LOGGER = logging.getLogger("mitmwall")
LOGGER.setLevel(logging.INFO)
LOGGER.propagate = False


def apply_log_level(log_level: int) -> None:
    """
    Apply the selected log level to the addon logger and its handlers.
    """

    LOGGER.setLevel(log_level)
    for handler in LOGGER.handlers:
        handler.setLevel(log_level)


def setup_logging() -> None:
    """
    Send addon logs to stderr so systemd journal captures them.
    """

    if not LOGGER.handlers:
        handler = logging.StreamHandler()
        handler.setLevel(logging.INFO)
        handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        LOGGER.addHandler(handler)

    try:
        addon_config = load_addon_config()
    except Exception as exc:
        default_config = default_addon_config()
        apply_log_level(default_config.log_level)
        message = (
            f"failed to load {ADDON_CONFIG_FILE}: {exc}; "
            + f"using log_level={default_config.log_level_name}"
        )
        LOGGER.error(message)
        return

    apply_log_level(addon_config.log_level)
