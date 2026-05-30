"""
Shared TOML helper functions for the mitmwall mitmproxy addon.
"""

from collections.abc import Sequence
from typing import TypeGuard


def is_toml_array(value: object) -> TypeGuard[Sequence[object]]:
    """
    Return whether a TOML value is an array.
    """

    return isinstance(value, list)


def is_toml_table(value: object) -> TypeGuard[dict[str, object]]:
    """
    Return whether a TOML value is a table.
    """

    return isinstance(value, dict)


def get_toml_array(raw_value: object, key: str, index: int) -> list[str]:
    """
    Normalize a TOML string or array-of-strings value into a list of strings.
    """

    if isinstance(raw_value, str):
        return [raw_value]
    if is_toml_array(raw_value) and raw_value:
        items: list[str] = []
        for item_index, item in enumerate(raw_value, start=1):
            if not isinstance(item, str) or not item.strip():
                raise ValueError(
                    f"allow rule #{index}: {key} item #{item_index} must be a non-empty string"
                )
            items.append(item)
        return items
    raise ValueError(
        f"allow rule #{index}: {key!r} must be a non-empty string or a non-empty list"
    )
