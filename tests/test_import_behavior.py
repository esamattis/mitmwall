"""
Unit tests for mitmproxy addon import behavior.
"""

import importlib
import sys
import unittest
from collections.abc import Iterable
from types import ModuleType
from unittest.mock import patch


def save_modules(module_names: Iterable[str]) -> dict[str, ModuleType | None]:
    """
    Save the current sys.modules entries for the given module names.
    """

    return {module_name: sys.modules.get(module_name) for module_name in module_names}


def clear_modules(module_names: Iterable[str]) -> None:
    """
    Remove the given modules from sys.modules when they are present.
    """

    for module_name in module_names:
        _module = sys.modules.pop(module_name, None)


def restore_modules(saved_modules: dict[str, ModuleType | None]) -> None:
    """
    Restore previously saved sys.modules entries.
    """

    for module_name in saved_modules:
        _module = sys.modules.pop(module_name, None)

    for module_name, module in saved_modules.items():
        if module is not None:
            sys.modules[module_name] = module


class AddonImportBehaviorTests(unittest.TestCase):
    """
    Verify addon imports avoid runtime side effects in tests.
    """

    def test_importing_pathname_pattern_does_not_import_runtime_addon(self) -> None:
        """
        Verify submodule imports do not eagerly import the runtime addon module.
        """

        module_names = [
            "mitmproxy_addon.pathname_pattern",
            "mitmproxy_addon.addon",
            "mitmproxy_addon.main",
        ]
        saved_modules = save_modules(module_names)
        clear_modules(module_names)

        try:
            module = importlib.import_module("mitmproxy_addon.pathname_pattern")

            self.assertTrue(hasattr(module, "compile_pathname_pattern"))
            self.assertNotIn("mitmproxy_addon.addon", sys.modules)
        finally:
            restore_modules(saved_modules)

    def test_importing_main_does_not_load_runtime_addon_config(self) -> None:
        """
        Verify importing the addon entrypoint does not read runtime config.
        """

        module_names = [
            "mitmproxy_addon.main",
            "mitmproxy_addon.addon",
            "mitmproxy_addon.addon_logging",
        ]
        saved_modules = save_modules(module_names)
        clear_modules(module_names)

        try:
            import mitmproxy_addon.addon_config as addon_config

            with patch.object(
                addon_config,
                "load_addon_config",
                side_effect=AssertionError(
                    "importing mitmproxy_addon.main should not load runtime config"
                ),
            ):
                module = importlib.import_module("mitmproxy_addon.main")

            self.assertTrue(hasattr(module, "addons"))
        finally:
            restore_modules(saved_modules)


if __name__ == "__main__":
    _test_program = unittest.main(verbosity=2)
