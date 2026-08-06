"""
Unit tests for migrations from older mitmwall versions.
"""

import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.systemd import migrations


class ResolverStateMigrationTests(unittest.TestCase):
    """Verify migration of the historical runtime resolver snapshot."""

    def test_moves_legacy_state_to_persistent_storage(self) -> None:
        """The old snapshot is copied securely and removed from runtime state."""

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            legacy_dir = root / "run" / "mitmwall"
            state_dir = root / "var" / "lib" / "mitmwall"
            legacy_file = legacy_dir / "resolv-conf-state.json"
            state_file = state_dir / "resolv-conf-state.json"
            legacy_dir.mkdir(parents=True)
            _ = legacy_file.write_bytes(b'{"kind": "file"}\n')

            with (
                patch.object(migrations, "LEGACY_RESOLVER_STATE_DIR", legacy_dir),
                patch.object(migrations, "LEGACY_RESOLVER_STATE_FILE", legacy_file),
                patch.object(migrations, "RESOLVER_STATE_DIR", state_dir),
                patch.object(migrations, "RESOLVER_STATE_FILE", state_file),
            ):
                migrations.migrate_legacy_resolver_state()

            self.assertEqual(state_file.read_bytes(), b'{"kind": "file"}\n')
            self.assertEqual(stat.S_IMODE(state_file.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(state_dir.stat().st_mode), 0o700)
            self.assertFalse(legacy_file.exists())
            self.assertFalse(legacy_dir.exists())

    def test_current_state_wins_over_legacy_state(self) -> None:
        """A stale legacy snapshot never replaces an existing current snapshot."""

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            legacy_dir = root / "legacy"
            state_dir = root / "current"
            legacy_file = legacy_dir / "resolv-conf-state.json"
            state_file = state_dir / "resolv-conf-state.json"
            legacy_dir.mkdir()
            state_dir.mkdir()
            _ = legacy_file.write_text("legacy", encoding="utf-8")
            _ = state_file.write_text("current", encoding="utf-8")

            with (
                patch.object(migrations, "LEGACY_RESOLVER_STATE_DIR", legacy_dir),
                patch.object(migrations, "LEGACY_RESOLVER_STATE_FILE", legacy_file),
                patch.object(migrations, "RESOLVER_STATE_FILE", state_file),
            ):
                migrations.migrate_legacy_resolver_state()

            self.assertEqual(state_file.read_text(encoding="utf-8"), "current")
            self.assertFalse(legacy_file.exists())


class StartupMigrationTests(unittest.TestCase):
    """Verify centralized startup migration orchestration."""

    @patch("src.systemd.migrations.clear_legacy_redirect_rules")
    @patch("src.systemd.migrations.migrate_legacy_resolver_state")
    def test_runs_all_migrations(
        self, mock_resolver: MagicMock, mock_firewall: MagicMock
    ) -> None:
        """The public entrypoint runs each migration once."""

        firewalls = (MagicMock(), MagicMock())

        migrations.run_startup_migrations(firewalls)

        mock_resolver.assert_called_once_with()
        mock_firewall.assert_called_once_with(firewalls)
