"""
Manage the Proxmox VE LXC ``/etc/resolv.conf`` compatibility workaround.

Proxmox VE (PVE) commonly gives an LXC container its DNS servers and search
domains by writing a regular ``/etc/resolv.conf`` containing an upstream
address. PVE provides this resolver configuration; it does not handle DNS
queries itself. Applications normally read the file and send packets directly
to the listed server.

In the target LXC environment, redirecting non-loopback UDP DNS traffic to
mitmwall's local proxy creates an incompatible hairpin path. Mitmwall avoids
that path by making applications use systemd-resolved's loopback stub while DNS
interception is active.

Mitmwall does not copy the PVE-provided servers into ``resolved.conf``, call
``resolvectl`` to register them, or otherwise persist them as
systemd-resolved configuration. In the affected PVE setup, the running
systemd-resolved process has already read the regular ``/etc/resolv.conf`` and
retains its upstream servers and search domains in process memory. Replacing the
file changes where applications send queries, but the existing resolved process
continues using those remembered upstream settings. This reliance matters only
when PVE's file is resolved's sole source; resolved may instead receive durable
DNS configuration from networkd, NetworkManager, DHCP, or ``resolved.conf``.

The workaround operates in these stages:

1. Before mitmwall starts, ``/etc/resolv.conf`` remains PVE-managed so the
   running systemd-resolved process can learn its upstream servers and search
   domains and retain them in memory.
2. During ``ExecStartPre``, this module detects a non-loopback nameserver,
   verifies that systemd-resolved and its stub are available, saves the original
   regular file or symlink under ``/var/lib/mitmwall``, and atomically replaces
   it with a symlink to ``/run/systemd/resolve/stub-resolv.conf``. Configurations
   that already use only loopback nameservers are unchanged.
3. While mitmwall runs, application DNS packets are redirected to mitmwall on
   port 58053. Allowed queries go from the exempt mitmwall user to
   systemd-resolved, which contacts the PVE-provided upstream server remembered
   from the original file.
4. When systemd-resolved is explicitly stopped or restarted, systemd stops
   mitmwall first. ``ExecStopPost`` restores the PVE file before resolved starts
   again, because a new resolved process has lost the old process's in-memory
   settings and must read the original file again. The unit's ``BindsTo=``,
   ``After=``, and ``PartOf=`` relationships enforce this lifecycle ordering.
5. When mitmwall stops normally, it removes its firewall rules and this module
   restores the saved file or symlink. A resolver configuration replaced by
   another manager while mitmwall was active is kept rather than overwritten.

Lifecycle coupling fixes the earlier failure where resolved could restart while
``/etc/resolv.conf`` pointed to its own stub and lose PVE settings that existed
only in the original file. If resolved unexpectedly becomes inactive,
``BindsTo=`` stops mitmwall and restores direct DNS safely, although it does not
guarantee that mitmwall automatically returns after resolved recovers.

Set ``manage_resolv_conf = false`` in ``/etc/mitmwall/config.toml`` to disable
startup detection and replacement. Restoration still runs when saved state
exists so disabling the option while mitmwall is active remains safe.
"""

import base64
from dataclasses import dataclass
import ipaddress
import json
import logging
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import tomllib
from typing import Literal, cast

from src.addon.constants import ADDON_CONFIG_FILE, DEFAULT_MANAGE_RESOLV_CONF
from src.systemd.migrations import (
    LEGACY_RESOLVER_STATE_FILE,
    RESOLVER_STATE_DIR,
    RESOLVER_STATE_FILE,
)
from src.utils.toml_helpers import is_toml_table

LOGGER = logging.getLogger("mitmwall.resolv_conf")
RESOLV_CONF = Path("/etc/resolv.conf")
SYSTEMD_RESOLVED_STUB = Path("/run/systemd/resolve/stub-resolv.conf")


@dataclass(frozen=True)
class ResolverState:
    """
    Original resolv.conf representation saved while mitmwall is running.
    """

    kind: Literal["file", "symlink"]
    uid: int
    gid: int
    mode: int
    content: bytes | None = None
    target: str | None = None


def resolv_conf_handling_enabled(config_path: Path = ADDON_CONFIG_FILE) -> bool:
    """
    Return whether config.toml enables mitmwall's resolv.conf handling.
    """

    if not config_path.exists():
        return DEFAULT_MANAGE_RESOLV_CONF

    with config_path.open("rb") as file:
        config_value = cast(object, tomllib.load(file))
    if not is_toml_table(config_value):
        raise ValueError("top-level TOML value must be a table")

    enabled = config_value.get("manage_resolv_conf", DEFAULT_MANAGE_RESOLV_CONF)
    if not isinstance(enabled, bool):
        raise ValueError("'manage_resolv_conf' must be a boolean")
    return enabled


def resolv_conf_uses_external_nameserver(path: Path) -> bool:
    """
    Return whether resolv.conf contains at least one non-loopback nameserver.

    PVE commonly configures LXC clients to query upstream resolvers directly.
    Redirecting those queries to a local proxy creates a non-loopback hairpin
    that does not retain the expected reply source. A loopback resolver avoids
    that incompatible path.
    """

    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return False

    for raw_line in text.splitlines():
        line = raw_line.partition("#")[0].strip()
        fields = line.split()
        if len(fields) < 2 or fields[0] != "nameserver":
            continue

        address = fields[1].split("%", maxsplit=1)[0]
        try:
            if not ipaddress.ip_address(address).is_loopback:
                return True
        except ValueError:
            return True

    return False


def write_resolver_state(state: ResolverState) -> None:
    """
    Persist the original resolver configuration atomically in root-only state.
    """

    RESOLVER_STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    RESOLVER_STATE_DIR.chmod(0o700)
    payload: dict[str, object] = {
        "kind": state.kind,
        "uid": state.uid,
        "gid": state.gid,
        "mode": state.mode,
    }
    if state.content is not None:
        payload["content"] = base64.b64encode(state.content).decode("ascii")
    if state.target is not None:
        payload["target"] = state.target

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".resolv-conf-state-", dir=RESOLVER_STATE_DIR
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as file:
            descriptor = -1
            json.dump(payload, file, sort_keys=True)
            _ = file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary_path, RESOLVER_STATE_FILE)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary_path.unlink(missing_ok=True)


def read_resolver_state(path: Path) -> ResolverState:
    """
    Load and validate resolver state written by write_resolver_state().
    """

    try:
        value = cast(object, json.loads(path.read_text("utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError("cannot read saved resolver configuration") from error

    if not isinstance(value, dict):
        raise RuntimeError("saved resolver configuration is not a JSON object")
    fields = cast(dict[object, object], value)
    kind = fields.get("kind")
    uid = fields.get("uid")
    gid = fields.get("gid")
    mode = fields.get("mode")
    if kind not in ("file", "symlink"):
        raise RuntimeError("saved resolver configuration has an invalid kind")
    if type(uid) is not int or type(gid) is not int or type(mode) is not int:
        raise RuntimeError("saved resolver configuration has invalid metadata")

    if kind == "file":
        encoded_content = fields.get("content")
        if not isinstance(encoded_content, str):
            raise RuntimeError("saved resolver file has no content")
        try:
            content = base64.b64decode(encoded_content, validate=True)
        except ValueError as error:
            raise RuntimeError("saved resolver file content is invalid") from error
        return ResolverState(kind, uid, gid, mode, content=content)

    target = fields.get("target")
    if not isinstance(target, str):
        raise RuntimeError("saved resolver symlink has no target")
    return ResolverState(kind, uid, gid, mode, target=target)


def find_resolver_state_file() -> Path | None:
    """
    Return the persistent state file or a state file from an older installation.
    """

    if RESOLVER_STATE_FILE.exists():
        return RESOLVER_STATE_FILE
    if LEGACY_RESOLVER_STATE_FILE.exists():
        return LEGACY_RESOLVER_STATE_FILE
    return None


def remove_resolver_state(path: Path) -> None:
    """
    Remove a resolver state file and its directory when otherwise empty.
    """

    path.unlink()
    try:
        path.parent.rmdir()
    except OSError:
        pass


def resolv_conf_is_mitmwall_stub() -> bool:
    """
    Return whether resolv.conf is the stub symlink installed by mitmwall.
    """

    try:
        return RESOLV_CONF.is_symlink() and os.readlink(RESOLV_CONF) == str(
            SYSTEMD_RESOLVED_STUB
        )
    except OSError:
        return False


def replace_with_symlink(path: Path, target: str) -> None:
    """
    Atomically replace a path with a symbolic link to target.
    """

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.mitmwall-", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    os.close(descriptor)
    try:
        temporary_path.unlink()
        temporary_path.symlink_to(target)
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def replace_with_file(path: Path, state: ResolverState) -> None:
    """
    Atomically replace a path with the regular file stored in resolver state.
    """

    if state.content is None:
        raise RuntimeError("saved resolver file has no content")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.mitmwall-", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, state.mode)
        os.fchown(descriptor, state.uid, state.gid)
        with os.fdopen(descriptor, "wb") as file:
            descriptor = -1
            _ = file.write(state.content)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary_path, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary_path.unlink(missing_ok=True)


def save_resolver_state() -> None:
    """
    Save the current regular file or symlink without replacing existing state.
    """

    if find_resolver_state_file() is not None:
        return

    metadata = RESOLV_CONF.lstat()
    mode = stat.S_IMODE(metadata.st_mode)
    if stat.S_ISLNK(metadata.st_mode):
        state = ResolverState(
            "symlink",
            metadata.st_uid,
            metadata.st_gid,
            mode,
            target=os.readlink(RESOLV_CONF),
        )
    elif stat.S_ISREG(metadata.st_mode):
        state = ResolverState(
            "file",
            metadata.st_uid,
            metadata.st_gid,
            mode,
            content=RESOLV_CONF.read_bytes(),
        )
    else:
        raise RuntimeError(f"{RESOLV_CONF} is not a regular file or symlink")
    write_resolver_state(state)


def configure_system_resolver(config_path: Path = ADDON_CONFIG_FILE) -> None:
    """
    Use systemd-resolved's loopback stub when enabled and resolv.conf points upstream.

    This makes PVE-managed LXC resolver configuration compatible with
    mitmwall's local UDP REDIRECT while retaining transparent DNS filtering.
    The original resolver path is saved for restore_system_resolver.
    """

    if not resolv_conf_handling_enabled(config_path):
        LOGGER.info("resolv.conf handling is disabled; leaving %s unchanged", RESOLV_CONF)
        return
    if not resolv_conf_uses_external_nameserver(RESOLV_CONF):
        LOGGER.info("%s does not use an external nameserver; leaving it unchanged", RESOLV_CONF)
        return

    resolved = subprocess.run(
        ["systemctl", "is-active", "--quiet", "systemd-resolved.service"],
        capture_output=True,
    )
    if resolved.returncode != 0:
        raise RuntimeError(
            f"{RESOLV_CONF} uses an external nameserver, but systemd-resolved is not active"
        )
    if not SYSTEMD_RESOLVED_STUB.is_file():
        raise RuntimeError(
            f"systemd-resolved stub configuration is missing: {SYSTEMD_RESOLVED_STUB}"
        )
    if resolv_conf_uses_external_nameserver(SYSTEMD_RESOLVED_STUB):
        raise RuntimeError(
            f"systemd-resolved stub does not use a loopback nameserver: {SYSTEMD_RESOLVED_STUB}"
        )

    previous_state_file = find_resolver_state_file()
    if previous_state_file is not None:
        remove_resolver_state(previous_state_file)
    save_resolver_state()
    replace_with_symlink(RESOLV_CONF, str(SYSTEMD_RESOLVED_STUB))
    LOGGER.info("switched %s to systemd-resolved stub %s", RESOLV_CONF, SYSTEMD_RESOLVED_STUB)


def restore_system_resolver() -> None:
    """
    Restore the exact resolv.conf file or symlink saved during service start.
    """

    state_file = find_resolver_state_file()
    if state_file is None:
        LOGGER.info("no saved resolv.conf configuration to restore")
        return

    try:
        _ = RESOLV_CONF.lstat()
    except FileNotFoundError:
        pass
    else:
        if not resolv_conf_is_mitmwall_stub():
            LOGGER.info(
                "%s changed while mitmwall was running; keeping current configuration",
                RESOLV_CONF,
            )
            remove_resolver_state(state_file)
            return

    state = read_resolver_state(state_file)
    if state.kind == "file":
        replace_with_file(RESOLV_CONF, state)
    else:
        if state.target is None:
            raise RuntimeError("saved resolver symlink has no target")
        replace_with_symlink(RESOLV_CONF, state.target)
        os.chown(RESOLV_CONF, state.uid, state.gid, follow_symlinks=False)

    remove_resolver_state(state_file)
    LOGGER.info("restored %s from saved resolver configuration", RESOLV_CONF)
