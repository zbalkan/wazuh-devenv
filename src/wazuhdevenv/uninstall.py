"""Teardown for a wazuhdevenv-managed environment."""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

from .errors import ConfigurationError, WazuhDevenvError
from .paths import InvokingUser
from .provisioning import (
    APT_REPOSITORY,
    OSSEC_CONF,
    RPM_REPOSITORY,
    WINDOWS_RULES,
    WAZUH_HOME,
    PackageManager,
    _privileged_exists,
    _read_optional_privileged,
    _render_ossec_config,
    _render_windows_rule_testing,
    _rewrite_preserving_metadata,
    _same_bind_mount,
    _write_privileged,
    is_wazuh_active,
    is_wazuh_enabled,
    start_wazuh,
    stop_wazuh,
    wait_for_logtest,
)
from .runner import CommandRunner
from .state import load_state

LOG = logging.getLogger(__name__)

OSSEC_BACKUP = OSSEC_CONF.with_name("ossec.conf.wazuhdevenv.bak")
WINDOWS_RULES_BACKUP = WINDOWS_RULES.with_name(
    WINDOWS_RULES.name + ".wazuhdevenv.bak"
)
APT_REPOSITORY_PATH = Path("/etc/apt/sources.list.d/wazuh.list")
RPM_REPOSITORY_PATH = Path("/etc/yum.repos.d/wazuh.repo")
APT_KEYRING_PATH = Path("/usr/share/keyrings/wazuh.gpg")


def _required_state(home: Path) -> tuple[dict[str, object], Path, dict[str, object]]:
    state = load_state(home)
    workspace = state.get("workspace")
    if not isinstance(workspace, str):
        raise WazuhDevenvError("workspace is not initialized; nothing to uninstall")

    provenance = state.get("provisioning")
    if not isinstance(provenance, dict):
        raise ConfigurationError(
            "state predates uninstall provenance tracking; automatic cleanup "
            "would have to guess what wazuhdevenv created"
        )
    return state, Path(workspace), provenance


def _targets(values: object) -> set[Path]:
    if not isinstance(values, list):
        return set()
    return {Path(value) for value in values if isinstance(value, str)}


def _preflight_mounts(
    runner: CommandRunner,
    workspace: Path,
    preexisting: set[Path],
) -> None:
    for name in ("rules", "decoders"):
        target = WAZUH_HOME / "etc" / name
        if target in preexisting:
            continue
        if (
            runner.run(
                ["mountpoint", "-q", str(target)],
                privileged=True,
                check=False,
            ).returncode
            != 0
        ):
            continue
        if not _same_bind_mount(runner, (workspace / name).resolve(), target):
            raise ConfigurationError(
                f"{target} is mounted from unexpected content; refusing to unmount it"
            )


def _remove_mounts(
    runner: CommandRunner,
    workspace: Path,
    preexisting: set[Path],
) -> None:
    for name in reversed(("rules", "decoders")):
        target = WAZUH_HOME / "etc" / name
        if target in preexisting:
            continue
        if _same_bind_mount(runner, (workspace / name).resolve(), target):
            runner.run(["umount", str(target)], privileged=True)


def _remove_fstab_entries(
    runner: CommandRunner,
    workspace: Path,
    preexisting: set[Path],
) -> None:
    path = Path("/etc/fstab")
    text = _read_optional_privileged(runner, path)
    if text is None:
        return

    expected = {
        WAZUH_HOME / "etc" / name: (
            f"{(workspace / name).resolve()} "
            f"{WAZUH_HOME / 'etc' / name} none bind 0 0"
        )
        for name in ("rules", "decoders")
        if WAZUH_HOME / "etc" / name not in preexisting
    }

    output: list[str] = []
    changed = False
    for raw in text.splitlines(keepends=True):
        line = raw.strip()
        fields = line.split()
        target = Path(fields[1]) if len(fields) >= 2 and not line.startswith("#") else None
        if target not in expected:
            output.append(raw)
            continue
        if line != expected[target]:
            raise ConfigurationError(
                f"fstab entry for {target} changed since initialization"
            )
        changed = True

    if changed:
        _rewrite_preserving_metadata(runner, path, "".join(output))


def _preflight_restore(
    runner: CommandRunner,
    target: Path,
    backup: Path,
    render,
) -> None:
    if not _privileged_exists(runner, backup):
        raise ConfigurationError(f"required backup is missing: {backup}")
    original = runner.capture(["cat", str(backup)], privileged=True)
    current = runner.capture(["cat", str(target)], privileged=True)
    if current != render(original):
        raise ConfigurationError(
            f"{target} changed after initialization; refusing to overwrite it"
        )


def _restore_backup(runner: CommandRunner, target: Path, backup: Path) -> None:
    runner.run(
        [
            "cp",
            "--preserve=mode,ownership,timestamps",
            str(backup),
            str(target),
        ],
        privileged=True,
    )


def _cleanup_workspace_access(
    runner: CommandRunner,
    workspace: Path,
    user: InvokingUser,
) -> None:
    if runner.trusted_which("setfacl"):
        for name in ("rules", "decoders"):
            path = workspace / name
            if path.is_dir() and not path.is_symlink():
                runner.run_as_user(
                    ["setfacl", "-d", "-x", "u:wazuh,g:wazuh", str(path)],
                    check=False,
                )

    if runner.run(["getent", "group", "wazuh"], check=False).returncode != 0:
        return

    for name in ("rules", "decoders"):
        path = workspace / name
        if path.is_dir() and not path.is_symlink():
            runner.run(
                [
                    "find",
                    str(path),
                    "-group",
                    "wazuh",
                    "-exec",
                    "chgrp",
                    str(user.gid),
                    "{}",
                    "+",
                ],
                privileged=True,
            )


def _remove_group_membership(
    runner: CommandRunner,
    user: InvokingUser,
    provenance: dict[str, object],
) -> None:
    if provenance.get("group_membership_added") is not True:
        return
    if runner.run(["getent", "group", "wazuh"], check=False).returncode == 0:
        runner.run(["gpasswd", "-d", user.name, "wazuh"], privileged=True)


def _remove_wazuh(runner: CommandRunner, package_manager: PackageManager) -> None:
    if package_manager.installed_version() is not None:
        if package_manager.family == "apt":
            runner.run(
                ["apt-get", "remove", "--purge", "wazuh-manager", "-y"],
                privileged=True,
            )
        else:
            runner.run(
                [package_manager.command, "-y", "remove", "wazuh-manager"],
                privileged=True,
            )

    runner.run(["rm", "-rf", str(WAZUH_HOME)], privileged=True)


def _restore_repository(
    runner: CommandRunner,
    package_manager: PackageManager,
    before: object,
) -> None:
    path = (
        APT_REPOSITORY_PATH
        if package_manager.family == "apt"
        else RPM_REPOSITORY_PATH
    )
    current = _read_optional_privileged(runner, path)
    managed = (
        {APT_REPOSITORY, f"#{APT_REPOSITORY}"}
        if package_manager.family == "apt"
        else {
            RPM_REPOSITORY.format(enabled=0),
            RPM_REPOSITORY.format(enabled=1),
        }
    )

    if current is not None and current not in managed:
        LOG.warning("Leaving modified Wazuh repository configuration in place: %s", path)
        return

    if before is None:
        if current is not None:
            runner.run(["rm", "-f", str(path)], privileged=True)
    elif isinstance(before, str):
        if current is None:
            _write_privileged(runner, path, before)
        elif current != before:
            _rewrite_preserving_metadata(runner, path, before)
    else:
        raise ConfigurationError("invalid repository provenance in state.json")

    if package_manager.family == "apt":
        runner.run(["apt-get", "update"], privileged=True)


def _restore_service(
    runner: CommandRunner,
    *,
    was_active: bool,
    was_enabled: bool | None,
) -> None:
    if was_active:
        start_wazuh(runner, enable=was_enabled)
        wait_for_logtest(runner)
        return
    if was_enabled is not None:
        action = "enable" if was_enabled else "disable"
        runner.run(["systemctl", action, "wazuh-manager"], privileged=True)


def uninstall_environment(home: Path, user: InvokingUser) -> Path:
    _, workspace, provenance = _required_state(home)
    runner = CommandRunner(user)
    package_manager = PackageManager(runner)

    installed_by_tool = provenance.get("wazuh_installed_by_tool") is True
    preexisting_mounts = _targets(provenance.get("preexisting_mounts"))
    preexisting_fstab = _targets(provenance.get("preexisting_fstab_entries"))

    _preflight_mounts(runner, workspace, preexisting_mounts)

    if not installed_by_tool:
        _preflight_restore(
            runner, OSSEC_CONF, OSSEC_BACKUP, _render_ossec_config
        )
        _preflight_restore(
            runner,
            WINDOWS_RULES,
            WINDOWS_RULES_BACKUP,
            _render_windows_rule_testing,
        )

    service_was_active = is_wazuh_active(runner)
    service_was_enabled = is_wazuh_enabled(runner)

    stop_wazuh(runner)
    _remove_fstab_entries(runner, workspace, preexisting_fstab)
    _remove_mounts(runner, workspace, preexisting_mounts)
    _cleanup_workspace_access(runner, workspace, user)
    _remove_group_membership(runner, user, provenance)

    if installed_by_tool:
        _remove_wazuh(runner, package_manager)
        _restore_repository(
            runner,
            package_manager,
            provenance.get("repository_before"),
        )
        if (
            package_manager.family == "apt"
            and provenance.get("apt_keyring_preexisting") is False
            and _privileged_exists(runner, APT_KEYRING_PATH)
        ):
            runner.run(["rm", "-f", str(APT_KEYRING_PATH)], privileged=True)
    else:
        _restore_backup(runner, OSSEC_CONF, OSSEC_BACKUP)
        _restore_backup(runner, WINDOWS_RULES, WINDOWS_RULES_BACKUP)
        _restore_service(
            runner,
            was_active=service_was_active,
            was_enabled=service_was_enabled,
        )

    if provenance.get("workspace_venv_created_by_tool") is True:
        venv = workspace / ".venv"
        if venv.is_symlink():
            raise ConfigurationError(
                f"workspace virtual environment became a symlink: {venv}"
            )
        if venv.exists():
            shutil.rmtree(venv)

    return workspace
