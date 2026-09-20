"""Safe teardown of a wazuhdevenv-managed environment."""

from __future__ import annotations

import logging
import shutil
from dataclasses import dataclass
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


@dataclass(frozen=True)
class UninstallResult:
    workspace: Path
    wazuh_removed: bool
    legacy_state: bool


def _require_workspace(state: dict[str, object]) -> Path:
    value = state.get("workspace")
    if not isinstance(value, str):
        raise WazuhDevenvError(
            "workspace is not initialized; nothing to uninstall"
        )
    return Path(value)


def _metadata(state: dict[str, object]) -> tuple[dict[str, object], bool]:
    value = state.get("provisioning")
    if isinstance(value, dict):
        return value, False
    LOG.warning(
        "State predates uninstall provenance tracking; Wazuh Manager and "
        "workspace virtual environment will be preserved."
    )
    return {}, True


def _target(name: str) -> Path:
    return WAZUH_HOME / "etc" / name


def _preflight_mounts(
    runner: CommandRunner,
    workspace: Path,
    preexisting_mounts: set[Path],
) -> None:
    for name in ("rules", "decoders"):
        target = _target(name)
        if target in preexisting_mounts:
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
        source = (workspace / name).resolve()
        if not _same_bind_mount(runner, source, target):
            raise ConfigurationError(
                f"{target} is mounted from unexpected content; refusing to unmount it"
            )


def _remove_managed_mounts(
    runner: CommandRunner,
    workspace: Path,
    preexisting_mounts: set[Path],
) -> None:
    for name in reversed(("rules", "decoders")):
        target = _target(name)
        if target in preexisting_mounts:
            continue
        source = (workspace / name).resolve()
        if _same_bind_mount(runner, source, target):
            runner.run(["umount", str(target)], privileged=True)


def _remove_managed_fstab_entries(
    runner: CommandRunner,
    workspace: Path,
    preexisting_targets: set[Path],
) -> None:
    path = Path("/etc/fstab")
    text = _read_optional_privileged(runner, path)
    if text is None:
        return

    managed: dict[Path, str] = {}
    for name in ("rules", "decoders"):
        target = _target(name)
        if target in preexisting_targets:
            continue
        source = (workspace / name).resolve()
        managed[target] = f"{source} {target} none bind 0 0"

    if not managed:
        return

    changed = False
    output: list[str] = []
    for raw in text.splitlines(keepends=True):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            output.append(raw)
            continue

        fields = stripped.split()
        target = Path(fields[1]) if len(fields) >= 2 else None
        if target not in managed:
            output.append(raw)
            continue

        if stripped != managed[target]:
            raise ConfigurationError(
                f"fstab entry for {target} changed since initialization; "
                "refusing to remove it"
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
        raise ConfigurationError(
            f"required pre-initialization backup is missing: {backup}"
        )
    original = runner.capture(["cat", str(backup)], privileged=True)
    expected = render(original)
    current = runner.capture(["cat", str(target)], privileged=True)
    if current != expected:
        raise ConfigurationError(
            f"{target} changed after wazuhdevenv initialization; "
            "refusing to overwrite later changes"
        )


def _restore_backup(
    runner: CommandRunner,
    target: Path,
    backup: Path,
    *,
    remove_backup: bool,
) -> None:
    runner.run(
        [
            "cp",
            "--preserve=mode,ownership,timestamps",
            str(backup),
            str(target),
        ],
        privileged=True,
    )
    if remove_backup:
        runner.run(["rm", "-f", str(backup)], privileged=True)


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
                    [
                        "setfacl",
                        "-d",
                        "-x",
                        "u:wazuh,g:wazuh",
                        str(path),
                    ],
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
    *,
    added_by_tool: bool,
) -> None:
    if not added_by_tool:
        return
    if runner.run(["getent", "group", "wazuh"], check=False).returncode != 0:
        return
    runner.run(["gpasswd", "-d", user.name, "wazuh"], privileged=True)


def _repository_path(family: str) -> Path:
    return APT_REPOSITORY_PATH if family == "apt" else RPM_REPOSITORY_PATH


def _managed_repository_contents(family: str) -> set[str]:
    if family == "apt":
        return {APT_REPOSITORY, f"#{APT_REPOSITORY}"}
    return {
        RPM_REPOSITORY.format(enabled=0),
        RPM_REPOSITORY.format(enabled=1),
    }


def _preflight_repository(
    runner: CommandRunner,
    family: str,
    repository_before: object,
) -> None:
    path = _repository_path(family)
    current = _read_optional_privileged(runner, path)
    if current is None:
        return
    if current not in _managed_repository_contents(family):
        raise ConfigurationError(
            f"Wazuh repository configuration changed since initialization: {path}"
        )
    if repository_before is not None and not isinstance(repository_before, str):
        raise ConfigurationError("invalid repository provenance in state.json")


def _restore_repository(
    runner: CommandRunner,
    family: str,
    repository_before: object,
) -> None:
    path = _repository_path(family)
    current = _read_optional_privileged(runner, path)

    if repository_before is None:
        if current is not None:
            runner.run(["rm", "-f", str(path)], privileged=True)
    else:
        if not isinstance(repository_before, str):
            raise ConfigurationError("invalid repository provenance in state.json")
        if current is None:
            _write_privileged(runner, path, repository_before)
        elif current != repository_before:
            _rewrite_preserving_metadata(runner, path, repository_before)

    if family == "apt":
        runner.run(["apt-get", "update"], privileged=True)


def _remove_wazuh(
    runner: CommandRunner,
    package_manager: PackageManager,
) -> None:
    if package_manager.installed_version() is None:
        return
    if package_manager.family == "apt":
        runner.run(
            ["apt-get", "remove", "--purge", "wazuh-manager", "-y"],
            privileged=True,
        )
        return

    runner.run(
        [package_manager.command, "-y", "remove", "wazuh-manager"],
        privileged=True,
    )
    runner.run(["rm", "-rf", str(WAZUH_HOME)], privileged=True)


def _restore_service_state(
    runner: CommandRunner,
    *,
    was_active: bool,
    was_enabled: bool | None,
) -> None:
    if was_active:
        start_wazuh(runner, enable=was_enabled)
        wait_for_logtest(runner)
        return

    stop_wazuh(runner)
    if was_enabled is None:
        return
    action = "enable" if was_enabled else "disable"
    runner.run(
        ["systemctl", action, "wazuh-manager"],
        privileged=True,
    )


def uninstall_environment(
    home: Path,
    user: InvokingUser,
) -> UninstallResult:
    state = load_state(home)
    workspace = _require_workspace(state)
    metadata, legacy_state = _metadata(state)

    runner = CommandRunner(user)
    package_manager = PackageManager(runner)

    installed_by_tool = bool(metadata.get("wazuh_installed_by_tool", False))
    preexisting_mounts = {
        Path(value)
        for value in metadata.get("preexisting_mounts", [])
        if isinstance(value, str)
    }
    preexisting_fstab = {
        Path(value)
        for value in metadata.get("preexisting_fstab_entries", [])
        if isinstance(value, str)
    }

    _preflight_mounts(runner, workspace, preexisting_mounts)

    repository_before = metadata.get("repository_before")
    family = metadata.get("package_manager_family")
    if installed_by_tool:
        if family not in {"apt", "rpm"}:
            raise ConfigurationError(
                "missing package-manager provenance; refusing to remove Wazuh Manager"
            )
        if family != package_manager.family:
            raise ConfigurationError(
                "package manager differs from initialization; refusing to remove Wazuh Manager"
            )
        _preflight_repository(runner, family, repository_before)
    else:
        _preflight_restore(
            runner,
            OSSEC_CONF,
            OSSEC_BACKUP,
            _render_ossec_config,
        )
        _preflight_restore(
            runner,
            WINDOWS_RULES,
            WINDOWS_RULES_BACKUP,
            _render_windows_rule_testing,
        )

    if legacy_state:
        service_was_active = is_wazuh_active(runner)
        service_was_enabled = is_wazuh_enabled(runner)
    else:
        active_value = metadata.get("service_was_active")
        enabled_value = metadata.get("service_was_enabled")
        if not isinstance(active_value, bool):
            raise ConfigurationError("invalid service-state provenance in state.json")
        if enabled_value is not None and not isinstance(enabled_value, bool):
            raise ConfigurationError("invalid service-state provenance in state.json")
        service_was_active = active_value
        service_was_enabled = enabled_value

    stop_wazuh(runner)
    _remove_managed_mounts(runner, workspace, preexisting_mounts)
    _remove_managed_fstab_entries(runner, workspace, preexisting_fstab)
    _cleanup_workspace_access(runner, workspace, user)
    _remove_group_membership(
        runner,
        user,
        added_by_tool=bool(metadata.get("group_membership_added", False)),
    )

    if installed_by_tool:
        _remove_wazuh(runner, package_manager)
        _restore_repository(runner, family, repository_before)
        if (
            family == "apt"
            and metadata.get("apt_keyring_preexisting") is False
            and _privileged_exists(runner, APT_KEYRING_PATH)
        ):
            runner.run(
                ["rm", "-f", str(APT_KEYRING_PATH)],
                privileged=True,
            )
    else:
        _restore_backup(
            runner,
            OSSEC_CONF,
            OSSEC_BACKUP,
            remove_backup=not bool(metadata.get("ossec_backup_preexisting", True)),
        )
        _restore_backup(
            runner,
            WINDOWS_RULES,
            WINDOWS_RULES_BACKUP,
            remove_backup=not bool(
                metadata.get("windows_backup_preexisting", True)
            ),
        )
        _restore_service_state(
            runner,
            was_active=service_was_active,
            was_enabled=service_was_enabled,
        )

    if bool(metadata.get("workspace_venv_created_by_tool", False)):
        venv = workspace / ".venv"
        if venv.is_symlink():
            raise ConfigurationError(
                f"workspace virtual environment became a symlink: {venv}"
            )
        if venv.exists():
            shutil.rmtree(venv)

    return UninstallResult(
        workspace=workspace,
        wazuh_removed=installed_by_tool,
        legacy_state=legacy_state,
    )
