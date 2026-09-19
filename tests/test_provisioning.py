from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

import wazuhdevenv.provisioning as provisioning
from wazuhdevenv.errors import ConfigurationError
from wazuhdevenv.paths import InvokingUser
from wazuhdevenv.provisioning import (
    PackageManager,
    ProvisioningSnapshot,
    WorkspaceMutations,
    _plan_adoption,
    _adopt_existing,
    _normalize_wazuh_version,
    _replace_block_child,
    _replace_simple_tag,
)


class LocalRunner:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []
        self.privileged_captures: list[list[str]] = []

    def capture(self, args: list[str], *, privileged: bool = False) -> str:
        if privileged:
            self.privileged_captures.append(args)
        if args[0] == "find":
            root = Path(args[1])
            rows: list[str] = []
            for path in sorted(root.rglob("*")):
                relative = path.relative_to(root).as_posix()
                if path.is_symlink():
                    kind = "l"
                elif path.is_dir():
                    kind = "d"
                elif path.is_file():
                    kind = "f"
                else:
                    kind = "?"
                rows.append(f"{kind}\t{relative}")
            return "\n".join(rows) + ("\n" if rows else "")
        if args[0] == "sha256sum":
            path = Path(args[1])
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            return f"{digest}  {path}\n"
        raise AssertionError(f"unexpected capture command: {args}")

    def run(
        self,
        args: list[str],
        *,
        privileged: bool = False,
        check: bool = True,
    ) -> SimpleNamespace:
        del privileged, check
        self.commands.append(args)
        if args[0] == "mkdir":
            Path(args[-1]).mkdir(parents=True, exist_ok=True)
        elif args[0] == "cp":
            shutil.copy2(args[-2], args[-1])
        elif args[0] == "rm":
            Path(args[-1]).unlink(missing_ok=True)
        elif args[0] == "rmdir":
            try:
                Path(args[-1]).rmdir()
            except OSError:
                pass
        return SimpleNamespace(returncode=0)


def test_replace_simple_tag_is_idempotent() -> None:
    source = "<logall_json>no</logall_json>"
    changed = _replace_simple_tag(source, "logall_json", "yes", {"yes", "no"})
    assert changed == "<logall_json>yes</logall_json>"
    assert _replace_simple_tag(changed, "logall_json", "yes", {"yes", "no"}) == changed


def test_replace_simple_tag_rejects_unknown_state() -> None:
    with pytest.raises(ConfigurationError):
        _replace_simple_tag("<logall_json>maybe</logall_json>", "logall_json", "yes", {"yes", "no"})


def test_replace_block_child_changes_only_selected_block() -> None:
    source = """<rootcheck>
  <disabled>no</disabled>
</rootcheck>
<syscheck>
  <disabled>no</disabled>
</syscheck>
"""
    changed = _replace_block_child(
        source,
        r"<rootcheck>.*?</rootcheck>",
        "disabled",
        "yes",
        {"yes", "no"},
        "rootcheck",
    )
    assert "<rootcheck>\n  <disabled>yes</disabled>" in changed
    assert "<syscheck>\n  <disabled>no</disabled>" in changed


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("4.14.8", "4.14.8"),
        ("4.14.8-1", "4.14.8"),
        ("1:4.14.8-1", "4.14.8"),
        ("wazuh-manager-4.14.8-1.x86_64", "4.14.8"),
    ],
)
def test_normalize_wazuh_version(value: str, expected: str) -> None:
    assert _normalize_wazuh_version(value) == expected


def test_normalize_wazuh_version_rejects_invalid_value() -> None:
    with pytest.raises(ConfigurationError):
        _normalize_wazuh_version("not-a-version")


def test_wazuh_local_rules_sample_is_never_adopted(tmp_path: Path) -> None:
    runner = LocalRunner()
    source = tmp_path / "workspace/rules"
    target = tmp_path / "wazuh/rules"
    source.mkdir(parents=True)
    target.mkdir(parents=True)
    (target / "local_rules.xml").write_text(
        "arbitrary upstream sample content\n",
        encoding="utf-8",
    )

    _adopt_existing(runner, source, target)

    assert not (source / "local_rules.xml").exists()
    assert not any(command[0] == "cp" for command in runner.commands)


def test_workspace_local_rules_always_wins_over_wazuh_sample(tmp_path: Path) -> None:
    runner = LocalRunner()
    source = tmp_path / "workspace/rules"
    target = tmp_path / "wazuh/rules"
    source.mkdir(parents=True)
    target.mkdir(parents=True)
    (source / "local_rules.xml").write_text("workspace rule\n", encoding="utf-8")
    (target / "local_rules.xml").write_text(
        "different upstream sample\n",
        encoding="utf-8",
    )

    _adopt_existing(runner, source, target)

    assert (source / "local_rules.xml").read_text(encoding="utf-8") == "workspace rule\n"
    assert not any(command[0] == "cp" for command in runner.commands)


def test_wazuh_local_decoder_sample_is_never_adopted(tmp_path: Path) -> None:
    runner = LocalRunner()
    source = tmp_path / "workspace/decoders"
    target = tmp_path / "wazuh/decoders"
    source.mkdir(parents=True)
    target.mkdir(parents=True)
    (target / "local_decoder.xml").write_text(
        "arbitrary upstream decoder sample\n",
        encoding="utf-8",
    )

    _adopt_existing(runner, source, target)

    assert not (source / "local_decoder.xml").exists()
    assert not any(command[0] == "cp" for command in runner.commands)


def test_custom_wazuh_file_is_copied_into_empty_workspace(tmp_path: Path) -> None:
    runner = LocalRunner()
    source = tmp_path / "workspace/rules"
    target = tmp_path / "wazuh/rules"
    source.mkdir(parents=True)
    target.mkdir(parents=True)
    (target / "custom.xml").write_text("<group name=\"custom,\"/>\n", encoding="utf-8")

    _adopt_existing(runner, source, target)

    assert (source / "custom.xml").read_text(encoding="utf-8") == '<group name="custom,"/>\n'
    assert (target / "custom.xml").is_file()


def test_adoption_fails_before_copying_when_later_file_conflicts(tmp_path: Path) -> None:
    runner = LocalRunner()
    source = tmp_path / "workspace/rules"
    target = tmp_path / "wazuh/rules"
    source.mkdir(parents=True)
    target.mkdir(parents=True)

    (target / "a.xml").write_text("adopt me\n", encoding="utf-8")
    (target / "b.xml").write_text("target version\n", encoding="utf-8")
    (source / "b.xml").write_text("workspace version\n", encoding="utf-8")

    with pytest.raises(ConfigurationError, match="conflicting existing Wazuh content"):
        _adopt_existing(runner, source, target)

    assert not (source / "a.xml").exists()
    assert not any(command[0] == "cp" for command in runner.commands)


def test_initialize_rolls_back_after_post_stop_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    user = InvokingUser("tester", os.getuid(), os.getgid(), tmp_path)
    snapshot = ProvisioningSnapshot(
        service_was_active=True,
        ossec_conf="original",
        windows_rules="original",
        fstab="original",
        preexisting_mounts=frozenset(),
        workspace_metadata=(),
    )

    class FakePackageManager:
        def __init__(self, runner: object) -> None:
            del runner

        def ensure_system_dependencies(self) -> None:
            events.append("dependencies")

        def install_wazuh(self, requested_version: str | None) -> str:
            del requested_version
            events.append("install")
            return "4.14.8"

    monkeypatch.setattr(provisioning, "ensure_linux", lambda: None)
    monkeypatch.setattr(provisioning, "CommandRunner", lambda user: object())
    monkeypatch.setattr(provisioning, "PackageManager", FakePackageManager)
    monkeypatch.setattr(provisioning, "prepare_workspace", lambda *args: events.append("workspace"))
    monkeypatch.setattr(provisioning, "ensure_workspace_venv", lambda *args: events.append("venv"))
    monkeypatch.setattr(
        provisioning,
        "preflight_bind_mounts",
        lambda *args, **kwargs: events.append("preflight"),
    )
    monkeypatch.setattr(provisioning, "is_wazuh_active", lambda runner: True)
    monkeypatch.setattr(provisioning, "_capture_snapshot", lambda *args: snapshot)
    monkeypatch.setattr(
        provisioning,
        "_render_ossec_config",
        lambda value: value,
    )
    monkeypatch.setattr(
        provisioning,
        "_render_windows_rule_testing",
        lambda value: value,
    )
    monkeypatch.setattr(provisioning, "stop_wazuh", lambda runner: events.append("stop") or True)
    monkeypatch.setattr(provisioning, "configure_ossec", lambda runner: events.append("ossec"))
    monkeypatch.setattr(
        provisioning,
        "configure_windows_rule_testing",
        lambda runner: events.append("windows"),
    )
    monkeypatch.setattr(
        provisioning,
        "configure_bind_mounts",
        lambda *args, **kwargs: events.append("mounts"),
    )
    monkeypatch.setattr(
        provisioning,
        "configure_permissions",
        lambda *args: events.append("permissions"),
    )
    monkeypatch.setattr(
        provisioning,
        "ensure_group_membership",
        lambda *args: events.append("group"),
    )

    def fail_validation(runner: object) -> None:
        del runner
        events.append("validate")
        raise ConfigurationError("invalid configuration")

    monkeypatch.setattr(provisioning, "validate_wazuh", fail_validation)
    monkeypatch.setattr(
        provisioning,
        "_rollback_provisioning",
        lambda *args: events.append("rollback"),
    )

    with pytest.raises(ConfigurationError, match="invalid configuration"):
        provisioning.initialize(tmp_path / "workspace", tmp_path / "home", user)

    assert events[-2:] == ["validate", "rollback"]
    assert events.index("stop") < events.index("permissions") < events.index("validate")



def test_adoption_inspects_workspace_through_privileged_runner(tmp_path: Path) -> None:
    runner = LocalRunner()
    source = tmp_path / "workspace/rules"
    target = tmp_path / "wazuh/rules"
    source.mkdir(parents=True)
    target.mkdir(parents=True)
    (source / "custom.xml").write_text("same\n", encoding="utf-8")
    (target / "custom.xml").write_text("same\n", encoding="utf-8")

    _adopt_existing(runner, source, target)

    source_commands = [
        command
        for command in runner.privileged_captures
        if any(str(source) in argument for argument in command)
    ]
    assert source_commands
    assert any(command[0] == "find" for command in source_commands)
    assert any(command[0] == "sha256sum" for command in source_commands)


def test_prepare_workspace_chowns_new_root_when_invoked_as_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "new-workspace"
    user = InvokingUser("test", 1234, 5678, tmp_path)
    calls: list[tuple[Path, int, int]] = []

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        os,
        "chown",
        lambda path, uid, gid: calls.append((Path(path), uid, gid)),
    )

    provisioning.prepare_workspace(workspace, user)

    assert (workspace, 1234, 5678) in calls



class DpkgRunner:
    def __init__(self, states: dict[str, str]) -> None:
        self.states = states

    def capture(self, args: list[str], *, privileged: bool = False) -> str:
        del privileged
        if args[:2] != ["dpkg-query", "-W"]:
            raise AssertionError(f"unexpected command: {args}")
        package = args[-1]
        value = self.states.get(package)
        if value is None:
            raise provisioning.CommandError(f"package not found: {package}")
        return value


def _apt_manager(runner: object) -> PackageManager:
    manager = object.__new__(PackageManager)
    manager.runner = runner
    manager.family = "apt"
    manager.command = "apt-get"
    return manager


def test_removed_apt_wazuh_package_is_not_reported_as_installed() -> None:
    manager = _apt_manager(
        DpkgRunner(
            {
                "wazuh-manager": "deinstall ok config-files\t4.14.8-1\n",
            }
        )
    )

    assert manager.installed_version() is None


def test_installed_apt_wazuh_package_returns_normalized_version() -> None:
    manager = _apt_manager(
        DpkgRunner(
            {
                "wazuh-manager": "install ok installed\t4.14.8-1\n",
            }
        )
    )

    assert manager.installed_version() == "4.14.8"


def test_apt_dependency_probe_reinstalls_config_files_state() -> None:
    states = {
        "python3-venv": "deinstall ok config-files\t3.13.0-1\n",
        "util-linux": "install ok installed\t2.40.0\n",
        "coreutils": "install ok installed\t9.5\n",
        "findutils": "install ok installed\t4.10\n",
        "gnupg": "install ok installed\t2.4\n",
        "apt-transport-https": "install ok installed\t2.9\n",
    }
    manager = _apt_manager(DpkgRunner(states))
    installed: list[list[str]] = []
    manager._apt_install = lambda packages: installed.append(packages)  # type: ignore[method-assign]

    manager.ensure_system_dependencies()

    assert installed == [["python3-venv"]]



def test_adoption_plan_does_not_mutate_workspace(tmp_path: Path) -> None:
    runner = LocalRunner()
    source = tmp_path / "workspace/rules"
    target = tmp_path / "wazuh/rules"
    source.mkdir(parents=True)
    target.mkdir(parents=True)
    (target / "custom.xml").write_text("target\n", encoding="utf-8")

    plan = _plan_adoption(runner, source, target)

    assert len(plan.copies) == 1
    assert not (source / "custom.xml").exists()
    assert not any(command[0] == "cp" for command in runner.commands)


def test_restore_workspace_removes_adopted_files_and_restores_metadata(
    tmp_path: Path,
) -> None:
    runner = LocalRunner()
    source = tmp_path / "workspace/rules"
    source.mkdir(parents=True)
    copied = source / "adopted.xml"
    copied.write_text("adopted\n", encoding="utf-8")
    snapshot = ProvisioningSnapshot(
        service_was_active=False,
        ossec_conf="",
        windows_rules="",
        fstab="",
        preexisting_mounts=frozenset(),
        workspace_metadata=(
            provisioning.WorkspaceMetadata(source, "755", os.getuid(), os.getgid()),
        ),
    )
    mutations = WorkspaceMutations(copied_files=[copied])

    errors = provisioning._restore_workspace(runner, snapshot, mutations)

    assert errors == []
    assert not copied.exists()
    assert any(command[0] == "chown" for command in runner.commands)
    assert any(command[0] == "chmod" for command in runner.commands)



@pytest.mark.parametrize(
    "threads",
    ["1", "32", "128", "auto"],
)
def test_render_ossec_accepts_documented_rule_test_threads(threads: str) -> None:
    assert provisioning._valid_rule_test_threads(threads)


@pytest.mark.parametrize("threads", ["0", "129", "four"])
def test_render_ossec_rejects_invalid_rule_test_threads(threads: str) -> None:
    assert not provisioning._valid_rule_test_threads(threads)


@pytest.mark.parametrize(
    "timeout",
    ["30s", "1m", "24h", "365d"],
)
def test_render_ossec_accepts_documented_session_timeout(timeout: str) -> None:
    assert provisioning._valid_rule_test_session_timeout(timeout)


@pytest.mark.parametrize("timeout", ["0s", "366d", "1h 30m", "forever"])
def test_render_ossec_rejects_invalid_session_timeout(timeout: str) -> None:
    assert not provisioning._valid_rule_test_session_timeout(timeout)


def test_empty_target_still_rejects_workspace_symlink(tmp_path: Path) -> None:
    runner = LocalRunner()
    source = tmp_path / "workspace/rules"
    target = tmp_path / "wazuh/rules"
    source.mkdir(parents=True)
    target.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.write_text("x", encoding="utf-8")
    (source / "link.xml").symlink_to(outside)

    with pytest.raises(ConfigurationError, match="must not contain symlinks"):
        _plan_adoption(runner, source, target)


def test_ensure_group_membership_reports_whether_it_mutated() -> None:
    class GroupRunner:
        def __init__(self, groups: str) -> None:
            self.groups = groups
            self.commands: list[list[str]] = []

        def capture(self, args: list[str], **kwargs: object) -> str:
            return self.groups

        def run(self, args: list[str], **kwargs: object) -> SimpleNamespace:
            self.commands.append(args)
            return SimpleNamespace(returncode=0)

    user = InvokingUser("tester", 1000, 1000, Path("/home/tester"))
    existing = GroupRunner("tester wazuh")
    added = GroupRunner("tester")

    assert provisioning.ensure_group_membership(existing, user) is False
    assert provisioning.ensure_group_membership(added, user) is True
    assert added.commands == [["usermod", "-a", "-G", "wazuh", "tester"]]


def test_rollback_stops_manager_that_was_initially_inactive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    user = InvokingUser("tester", 1000, 1000, tmp_path)
    snapshot = ProvisioningSnapshot(
        service_was_active=False,
        ossec_conf="original",
        windows_rules="original",
        fstab="original",
        preexisting_mounts=frozenset(),
        service_was_enabled=False,
        workspace_metadata=(),
    )

    runner = LocalRunner()
    monkeypatch.setattr(provisioning, "stop_wazuh", lambda runner: events.append("stop") or True)
    monkeypatch.setattr(provisioning, "_same_bind_mount", lambda *args: True)
    monkeypatch.setattr(provisioning, "_restore_workspace", lambda *args: [])
    monkeypatch.setattr(provisioning, "_restore_text_if_changed", lambda *args: None)
    monkeypatch.setattr(provisioning, "set_wazuh_enabled", lambda runner, value: events.append(f"enabled:{value}"))
    monkeypatch.setattr(provisioning, "remove_group_membership", lambda *args: events.append("group-removed"))

    provisioning._rollback_provisioning(
        runner,
        tmp_path / "workspace",
        snapshot,
        WorkspaceMutations(),
        user,
        True,
    )

    assert events[0] == "stop"
    assert "enabled:False" in events
    assert "group-removed" in events
    assert not any(event == "start" for event in events)
    assert ["umount", "/var/ossec/etc/decoders"] in runner.commands
    assert ["umount", "/var/ossec/etc/rules"] in runner.commands



def test_state_save_failure_rolls_back_completed_provisioning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    user = InvokingUser("tester", os.getuid(), os.getgid(), tmp_path)
    snapshot = ProvisioningSnapshot(
        service_was_active=False,
        ossec_conf="original",
        windows_rules="original",
        fstab="original",
        preexisting_mounts=frozenset(),
        service_was_enabled=False,
        workspace_metadata=(),
    )

    class FakePackageManager:
        def __init__(self, runner: object) -> None:
            del runner

        def ensure_system_dependencies(self) -> None:
            pass

        def install_wazuh(self, requested_version: str | None) -> str:
            del requested_version
            return "4.14.8"

    monkeypatch.setattr(provisioning, "ensure_linux", lambda: None)
    monkeypatch.setattr(provisioning, "CommandRunner", lambda user: object())
    monkeypatch.setattr(provisioning, "PackageManager", FakePackageManager)
    monkeypatch.setattr(provisioning, "prepare_workspace", lambda *args: None)
    monkeypatch.setattr(provisioning, "ensure_workspace_venv", lambda *args: None)
    monkeypatch.setattr(provisioning, "preflight_bind_mounts", lambda *args: None)
    monkeypatch.setattr(provisioning, "is_wazuh_active", lambda runner: False)
    monkeypatch.setattr(provisioning, "_capture_snapshot", lambda *args: snapshot)
    monkeypatch.setattr(provisioning, "_render_ossec_config", lambda value: value)
    monkeypatch.setattr(provisioning, "_render_windows_rule_testing", lambda value: value)
    monkeypatch.setattr(provisioning, "ensure_group_membership", lambda *args: False)
    monkeypatch.setattr(provisioning, "stop_wazuh", lambda *args: False)
    monkeypatch.setattr(provisioning, "configure_ossec", lambda *args: None)
    monkeypatch.setattr(provisioning, "configure_windows_rule_testing", lambda *args: None)
    monkeypatch.setattr(provisioning, "configure_bind_mounts", lambda *args, **kwargs: None)
    monkeypatch.setattr(provisioning, "configure_permissions", lambda *args: None)
    monkeypatch.setattr(provisioning, "validate_wazuh", lambda *args: None)
    monkeypatch.setattr(provisioning, "start_wazuh", lambda *args, **kwargs: None)
    monkeypatch.setattr(provisioning, "wait_for_logtest", lambda *args: None)
    monkeypatch.setattr(provisioning, "load_state", lambda *args: {"schema_version": 1})
    monkeypatch.setattr(
        provisioning,
        "save_state",
        lambda *args: (_ for _ in ()).throw(RuntimeError("state failure")),
    )
    monkeypatch.setattr(
        provisioning,
        "_rollback_provisioning",
        lambda *args: events.append("rollback"),
    )

    with pytest.raises(RuntimeError, match="state failure"):
        provisioning.initialize(tmp_path / "workspace", tmp_path / "home", user)

    assert events == ["rollback"]



@pytest.mark.parametrize("value", ["1", "250", "500"])
def test_rule_test_max_sessions_accepts_documented_range(value: str) -> None:
    assert provisioning._valid_rule_test_max_sessions(value)


@pytest.mark.parametrize("value", ["0", "501", "many"])
def test_rule_test_max_sessions_rejects_out_of_range_values(value: str) -> None:
    assert not provisioning._valid_rule_test_max_sessions(value)
