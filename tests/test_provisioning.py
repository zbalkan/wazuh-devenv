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
    ProvisioningSnapshot,
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


def test_stock_placeholder_does_not_override_workspace_rule(tmp_path: Path) -> None:
    runner = LocalRunner()
    source = tmp_path / "workspace/rules"
    target = tmp_path / "wazuh/rules"
    source.mkdir(parents=True)
    target.mkdir(parents=True)

    (source / "local_rules.xml").write_text("<group name=\"custom,\"/>\n", encoding="utf-8")
    (target / "local_rules.xml").write_text(
        """<!-- Local rules -->

<!-- Modify it at your will. -->
<!-- Copyright (C) 2015, Wazuh Inc. -->

<!-- Example -->
<group name="local,syslog,sshd,">

  <!--
  Dec 10 01:02:02 host sshd[1234]: Failed none for root from 1.1.1.1 port 1066 ssh2
  -->
  <rule id="100001" level="5">
    <if_sid>5716</if_sid>
    <srcip>1.1.1.1</srcip>
    <description>sshd: authentication failed from IP 1.1.1.1.</description>
    <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>

</group>
""",
        encoding="utf-8",
    )

    _adopt_existing(runner, source, target)

    assert (source / "local_rules.xml").read_text(encoding="utf-8") == '<group name="custom,"/>\n'
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
    monkeypatch.setattr(provisioning, "preflight_bind_mounts", lambda *args: events.append("preflight"))
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
        lambda *args: events.append("mounts"),
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
    assert "stop" in events



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
        if str(source) in command
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
