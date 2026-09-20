from __future__ import annotations

import json
from pathlib import Path

import pytest

import wazuhdevenv.uninstall as uninstall
from wazuhdevenv.errors import ConfigurationError


def test_required_state_accepts_legacy_state(tmp_path: Path) -> None:
    home = tmp_path / "managed"
    home.mkdir()
    workspace = tmp_path / "workspace"
    (home / "state.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "workspace": str(workspace),
                "wazuh_home": "/var/ossec",
                "wazuh_version": "4.14.8",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    _, resolved, provenance, legacy = uninstall._required_state(home)

    assert resolved == workspace
    assert provenance == {}
    assert legacy is True


def test_required_state_reads_uninstall_provenance(tmp_path: Path) -> None:
    home = tmp_path / "managed"
    home.mkdir()
    workspace = tmp_path / "workspace"
    provenance = {"wazuh_installed_by_tool": True}
    (home / "state.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "workspace": str(workspace),
                "provisioning": provenance,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    _, resolved, loaded, legacy = uninstall._required_state(home)

    assert resolved == workspace
    assert loaded == provenance
    assert legacy is False


def test_remove_fstab_entries_preserves_unrelated_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    rules = (workspace / "rules").resolve()
    decoders = (workspace / "decoders").resolve()
    original = (
        "UUID=root / ext4 defaults 0 1\n"
        f"{rules} /var/ossec/etc/rules none bind 0 0\n"
        f"{decoders} /var/ossec/etc/decoders none bind 0 0\n"
        "# keep this comment\n"
    )
    writes: list[str] = []

    monkeypatch.setattr(
        uninstall,
        "_read_optional_privileged",
        lambda runner, path: original,
    )
    monkeypatch.setattr(
        uninstall,
        "_rewrite_preserving_metadata",
        lambda runner, path, text: writes.append(text),
    )

    uninstall._remove_fstab_entries(object(), workspace, set())

    assert writes == [
        "UUID=root / ext4 defaults 0 1\n"
        "# keep this comment\n"
    ]


def test_remove_fstab_entries_refuses_changed_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    original = (
        "/somewhere-else /var/ossec/etc/rules none bind 0 0\n"
    )

    monkeypatch.setattr(
        uninstall,
        "_read_optional_privileged",
        lambda runner, path: original,
    )

    with pytest.raises(ConfigurationError, match="changed since initialization"):
        uninstall._remove_fstab_entries(object(), workspace, set())



def test_preflight_wazuh_version_rejects_changed_installation() -> None:
    class FakePackageManager:
        def installed_version(self) -> str:
            return "4.15.0"

    with pytest.raises(ConfigurationError, match="changed since initialization"):
        uninstall._preflight_wazuh_version(
            FakePackageManager(),
            {"wazuh_version": "4.14.8"},
        )


def test_preflight_wazuh_version_allows_removed_package() -> None:
    class FakePackageManager:
        def installed_version(self) -> None:
            return None

    uninstall._preflight_wazuh_version(
        FakePackageManager(),
        {"wazuh_version": "4.14.8"},
    )



def test_targets_rejects_malformed_provenance() -> None:
    with pytest.raises(ConfigurationError, match="preexisting_mounts"):
        uninstall._targets(["/var/ossec/etc/rules", 123], "preexisting_mounts")


def test_restore_service_restarts_with_recorded_enablement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[object] = []

    monkeypatch.setattr(
        uninstall,
        "start_wazuh",
        lambda runner, *, enable: events.append(("start", enable)),
    )
    monkeypatch.setattr(
        uninstall,
        "wait_for_logtest",
        lambda runner: events.append("ready"),
    )

    uninstall._restore_service(
        object(),
        was_active=True,
        was_enabled=False,
    )

    assert events == [("start", False), "ready"]


def test_remove_group_membership_is_idempotent() -> None:
    class FakeRunner:
        def run(
            self,
            args: list[str],
            *,
            privileged: bool = False,
            check: bool = True,
        ):
            del privileged, check
            assert args == ["getent", "group", "wazuh"]
            return type("Result", (), {"returncode": 0})()

        def capture(
            self,
            args: list[str],
            *,
            privileged: bool = False,
        ) -> str:
            assert args == ["id", "-nG", "tester"]
            assert privileged is True
            return "tester users\n"

    removed = uninstall._remove_group_membership(
        FakeRunner(),
        type(
            "User",
            (),
            {"name": "tester"},
        )(),
        {"group_membership_added": True},
    )

    assert removed is False


def test_format_uninstall_report_lists_remnants_explicitly(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    managed_home = tmp_path / "managed"
    result = uninstall.UninstallResult(
        workspace=workspace,
        removed=("Wazuh Manager package",),
        restored=("pre-initialization repository configuration",),
        preserved=(f"user workspace content: {workspace / 'rules'}",),
        remnants=("system prerequisite packages retained: util-linux",),
    )

    report = uninstall.format_uninstall_report(result, managed_home)

    assert "Removed:" in report
    assert "Restored:" in report
    assert "Preserved:" in report
    assert "Remnants:" in report
    assert f"managed state: {managed_home}" in report
    assert "system prerequisite packages retained: util-linux" in report


def test_strings_rejects_malformed_dependency_provenance() -> None:
    with pytest.raises(ConfigurationError, match="system_dependencies_installed"):
        uninstall._strings(
            ["util-linux", 123],
            "system_dependencies_installed",
        )


def test_preflight_restore_accepts_already_restored_state() -> None:
    original = "<config>original</config>"

    class FakeRunner:
        def capture(
            self,
            args: list[str],
            *,
            privileged: bool = False,
        ) -> str:
            assert args == ["cat", "/var/ossec/etc/ossec.conf"]
            assert privileged is True
            return original

    uninstall._preflight_restore(
        FakeRunner(),
        Path("/var/ossec/etc/ossec.conf"),
        original,
        lambda value: value.replace("original", "configured"),
    )


def test_preflight_restore_rejects_unattributed_later_change() -> None:
    class FakeRunner:
        def capture(
            self,
            args: list[str],
            *,
            privileged: bool = False,
        ) -> str:
            del args
            assert privileged is True
            return "<config>changed later</config>"

    with pytest.raises(ConfigurationError, match="changed after initialization"):
        uninstall._preflight_restore(
            FakeRunner(),
            Path("/var/ossec/etc/ossec.conf"),
            "<config>original</config>",
            lambda value: value.replace("original", "configured"),
        )
