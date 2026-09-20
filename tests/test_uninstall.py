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
