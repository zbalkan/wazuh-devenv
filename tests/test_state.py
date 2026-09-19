import json
from pathlib import Path

import pytest

from wazuhdevenv.errors import ConfigurationError
from wazuhdevenv.state import ensure_managed_home, load_state, managed_lock, save_state


def test_managed_home_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "managed"
    link.symlink_to(target, target_is_directory=True)

    with pytest.raises(ConfigurationError, match="managed home must not be a symlink"):
        ensure_managed_home(link)


def test_managed_subdirectory_rejects_symlink(tmp_path: Path) -> None:
    home = tmp_path / "managed"
    home.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    (home / "cache").symlink_to(target, target_is_directory=True)

    with pytest.raises(ConfigurationError, match="managed state directory must not be a symlink"):
        ensure_managed_home(home)


def test_state_file_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "external.json"
    target.write_text('{"schema_version": 1}\n', encoding="utf-8")
    (tmp_path / "state.json").symlink_to(target)

    with pytest.raises(ConfigurationError, match="state file must not be a symlink"):
        load_state(tmp_path)


def test_lock_file_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "external.lock"
    target.touch()
    (tmp_path / "wazuhdevenv.lock").symlink_to(target)

    with pytest.raises(ConfigurationError, match="lock file must not be a symlink"):
        with managed_lock(tmp_path):
            pass


def test_lock_file_rejects_symlink_even_if_precheck_misses_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "external.lock"
    target.touch()
    lock = tmp_path / "wazuhdevenv.lock"
    lock.symlink_to(target)

    original_is_symlink = Path.is_symlink

    def stale_is_symlink(path: Path) -> bool:
        if path == lock:
            return False
        return original_is_symlink(path)

    monkeypatch.setattr(Path, "is_symlink", stale_is_symlink)

    with pytest.raises(ConfigurationError, match="lock file must not be a symlink"):
        with managed_lock(tmp_path):
            pass


def test_managed_lock_prevents_second_writer(tmp_path: Path) -> None:
    with managed_lock(tmp_path):
        with pytest.raises(RuntimeError, match="another wazuhdevenv operation"):
            with managed_lock(tmp_path):
                pass


def test_state_round_trip(tmp_path: Path) -> None:
    save_state(tmp_path, {"workspace": "/tmp/workspace"})

    assert load_state(tmp_path) == {
        "schema_version": 1,
        "workspace": "/tmp/workspace",
    }


@pytest.mark.parametrize("schema", [2, True, False, 1.0, "1"])
def test_save_state_rejects_unsupported_schema(
    tmp_path: Path,
    schema: object,
) -> None:
    with pytest.raises(ValueError, match="unsupported state schema version"):
        save_state(tmp_path, {"schema_version": schema})

    assert not (tmp_path / "state.json").exists()


@pytest.mark.parametrize("schema_json", ["2", "true", "false", "1.0", "\"1\""])
def test_load_state_rejects_unsupported_schema(
    tmp_path: Path,
    schema_json: str,
) -> None:
    (tmp_path / "state.json").write_text(
        f'{{"schema_version": {schema_json}}}\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unsupported state file"):
        load_state(tmp_path)
