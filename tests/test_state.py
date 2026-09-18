from pathlib import Path

import pytest

from wazuhdevenv.errors import ConfigurationError
from wazuhdevenv.paths import InvokingUser
from wazuhdevenv.state import ensure_managed_home, load_state, managed_lock


def _user(tmp_path: Path) -> InvokingUser:
    return InvokingUser("test", 1000, 1000, tmp_path)


def test_managed_home_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "managed"
    link.symlink_to(target, target_is_directory=True)

    with pytest.raises(ConfigurationError):
        ensure_managed_home(link, _user(tmp_path))


def test_managed_subdirectory_rejects_symlink(tmp_path: Path) -> None:
    home = tmp_path / "managed"
    home.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    (home / "cache").symlink_to(target, target_is_directory=True)

    with pytest.raises(ConfigurationError):
        ensure_managed_home(home, _user(tmp_path))


def test_state_file_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "external.json"
    target.write_text('{"schema_version": 1}\n', encoding="utf-8")
    (tmp_path / "state.json").symlink_to(target)

    with pytest.raises(ConfigurationError):
        load_state(tmp_path)


def test_lock_file_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "external.lock"
    target.touch()
    (tmp_path / "wazuhdevenv.lock").symlink_to(target)

    with pytest.raises(ConfigurationError):
        with managed_lock(tmp_path):
            pass
