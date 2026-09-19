import os
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
        with managed_lock(tmp_path, _user(tmp_path)):
            pass



def test_root_lock_creation_chowns_open_file_to_invoking_user(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = InvokingUser("test", 1234, 5678, tmp_path)
    calls: list[tuple[int, int, int]] = []

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        os,
        "fchown",
        lambda fd, uid, gid: calls.append((fd, uid, gid)),
    )

    with managed_lock(tmp_path, user):
        pass

    assert calls
    assert calls[0][1:] == (1234, 5678)



def test_save_state_rejects_unsupported_schema(tmp_path: Path) -> None:
    from wazuhdevenv.state import save_state

    with pytest.raises(ValueError, match="unsupported state schema version"):
        save_state(
            tmp_path,
            {"schema_version": 2, "workspace": "/tmp/workspace"},
            _user(tmp_path),
        )

    assert not (tmp_path / "state.json").exists()



@pytest.mark.parametrize("schema", [True, False, 1.0, "1"])
def test_save_state_rejects_non_integer_schema_values(
    tmp_path: Path,
    schema: object,
) -> None:
    from wazuhdevenv.state import save_state

    with pytest.raises(ValueError, match="unsupported state schema version"):
        save_state(
            tmp_path,
            {"schema_version": schema},
            _user(tmp_path),
        )


@pytest.mark.parametrize("schema_json", ["true", "false", "1.0", "\"1\""])
def test_load_state_rejects_non_integer_schema_values(
    tmp_path: Path,
    schema_json: str,
) -> None:
    (tmp_path / "state.json").write_text(
        f'{{"schema_version": {schema_json}}}\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unsupported state file"):
        load_state(tmp_path)



def test_managed_lock_uses_open_directory_descriptor_if_path_is_swapped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "managed"
    home.mkdir()
    original = tmp_path / "managed-original"
    outside = tmp_path / "outside"
    outside.mkdir()

    real_open = os.open
    swapped = False

    def racing_open(
        path: object,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if not swapped and dir_fd is None and Path(path) == home:
            fd = real_open(path, flags, mode)
            os.replace(home, original)
            home.symlink_to(outside, target_is_directory=True)
            swapped = True
            return fd
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", racing_open)

    with managed_lock(home, _user(tmp_path)):
        pass

    assert (original / "wazuhdevenv.lock").is_file()
    assert not (outside / "wazuhdevenv.lock").exists()
