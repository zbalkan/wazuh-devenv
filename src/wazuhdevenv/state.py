"""Managed wazuh-devenv state and process locking."""

from __future__ import annotations

import errno
import fcntl
import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .errors import ConfigurationError
from .paths import InvokingUser


def ensure_managed_home(path: Path, user: InvokingUser) -> None:
    if path.is_symlink():
        raise ConfigurationError(f"managed home must not be a symlink: {path}")
    path.mkdir(parents=True, exist_ok=True)
    for name in ("cache", "staging", "corpora", "logs"):
        child = path / name
        if child.is_symlink():
            raise ConfigurationError(f"managed state directory must not be a symlink: {child}")
        child.mkdir(exist_ok=True)
    if os.geteuid() == 0 and user.uid != 0:
        for item in (
            path,
            path / "cache",
            path / "staging",
            path / "corpora",
            path / "logs",
        ):
            os.chown(item, user.uid, user.gid)


@contextmanager
def managed_lock(path: Path, user: InvokingUser) -> Iterator[None]:
    lock_path = path / "wazuhdevenv.lock"
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        directory_fd = os.open(path, directory_flags)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise ConfigurationError(
                f"managed home must be a real directory: {path}"
            ) from exc
        raise

    try:
        lock_flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW
        try:
            fd = os.open(
                "wazuhdevenv.lock",
                lock_flags,
                0o600,
                dir_fd=directory_fd,
            )
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise ConfigurationError(
                    f"lock file must not be a symlink: {lock_path}"
                ) from exc
            raise

        with os.fdopen(fd, "a+", encoding="utf-8") as stream:
            if os.geteuid() == 0 and user.uid != 0:
                os.fchown(stream.fileno(), user.uid, user.gid)
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeError(
                    "another wazuhdevenv operation is already running"
                ) from exc
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
    finally:
        os.close(directory_fd)


def _valid_schema_version(value: object) -> bool:
    return type(value) is int and value == 1


def load_state(path: Path) -> dict[str, object]:
    state_path = path / "state.json"
    if state_path.is_symlink():
        raise ConfigurationError(f"state file must not be a symlink: {state_path}")
    if not state_path.exists():
        return {"schema_version": 1}
    data = json.loads(state_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not _valid_schema_version(data.get("schema_version")):
        raise ValueError(f"unsupported state file: {state_path}")
    return data


def save_state(path: Path, state: dict[str, object], user: InvokingUser) -> None:
    schema_version = state.get("schema_version", 1)
    if not _valid_schema_version(schema_version):
        raise ValueError(f"unsupported state schema version: {schema_version}")
    state = {**state, "schema_version": 1}
    target = path / "state.json"
    fd, temporary_name = tempfile.mkstemp(prefix=".state.", dir=path, text=True)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(state, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if os.geteuid() == 0 and user.uid != 0:
            os.chown(temporary, user.uid, user.gid)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
