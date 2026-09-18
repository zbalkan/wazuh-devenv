"""Managed wazuh-devenv state and process locking."""

from __future__ import annotations

import fcntl
import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .paths import InvokingUser


def ensure_managed_home(path: Path, user: InvokingUser) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / "cache").mkdir(exist_ok=True)
    (path / "staging").mkdir(exist_ok=True)
    (path / "logs").mkdir(exist_ok=True)
    if os.geteuid() == 0 and user.uid != 0:
        for item in (path, path / "cache", path / "staging", path / "logs"):
            os.chown(item, user.uid, user.gid)


@contextmanager
def managed_lock(path: Path) -> Iterator[None]:
    lock_path = path / "wazuhdevenv.lock"
    with lock_path.open("a+", encoding="utf-8") as stream:
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("another wazuhdevenv operation is already running") from exc
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def load_state(path: Path) -> dict[str, object]:
    state_path = path / "state.json"
    if not state_path.exists():
        return {"schema_version": 1}
    data = json.loads(state_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError(f"unsupported state file: {state_path}")
    return data


def save_state(path: Path, state: dict[str, object], user: InvokingUser) -> None:
    state = {"schema_version": 1, **state}
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
