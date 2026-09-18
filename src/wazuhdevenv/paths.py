"""User, workspace, and managed-state path resolution."""

from __future__ import annotations

import os
import pwd
from dataclasses import dataclass
from pathlib import Path

from .errors import ConfigurationError


@dataclass(frozen=True)
class InvokingUser:
    name: str
    uid: int
    gid: int
    home: Path

    @classmethod
    def current(cls) -> "InvokingUser":
        sudo_user = os.environ.get("SUDO_USER")
        if os.geteuid() == 0 and sudo_user and sudo_user != "root":
            entry = pwd.getpwnam(sudo_user)
        else:
            entry = pwd.getpwuid(os.getuid())
        return cls(entry.pw_name, entry.pw_uid, entry.pw_gid, Path(entry.pw_dir))


def managed_home(user: InvokingUser) -> Path:
    override = os.environ.get("WAZUHDEVENV_HOME")
    if override:
        path = Path(override).expanduser()
        return path if path.is_absolute() else (Path.cwd() / path).resolve()
    return user.home / ".wazuhdevenv"


def resolve_workspace(value: str | None) -> Path:
    path = Path(value or ".").expanduser().resolve()
    forbidden_roots = (
        Path("/etc"),
        Path("/var"),
        Path("/usr"),
        Path("/opt"),
        Path("/bin"),
        Path("/sbin"),
        Path("/lib"),
        Path("/lib64"),
        Path("/boot"),
        Path("/dev"),
        Path("/proc"),
        Path("/sys"),
        Path("/run"),
    )
    if path == Path("/") or any(path == root or root in path.parents for root in forbidden_roots):
        raise ConfigurationError(f"refusing to use system directory as workspace: {path}")
    return path
