"""User, workspace, and managed-state path resolution."""

from __future__ import annotations

import os
import pwd
from dataclasses import dataclass
from pathlib import Path

from .errors import ConfigurationError


FORBIDDEN_SYSTEM_ROOTS = (
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


def _reject_system_path(path: Path, purpose: str) -> Path:
    if path == Path("/") or any(
        path == root or root in path.parents for root in FORBIDDEN_SYSTEM_ROOTS
    ):
        raise ConfigurationError(f"refusing to use system directory as {purpose}: {path}")
    return path


@dataclass(frozen=True)
class InvokingUser:
    name: str
    uid: int
    gid: int
    home: Path

    @classmethod
    def current(cls) -> "InvokingUser":
        sudo_user = os.environ.get("SUDO_USER")
        try:
            if os.geteuid() == 0 and sudo_user and sudo_user != "root":
                entry = pwd.getpwnam(sudo_user)
            else:
                entry = pwd.getpwuid(os.getuid())
        except KeyError as exc:
            account = sudo_user if sudo_user and sudo_user != "root" else str(os.getuid())
            raise ConfigurationError(f"invoking user does not exist: {account}") from exc
        return cls(entry.pw_name, entry.pw_uid, entry.pw_gid, Path(entry.pw_dir))


def managed_home(user: InvokingUser) -> Path:
    override = os.environ.get("WAZUHDEVENV_HOME")
    if override:
        path = Path(override).expanduser()
        path = path.resolve() if path.is_absolute() else (Path.cwd() / path).resolve()
        return _reject_system_path(path, "managed home")
    return user.home / ".wazuhdevenv"


def resolve_workspace(value: str | None) -> Path:
    path = Path(value or ".").expanduser().resolve()
    return _reject_system_path(path, "workspace")
