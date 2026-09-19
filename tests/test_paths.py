from pathlib import Path

import pytest

from wazuhdevenv.errors import ConfigurationError
import os
import pwd

import wazuhdevenv.paths as paths
from wazuhdevenv.paths import InvokingUser, managed_home, resolve_workspace


def test_workspace_is_resolved(tmp_path: Path) -> None:
    assert resolve_workspace(str(tmp_path)) == tmp_path.resolve()


@pytest.mark.parametrize(
    "path",
    ["/", "/etc", "/etc/wazuh-project", "/var/tmp/project", "/usr/local/project", "/opt/project"],
)
def test_sensitive_system_workspaces_are_rejected(path: str) -> None:
    with pytest.raises(ConfigurationError):
        resolve_workspace(path)



def test_workspace_default_and_relative_paths_are_resolved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    assert resolve_workspace(None) == tmp_path
    assert resolve_workspace("project") == tmp_path / "project"


def test_workspace_expands_home(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    assert resolve_workspace("~/project") == tmp_path / "project"


@pytest.mark.parametrize("override", ["/", "/etc/wazuhdevenv", "/var/lib/wazuhdevenv"])
def test_managed_home_rejects_sensitive_system_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    override: str,
) -> None:
    monkeypatch.setenv("WAZUHDEVENV_HOME", override)
    user = InvokingUser("test", 1000, 1000, tmp_path)

    with pytest.raises(ConfigurationError):
        managed_home(user)


def test_unknown_sudo_user_is_reported_as_configuration_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "definitely-missing-user")
    monkeypatch.setattr(
        pwd,
        "getpwnam",
        lambda name: (_ for _ in ()).throw(KeyError(name)),
    )

    with pytest.raises(ConfigurationError, match="invoking user does not exist"):
        paths.InvokingUser.current()
