from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from wazuhdevenv.errors import CommandError
from wazuhdevenv.paths import InvokingUser
from wazuhdevenv.runner import CommandRunner


def _user(tmp_path: Path) -> InvokingUser:
    return InvokingUser("test", 1000, 1000, tmp_path)


def test_privileged_absolute_executable_does_not_require_caller_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        shutil,
        "which",
        lambda executable, path=None: "/usr/bin/sudo" if executable == "sudo" else None,
    )

    runner = CommandRunner(_user(tmp_path))

    assert runner.command(
        ["/var/ossec/bin/wazuh-analysisd", "-t"],
        privileged=True,
    ) == [
        "/usr/bin/sudo",
        "--",
        "/var/ossec/bin/wazuh-analysisd",
        "-t",
    ]


def test_unprivileged_absolute_executable_still_requires_caller_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(shutil, "which", lambda executable, path=None: None)
    runner = CommandRunner(_user(tmp_path))

    with pytest.raises(CommandError, match="required command not found"):
        runner.command(["/var/ossec/bin/wazuh-analysisd", "-t"])



def test_privileged_relative_command_ignores_caller_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 1000)

    def fake_which(executable: str, path: str | None = None) -> str | None:
        if path is None:
            return f"/tmp/attacker/{executable}"
        if executable == "sudo":
            return "/usr/bin/sudo"
        if executable == "cat":
            return "/usr/bin/cat"
        return None

    monkeypatch.setattr(shutil, "which", fake_which)
    runner = CommandRunner(_user(tmp_path))

    assert runner.command(["cat", "/etc/fstab"], privileged=True) == [
        "/usr/bin/sudo",
        "--",
        "/usr/bin/cat",
        "/etc/fstab",
    ]


def test_root_capture_as_user_runs_workspace_python_as_invoking_user(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        shutil,
        "which",
        lambda executable, path=None: "/usr/bin/sudo" if executable == "sudo" else None,
    )
    commands: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> object:
        commands.append(command)
        return type("Result", (), {"returncode": 0, "stdout": "0.1.0rc1\n", "stderr": ""})()

    monkeypatch.setattr("wazuhdevenv.runner.subprocess.run", fake_run)
    runner = CommandRunner(_user(tmp_path))
    python = tmp_path / "workspace/.venv/bin/python"

    assert runner.capture_as_user([str(python), "-c", "print('x')"]) == "0.1.0rc1\n"
    assert commands == [[
        "/usr/bin/sudo",
        "-u",
        "test",
        "-H",
        "--",
        str(python),
        "-c",
        "print('x')",
    ]]



@pytest.mark.parametrize("executable", ["./tool", "../tool", "subdir/tool"])
def test_privileged_relative_command_with_path_component_is_rejected(
    tmp_path: Path,
    executable: str,
) -> None:
    runner = CommandRunner(_user(tmp_path))

    with pytest.raises(CommandError, match="absolute path or bare command name"):
        runner.command([executable], privileged=True)
