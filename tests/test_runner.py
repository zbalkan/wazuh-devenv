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
        lambda executable: "/usr/bin/sudo" if executable == "sudo" else None,
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
    monkeypatch.setattr(shutil, "which", lambda executable: None)
    runner = CommandRunner(_user(tmp_path))

    with pytest.raises(CommandError, match="required command not found"):
        runner.command(["/var/ossec/bin/wazuh-analysisd", "-t"])
