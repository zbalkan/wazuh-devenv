from __future__ import annotations

import argparse
import json
from contextlib import contextmanager
from pathlib import Path

import pytest

import wazuhdevenv.cli as cli
from wazuhdevenv.corpus import CorpusRelease
from wazuhdevenv.paths import InvokingUser


def _user(tmp_path: Path) -> InvokingUser:
    return InvokingUser("test", 1000, 1000, tmp_path)


@pytest.mark.parametrize("check", [False, True])
def test_update_command_uses_managed_lock_with_home_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    check: bool,
) -> None:
    user = _user(tmp_path)
    home = tmp_path / "managed"
    home.mkdir()
    lock_calls: list[Path] = []

    @contextmanager
    def fake_lock(path: Path):
        lock_calls.append(path)
        yield

    release = CorpusRelease(
        manifest={
            "schema_version": 1,
            "corpus_version": "4.14.8-r1",
            "wazuh": {"requires": "==4.14.8"},
        },
        manifest_url="manifest",
        archive_url="archive",
        checksum_url="checksum",
    )
    resolve_calls: list[tuple[str, str]] = []
    update_calls: list[tuple[Path, str, str]] = []

    monkeypatch.setattr(cli, "managed_lock", fake_lock)
    monkeypatch.setattr(cli, "_installed_wazuh_version", lambda *args: "4.14.8")
    monkeypatch.setattr(cli, "_workspace_wazuhtester_version", lambda *args: "0.1.0rc1")
    monkeypatch.setattr(
        cli,
        "resolve_release",
        lambda version, tester: resolve_calls.append((version, tester)) or release,
    )
    monkeypatch.setattr(
        cli,
        "update_corpus",
        lambda path, version, tester: (
            update_calls.append((path, version, tester)) or "4.14.8-r1"
        ),
    )

    assert cli._update_command(argparse.Namespace(check=check), user, home) == 0
    assert lock_calls == [home]
    if check:
        assert resolve_calls == [("4.14.8", "0.1.0rc1")]
        assert update_calls == []
    else:
        assert resolve_calls == []
        assert update_calls == [(home, "4.14.8", "0.1.0rc1")]



def test_configure_logging_refuses_symlinked_log_file(tmp_path: Path) -> None:
    home = tmp_path / "managed"
    logs = home / "logs"
    logs.mkdir(parents=True)
    victim = tmp_path / "victim.log"
    victim.write_text("unchanged\n", encoding="utf-8")
    (logs / "wazuhdevenv.log").symlink_to(victim)

    with pytest.raises(cli.ConfigurationError, match="log file must not be a symlink"):
        cli._configure_logging(home, False)

    assert victim.read_text(encoding="utf-8") == "unchanged\n"



def test_workspace_wazuhtester_probe_uses_invoking_user_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    python = workspace / ".venv/bin/python"
    python.parent.mkdir(parents=True)
    python.touch()
    home = tmp_path / "managed"
    home.mkdir()
    (home / "state.json").write_text(
        json.dumps({"schema_version": 1, "workspace": str(workspace)}) + "\n",
        encoding="utf-8",
    )
    calls: list[list[str]] = []
    users: list[InvokingUser] = []
    invoking_user = _user(tmp_path)

    class FakeRunner:
        def __init__(self, user: InvokingUser) -> None:
            users.append(user)

        def capture_as_user(self, args: list[str]) -> str:
            calls.append(args)
            return "0.1.0rc1\n"

    monkeypatch.setattr(cli, "CommandRunner", FakeRunner)

    assert cli._workspace_wazuhtester_version(invoking_user, home) == "0.1.0rc1"
    assert users == [invoking_user]
    assert calls and calls[0][0] == str(python)



def test_init_propagates_corpus_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = _user(tmp_path)
    home = tmp_path / "managed"
    home.mkdir()

    @contextmanager
    def fake_lock(path: Path):
        assert path == home
        yield

    monkeypatch.setattr(cli, "managed_lock", fake_lock)
    monkeypatch.setattr(cli, "resolve_workspace", lambda value: tmp_path / "workspace")
    monkeypatch.setattr(cli, "initialize", lambda *args, **kwargs: "4.14.8")
    monkeypatch.setattr(cli, "_workspace_wazuhtester_version", lambda *args: "0.1.0rc1")

    def fail_corpus(*args: object, **kwargs: object) -> str:
        raise cli.CorpusError("release unavailable")

    monkeypatch.setattr(cli, "update_corpus", fail_corpus)

    with pytest.raises(
        cli.CorpusError,
        match=r"initialization completed.*release unavailable.*Do not run.*update",
    ):
        cli._init_command(
            argparse.Namespace(path=None, wazuh_version=None, skip_corpus=False),
            user,
            home,
        )


def test_main_rejects_direct_root_invocation(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)

    assert cli.main(["update"]) == 1
    assert "run wazuhdevenv as the developer, not as root" in capsys.readouterr().err
