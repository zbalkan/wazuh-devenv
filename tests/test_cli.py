from __future__ import annotations

import argparse
import json
from contextlib import contextmanager
from pathlib import Path

import pytest

import wazuhdevenv.cli as cli
from wazuhdevenv.corpus import CorpusRelease
from wazuhdevenv.paths import InvokingUser
from wazuhdevenv.uninstall import UninstallResult


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



def test_init_help_does_not_advertise_reconciliation() -> None:
    help_text = cli._parser().format_help()

    assert "Provision a development workspace" in help_text
    assert "reconcile" not in help_text


def test_missing_workspace_venv_does_not_recommend_init(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    home = tmp_path / "managed"
    home.mkdir()
    (home / "state.json").write_text(
        json.dumps({"schema_version": 1, "workspace": str(workspace)}) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(cli.WazuhDevenvError) as exc_info:
        cli._workspace_wazuhtester_version(_user(tmp_path), home)

    message = str(exc_info.value)
    assert "virtual environment is missing" in message
    assert "wazuhdevenv update" in message
    assert "wazuhdevenv init" not in message


def test_missing_wazuhtester_does_not_recommend_init(
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

    class FakeRunner:
        def __init__(self, user: InvokingUser) -> None:
            del user

        def capture_as_user(self, args: list[str]) -> str:
            del args
            raise cli.WazuhDevenvError("missing package")

    monkeypatch.setattr(cli, "CommandRunner", FakeRunner)

    with pytest.raises(cli.WazuhDevenvError) as exc_info:
        cli._workspace_wazuhtester_version(_user(tmp_path), home)

    message = str(exc_info.value)
    assert "wazuhtester is not installed" in message
    assert "wazuhdevenv update" in message
    assert "wazuhdevenv init" not in message


def test_missing_wazuh_manager_does_not_recommend_init(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "managed"
    home.mkdir()
    (home / "state.json").write_text(
        json.dumps({"schema_version": 1, "wazuh_version": "4.14.8"}) + "\n",
        encoding="utf-8",
    )

    class FakePackageManager:
        def __init__(self, runner: object) -> None:
            del runner

        def installed_version(self) -> None:
            return None

    monkeypatch.setattr(cli, "PackageManager", FakePackageManager)

    with pytest.raises(cli.WazuhDevenvError) as exc_info:
        cli._installed_wazuh_version(_user(tmp_path), home)

    message = str(exc_info.value)
    assert "Wazuh Manager is not installed" in message
    assert "wazuhdevenv update" in message
    assert "wazuhdevenv init" not in message


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


def test_coverage_command_uses_initialized_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace = tmp_path / "workspace"
    home = tmp_path / "managed"
    home.mkdir()
    (home / "state.json").write_text(
        json.dumps({"schema_version": 1, "workspace": str(workspace)}) + "\n",
        encoding="utf-8",
    )

    sentinel = object()
    monkeypatch.setattr(cli, "analyze_workspace", lambda path: sentinel if path == workspace else None)
    monkeypatch.setattr(cli, "format_report", lambda result: "coverage report" if result is sentinel else "wrong")

    assert cli._coverage_command(home) == 0
    assert capsys.readouterr().out == "coverage report\n"


def test_coverage_command_requires_initialized_workspace(tmp_path: Path) -> None:
    home = tmp_path / "managed"
    home.mkdir()

    with pytest.raises(cli.WazuhDevenvError, match="workspace is not initialized"):
        cli._coverage_command(home)



def test_uninstall_command_uses_lock_removes_state_and_reports_remnants(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    user = _user(tmp_path)
    home = tmp_path / "managed"
    home.mkdir()
    workspace = tmp_path / "workspace"
    lock_calls: list[Path] = []
    removed: list[Path] = []
    lock_active = False

    @contextmanager
    def fake_lock(path: Path):
        nonlocal lock_active
        lock_calls.append(path)
        lock_active = True
        try:
            yield
        finally:
            lock_active = False

    monkeypatch.setattr(cli, "managed_lock", fake_lock)
    result = UninstallResult(
        workspace=workspace,
        removed=("bind mount: /var/ossec/etc/rules",),
        restored=(),
        preserved=(f"user workspace content: {workspace / 'rules'}",),
        remnants=("wazuhdevenv CLI remains installed",),
    )
    monkeypatch.setattr(
        cli,
        "uninstall_environment",
        lambda path, invoking_user: (
            result
            if path == home and invoking_user == user
            else None
        ),
    )

    def remove_state(path: Path) -> None:
        assert lock_active is True
        removed.append(path)

    monkeypatch.setattr(cli.shutil, "rmtree", remove_state)

    assert cli._uninstall_command(user, home) == 0
    assert lock_calls == [home]
    assert removed == [home]

    output = capsys.readouterr().out
    assert "Uninstall complete." in output
    assert "Removed:" in output
    assert "Preserved:" in output
    assert "Remnants:" in output
    assert f"managed state: {home}" in output
    assert "wazuhdevenv CLI remains installed" in output


def test_parser_exposes_uninstall_command() -> None:
    args = cli._parser().parse_args(["uninstall"])

    assert args.command == "uninstall"
