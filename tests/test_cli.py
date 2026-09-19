from __future__ import annotations

import argparse
from contextlib import contextmanager
from pathlib import Path

import pytest

import wazuhdevenv.cli as cli
from wazuhdevenv.corpus import CorpusRelease
from wazuhdevenv.paths import InvokingUser


def _user(tmp_path: Path) -> InvokingUser:
    return InvokingUser("test", 1000, 1000, tmp_path)


@pytest.mark.parametrize("check", [False, True])
def test_update_command_passes_invoking_user_to_managed_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    check: bool,
) -> None:
    user = _user(tmp_path)
    home = tmp_path / "managed"
    home.mkdir()
    lock_calls: list[tuple[Path, InvokingUser]] = []

    @contextmanager
    def fake_lock(path: Path, owner: InvokingUser):
        lock_calls.append((path, owner))
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
    update_calls: list[tuple[Path, str, str, InvokingUser]] = []

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
        lambda path, version, tester, owner: (
            update_calls.append((path, version, tester, owner)) or "4.14.8-r1"
        ),
    )

    assert cli._update_command(argparse.Namespace(check=check), user, home) == 0
    assert lock_calls == [(home, user)]
    if check:
        assert resolve_calls == [("4.14.8", "0.1.0rc1")]
        assert update_calls == []
    else:
        assert resolve_calls == []
        assert update_calls == [(home, "4.14.8", "0.1.0rc1", user)]



def test_configure_logging_refuses_symlinked_log_file(tmp_path: Path) -> None:
    home = tmp_path / "managed"
    logs = home / "logs"
    logs.mkdir(parents=True)
    victim = tmp_path / "victim.log"
    victim.write_text("unchanged\n", encoding="utf-8")
    (logs / "wazuhdevenv.log").symlink_to(victim)

    with pytest.raises(cli.ConfigurationError, match="log file must not be a symlink"):
        cli._configure_logging(home, _user(tmp_path), False)

    assert victim.read_text(encoding="utf-8") == "unchanged\n"
