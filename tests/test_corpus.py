from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import warnings
import zipfile
from pathlib import Path

import pytest

import wazuhdevenv.corpus as corpus
from wazuhdevenv.corpus import CorpusRelease, _matches_requirement, _release_key, _safe_extract, _validate_member
from wazuhdevenv.errors import CorpusError
from wazuhdevenv.paths import InvokingUser


def test_release_key_orders_corpus_revisions() -> None:
    assert _release_key("4.14-r2") > _release_key("4.14-r1")
    assert _release_key("4.15-r1") > _release_key("4.14-r99")


def test_manifest_requirement_matching() -> None:
    manifest = {
        "wazuh": {"requires": ">=4.14.7,<4.15.0"},
        "python": {"requires": ">=3.10"},
        "wazuhtester": {"requires": ">=0.1,<0.2"},
    }
    assert _matches_requirement(manifest, "wazuh", "4.14.7")
    assert not _matches_requirement(manifest, "wazuh", "4.15.0")
    assert _matches_requirement(manifest, "wazuhtester", "0.1.0")
    assert not _matches_requirement(manifest, "wazuhtester", "0.2.0")


@pytest.mark.parametrize("name", ["/etc/passwd", "../escape", "tests/../../escape"])
def test_archive_paths_cannot_escape_root(name: str) -> None:
    info = zipfile.ZipInfo(name)
    with pytest.raises(CorpusError):
        _validate_member(info)


def test_symlink_archive_member_is_rejected() -> None:
    info = zipfile.ZipInfo("tests/link")
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with pytest.raises(CorpusError):
        _validate_member(info)


def test_regular_archive_member_is_allowed() -> None:
    info = zipfile.ZipInfo("tests/test_example.py")
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    _validate_member(info)


def test_duplicate_archive_destinations_are_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "duplicate.zip"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(archive, "w") as target:
            target.writestr("tests/test_example.py", "first")
            target.writestr("tests/test_example.py", "second")

    with pytest.raises(CorpusError, match="duplicate archive destination"):
        _safe_extract(archive, tmp_path / "out")


def test_failed_state_write_rolls_back_tests_and_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    active = home / "tests"
    active.mkdir()
    (active / "old.py").write_text("old\n", encoding="utf-8")

    old_manifest = {"schema_version": 1, "corpus_version": "4.14-r0"}
    manifest_target = home / "corpus-manifest.json"
    manifest_target.write_text(json.dumps(old_manifest), encoding="utf-8")

    new_manifest = {
        "schema_version": 1,
        "corpus_version": "4.14-r1",
        "wazuh": {"requires": ">=4.14.7,<4.15.0"},
        "python": {"requires": ">=3.10"},
        "wazuhtester": {"requires": ">=0.1,<0.2"},
    }
    archive_path = tmp_path / "corpus.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("manifest.json", json.dumps(new_manifest))
        archive.writestr("tests/new.py", "new\n")

    archive_bytes = archive_path.read_bytes()
    checksum = hashlib.sha256(archive_bytes).hexdigest().encode("ascii")
    payloads = {
        "archive": archive_bytes,
        "checksum": checksum + b"  corpus.zip\n",
    }
    monkeypatch.setattr(corpus, "_request", lambda url: payloads[url])

    def fail_state_write(*args: object, **kwargs: object) -> None:
        raise RuntimeError("simulated state write failure")

    monkeypatch.setattr(corpus, "save_state", fail_state_write)

    release = CorpusRelease(
        manifest=new_manifest,
        manifest_url="manifest",
        archive_url="archive",
        checksum_url="checksum",
    )
    user = InvokingUser("test", os.getuid(), os.getgid(), tmp_path)

    with pytest.raises(RuntimeError, match="simulated state write failure"):
        corpus.install_release(home, release, "4.14.7", user, "0.1.0")

    assert (home / "tests/old.py").read_text(encoding="utf-8") == "old\n"
    assert not (home / "tests/new.py").exists()
    assert json.loads(manifest_target.read_text(encoding="utf-8")) == old_manifest
    assert not (home / "corpus-manifest.previous.json").exists()



def test_cache_archive_written_by_root_is_chowned_to_invoking_user(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "cache.zip"
    user = InvokingUser("test", 1234, 5678, tmp_path)
    calls: list[tuple[int, int, int]] = []

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        os,
        "fchown",
        lambda fd, uid, gid: calls.append((fd, uid, gid)),
    )

    corpus._write_owned_bytes(target, b"archive", user)

    assert target.read_bytes() == b"archive"
    assert calls
    assert calls[0][1:] == (1234, 5678)



def test_empty_checksum_asset_raises_corpus_error(tmp_path: Path) -> None:
    archive = tmp_path / "corpus.zip"
    archive.write_bytes(b"content")

    with pytest.raises(CorpusError, match="invalid SHA-256 checksum asset"):
        corpus._verify_checksum(archive, "")


class FakeResponse:
    def __init__(self, content: bytes = b"{}") -> None:
        self.content = content

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return self.content


def test_public_asset_request_does_not_send_github_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[object] = []
    monkeypatch.setenv("GITHUB_TOKEN", "secret-token")

    def fake_urlopen(request: object, timeout: int) -> FakeResponse:
        del timeout
        requests.append(request)
        return FakeResponse(b"asset")

    monkeypatch.setattr(corpus.urllib.request, "urlopen", fake_urlopen)

    assert corpus._request("https://github.com/owner/repo/releases/download/v1/file.zip") == b"asset"
    request = requests[0]
    assert isinstance(request, corpus.urllib.request.Request)
    assert request.get_header("Authorization") is None


def test_authenticated_api_request_sends_github_token_only_to_api_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[object] = []
    monkeypatch.setenv("GITHUB_TOKEN", "secret-token")

    def fake_urlopen(request: object, timeout: int) -> FakeResponse:
        del timeout
        requests.append(request)
        return FakeResponse(b"[]")

    monkeypatch.setattr(corpus.urllib.request, "urlopen", fake_urlopen)

    assert corpus._request(
        "https://api.github.com/repos/owner/repo/releases",
        authenticated=True,
    ) == b"[]"
    request = requests[0]
    assert isinstance(request, corpus.urllib.request.Request)
    assert request.get_header("Authorization") == "Bearer secret-token"

    with pytest.raises(CorpusError, match="restricted to api.github.com"):
        corpus._request(
            "https://github.com/owner/repo/releases/download/v1/file.zip",
            authenticated=True,
        )



def test_atomic_owned_write_replaces_symlink_without_following_it(
    tmp_path: Path,
) -> None:
    victim = tmp_path / "victim"
    victim.write_bytes(b"unchanged")
    target = tmp_path / "archive.zip"
    target.symlink_to(victim)

    user = InvokingUser("test", os.getuid(), os.getgid(), tmp_path)
    corpus._write_owned_bytes(target, b"new archive", user)

    assert victim.read_bytes() == b"unchanged"
    assert not target.is_symlink()
    assert target.read_bytes() == b"new archive"


def test_post_commit_backup_cleanup_failure_keeps_new_state_and_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / "cache").mkdir()
    (home / "staging").mkdir()
    active = home / "tests"
    active.mkdir()
    (active / "old.py").write_text("old\n", encoding="utf-8")
    (home / "state.json").write_text(
        json.dumps({"schema_version": 1, "active_corpus": "4.14-r0"}) + "\n",
        encoding="utf-8",
    )

    manifest = {
        "schema_version": 1,
        "corpus_version": "4.14-r1",
        "wazuh": {"requires": "==4.14.8"},
        "python": {"requires": ">=3.10"},
        "wazuhtester": {"requires": ">=0.1.0rc1,<0.2"},
    }
    archive_path = tmp_path / "corpus.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        archive.writestr("tests/new.py", "new\n")
    archive_bytes = archive_path.read_bytes()
    checksum = hashlib.sha256(archive_bytes).hexdigest().encode("ascii")
    payloads = {
        "archive": archive_bytes,
        "checksum": checksum + b"  corpus.zip\n",
    }
    monkeypatch.setattr(corpus, "_request", lambda url, **kwargs: payloads[url])

    previous = home / "tests.previous"
    real_rmtree = shutil.rmtree

    def fail_backup_cleanup(path: object, *args: object, **kwargs: object) -> None:
        if Path(path) == previous and previous.exists() and not kwargs.get("ignore_errors"):
            raise OSError("simulated cleanup failure")
        real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(shutil, "rmtree", fail_backup_cleanup)

    release = CorpusRelease(
        manifest=manifest,
        manifest_url="manifest",
        archive_url="archive",
        checksum_url="checksum",
    )
    user = InvokingUser("test", os.getuid(), os.getgid(), tmp_path)

    corpus.install_release(home, release, "4.14.8", user, "0.1.0rc1")

    state = json.loads((home / "state.json").read_text(encoding="utf-8"))
    assert state["active_corpus"] == "4.14-r1"
    assert (home / "tests/new.py").read_text(encoding="utf-8") == "new\n"
    assert previous.exists()
    assert (previous / "old.py").read_text(encoding="utf-8") == "old\n"
