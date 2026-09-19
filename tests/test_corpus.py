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
    assert _release_key("4.14.8-r2") > _release_key("4.14.8-r1")
    assert _release_key("4.15-r1") > _release_key("4.14.99-r99")


def test_manifest_requirement_matching() -> None:
    manifest = {
        "wazuh": {"requires": ">=4.14.7,<4.15.0"},
        "python": {"requires": ">=3.10"},
        "wazuhtester": {"requires": ">=0.1.0rc1,<0.2"},
    }
    assert _matches_requirement(manifest, "wazuh", "4.14.7")
    assert not _matches_requirement(manifest, "wazuh", "4.15.0")
    assert _matches_requirement(manifest, "wazuhtester", "0.1.0rc1")
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
        "wazuhtester": {"requires": ">=0.1.0rc1,<0.2"},
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





def _release_metadata(version: str, manifest_url: str) -> dict[str, object]:
    return {
        "draft": False,
        "prerelease": False,
        "assets": [
            {"name": "manifest.json", "browser_download_url": manifest_url},
            {
                "name": f"wazuh-rule-tests-{version}.zip",
                "browser_download_url": f"archive-{version}",
            },
            {
                "name": f"wazuh-rule-tests-{version}.zip.sha256",
                "browser_download_url": f"checksum-{version}",
            },
        ],
    }


def _manifest(version: str, *, tester: str = ">=0.1.0rc1,<0.2") -> dict[str, object]:
    return {
        "schema_version": 1,
        "corpus_version": version,
        "wazuh": {"requires": "==4.14.8"},
        "python": {"requires": ">=3.10"},
        "wazuhtester": {"requires": tester},
    }


def test_resolve_release_selects_highest_compatible_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    releases = [
        {**_release_metadata("4.14.8-r1", "manifest-r1"), "draft": True},
        {**_release_metadata("4.14.8-r2", "manifest-r2"), "prerelease": True},
        _release_metadata("4.14.8-r3", "manifest-r3"),
        _release_metadata("4.14.8-r4", "manifest-r4"),
        _release_metadata("unexpected", "manifest-bad"),
    ]
    manifests = {
        "manifest-r3": _manifest("4.14.8-r3"),
        "manifest-r4": _manifest("4.14.8-r4"),
        "manifest-bad": _manifest("unexpected"),
    }

    def request(url: str, *, authenticated: bool = False) -> bytes:
        del authenticated
        if url == corpus.RELEASES_API:
            return json.dumps(releases).encode()
        return json.dumps(manifests[url]).encode()

    monkeypatch.setattr(corpus, "_request", request)

    release = corpus.resolve_release("4.14.8", "0.1.0rc1")

    assert release.version == "4.14.8-r4"


def test_resolve_release_reports_requirement_mismatches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    releases = [_release_metadata("4.14.8-r1", "manifest-r1")]
    manifest = _manifest("4.14.8-r1", tester=">=0.1,<0.2")

    def request(url: str, *, authenticated: bool = False) -> bytes:
        del authenticated
        if url == corpus.RELEASES_API:
            return json.dumps(releases).encode()
        return json.dumps(manifest).encode()

    monkeypatch.setattr(corpus, "_request", request)

    with pytest.raises(CorpusError, match="wazuhtester mismatches=1"):
        corpus.resolve_release("4.14.8", "0.1.0rc1")


def test_checksum_mismatch_is_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "corpus.zip"
    archive.write_bytes(b"content")

    with pytest.raises(CorpusError, match="corpus checksum mismatch"):
        corpus._verify_checksum(archive, "0" * 64)


def _build_archive(tmp_path: Path, manifest: dict[str, object], payload: str) -> bytes:
    path = tmp_path / f"{manifest['corpus_version']}.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        archive.writestr("tests/test_payload.py", payload)
    return path.read_bytes()


def test_corpus_activation_uses_single_atomic_current_pointer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    for name in ("cache", "staging", "corpora"):
        (home / name).mkdir(parents=True, exist_ok=True)
    user = InvokingUser("test", os.getuid(), os.getgid(), tmp_path)

    first_manifest = _manifest("4.14.8-r1")
    second_manifest = _manifest("4.14.8-r2")
    first_bytes = _build_archive(tmp_path, first_manifest, "first\n")
    second_bytes = _build_archive(tmp_path, second_manifest, "second\n")
    payloads = {
        "archive-r1": first_bytes,
        "checksum-r1": hashlib.sha256(first_bytes).hexdigest().encode(),
        "archive-r2": second_bytes,
        "checksum-r2": hashlib.sha256(second_bytes).hexdigest().encode(),
    }
    monkeypatch.setattr(corpus, "_request", lambda url, **kwargs: payloads[url])

    first = CorpusRelease(first_manifest, "manifest-r1", "archive-r1", "checksum-r1")
    second = CorpusRelease(second_manifest, "manifest-r2", "archive-r2", "checksum-r2")

    corpus.install_release(home, first, "4.14.8", user, "0.1.0rc1")
    first_target = os.readlink(home / "current-corpus")
    assert (home / "tests").is_symlink()
    assert (home / "corpus-manifest.json").is_symlink()
    assert (home / "tests/test_payload.py").read_text() == "first\n"

    corpus.install_release(home, second, "4.14.8", user, "0.1.0rc1")
    second_target = os.readlink(home / "current-corpus")

    assert second_target != first_target
    assert (home / "tests/test_payload.py").read_text() == "second\n"
    assert json.loads((home / "corpus-manifest.json").read_text())["corpus_version"] == "4.14.8-r2"


def test_update_corpus_skips_install_for_active_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    target = tmp_path / "active-tests"
    target.mkdir()
    (home / "tests").symlink_to(target, target_is_directory=True)
    (home / "state.json").write_text(
        json.dumps({"schema_version": 1, "active_corpus": "4.14.8-r2"}) + "\n",
        encoding="utf-8",
    )
    release = CorpusRelease(_manifest("4.14.8-r2"), "manifest", "archive", "checksum")
    monkeypatch.setattr(corpus, "resolve_release", lambda *args: release)
    monkeypatch.setattr(
        corpus,
        "install_release",
        lambda *args: (_ for _ in ()).throw(AssertionError("must not install")),
    )

    assert corpus.update_corpus(
        home,
        "4.14.8",
        "0.1.0rc1",
        InvokingUser("test", os.getuid(), os.getgid(), tmp_path),
    ) == "4.14.8-r2"



def test_reinstall_never_reuses_user_writable_corpus_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    for name in ("cache", "staging", "corpora"):
        (home / name).mkdir(parents=True, exist_ok=True)

    manifest = _manifest("4.14.8-r2")
    archive_bytes = _build_archive(tmp_path, manifest, "verified\n")
    payloads = {
        "archive": archive_bytes,
        "checksum": hashlib.sha256(archive_bytes).hexdigest().encode(),
    }
    monkeypatch.setattr(corpus, "_request", lambda url, **kwargs: payloads[url])

    # Simulate a previously user-writable release tree containing a malicious
    # descendant symlink. Reinstallation must leave it entirely untouched.
    tainted = home / "corpora/4.14.8-r2-tainted"
    (tainted / "tests").mkdir(parents=True)
    victim = tmp_path / "root-owned-target"
    victim.write_text("unchanged\n", encoding="utf-8")
    (tainted / "tests/escape").symlink_to(victim)

    chowned: list[Path] = []
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "fchown", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        os,
        "chown",
        lambda path, uid, gid, **kwargs: chowned.append(Path(path)),
    )
    monkeypatch.setattr(os, "lchown", lambda *args, **kwargs: None)

    release = CorpusRelease(manifest, "manifest", "archive", "checksum")
    user = InvokingUser("test", 1234, 5678, tmp_path)

    corpus.install_release(home, release, "4.14.8", user, "0.1.0rc1")

    active = (home / "current-corpus").resolve()
    assert active != tainted
    assert active.parent == home / "corpora"
    assert victim.read_text(encoding="utf-8") == "unchanged\n"
    assert all(tainted not in path.parents and path != tainted for path in chowned)


def test_chown_corpus_tree_never_follows_symlinks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "release"
    tests = root / "tests"
    tests.mkdir(parents=True)
    victim = tmp_path / "victim"
    victim.write_text("unchanged\n", encoding="utf-8")
    link = tests / "escape"
    link.symlink_to(victim)

    calls: list[tuple[Path, bool | None]] = []
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    def fake_chown(
        path: object,
        uid: int,
        gid: int,
        *,
        follow_symlinks: bool = True,
    ) -> None:
        del uid, gid
        calls.append((Path(path), follow_symlinks))

    monkeypatch.setattr(os, "chown", fake_chown)

    corpus._chown_corpus_tree(
        root,
        InvokingUser("test", 1234, 5678, tmp_path),
    )

    link_calls = [follow for path, follow in calls if path == link]
    assert link_calls == [False]
    assert victim.read_text(encoding="utf-8") == "unchanged\n"



def test_recover_legacy_accessors_restores_interrupted_migration(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    legacy_tests = home / "tests.legacy"
    legacy_tests.mkdir()
    (legacy_tests / "old.py").write_text("old\n", encoding="utf-8")
    (home / "corpus-manifest.legacy.json").write_text(
        '{"schema_version": 1, "corpus_version": "4.14.8-r1"}\n',
        encoding="utf-8",
    )

    corpus._recover_legacy_accessors(home)

    assert (home / "tests/old.py").read_text(encoding="utf-8") == "old\n"
    assert (home / "corpus-manifest.json").is_file()
    assert not legacy_tests.exists()
    assert not (home / "corpus-manifest.legacy.json").exists()


def test_recover_legacy_accessors_cleans_stale_backups_after_committed_migration(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    release = home / "corpora/release"
    (release / "tests").mkdir(parents=True)
    (release / "manifest.json").write_text(
        '{"schema_version": 1, "corpus_version": "4.14.8-r2"}\n',
        encoding="utf-8",
    )
    (home / "current-corpus").symlink_to("corpora/release")
    (home / "tests").symlink_to("current-corpus/tests")
    (home / "corpus-manifest.json").symlink_to("current-corpus/manifest.json")
    (home / "tests.legacy").mkdir()
    (home / "corpus-manifest.legacy.json").write_text("{}\n", encoding="utf-8")

    corpus._recover_legacy_accessors(home)

    assert not (home / "tests.legacy").exists()
    assert not (home / "corpus-manifest.legacy.json").exists()
    assert (home / "tests").is_symlink()
    assert (home / "corpus-manifest.json").is_symlink()


def test_recover_legacy_accessors_reports_ambiguous_plain_content(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    (home / "tests").mkdir(parents=True)
    (home / "tests.legacy").mkdir()

    with pytest.raises(CorpusError, match="inspect .* then remove the obsolete copy"):
        corpus._recover_legacy_accessors(home)
