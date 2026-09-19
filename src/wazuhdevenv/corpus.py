"""Discovery, verification, and atomic installation of rule-test corpora."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import shutil
import stat
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

from .errors import CorpusError
from .paths import InvokingUser
from .state import load_state, save_state

RELEASES_API = "https://api.github.com/repos/zbalkan/wazuh-rule-tests/releases?per_page=100"
USER_AGENT = "wazuh-devenv"
LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class CorpusRelease:
    manifest: dict[str, object]
    manifest_url: str
    archive_url: str
    checksum_url: str

    @property
    def version(self) -> str:
        return str(self.manifest["corpus_version"])


def _request(url: str, *, authenticated: bool = False) -> bytes:
    headers = {"User-Agent": USER_AGENT}
    if authenticated:
        if not url.startswith("https://api.github.com/"):
            raise CorpusError("authenticated downloads are restricted to api.github.com")
        headers["Accept"] = "application/vnd.github+json"
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CorpusError(f"failed to download {url}: {exc}") from exc


def _release_key(value: str) -> tuple[Version, int]:
    series, separator, revision = value.rpartition("-r")
    if not separator or not revision.isdigit():
        raise CorpusError(f"invalid corpus version: {value}")
    try:
        parsed = Version(series)
    except InvalidVersion as exc:
        raise CorpusError(f"invalid corpus version: {value}") from exc
    if parsed.is_prerelease or parsed.is_devrelease:
        raise CorpusError(f"invalid corpus version: {value}")
    return parsed, int(revision)


def _asset_url(release: dict[str, object], name: str) -> str | None:
    for asset in release.get("assets", []):
        if isinstance(asset, dict) and asset.get("name") == name:
            url = asset.get("browser_download_url")
            return str(url) if url else None
    return None


def _matches_requirement(manifest: dict[str, object], section: str, version: str) -> bool:
    value = manifest.get(section)
    if not isinstance(value, dict) or not value.get("requires"):
        return False
    try:
        return Version(version) in SpecifierSet(str(value["requires"]))
    except Exception:
        return False


def resolve_release(wazuh_version: str, wazuhtester_version: str) -> CorpusRelease:
    try:
        releases = json.loads(_request(RELEASES_API, authenticated=True))
    except json.JSONDecodeError as exc:
        raise CorpusError("GitHub returned invalid release metadata") from exc
    if not isinstance(releases, list):
        raise CorpusError("unexpected GitHub release response")

    compatible: list[tuple[tuple[Version, int], CorpusRelease]] = []
    current = Version(wazuh_version)
    mismatch_counts = {"wazuh": 0, "python": 0, "wazuhtester": 0, "version": 0}
    inspected_manifests = 0

    for release in releases:
        if not isinstance(release, dict) or release.get("draft") or release.get("prerelease"):
            continue
        manifest_url = _asset_url(release, "manifest.json")
        if not manifest_url:
            continue
        try:
            manifest = json.loads(_request(manifest_url))
        except (json.JSONDecodeError, CorpusError):
            continue
        if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
            continue
        inspected_manifests += 1
        if not _matches_requirement(manifest, "wazuh", str(current)):
            mismatch_counts["wazuh"] += 1
            continue
        if not _matches_requirement(
            manifest,
            "python",
            f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        ):
            mismatch_counts["python"] += 1
            continue
        if not _matches_requirement(manifest, "wazuhtester", wazuhtester_version):
            mismatch_counts["wazuhtester"] += 1
            continue

        version = str(manifest.get("corpus_version", ""))
        try:
            version_key = _release_key(version)
        except CorpusError:
            mismatch_counts["version"] += 1
            continue

        archive_url = _asset_url(release, f"wazuh-rule-tests-{version}.zip")
        checksum_url = _asset_url(release, f"wazuh-rule-tests-{version}.zip.sha256")
        if archive_url and checksum_url:
            compatible.append(
                (
                    version_key,
                    CorpusRelease(manifest, manifest_url, archive_url, checksum_url),
                )
            )

    if not compatible:
        detail = (
            f"inspected {inspected_manifests} manifests; "
            f"Wazuh mismatches={mismatch_counts['wazuh']}, "
            f"Python mismatches={mismatch_counts['python']}, "
            f"wazuhtester mismatches={mismatch_counts['wazuhtester']}, "
            f"invalid corpus versions={mismatch_counts['version']}"
        )
        raise CorpusError(
            "no released rule-test corpus is compatible with "
            f"Wazuh {wazuh_version}, Python {sys.version_info.major}.{sys.version_info.minor}, "
            f"and wazuhtester {wazuhtester_version}; {detail}"
        )
    return max(compatible, key=lambda item: item[0])[1]


def _verify_checksum(archive: Path, checksum_text: str) -> str:
    fields = checksum_text.strip().split()
    if not fields:
        raise CorpusError("invalid SHA-256 checksum asset")
    expected = fields[0].lower()
    if len(expected) != 64 or any(ch not in "0123456789abcdef" for ch in expected):
        raise CorpusError("invalid SHA-256 checksum asset")
    actual = hashlib.sha256(archive.read_bytes()).hexdigest()
    if actual != expected:
        raise CorpusError(f"corpus checksum mismatch: expected {expected}, got {actual}")
    return actual


def _validate_member(info: zipfile.ZipInfo) -> None:
    path = PurePosixPath(info.filename)
    if path.is_absolute() or ".." in path.parts:
        raise CorpusError(f"unsafe archive path: {info.filename}")
    mode = info.external_attr >> 16
    kind = stat.S_IFMT(mode)
    if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
        raise CorpusError(f"unsupported archive entry: {info.filename}")


def _safe_extract(archive: Path, destination: Path) -> None:
    with zipfile.ZipFile(archive) as source:
        seen: set[PurePosixPath] = set()
        for info in source.infolist():
            _validate_member(info)
            normalized = PurePosixPath(info.filename)
            if normalized in seen:
                raise CorpusError(f"duplicate archive destination: {info.filename}")
            seen.add(normalized)
        source.extractall(destination)


def _write_owned_temp(
    directory: Path,
    prefix: str,
    content: bytes,
    user: InvokingUser,
) -> Path:
    fd, name = tempfile.mkstemp(prefix=prefix, dir=directory)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
            if os.geteuid() == 0 and user.uid != 0:
                os.fchown(stream.fileno(), user.uid, user.gid)
        return temporary
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _write_owned_bytes(path: Path, content: bytes, user: InvokingUser) -> None:
    temporary = _write_owned_temp(path.parent, f".{path.name}.", content, user)
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_symlink(link: Path, target: str, user: InvokingUser) -> None:
    temporary = link.parent / f".{link.name}.{secrets.token_hex(16)}"
    try:
        os.symlink(target, temporary)
        if os.geteuid() == 0 and user.uid != 0:
            os.lchown(temporary, user.uid, user.gid)
        os.replace(temporary, link)
    finally:
        temporary.unlink(missing_ok=True)


def _remove_managed_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


def _corpus_tree_is_symlink_free(root: Path) -> bool:
    for current, directories, files in os.walk(root, followlinks=False):
        directory = Path(current)
        for name in (*directories, *files):
            if (directory / name).is_symlink():
                return False
    return True


def _current_corpus_is_managed(home: Path) -> bool:
    current = home / "current-corpus"
    if not current.is_symlink():
        return False
    try:
        target = current.resolve(strict=True)
        corpora = (home / "corpora").resolve(strict=True)
    except OSError:
        return False
    if target.parent != corpora:
        return False

    tests = target / "tests"
    manifest = target / "manifest.json"
    if tests.is_symlink() or manifest.is_symlink():
        return False
    if not tests.is_dir() or not manifest.is_file():
        return False
    return _corpus_tree_is_symlink_free(target)


def _validate_legacy_backup(path: Path, *, directory: bool) -> None:
    if path.is_symlink():
        raise CorpusError(f"legacy corpus backup must not be a symlink: {path}")
    valid = path.is_dir() if directory else path.is_file()
    if not valid:
        expected = "directory" if directory else "regular file"
        raise CorpusError(f"legacy corpus backup must be a {expected}: {path}")


def _recover_legacy_accessors(home: Path) -> None:
    current_valid = _current_corpus_is_managed(home)

    for accessor, legacy, expected_target, legacy_is_directory in (
        (home / "tests", home / "tests.legacy", "current-corpus/tests", True),
        (
            home / "corpus-manifest.json",
            home / "corpus-manifest.legacy.json",
            "current-corpus/manifest.json",
            False,
        ),
    ):
        if not os.path.lexists(legacy):
            continue

        if (
            current_valid
            and accessor.is_symlink()
            and os.readlink(accessor) == expected_target
        ):
            _remove_managed_path(legacy)
            continue

        _validate_legacy_backup(legacy, directory=legacy_is_directory)

        if os.path.lexists(accessor):
            if accessor.is_symlink():
                accessor.unlink()
            else:
                raise CorpusError(
                    "interrupted corpus migration left both active and backup content; "
                    f"inspect {accessor} and {legacy}, then remove the obsolete copy"
                )
        os.replace(legacy, accessor)


def _prepare_corpus_accessors(
    home: Path,
    user: InvokingUser,
) -> tuple[Path | None, Path | None]:
    tests = home / "tests"
    manifest = home / "corpus-manifest.json"
    legacy_tests = home / "tests.legacy"
    legacy_manifest = home / "corpus-manifest.legacy.json"

    old_tests_link = os.readlink(tests) if tests.is_symlink() else None
    old_manifest_link = os.readlink(manifest) if manifest.is_symlink() else None
    moved_tests: Path | None = None
    moved_manifest: Path | None = None

    try:
        if os.path.lexists(tests) and not tests.is_symlink():
            if legacy_tests.exists():
                raise CorpusError(f"legacy corpus backup already exists: {legacy_tests}")
            os.replace(tests, legacy_tests)
            moved_tests = legacy_tests

        if os.path.lexists(manifest) and not manifest.is_symlink():
            if legacy_manifest.exists():
                raise CorpusError(
                    f"legacy corpus manifest backup already exists: {legacy_manifest}"
                )
            os.replace(manifest, legacy_manifest)
            moved_manifest = legacy_manifest

        _atomic_symlink(tests, "current-corpus/tests", user)
        _atomic_symlink(manifest, "current-corpus/manifest.json", user)
        return moved_tests, moved_manifest
    except Exception:
        if old_tests_link is not None:
            _atomic_symlink(tests, old_tests_link, user)
        else:
            if tests.is_symlink():
                tests.unlink()
            if moved_tests is not None and moved_tests.exists():
                os.replace(moved_tests, tests)

        if old_manifest_link is not None:
            _atomic_symlink(manifest, old_manifest_link, user)
        else:
            if manifest.is_symlink():
                manifest.unlink()
            if moved_manifest is not None and moved_manifest.exists():
                os.replace(moved_manifest, manifest)
        raise


def _chown_corpus_tree(root: Path, user: InvokingUser) -> None:
    if os.geteuid() != 0 or user.uid == 0:
        return

    # The top-level directory is created by the current root process with mode
    # 0700. Keep it root-owned until every descendant has been processed so the
    # invoking user cannot race the ownership walk.
    for current, directories, files in os.walk(
        root,
        topdown=False,
        followlinks=False,
    ):
        directory = Path(current)
        for name in files:
            os.chown(
                directory / name,
                user.uid,
                user.gid,
                follow_symlinks=False,
            )
        for name in directories:
            os.chown(
                directory / name,
                user.uid,
                user.gid,
                follow_symlinks=False,
            )
        os.chown(
            directory,
            user.uid,
            user.gid,
            follow_symlinks=False,
        )


def install_release(
    home: Path,
    release: CorpusRelease,
    wazuh_version: str,
    user: InvokingUser,
    wazuhtester_version: str,
) -> None:
    cache = home / "cache"
    staging_root = home / "staging"
    corpora_root = home / "corpora"
    for directory in (cache, staging_root, corpora_root):
        if directory.is_symlink():
            raise CorpusError(f"managed corpus directory must not be a symlink: {directory}")
        directory.mkdir(parents=True, exist_ok=True)

    archive = cache / f"wazuh-rule-tests-{release.version}.zip"
    _write_owned_bytes(archive, _request(release.archive_url), user)
    digest = _verify_checksum(
        archive,
        _request(release.checksum_url).decode("ascii", errors="strict"),
    )

    # Never reuse an existing corpus tree. Once a completed tree is handed to
    # the invoking user it must be considered mutable and untrusted. A fresh
    # root-owned 0700 directory gives validation and ownership transfer an
    # attacker-inaccessible working tree.
    release_root = Path(
        tempfile.mkdtemp(
            prefix=f"{release.version}-{digest[:12]}.",
            dir=corpora_root,
        )
    )
    current_link = home / "current-corpus"
    old_current_target = (
        os.readlink(current_link) if current_link.is_symlink() else None
    )
    if os.path.lexists(current_link) and not current_link.is_symlink():
        shutil.rmtree(release_root, ignore_errors=True)
        raise CorpusError(f"current corpus pointer must be a symlink: {current_link}")

    moved_tests: Path | None = None
    moved_manifest: Path | None = None
    pointer_swapped = False
    try:
        _recover_legacy_accessors(home)
        _safe_extract(archive, release_root)
        embedded_path = release_root / "manifest.json"
        tests_path = release_root / "tests"
        if not embedded_path.is_file() or not tests_path.is_dir():
            raise CorpusError("corpus archive must contain manifest.json and tests/")
        embedded = json.loads(embedded_path.read_text(encoding="utf-8"))
        if embedded != release.manifest:
            raise CorpusError("standalone and embedded corpus manifests differ")

        _chown_corpus_tree(release_root, user)

        moved_tests, moved_manifest = _prepare_corpus_accessors(home, user)
        _atomic_symlink(
            current_link,
            os.path.relpath(release_root, home),
            user,
        )
        pointer_swapped = True

        state = load_state(home)
        state.update(
            {
                "wazuh_version": wazuh_version,
                "active_corpus": release.version,
                "wazuhtester_version": wazuhtester_version,
                "corpus_installed_at": datetime.now(timezone.utc)
                .replace(microsecond=0)
                .isoformat(),
            }
        )
        save_state(home, state, user)
    except Exception:
        if pointer_swapped:
            if old_current_target is None:
                current_link.unlink(missing_ok=True)
            else:
                _atomic_symlink(current_link, old_current_target, user)

        if old_current_target is None:
            for accessor in (home / "tests", home / "corpus-manifest.json"):
                if accessor.is_symlink():
                    accessor.unlink()
            if moved_tests is not None and moved_tests.exists():
                os.replace(moved_tests, home / "tests")
            if moved_manifest is not None and moved_manifest.exists():
                os.replace(moved_manifest, home / "corpus-manifest.json")

        shutil.rmtree(release_root, ignore_errors=True)
        raise
    else:
        for legacy in (moved_tests, moved_manifest):
            if legacy is None or not legacy.exists():
                continue
            try:
                if legacy.is_dir():
                    shutil.rmtree(legacy)
                else:
                    legacy.unlink()
            except OSError as exc:
                LOG.warning("Could not remove legacy corpus backup %s: %s", legacy, exc)

def update_corpus(
    home: Path,
    wazuh_version: str,
    wazuhtester_version: str,
    user: InvokingUser,
) -> str:
    release = resolve_release(wazuh_version, wazuhtester_version)
    state = load_state(home)
    if state.get("active_corpus") == release.version and (home / "tests").is_dir():
        return release.version
    install_release(home, release, wazuh_version, user, wazuhtester_version)
    return release.version
