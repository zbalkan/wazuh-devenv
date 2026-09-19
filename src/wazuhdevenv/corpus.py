"""Discovery, verification, and atomic installation of rule-test corpora."""

from __future__ import annotations

import hashlib
import json
import os
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
from packaging.version import Version

from .errors import CorpusError
from .paths import InvokingUser
from .state import load_state, save_state

RELEASES_API = "https://api.github.com/repos/zbalkan/wazuh-rule-tests/releases?per_page=100"
USER_AGENT = "wazuh-devenv"


@dataclass(frozen=True)
class CorpusRelease:
    manifest: dict[str, object]
    manifest_url: str
    archive_url: str
    checksum_url: str

    @property
    def version(self) -> str:
        return str(self.manifest["corpus_version"])


def _request(url: str) -> bytes:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CorpusError(f"failed to download {url}: {exc}") from exc


def _release_key(value: str) -> tuple[int, int, int]:
    try:
        series, revision = value.split("-r", 1)
        major, minor = series.split(".", 1)
        return int(major), int(minor), int(revision)
    except (ValueError, AttributeError) as exc:
        raise CorpusError(f"invalid corpus version: {value}") from exc


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
        releases = json.loads(_request(RELEASES_API))
    except json.JSONDecodeError as exc:
        raise CorpusError("GitHub returned invalid release metadata") from exc
    if not isinstance(releases, list):
        raise CorpusError("unexpected GitHub release response")

    compatible: list[CorpusRelease] = []
    current = Version(wazuh_version)

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
        if not _matches_requirement(manifest, "wazuh", str(current)):
            continue
        if not _matches_requirement(manifest, "python", f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"):
            continue
        if not _matches_requirement(manifest, "wazuhtester", wazuhtester_version):
            continue

        version = str(manifest.get("corpus_version", ""))
        archive_url = _asset_url(release, f"wazuh-rule-tests-{version}.zip")
        checksum_url = _asset_url(release, f"wazuh-rule-tests-{version}.zip.sha256")
        if archive_url and checksum_url:
            compatible.append(CorpusRelease(manifest, manifest_url, archive_url, checksum_url))

    if not compatible:
        raise CorpusError(
            "no released rule-test corpus is compatible with "
            f"Wazuh {wazuh_version}, Python {sys.version_info.major}.{sys.version_info.minor}, "
            f"and wazuhtester {wazuhtester_version}"
        )
    return max(compatible, key=lambda item: _release_key(item.version))


def _verify_checksum(archive: Path, checksum_text: str) -> None:
    expected = checksum_text.strip().split()[0].lower()
    if len(expected) != 64 or any(ch not in "0123456789abcdef" for ch in expected):
        raise CorpusError("invalid SHA-256 checksum asset")
    actual = hashlib.sha256(archive.read_bytes()).hexdigest()
    if actual != expected:
        raise CorpusError(f"corpus checksum mismatch: expected {expected}, got {actual}")


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


def _write_owned_bytes(path: Path, content: bytes, user: InvokingUser) -> None:
    path.write_bytes(content)
    if os.geteuid() == 0 and user.uid != 0:
        os.chown(path, user.uid, user.gid)


def install_release(
    home: Path,
    release: CorpusRelease,
    wazuh_version: str,
    user: InvokingUser,
    wazuhtester_version: str,
) -> None:
    cache = home / "cache"
    staging_root = home / "staging"
    cache.mkdir(parents=True, exist_ok=True)
    staging_root.mkdir(parents=True, exist_ok=True)

    archive = cache / f"wazuh-rule-tests-{release.version}.zip"
    _write_owned_bytes(archive, _request(release.archive_url), user)
    _verify_checksum(archive, _request(release.checksum_url).decode("ascii", errors="strict"))

    staging = Path(tempfile.mkdtemp(prefix="corpus.", dir=staging_root))
    activated = False
    had_previous = False
    manifest_activated = False
    had_previous_manifest = False
    manifest_target = home / "corpus-manifest.json"
    previous_manifest = home / "corpus-manifest.previous.json"
    try:
        _safe_extract(archive, staging)
        embedded_path = staging / "manifest.json"
        tests_path = staging / "tests"
        if not embedded_path.is_file() or not tests_path.is_dir():
            raise CorpusError("corpus archive must contain manifest.json and tests/")
        embedded = json.loads(embedded_path.read_text(encoding="utf-8"))
        if embedded != release.manifest:
            raise CorpusError("standalone and embedded corpus manifests differ")

        active = home / "tests"
        previous = home / "tests.previous"
        if previous.exists():
            shutil.rmtree(previous)
        if active.exists():
            os.replace(active, previous)
            had_previous = True
        os.replace(tests_path, active)
        activated = True

        temporary_manifest = home / ".corpus-manifest.json.tmp"
        temporary_manifest.write_text(
            json.dumps(release.manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if previous_manifest.exists():
            previous_manifest.unlink()
        if manifest_target.exists():
            os.replace(manifest_target, previous_manifest)
            had_previous_manifest = True
        os.replace(temporary_manifest, manifest_target)
        manifest_activated = True

        if os.geteuid() == 0 and user.uid != 0:
            for root, directories, files in os.walk(active):
                os.chown(root, user.uid, user.gid)
                for name in directories:
                    os.chown(Path(root) / name, user.uid, user.gid)
                for name in files:
                    os.chown(Path(root) / name, user.uid, user.gid)
            os.chown(manifest_target, user.uid, user.gid)

        state = load_state(home)
        state.update(
            {
                "wazuh_version": wazuh_version,
                "active_corpus": release.version,
                "wazuhtester_version": wazuhtester_version,
                "corpus_installed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            }
        )
        save_state(home, state, user)

        if previous.exists():
            shutil.rmtree(previous)
        previous_manifest.unlink(missing_ok=True)
    except Exception:
        active = home / "tests"
        previous = home / "tests.previous"
        if activated and active.exists():
            shutil.rmtree(active)
        if had_previous and previous.exists():
            os.replace(previous, active)
        if manifest_activated and manifest_target.exists():
            manifest_target.unlink()
        if had_previous_manifest and previous_manifest.exists():
            os.replace(previous_manifest, manifest_target)
        raise
    finally:
        shutil.rmtree(staging, ignore_errors=True)


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
