"""Idempotent provisioning for a Wazuh development workspace."""

from __future__ import annotations

import logging
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .errors import CommandError, ConfigurationError, UnsupportedPlatformError
from .paths import InvokingUser
from .runner import CommandRunner
from .state import load_state, save_state

LOG = logging.getLogger(__name__)

WAZUH_HOME = Path("/var/ossec")
OSSEC_CONF = WAZUH_HOME / "etc/ossec.conf"
WINDOWS_RULES = WAZUH_HOME / "ruleset/rules/0575-win-base_rules.xml"
LOGTEST_SOCKET = WAZUH_HOME / "queue/sockets/logtest"

DISPOSABLE_WAZUH_SAMPLES = {
    ("rules", "local_rules.xml"),
    ("decoders", "local_decoder.xml"),
}

WINDOWS_RULE_DEFAULT = """  <rule id="60000" level="0">
    <category>ossec</category>
    <decoded_as>windows_eventchannel</decoded_as>
    <field name="win.system.providerName">\\.+</field>
    <options>no_full_log</options>
    <description>Group of windows rules.</description>
  </rule>"""

WINDOWS_RULE_EXPECTED = """  <rule id="60000" level="0">
    <!-- <category>ossec</category> -->
    <!-- <decoded_as>windows_eventchannel</decoded_as> -->
    <field name="win.system.providerName">\\.+</field>
    <options>no_full_log</options>
    <description>Group of windows rules.</description>
    <decoded_as>json</decoded_as>
  </rule>"""


def ensure_linux() -> None:
    if sys.platform != "linux":
        raise UnsupportedPlatformError("wazuh-devenv supports Linux only; use WSL on Windows")


def _write_privileged(
    runner: CommandRunner,
    target: Path,
    content: str,
    *,
    mode: str = "0644",
    owner: str = "root",
    group: str = "root",
) -> None:
    fd, name = tempfile.mkstemp(prefix=".wazuhdevenv.")
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        runner.run(
            ["install", "-m", mode, "-o", owner, "-g", group, str(temporary), str(target)],
            privileged=True,
        )
    finally:
        temporary.unlink(missing_ok=True)


def _privileged_exists(runner: CommandRunner, path: Path) -> bool:
    return runner.run(["test", "-e", str(path)], privileged=True, check=False).returncode == 0


def _rewrite_preserving_metadata(runner: CommandRunner, target: Path, content: str) -> None:
    metadata = runner.capture(["stat", "-Lc", "%a %U %G", str(target)], privileged=True).strip().split()
    if len(metadata) != 3:
        raise ConfigurationError(f"cannot determine metadata for {target}")
    mode, owner, group = metadata
    _write_privileged(runner, target, content, mode=mode, owner=owner, group=group)


def _download(url: str) -> Path:
    fd, name = tempfile.mkstemp(prefix="wazuhdevenv-download.")
    os.close(fd)
    target = Path(name)
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "wazuh-devenv"})
        with urllib.request.urlopen(request, timeout=30) as response:
            target.write_bytes(response.read())
        return target
    except Exception:
        target.unlink(missing_ok=True)
        raise


@dataclass(frozen=True)
class WorkspaceMetadata:
    path: Path
    mode: str
    uid: int
    gid: int


@dataclass
class WorkspaceMutations:
    copied_files: list[Path] = field(default_factory=list)
    created_directories: list[Path] = field(default_factory=list)


@dataclass(frozen=True)
class AdoptionPlan:
    copies: tuple[tuple[Path, Path], ...]
    directories: tuple[Path, ...]


@dataclass(frozen=True)
class ProvisioningSnapshot:
    service_was_active: bool
    ossec_conf: str
    windows_rules: str
    fstab: str
    preexisting_mounts: frozenset[Path]
    service_was_enabled: bool | None = None
    workspace_metadata: tuple[WorkspaceMetadata, ...] = ()


class PackageManager:
    def __init__(self, runner: CommandRunner) -> None:
        self.runner = runner
        if shutil.which("apt-get"):
            self.family = "apt"
            self.command = "apt-get"
        elif shutil.which("dnf"):
            self.family = "rpm"
            self.command = "dnf"
        elif shutil.which("yum"):
            self.family = "rpm"
            self.command = "yum"
        else:
            raise UnsupportedPlatformError("supported package manager not found (APT, DNF, or YUM)")

    def _apt_package_version(self, package: str) -> str | None:
        try:
            raw = self.runner.capture(
                [
                    "dpkg-query",
                    "-W",
                    "-f=${Status}\t${Version}\n",
                    package,
                ]
            )
        except CommandError:
            return None

        status, separator, version = raw.rstrip("\n").partition("\t")
        if status != "install ok installed" or not separator:
            return None
        version = version.strip()
        return version or None

    def installed_version(self) -> str | None:
        if self.family == "apt":
            raw = self._apt_package_version("wazuh-manager")
            if raw is None:
                return None
        else:
            try:
                raw = self.runner.capture(
                    ["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", "wazuh-manager"]
                )
            except CommandError:
                return None
        return _normalize_wazuh_version(raw)

    def _apt_install(self, packages: list[str]) -> None:
        self.runner.run(["apt-get", "update"], privileged=True)
        self.runner.run(
            ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "--no-install-recommends", *packages],
            privileged=True,
        )

    def ensure_system_dependencies(self) -> None:
        if self.family == "apt":
            packages = [
                "python3-venv",
                "util-linux",
                "coreutils",
                "findutils",
                "gnupg",
                "apt-transport-https",
            ]
            missing = [
                package
                for package in packages
                if self._apt_package_version(package) is None
            ]
            if missing:
                self._apt_install(missing)
            return

        packages = ["python3", "util-linux", "coreutils", "findutils", "gnupg2"]
        missing = [
            package
            for package in packages
            if self.runner.run(["rpm", "-q", package], check=False).returncode != 0
        ]
        if missing:
            self.runner.run(
                [self.command, "-y", "install", *missing],
                privileged=True,
            )

    def _setup_apt_repository(self) -> None:
        self._apt_install(["gnupg", "apt-transport-https"])
        keyring = Path("/usr/share/keyrings/wazuh.gpg")
        if not keyring.exists():
            key = _download("https://packages.wazuh.com/key/GPG-KEY-WAZUH")
            try:
                self.runner.run(
                    [
                        "gpg",
                        "--no-default-keyring",
                        "--keyring",
                        "gnupg-ring:/usr/share/keyrings/wazuh.gpg",
                        "--import",
                        str(key),
                    ],
                    privileged=True,
                )
                self.runner.run(["chmod", "0644", str(keyring)], privileged=True)
            finally:
                key.unlink(missing_ok=True)

        _write_privileged(
            self.runner,
            Path("/etc/apt/sources.list.d/wazuh.list"),
            "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main\n",
        )

    def _setup_rpm_repository(self) -> None:
        key = _download("https://packages.wazuh.com/key/GPG-KEY-WAZUH")
        try:
            self.runner.run(["rpm", "--import", str(key)], privileged=True)
        finally:
            key.unlink(missing_ok=True)

        repo = """[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
priority=1
"""
        _write_privileged(self.runner, Path("/etc/yum.repos.d/wazuh.repo"), repo)

    def install_wazuh(self, requested_version: str | None) -> str:
        current = self.installed_version()
        requested_normalized = (
            _normalize_wazuh_version(requested_version) if requested_version else None
        )
        if current:
            if requested_normalized and current != requested_normalized:
                raise ConfigurationError(
                    f"Wazuh {current} is already installed; requested {requested_version}. "
                    "wazuhdevenv does not perform Wazuh upgrades"
                )
            LOG.info("Wazuh Manager already installed: %s", current)
            return current

        LOG.info("Installing Wazuh Manager")
        if self.family == "apt":
            self._setup_apt_repository()
            package = "wazuh-manager"
            if requested_version:
                package += f"={requested_version}-1" if "-" not in requested_version else f"={requested_version}"
            self._apt_install([package])
            _write_privileged(
                self.runner,
                Path("/etc/apt/sources.list.d/wazuh.list"),
                "#deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main\n",
            )
            self.runner.run(["apt-get", "update"], privileged=True)
        else:
            self._setup_rpm_repository()
            package = "wazuh-manager"
            if requested_version:
                package += f"-{requested_version}-1" if "-" not in requested_version else f"-{requested_version}"
            self.runner.run([self.command, "-y", "install", package], privileged=True)
            repo_path = Path("/etc/yum.repos.d/wazuh.repo")
            repo = self.runner.capture(["cat", str(repo_path)], privileged=True)
            repo = re.sub(r"(?m)^enabled=1$", "enabled=0", repo)
            _write_privileged(self.runner, repo_path, repo)

        installed = self.installed_version()
        if not installed:
            raise ConfigurationError("Wazuh package installation completed but version could not be determined")
        return installed


def _normalize_wazuh_version(value: str) -> str:
    match = re.search(r"\d+\.\d+\.\d+", value)
    if not match:
        raise ConfigurationError(f"cannot determine Wazuh version from {value!r}")
    return match.group(0)


def _replace_simple_tag(text: str, tag: str, value: str, allowed: set[str]) -> str:
    pattern = re.compile(rf"(<{re.escape(tag)}>\s*)([^<]*?)(\s*</{re.escape(tag)}>)")
    match = pattern.search(text)
    if not match:
        raise ConfigurationError(f"missing <{tag}> in ossec.conf")
    current = match.group(2).strip()
    if current not in allowed:
        raise ConfigurationError(f"unexpected <{tag}> value: {current!r}")
    return text[: match.start()] + match.group(1) + value + match.group(3) + text[match.end() :]


def _replace_block_child(
    text: str,
    block_pattern: str,
    child: str,
    value: str,
    allowed: set[str] | Callable[[str], bool],
    description: str,
) -> str:
    block_re = re.compile(block_pattern, re.DOTALL)
    block_match = block_re.search(text)
    if not block_match:
        raise ConfigurationError(f"missing {description} block in ossec.conf")
    block = block_match.group(0)
    child_re = re.compile(rf"(<{re.escape(child)}>\s*)([^<]*?)(\s*</{re.escape(child)}>)")
    child_match = child_re.search(block)
    if not child_match:
        raise ConfigurationError(f"missing <{child}> in {description} block")
    current = child_match.group(2).strip()
    valid = allowed(current) if callable(allowed) else current in allowed
    if not valid:
        raise ConfigurationError(f"unexpected {description} <{child}> value: {current!r}")
    replacement = block[: child_match.start()] + child_match.group(1) + value + child_match.group(3) + block[child_match.end() :]
    return text[: block_match.start()] + replacement + text[block_match.end() :]


def _valid_rule_test_threads(value: str) -> bool:
    if value == "auto":
        return True
    return value.isdigit() and 1 <= int(value) <= 128


def _valid_rule_test_max_sessions(value: str) -> bool:
    return value.isdigit() and 1 <= int(value) <= 500


def _valid_rule_test_session_timeout(value: str) -> bool:
    match = re.fullmatch(r"([1-9]\d*)([smhd])", value)
    if not match:
        return False
    amount = int(match.group(1))
    unit = match.group(2)
    multiplier = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    return amount * multiplier <= 365 * 86400


def _render_ossec_config(original: str) -> str:
    text = original
    text = _replace_simple_tag(text, "logall_json", "yes", {"yes", "no"})
    text = _replace_block_child(
        text,
        r"<logging>.*?</logging>",
        "log_format",
        "plain,json",
        {"plain", "json", "plain,json"},
        "logging",
    )
    text = _replace_block_child(
        text,
        r'<wodle\s+name=["\']syscollector["\'][^>]*>.*?</wodle>',
        "disabled",
        "yes",
        {"yes", "no"},
        "syscollector",
    )
    text = _replace_block_child(
        text,
        r"<rootcheck>.*?</rootcheck>",
        "disabled",
        "yes",
        {"yes", "no"},
        "rootcheck",
    )
    text = _replace_block_child(
        text,
        r"<syscheck>.*?</syscheck>",
        "disabled",
        "yes",
        {"yes", "no"},
        "syscheck",
    )
    text = _replace_block_child(
        text,
        r"<sca>.*?</sca>",
        "enabled",
        "no",
        {"yes", "no"},
        "sca",
    )
    text = _replace_block_child(
        text,
        r"<indexer>.*?</indexer>",
        "enabled",
        "no",
        {"yes", "no"},
        "indexer",
    )
    text = _replace_block_child(
        text,
        r"<vulnerability-detection>.*?</vulnerability-detection>",
        "enabled",
        "no",
        {"yes", "no"},
        "vulnerability-detection",
    )
    text = _replace_block_child(
        text,
        r"<rule_test>.*?</rule_test>",
        "threads",
        "auto",
        _valid_rule_test_threads,
        "rule_test",
    )
    text = _replace_block_child(
        text,
        r"<rule_test>.*?</rule_test>",
        "max_sessions",
        "500",
        _valid_rule_test_max_sessions,
        "rule_test",
    )
    return _replace_block_child(
        text,
        r"<rule_test>.*?</rule_test>",
        "session_timeout",
        "1m",
        _valid_rule_test_session_timeout,
        "rule_test",
    )


def configure_ossec(runner: CommandRunner) -> None:
    original = runner.capture(["cat", str(OSSEC_CONF)], privileged=True)
    text = _render_ossec_config(original)
    if text != original:
        backup = OSSEC_CONF.with_name("ossec.conf.wazuhdevenv.bak")
        if not _privileged_exists(runner, backup):
            runner.run(
                ["cp", "--preserve=mode,ownership,timestamps", str(OSSEC_CONF), str(backup)],
                privileged=True,
            )
        _rewrite_preserving_metadata(runner, OSSEC_CONF, text)


def _render_windows_rule_testing(text: str) -> str:
    if WINDOWS_RULE_EXPECTED in text:
        return text
    if WINDOWS_RULE_DEFAULT not in text:
        raise ConfigurationError("rule 60000 is in an unexpected state; refusing to rewrite it")
    return text.replace(WINDOWS_RULE_DEFAULT, WINDOWS_RULE_EXPECTED, 1)


def configure_windows_rule_testing(runner: CommandRunner) -> None:
    original = runner.capture(["cat", str(WINDOWS_RULES)], privileged=True)
    text = _render_windows_rule_testing(original)
    if text == original:
        return
    backup = WINDOWS_RULES.with_name(WINDOWS_RULES.name + ".wazuhdevenv.bak")
    if not _privileged_exists(runner, backup):
        runner.run(
            ["cp", "--preserve=mode,ownership,timestamps", str(WINDOWS_RULES), str(backup)],
            privileged=True,
        )
    _rewrite_preserving_metadata(runner, WINDOWS_RULES, text)


def prepare_workspace(workspace: Path, user: InvokingUser) -> None:
    created_workspace = not workspace.exists()
    workspace.mkdir(parents=True, exist_ok=True)
    if created_workspace and os.geteuid() == 0 and user.uid != 0:
        os.chown(workspace, user.uid, user.gid)

    for name in ("rules", "decoders", "tests"):
        path = workspace / name
        if path.is_symlink():
            raise ConfigurationError(f"workspace {name} path is a symlink: {path}")
        path.mkdir(exist_ok=True)
        if os.geteuid() == 0 and user.uid != 0:
            os.chown(path, user.uid, user.gid)


def _tree_entries(runner: CommandRunner, path: Path) -> dict[str, str]:
    output = runner.capture(
        ["find", str(path), "-mindepth", "1", "-printf", "%y\t%P\n"],
        privileged=True,
    )
    entries: dict[str, str] = {}
    for line in output.splitlines():
        if not line:
            continue
        try:
            kind, relative = line.split("\t", 1)
        except ValueError as exc:
            raise ConfigurationError(f"cannot inspect filesystem content under {path}") from exc
        entries[relative] = kind
    return entries


def _path_sha256(runner: CommandRunner, path: Path) -> str:
    output = runner.capture(["sha256sum", str(path)], privileged=True).strip()
    digest = output.split(maxsplit=1)[0] if output else ""
    if not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
        raise ConfigurationError(f"cannot determine SHA-256 for {path}")
    return digest.lower()


def _plan_adoption(
    runner: CommandRunner,
    source: Path,
    target: Path,
) -> AdoptionPlan:
    source_entries = _tree_entries(runner, source)
    for relative, kind in source_entries.items():
        if kind == "l":
            raise ConfigurationError(
                f"workspace content must not contain symlinks: {source / relative}"
            )
        if kind not in {"d", "f"}:
            raise ConfigurationError(
                f"unsupported workspace content under {source}: {relative}"
            )

    target_entries = _tree_entries(runner, target)
    if not target_entries:
        return AdoptionPlan((), ())

    copies: list[tuple[Path, Path]] = []
    for relative, kind in target_entries.items():
        target_entry = target / relative
        source_entry = source / relative
        source_kind = source_entries.get(relative)

        if (target.name, relative) in DISPOSABLE_WAZUH_SAMPLES:
            continue

        if kind == "d":
            if source_kind is not None and source_kind != "d":
                raise ConfigurationError(
                    f"cannot adopt {target_entry}: workspace path is not a directory"
                )
            continue
        if kind != "f":
            raise ConfigurationError(
                f"unsupported existing Wazuh content under {target}: {relative}"
            )

        target_digest = _path_sha256(runner, target_entry)

        if source_kind is not None:
            if source_kind != "f":
                raise ConfigurationError(
                    f"cannot adopt {target_entry}: workspace path is not a regular file"
                )
            source_digest = _path_sha256(runner, source_entry)
            if source_digest == target_digest:
                continue
            raise ConfigurationError(
                f"conflicting existing Wazuh content: {target_entry} and {source_entry}"
            )

        parent = Path(relative).parent
        while parent != Path("."):
            parent_kind = source_entries.get(parent.as_posix())
            if parent_kind is not None and parent_kind != "d":
                raise ConfigurationError(
                    f"cannot adopt {target_entry}: workspace parent is not a directory"
                )
            parent = parent.parent

        copies.append((target_entry, source_entry))

    directories: set[Path] = set()
    for _, source_entry in copies:
        parent = source_entry.parent
        while parent != source:
            relative_parent = parent.relative_to(source).as_posix()
            if relative_parent not in source_entries:
                directories.add(parent)
            parent = parent.parent

    return AdoptionPlan(
        tuple(copies),
        tuple(sorted(directories, key=lambda path: len(path.parts))),
    )


def _apply_adoption(
    runner: CommandRunner,
    plan: AdoptionPlan,
    mutations: WorkspaceMutations | None = None,
) -> None:
    for directory in plan.directories:
        runner.run(["mkdir", "-p", str(directory)], privileged=True)
        if mutations is not None and directory not in mutations.created_directories:
            mutations.created_directories.append(directory)

    for target_entry, source_entry in plan.copies:
        runner.run(
            ["cp", "--preserve=mode,timestamps", str(target_entry), str(source_entry)],
            privileged=True,
        )
        if mutations is not None:
            mutations.copied_files.append(source_entry)


def _adopt_existing(
    runner: CommandRunner,
    source: Path,
    target: Path,
    *,
    mutations: WorkspaceMutations | None = None,
) -> None:
    plan = _plan_adoption(runner, source, target)
    _apply_adoption(runner, plan, mutations)


def _same_bind_mount(runner: CommandRunner, source: Path, target: Path) -> bool:
    if runner.run(["mountpoint", "-q", str(target)], privileged=True, check=False).returncode != 0:
        return False
    source_id = runner.capture(["stat", "-Lc", "%d:%i", str(source)], privileged=True).strip()
    target_id = runner.capture(["stat", "-Lc", "%d:%i", str(target)], privileged=True).strip()
    return source_id == target_id


def _fstab_has_entry(runner: CommandRunner, source: Path, target: Path) -> bool:
    text = runner.capture(["cat", "/etc/fstab"], privileged=True)
    expected = f"{source} {target} none bind 0 0"
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) >= 2 and fields[1] == str(target):
            if line == expected:
                return True
            raise ConfigurationError(f"conflicting fstab entry for {target}: {line}")
    return False


def _ensure_fstab(runner: CommandRunner, source: Path, target: Path) -> None:
    if _fstab_has_entry(runner, source, target):
        return
    fstab_path = Path("/etc/fstab")
    text = runner.capture(["cat", str(fstab_path)], privileged=True)
    updated = text
    if updated and not updated.endswith("\n"):
        updated += "\n"
    updated += f"{source} {target} none bind 0 0\n"
    _rewrite_preserving_metadata(runner, fstab_path, updated)


def preflight_bind_mounts(
    runner: CommandRunner,
    workspace: Path,
) -> None:
    for name in ("rules", "decoders"):
        source = (workspace / name).resolve()
        target = WAZUH_HOME / "etc" / name
        if any(ch.isspace() for ch in str(source)):
            raise ConfigurationError(
                f"workspace path contains whitespace and cannot be persisted safely: {source}"
            )

        mounted = (
            runner.run(
                ["mountpoint", "-q", str(target)],
                privileged=True,
                check=False,
            ).returncode
            == 0
        )
        if mounted:
            if not _same_bind_mount(runner, source, target):
                raise ConfigurationError(
                    f"{target} is already a mount point for different content"
                )
        else:
            _plan_adoption(runner, source, target)

        _fstab_has_entry(runner, source, target)


def configure_bind_mounts(
    runner: CommandRunner,
    workspace: Path,
    *,
    mutations: WorkspaceMutations | None = None,
) -> None:
    for name in ("rules", "decoders"):
        source = (workspace / name).resolve()
        target = WAZUH_HOME / "etc" / name
        if any(ch.isspace() for ch in str(source)):
            raise ConfigurationError(f"workspace path contains whitespace and cannot be persisted safely: {source}")

        if runner.run(["mountpoint", "-q", str(target)], privileged=True, check=False).returncode == 0:
            if _same_bind_mount(runner, source, target):
                _ensure_fstab(runner, source, target)
                continue
            raise ConfigurationError(f"{target} is already a mount point for different content")

        _adopt_existing(
            runner,
            source,
            target,
            mutations=mutations,
        )
        runner.run(["mount", "--bind", str(source), str(target)], privileged=True)
        if runner.run(["mountpoint", "-q", str(target)], privileged=True, check=False).returncode != 0:
            raise ConfigurationError(f"bind mount failed: {source} -> {target}")
        _ensure_fstab(runner, source, target)


def configure_permissions(runner: CommandRunner, workspace: Path) -> None:
    for name in ("rules", "decoders"):
        path = workspace / name
        runner.run(["find", str(path), "-type", "d", "-exec", "chown", "root:wazuh", "{}", "+"], privileged=True)
        runner.run(["find", str(path), "-type", "d", "-exec", "chmod", "0770", "{}", "+"], privileged=True)
        runner.run(["find", str(path), "-type", "f", "-exec", "chown", "wazuh:wazuh", "{}", "+"], privileged=True)
        runner.run(["find", str(path), "-type", "f", "-exec", "chmod", "0660", "{}", "+"], privileged=True)


def ensure_group_membership(runner: CommandRunner, user: InvokingUser) -> bool:
    if user.uid == 0:
        return False
    groups = runner.capture(["id", "-nG", user.name]).split()
    if "wazuh" in groups:
        return False
    runner.run(["usermod", "-a", "-G", "wazuh", user.name], privileged=True)
    LOG.warning(
        "Added %s to wazuh group; a new login shell may be required outside wazuhdevenv",
        user.name,
    )
    return True


def remove_group_membership(runner: CommandRunner, user: InvokingUser) -> None:
    runner.run(["gpasswd", "-d", user.name, "wazuh"], privileged=True)


def _service_manager() -> str:
    if shutil.which("systemctl") and Path("/run/systemd/system").exists():
        return "systemd"
    if shutil.which("service"):
        return "sysv"
    raise UnsupportedPlatformError("supported service manager not found (systemd or service)")


def is_wazuh_enabled(runner: CommandRunner) -> bool | None:
    manager = _service_manager()
    if manager != "systemd":
        return None
    return (
        runner.run(
            ["systemctl", "is-enabled", "--quiet", "wazuh-manager"],
            privileged=True,
            check=False,
        ).returncode
        == 0
    )


def set_wazuh_enabled(runner: CommandRunner, enabled: bool) -> None:
    manager = _service_manager()
    if manager != "systemd":
        return
    action = "enable" if enabled else "disable"
    runner.run(["systemctl", action, "wazuh-manager"], privileged=True)


def is_wazuh_active(runner: CommandRunner) -> bool:
    manager = _service_manager()
    if manager == "systemd":
        return (
            runner.run(
                ["systemctl", "is-active", "--quiet", "wazuh-manager"],
                privileged=True,
                check=False,
            ).returncode
            == 0
        )
    return (
        runner.run(
            ["service", "wazuh-manager", "status"],
            privileged=True,
            check=False,
        ).returncode
        == 0
    )


def stop_wazuh(runner: CommandRunner) -> bool:
    was_active = is_wazuh_active(runner)
    if not was_active:
        return False
    manager = _service_manager()
    if manager == "systemd":
        runner.run(["systemctl", "stop", "wazuh-manager"], privileged=True)
    else:
        runner.run(["service", "wazuh-manager", "stop"], privileged=True)
    return True


def validate_wazuh(runner: CommandRunner) -> None:
    for executable in (
        "/var/ossec/bin/wazuh-syscheckd",
        "/var/ossec/bin/wazuh-logcollector",
        "/var/ossec/bin/wazuh-modulesd",
        "/var/ossec/bin/wazuh-analysisd",
    ):
        runner.run([executable, "-t"], privileged=True)


def start_wazuh(runner: CommandRunner, *, enable: bool = True) -> None:
    manager = _service_manager()
    if manager == "systemd":
        runner.run(["systemctl", "daemon-reload"], privileged=True)
        if enable:
            runner.run(["systemctl", "enable", "wazuh-manager"], privileged=True)
        runner.run(["systemctl", "restart", "wazuh-manager"], privileged=True)
    else:
        runner.run(["service", "wazuh-manager", "restart"], privileged=True)


def wait_for_logtest(runner: CommandRunner, timeout: int = 120, stable_for: int = 5) -> None:
    stable = 0
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready = (
            runner.run(["test", "-S", str(LOGTEST_SOCKET)], privileged=True, check=False).returncode == 0
        )
        if ready:
            stable += 1
            if stable >= stable_for:
                return
        else:
            stable = 0
        time.sleep(1)
    raise ConfigurationError(f"timeout waiting for stable logtest socket: {LOGTEST_SOCKET}")


def ensure_workspace_venv(runner: CommandRunner, workspace: Path) -> None:
    venv = workspace / ".venv"
    if venv.is_symlink():
        raise ConfigurationError(f"refusing to use symlinked virtual environment: {venv}")
    if not (venv / "pyvenv.cfg").is_file():
        if venv.exists() and not venv.is_dir():
            raise ConfigurationError(f"{venv} exists but is not a directory")
        runner.run_as_user([sys.executable, "-m", "venv", str(venv)])

    python = venv / "bin/python"
    if not python.exists():
        raise ConfigurationError(f"virtual environment Python not found: {python}")
    tester_spec = os.environ.get("WAZUHTESTER_SPEC", "wazuhtester>=0.1.0rc1,<0.2")
    runner.run_as_user([str(python), "-m", "pip", "install", "--upgrade", "pip"])
    runner.run_as_user([str(python), "-m", "pip", "install", "pytest>=8,<10", tester_spec])


def _capture_workspace_metadata(
    runner: CommandRunner,
    workspace: Path,
) -> tuple[WorkspaceMetadata, ...]:
    metadata: list[WorkspaceMetadata] = []
    for name in ("rules", "decoders"):
        root = workspace / name
        output = runner.capture(
            [
                "find",
                str(root),
                "-mindepth",
                "0",
                "-printf",
                "%m\t%U\t%G\t%p\n",
            ],
            privileged=True,
        )
        for line in output.splitlines():
            if not line:
                continue
            try:
                mode, uid, gid, path = line.split("\t", 3)
                metadata.append(
                    WorkspaceMetadata(Path(path), mode, int(uid), int(gid))
                )
            except (ValueError, TypeError) as exc:
                raise ConfigurationError(
                    f"cannot snapshot workspace metadata under {root}"
                ) from exc
    return tuple(metadata)


def _restore_workspace(
    runner: CommandRunner,
    snapshot: ProvisioningSnapshot,
    mutations: WorkspaceMutations,
) -> list[str]:
    errors: list[str] = []

    for path in reversed(mutations.copied_files):
        try:
            runner.run(["rm", "-f", "--", str(path)], privileged=True)
        except Exception as exc:
            errors.append(f"remove adopted file {path}: {exc}")

    for path in sorted(
        mutations.created_directories,
        key=lambda item: len(item.parts),
        reverse=True,
    ):
        try:
            runner.run(["rmdir", "--", str(path)], privileged=True, check=False)
        except Exception as exc:
            errors.append(f"remove adopted directory {path}: {exc}")

    for entry in snapshot.workspace_metadata:
        try:
            runner.run(
                ["chown", f"{entry.uid}:{entry.gid}", str(entry.path)],
                privileged=True,
            )
            runner.run(["chmod", entry.mode, str(entry.path)], privileged=True)
        except Exception as exc:
            errors.append(f"restore workspace metadata {entry.path}: {exc}")

    return errors


def _capture_snapshot(
    runner: CommandRunner,
    workspace: Path,
    service_was_active: bool,
) -> ProvisioningSnapshot:
    preexisting_mounts: set[Path] = set()
    for name in ("rules", "decoders"):
        source = (workspace / name).resolve()
        target = WAZUH_HOME / "etc" / name
        if _same_bind_mount(runner, source, target):
            preexisting_mounts.add(target)

    return ProvisioningSnapshot(
        service_was_active=service_was_active,
        ossec_conf=runner.capture(["cat", str(OSSEC_CONF)], privileged=True),
        windows_rules=runner.capture(["cat", str(WINDOWS_RULES)], privileged=True),
        fstab=runner.capture(["cat", "/etc/fstab"], privileged=True),
        preexisting_mounts=frozenset(preexisting_mounts),
        service_was_enabled=is_wazuh_enabled(runner),
        workspace_metadata=_capture_workspace_metadata(runner, workspace),
    )


def _restore_text_if_changed(
    runner: CommandRunner,
    path: Path,
    original: str,
) -> None:
    current = runner.capture(["cat", str(path)], privileged=True)
    if current != original:
        _rewrite_preserving_metadata(runner, path, original)


def _rollback_provisioning(
    runner: CommandRunner,
    workspace: Path,
    snapshot: ProvisioningSnapshot,
    mutations: WorkspaceMutations,
    user: InvokingUser,
    group_added: bool,
) -> None:
    recovery_errors: list[str] = []

    try:
        stop_wazuh(runner)
    except Exception as exc:
        recovery_errors.append(f"stop Wazuh Manager before rollback: {exc}")

    for name in reversed(("rules", "decoders")):
        source = (workspace / name).resolve()
        target = WAZUH_HOME / "etc" / name
        if target in snapshot.preexisting_mounts:
            continue
        try:
            if _same_bind_mount(runner, source, target):
                runner.run(["umount", str(target)], privileged=True)
        except Exception as exc:
            recovery_errors.append(f"unmount {target}: {exc}")

    recovery_errors.extend(_restore_workspace(runner, snapshot, mutations))

    for path, original in (
        (Path("/etc/fstab"), snapshot.fstab),
        (OSSEC_CONF, snapshot.ossec_conf),
        (WINDOWS_RULES, snapshot.windows_rules),
    ):
        try:
            _restore_text_if_changed(runner, path, original)
        except Exception as exc:
            recovery_errors.append(f"restore {path}: {exc}")

    if snapshot.service_was_active:
        try:
            start_wazuh(runner, enable=False)
            wait_for_logtest(runner)
        except Exception as exc:
            recovery_errors.append(f"restart Wazuh Manager: {exc}")

    if snapshot.service_was_enabled is not None:
        try:
            set_wazuh_enabled(runner, snapshot.service_was_enabled)
        except Exception as exc:
            recovery_errors.append(f"restore Wazuh Manager enablement: {exc}")

    if group_added:
        try:
            remove_group_membership(runner, user)
        except Exception as exc:
            recovery_errors.append(f"remove {user.name} from wazuh group: {exc}")

    if recovery_errors:
        LOG.error(
            "Provisioning rollback was incomplete: %s",
            "; ".join(recovery_errors),
        )


def initialize(
    workspace: Path,
    home: Path,
    user: InvokingUser,
    *,
    wazuh_version: str | None = None,
) -> str:
    ensure_linux()
    runner = CommandRunner(user)
    package_manager = PackageManager(runner)

    package_manager.ensure_system_dependencies()
    prepare_workspace(workspace, user)
    ensure_workspace_venv(runner, workspace)

    installed = package_manager.install_wazuh(wazuh_version)

    preflight_bind_mounts(runner, workspace)
    service_was_active = is_wazuh_active(runner)
    snapshot = _capture_snapshot(runner, workspace, service_was_active)

    # Validate every known configuration transformation before the service is stopped.
    _render_ossec_config(snapshot.ossec_conf)
    _render_windows_rule_testing(snapshot.windows_rules)

    mutations = WorkspaceMutations()
    group_added = False
    try:
        group_added = ensure_group_membership(runner, user)
        stop_wazuh(runner)
        configure_ossec(runner)
        configure_windows_rule_testing(runner)
        configure_bind_mounts(
            runner,
            workspace,
            mutations=mutations,
        )
        configure_permissions(runner, workspace)
        validate_wazuh(runner)
        start_wazuh(runner)
        wait_for_logtest(runner)
    except Exception:
        _rollback_provisioning(
            runner,
            workspace,
            snapshot,
            mutations,
            user,
            group_added,
        )
        raise

    state = load_state(home)
    state.update(
        {
            "workspace": str(workspace),
            "wazuh_home": str(WAZUH_HOME),
            "wazuh_version": installed,
        }
    )
    save_state(home, state, user)
    return installed
