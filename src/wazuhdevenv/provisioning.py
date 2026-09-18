"""Idempotent provisioning for a Wazuh development workspace."""

from __future__ import annotations

import logging
import os
import re
import shutil
import stat
import sys
import tempfile
import time
import urllib.request
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

    def installed_version(self) -> str | None:
        try:
            if self.family == "apt":
                raw = self.runner.capture(["dpkg-query", "-W", "-f=${Version}", "wazuh-manager"])
            else:
                raw = self.runner.capture(["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", "wazuh-manager"])
        except CommandError:
            return None
        match = re.search(r"\d+\.\d+\.\d+", raw)
        return match.group(0) if match else None

    def _apt_install(self, packages: list[str]) -> None:
        env = os.environ.copy()
        env["DEBIAN_FRONTEND"] = "noninteractive"
        self.runner.run(["apt-get", "update"], privileged=True, env=env)
        self.runner.run(
            ["apt-get", "install", "-y", "--no-install-recommends", *packages],
            privileged=True,
            env=env,
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
        if current:
            if requested_version and current != requested_version:
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
    allowed: set[str],
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
    if current not in allowed:
        raise ConfigurationError(f"unexpected {description} <{child}> value: {current!r}")
    replacement = block[: child_match.start()] + child_match.group(1) + value + child_match.group(3) + block[child_match.end() :]
    return text[: block_match.start()] + replacement + text[block_match.end() :]


def configure_ossec(runner: CommandRunner) -> None:
    original = runner.capture(["cat", str(OSSEC_CONF)], privileged=True)
    text = original
    text = _replace_simple_tag(text, "logall_json", "yes", {"yes", "no"})
    text = _replace_block_child(text, r"<logging>.*?</logging>", "log_format", "plain,json", {"plain", "json", "plain,json"}, "logging")
    text = _replace_block_child(
        text,
        r'<wodle\s+name=["\']syscollector["\'][^>]*>.*?</wodle>',
        "disabled",
        "yes",
        {"yes", "no"},
        "syscollector",
    )
    text = _replace_block_child(text, r"<rootcheck>.*?</rootcheck>", "disabled", "yes", {"yes", "no"}, "rootcheck")
    text = _replace_block_child(text, r"<syscheck>.*?</syscheck>", "disabled", "yes", {"yes", "no"}, "syscheck")
    text = _replace_block_child(text, r"<sca>.*?</sca>", "enabled", "no", {"yes", "no"}, "sca")
    text = _replace_block_child(text, r"<indexer>.*?</indexer>", "enabled", "no", {"yes", "no"}, "indexer")
    text = _replace_block_child(
        text,
        r"<vulnerability-detection>.*?</vulnerability-detection>",
        "enabled",
        "no",
        {"yes", "no"},
        "vulnerability-detection",
    )
    text = _replace_block_child(text, r"<rule_test>.*?</rule_test>", "threads", "auto", {"auto", "1", "2", "4", "8", "16"}, "rule_test")
    text = _replace_block_child(text, r"<rule_test>.*?</rule_test>", "max_sessions", "500", set(str(i) for i in range(1, 10001)), "rule_test")
    text = _replace_block_child(
        text,
        r"<rule_test>.*?</rule_test>",
        "session_timeout",
        "1m",
        {"1m", "5m", "10m", "15m", "30m", "1h"},
        "rule_test",
    )

    if text != original:
        backup = OSSEC_CONF.with_name("ossec.conf.wazuhdevenv.bak")
        if not backup.exists():
            runner.run(["cp", "--preserve=mode,ownership,timestamps", str(OSSEC_CONF), str(backup)], privileged=True)
        _write_privileged(runner, OSSEC_CONF, text, mode="0640", owner="root", group="wazuh")


def configure_windows_rule_testing(runner: CommandRunner) -> None:
    text = runner.capture(["cat", str(WINDOWS_RULES)], privileged=True)
    if WINDOWS_RULE_EXPECTED in text:
        return
    if WINDOWS_RULE_DEFAULT not in text:
        raise ConfigurationError("rule 60000 is in an unexpected state; refusing to rewrite it")
    backup = WINDOWS_RULES.with_name(WINDOWS_RULES.name + ".wazuhdevenv.bak")
    if not backup.exists():
        runner.run(["cp", "--preserve=mode,ownership,timestamps", str(WINDOWS_RULES), str(backup)], privileged=True)
    text = text.replace(WINDOWS_RULE_DEFAULT, WINDOWS_RULE_EXPECTED, 1)
    _write_privileged(runner, WINDOWS_RULES, text, mode="0640", owner="root", group="wazuh")


def prepare_workspace(workspace: Path, user: InvokingUser) -> None:
    workspace.mkdir(parents=True, exist_ok=True)
    for name in ("rules", "decoders", "tests"):
        path = workspace / name
        if path.is_symlink():
            raise ConfigurationError(f"workspace {name} path is a symlink: {path}")
        path.mkdir(exist_ok=True)
        if os.geteuid() == 0 and user.uid != 0:
            os.chown(path, user.uid, user.gid)


def _directory_entries(runner: CommandRunner, path: Path, *, privileged: bool) -> list[str]:
    output = runner.capture(
        ["find", str(path), "-mindepth", "1", "-maxdepth", "1", "-printf", "%f\n"],
        privileged=privileged,
    )
    return [line for line in output.splitlines() if line]


def _adopt_existing(runner: CommandRunner, source: Path, target: Path) -> None:
    target_entries = _directory_entries(runner, target, privileged=True)
    if not target_entries:
        return
    source_entries = [entry.name for entry in source.iterdir()]
    if source_entries:
        raise ConfigurationError(f"both {source} and {target} contain files; refusing an ambiguous merge")

    script = (
        "from pathlib import Path; import shutil,sys; "
        "src=Path(sys.argv[1]); dst=Path(sys.argv[2]); "
        "[shutil.move(str(p), str(dst / p.name)) for p in src.iterdir()]"
    )
    runner.run([sys.executable, "-c", script, str(target), str(source)], privileged=True)


def _mount_source(runner: CommandRunner, target: Path) -> str | None:
    result = runner.run(["mountpoint", "-q", str(target)], check=False)
    if result.returncode != 0:
        return None
    return runner.capture(["findmnt", "-n", "-o", "SOURCE", "--target", str(target)]).strip()


def _ensure_fstab(runner: CommandRunner, source: Path, target: Path) -> None:
    fstab_path = Path("/etc/fstab")
    text = runner.capture(["cat", str(fstab_path)], privileged=True)
    expected = f"{source} {target} none bind 0 0"
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) >= 2 and fields[1] == str(target):
            if line == expected:
                return
            raise ConfigurationError(f"conflicting fstab entry for {target}: {line}")
    updated = text
    if updated and not updated.endswith("\n"):
        updated += "\n"
    updated += expected + "\n"
    _write_privileged(runner, fstab_path, updated)


def configure_bind_mounts(runner: CommandRunner, workspace: Path) -> None:
    for name in ("rules", "decoders"):
        source = (workspace / name).resolve()
        target = WAZUH_HOME / "etc" / name
        if any(ch.isspace() for ch in str(source)):
            raise ConfigurationError(f"workspace path contains whitespace and cannot be persisted safely: {source}")

        existing_source = _mount_source(runner, target)
        if existing_source:
            try:
                if Path(existing_source).resolve() == source:
                    _ensure_fstab(runner, source, target)
                    continue
            except OSError:
                pass
            raise ConfigurationError(f"{target} is already mounted from {existing_source}")

        _adopt_existing(runner, source, target)
        runner.run(["mount", "--bind", str(source), str(target)], privileged=True)
        if _mount_source(runner, target) is None:
            raise ConfigurationError(f"bind mount failed: {source} -> {target}")
        _ensure_fstab(runner, source, target)


def configure_permissions(runner: CommandRunner, workspace: Path) -> None:
    for name in ("rules", "decoders"):
        path = workspace / name
        runner.run(["find", str(path), "-type", "d", "-exec", "chown", "root:wazuh", "{}", "+"], privileged=True)
        runner.run(["find", str(path), "-type", "d", "-exec", "chmod", "0770", "{}", "+"], privileged=True)
        runner.run(["find", str(path), "-type", "f", "-exec", "chown", "wazuh:wazuh", "{}", "+"], privileged=True)
        runner.run(["find", str(path), "-type", "f", "-exec", "chmod", "0660", "{}", "+"], privileged=True)


def ensure_group_membership(runner: CommandRunner, user: InvokingUser) -> None:
    groups = runner.capture(["id", "-nG", user.name]).split()
    if "wazuh" not in groups:
        runner.run(["usermod", "-a", "-G", "wazuh", user.name], privileged=True)
        LOG.warning("Added %s to wazuh group; a new login shell may be required outside wazuhdevenv", user.name)


def _service_manager() -> str:
    if shutil.which("systemctl") and Path("/run/systemd/system").exists():
        return "systemd"
    if shutil.which("service"):
        return "sysv"
    raise UnsupportedPlatformError("supported service manager not found (systemd or service)")


def stop_wazuh(runner: CommandRunner) -> None:
    manager = _service_manager()
    if manager == "systemd":
        active = runner.run(["systemctl", "is-active", "--quiet", "wazuh-manager"], privileged=True, check=False)
        if active.returncode == 0:
            runner.run(["systemctl", "stop", "wazuh-manager"], privileged=True)
    else:
        runner.run(["service", "wazuh-manager", "stop"], privileged=True, check=False)


def validate_wazuh(runner: CommandRunner) -> None:
    for executable in (
        "/var/ossec/bin/wazuh-syscheckd",
        "/var/ossec/bin/wazuh-logcollector",
        "/var/ossec/bin/wazuh-modulesd",
        "/var/ossec/bin/wazuh-analysisd",
    ):
        runner.run([executable, "-t"], privileged=True)


def start_wazuh(runner: CommandRunner) -> None:
    manager = _service_manager()
    if manager == "systemd":
        runner.run(["systemctl", "daemon-reload"], privileged=True)
        runner.run(["systemctl", "enable", "wazuh-manager"], privileged=True)
        runner.run(["systemctl", "restart", "wazuh-manager"], privileged=True)
    else:
        runner.run(["service", "wazuh-manager", "restart"], privileged=True)


def wait_for_logtest(timeout: int = 120, stable_for: int = 5) -> None:
    stable = 0
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            ready = stat.S_ISSOCK(LOGTEST_SOCKET.stat().st_mode)
        except FileNotFoundError:
            ready = False
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
    tester_spec = os.environ.get("WAZUHTESTER_SPEC", "wazuhtester>=0.1,<0.2")
    runner.run_as_user([str(python), "-m", "pip", "install", "--upgrade", "pip"])
    runner.run_as_user([str(python), "-m", "pip", "install", "pytest>=8,<10", tester_spec])


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

    prepare_workspace(workspace, user)
    ensure_workspace_venv(runner, workspace)

    installed = package_manager.install_wazuh(wazuh_version)

    stop_wazuh(runner)
    configure_ossec(runner)
    configure_windows_rule_testing(runner)
    configure_bind_mounts(runner, workspace)
    configure_permissions(runner, workspace)
    ensure_group_membership(runner, user)
    validate_wazuh(runner)
    start_wazuh(runner)
    wait_for_logtest()

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
