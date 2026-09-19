"""Command-line interface for wazuh-devenv."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from . import __version__
from .corpus import resolve_release, update_corpus
from .errors import WazuhDevenvError
from .paths import InvokingUser, managed_home, resolve_workspace
from .provisioning import PackageManager, initialize
from .runner import CommandRunner
from .state import ensure_managed_home, load_state, managed_lock

LOG = logging.getLogger("wazuhdevenv")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wazuhdevenv",
        description="Provision and maintain a local Wazuh rule-development environment.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true")

    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="Provision or reconcile a development workspace")
    init.add_argument("path", nargs="?", help="Workspace path (default: current directory)")
    init.add_argument("--wazuh-version", help="Install or require an exact Wazuh version")
    init.add_argument(
        "--skip-corpus",
        action="store_true",
        help="Do not download the compatible default rule-test corpus",
    )

    update = commands.add_parser("update", help="Install or refresh managed rule-test content")
    update.add_argument("--check", action="store_true", help="Resolve the compatible corpus without installing it")

    return parser


def _configure_logging(home: Path, user: InvokingUser, verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    log_path = home / "logs" / "wazuhdevenv.log"
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    handlers.append(file_handler)
    logging.basicConfig(level=level, format="%(levelname)s %(message)s", handlers=handlers)
    if os.geteuid() == 0 and user.uid != 0:
        try:
            os.chown(log_path, user.uid, user.gid)
        except OSError:
            pass


def _workspace_wazuhtester_version(user: InvokingUser, home: Path) -> str:
    state = load_state(home)
    workspace_value = state.get("workspace")
    if not isinstance(workspace_value, str):
        raise WazuhDevenvError("workspace is not initialized; run 'wazuhdevenv init' first")
    python = Path(workspace_value) / ".venv/bin/python"
    if not python.is_file():
        raise WazuhDevenvError(f"workspace virtual environment is missing: {python}")
    runner = CommandRunner(user)
    code = "from importlib.metadata import version; print(version('wazuhtester'))"
    try:
        return runner.capture([str(python), "-c", code]).strip()
    except WazuhDevenvError as exc:
        raise WazuhDevenvError(
            "wazuhtester is not installed in the workspace virtual environment; rerun 'wazuhdevenv init'"
        ) from exc


def _installed_wazuh_version(user: InvokingUser, home: Path) -> str:
    state = load_state(home)
    recorded = state.get("wazuh_version")
    runner = CommandRunner(user)
    actual = PackageManager(runner).installed_version()
    if not actual:
        raise WazuhDevenvError("Wazuh Manager is not installed; run 'wazuhdevenv init' first")
    if recorded and recorded != actual:
        LOG.warning("Recorded Wazuh version %s differs from installed version %s", recorded, actual)
    return actual


def _init_command(args: argparse.Namespace, user: InvokingUser, home: Path) -> int:
    workspace = resolve_workspace(args.path)
    with managed_lock(home):
        LOG.info("Provisioning workspace: %s", workspace)
        version = initialize(
            workspace,
            home,
            user,
            wazuh_version=args.wazuh_version,
        )
        LOG.info("Wazuh Manager ready: %s", version)
        if not args.skip_corpus:
            tester_version = _workspace_wazuhtester_version(user, home)
            corpus = update_corpus(home, version, tester_version, user)
            LOG.info("Managed rule-test corpus ready: %s", corpus)
    return 0


def _update_command(args: argparse.Namespace, user: InvokingUser, home: Path) -> int:
    with managed_lock(home):
        version = _installed_wazuh_version(user, home)
        tester_version = _workspace_wazuhtester_version(user, home)
        release = resolve_release(version, tester_version)
        if args.check:
            print(f"{release.version} (Wazuh {release.manifest['wazuh']['requires']})")
            return 0
        installed = update_corpus(home, version, tester_version, user)
        LOG.info("Managed rule-test corpus ready: %s", installed)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    logging_ready = False

    try:
        user = InvokingUser.current()
        home = managed_home(user)
        ensure_managed_home(home, user)
        _configure_logging(home, user, args.verbose)
        logging_ready = True

        if args.command == "init":
            return _init_command(args, user, home)
        if args.command == "update":
            return _update_command(args, user, home)
    except (WazuhDevenvError, ValueError, OSError, RuntimeError) as exc:
        if logging_ready:
            LOG.error("%s", exc)
        else:
            print(f"wazuhdevenv: {exc}", file=sys.stderr)
        return 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
