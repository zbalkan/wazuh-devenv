#!/usr/bin/env python3
from __future__ import annotations

import argparse
import logging
import os
import runpy
import sys
from pathlib import Path
from typing import Final, Sequence

from internal.coverage import run as run_coverage
from internal.tester import run as run_tests

APP_NAME: Final[str] = 'wazuh-devenv'
APP_VERSION: Final[str] = '1.0'
DESCRIPTION: Final[str] = f"{APP_NAME} ({APP_VERSION}) is a Wazuh rule and decoder testing tool."
ENCODING: Final[str] = "utf-8"
LOG_PATH: Final[str] = "/tmp/tester.log"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="main.py")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # coverage subcommand
    p_cov = subparsers.add_parser(
        "coverage",
        help="Run coverage.py",
    )
    p_cov.add_argument(
        "args",
        nargs=argparse.REMAINDER,
        help="(Optional) Arguments forwarded to coverage.py",
    )

    # qa subcommand
    p_qa = subparsers.add_parser(
        "qa",
        help="Run tester.py (QA) with all tester.py flags forwarded",
    )
    p_qa.add_argument(
        "args",
        nargs=argparse.REMAINDER,
        help="Arguments forwarded to tester.py (e.g. --verbosity 2 --failfast ...)",
    )

    # Add flags and parameters
    p_qa.add_argument(
        '--disable-builtin',
        action='store_true',
        help="Disable running built-in rule tests for regression. Enabled by default."
    )
    p_qa.add_argument(
        '--disable-custom',
        action='store_true',
        help="Disable running custom rule tests for regression. Enabled by default."
    )
    p_qa.add_argument(
        '--disable-behavioral',
        action='store_true',
        help="Disable running behavioral tests. Enabled by default."
    )
    p_qa.add_argument(
        '--verbosity',
        type=int,
        choices=[0, 1, 2],
        default=1,
        help="Set verbosity level for test output (0, 1, or 2). Default is 1."
    )
    p_qa.add_argument(
        '--failfast',
        action='store_false',
        help="Stop on first failed test. Disabled by default."
    )

    # Hidden flag to disable preflight tests
    # Beware that this flag is hidden and should be used with caution
    p_qa.add_argument(
        '--disable-preflight',
        action='store_true',
        help=argparse.SUPPRESS
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "coverage":
        run_coverage()

    if args.command == "qa":
        qa_args = args.qa
        if qa_args:
            run_tests(disable_preflight=qa_args.disable_preflight,
                      disable_builtin=qa_args.disable_builtin,
                      disable_custom=qa_args.disable_custom,
                      disable_behavioral=qa_args.disable_behavioral,
                      verbosity=qa_args.verbosity,
                      failfast=qa_args.failfast)
        else:
            run_tests()


def setup_logging() -> None:
    try:
        logging.basicConfig(
            filename=LOG_PATH,
            encoding=ENCODING,
            format="%(asctime)s.%(msecs)03d:%(name)s:%(levelname)s:%(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
            level=logging.INFO
        )

        sys.excepthook = lambda exc_type, exc_value, exc_traceback: logging.error(
            "Unhandled exception", exc_info=(exc_type, exc_value, exc_traceback))
    except Exception as e:
        print(e)


if __name__ == "__main__":
    try:
        setup_logging()

        logging.info(f'Starting {APP_NAME} v{APP_VERSION}')
        logging.info(DESCRIPTION)

        # Parse arguments

        logging.info('Exiting.')
    except KeyboardInterrupt:
        print('Cancelled by user.')
        logging.info('Cancelled by user.')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
    except Exception as ex:
        print('ERROR: ' + str(ex))
        logging.exception('Unhandled exception')
        try:
            sys.exit(1)
        except SystemExit:
            os._exit(1)
