#!/usr/bin/python3
# -*- coding: utf-8 -*-

import argparse
import logging
import os
import sys
from typing import Final

import pytest
from pytest import TestReport

APP_NAME: Final[str] = 'tester'
APP_VERSION: Final[str] = '0.1'
DESCRIPTION: Final[str] = f"{APP_NAME} ({APP_VERSION}) is a Wazuh rule and decoder testing tool."
ENCODING: Final[str] = "utf-8"


def setup_logging() -> None:
    log_path = f'/var/ossec/logs/{APP_NAME}.log'
    logging.basicConfig(
        filename=log_path,
        encoding=ENCODING,
        format='%(asctime)s:%(name)s:%(levelname)s:%(message)s',
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        level=logging.INFO
    )
    sys.excepthook = lambda exc_type, exc_value, exc_traceback: logging.error(
        "Unhandled exception", exc_info=(exc_type, exc_value, exc_traceback))


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_logreport(report: TestReport) -> None:
    """Hook to log test results."""
    if report.when == "call":  # Log only call phase (skips setup and teardown logs)
        if report.passed:
            logging.info(f"PASSED: {report.nodeid}")
        elif report.failed:
            logging.error(f"FAILED: {report.nodeid}")
        elif report.skipped:
            logging.warning(f"SKIPPED: {report.nodeid}")

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument(
        '--enable-builtin',
        action='store_true',
        help="Enable running built-in rule tests. Disabled by default."
    )
    parser.add_argument(
        '--verbosity',
        type=int,
        choices=[0, 1, 2],
        default=1,
        help="Set verbosity level for test output (0, 1, or 2). Default is 1."
    )
    return parser.parse_args()


def main() -> None:
    # Set up logging
    setup_logging()
    logging.info(f'Starting {APP_NAME} v{APP_VERSION}')
    logging.info(DESCRIPTION)

    # Parse arguments
    args = parse_arguments()

    # Build pytest arguments
    pytest_args = ["-q"] if args.verbosity == 0 else []
    if args.verbosity == 2:
        pytest_args.append("-v")
    if not args.enable_builtin:
        pytest_args.append("--ignore=src/tests/builtin")

    # Run pytest with constructed arguments
    # Preflight checks
    exit_code = pytest.main(pytest_args + ["src/tests/preflight"])
    if exit_code != 0:
        print('Preflight tests failed. Exiting.')
        logging.error('Preflight tests failed. Exiting.')
        exit(1)
    if args.enable_builtin:
        # built-in rule tests
        exit_code = pytest.main(pytest_args + ["src/tests/builtin"])

    # built-in rule tests
    exit_code = pytest.main(pytest_args + ["src/tests/custom"])

    # Log completion and exit status
    logging.info('Exiting.')
    sys.exit(exit_code)


if __name__ == "__main__":
    try:
        main()
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
