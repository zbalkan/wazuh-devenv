#!/usr/bin/python3

import argparse
import logging
import os
import sys
import unittest
from typing import Final, Optional

from internal.result import ResultRunTests

APP_NAME: Final[str] = 'tester'
APP_VERSION: Final[str] = '0.1'
DESCRIPTION: Final[str] = f"{APP_NAME} ({APP_VERSION}) is a Wazuh rule and decoder testing tool."
ENCODING: Final[str] = "utf-8"


def run_tests(test_directory: str, pattern: str = 'test_*.py', verbosity: int = 1) -> Optional[unittest.result.TestResult]:
    """Discover and run tests in the specified directory with a given pattern."""
    print(f'Running {test_directory} tests...')
    loader = unittest.TestLoader()
    tests = loader.discover(test_directory, pattern=pattern)
    runner = unittest.TextTestRunner(verbosity=verbosity)
    test_result = runner.run(tests)

    # Structure and log the results
    structured_result = ResultRunTests(test_result)
    print(structured_result.verbose_result)
    logging.info(structured_result.json_result)

    return test_result


def main(enable_builtin: bool, verbosity: int) -> None:
    # Run preflight tests
    preflight_result = run_tests('tests.preflight', verbosity=verbosity)
    if preflight_result and (preflight_result.errors or preflight_result.failures):
        print('Preflight tests failed. Exiting.')
        logging.error('Preflight tests failed. Exiting.')
        exit(1)

    # Conditionally run built-in rule tests if enabled
    if enable_builtin:
        run_tests('tests.regression_tests.builtin', verbosity=verbosity)

    # Run custom rule tests
    run_tests('tests.regression_tests.custom', verbosity=verbosity)


def setup_logging() -> None:
    log_path = os.path.join(f'/var/ossec/logs/{APP_NAME}.log')
    logging.basicConfig(
        filename=os.path.join(log_path),
        encoding=ENCODING,
        format='%(asctime)s:%(name)s:%(levelname)s:%(message)s',
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        level=logging.INFO
    )

    sys.excepthook = lambda exc_type, exc_value, exc_traceback: logging.error(
        "Unhandled exception", exc_info=(exc_type, exc_value, exc_traceback))


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=DESCRIPTION)

    # Add flags and parameters
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

    # Parse the arguments
    return parser.parse_args()


if __name__ == "__main__":
    try:
        setup_logging()

        logging.info(f'Starting {APP_NAME} v{APP_VERSION}')
        logging.info(DESCRIPTION)

        # Parse arguments
        args = parse_arguments()

        # Run the main function with parsed arguments
        main(enable_builtin=args.enable_builtin, verbosity=args.verbosity)

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
