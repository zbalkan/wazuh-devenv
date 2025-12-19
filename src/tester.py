#!/usr/bin/env python3

import argparse
import logging
import os
import sys
import unittest
from typing import Final, Optional

from internal.result import ResultRunTests

APP_NAME: Final[str] = 'wazuh-devenv tester'
APP_VERSION: Final[str] = '0.2'
DESCRIPTION: Final[str] = f"{APP_NAME} ({APP_VERSION}) is a Wazuh rule and decoder testing tool."
ENCODING: Final[str] = "utf-8"
LOG_PATH: Final[str] = "/tmp/tester.log"


def _failed(result: unittest.TestResult) -> bool:
    """Return True if the test result contains any errors or failures."""
    return bool(result.errors or result.failures)


def _run_suite(module: str, *, verbosity: int, failfast: bool) -> bool:
    """
    Run tests for `module` and return True if the suite passed.

    If `failfast` is True, abort immediately on failure.
    """
    result: Optional[unittest.TestResult] = run_tests(module, verbosity=verbosity)

    if result is None:
        logging.error("Test runner returned no result for %s", module)
        if failfast:
            raise SystemExit(1)
        return False

    if _failed(result):
        logging.error(
            "Test suite failed: %s (errors=%d, failures=%d)",
            module,
            len(result.errors),
            len(result.failures),
        )
        if failfast:
            raise SystemExit(1, result.errors, result.failures)
        return False

    logging.info("Test suite passed: %s", module)
    return True


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


def main(disable_preflight: bool = False,
         disable_builtin: bool = False,
         disable_custom: bool = False,
         disable_behavioral: bool = False,
         verbosity: int = 1,
         failfast: bool = False) -> None:

    # Preflight: keep original behavior (failures are fatal immediately).
    if not disable_preflight:
        preflight_ok = _run_suite(
                "tests.preflight_tests",
                verbosity=verbosity,
                failfast=True,
            )

        if not preflight_ok:
            msg = "Preflight tests failed. Exiting."
            raise SystemExit(msg)

    suites = (
        (disable_builtin, "tests.regression_tests.builtin"),
        (disable_custom, "tests.regression_tests.custom"),
        (disable_behavioral, "tests.behavioral_tests"),
    )

    success = True
    for disabled, module in suites:
        if disabled:
            continue
        success = _run_suite(module, verbosity=verbosity, failfast=failfast) and success

    print(f"See the logs at {LOG_PATH}")

    if success:
        print("All tests completed successfully. Exiting.")
        return

    raise Exception("Tests failed.", )


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


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=DESCRIPTION)

    # Add flags and parameters
    parser.add_argument(
        '--disable-builtin',
        action='store_true',
        help="Disable running built-in rule tests for regression. Enabled by default."
    )
    parser.add_argument(
        '--disable-custom',
        action='store_true',
        help="Disable running custom rule tests for regression. Enabled by default."
    )
    parser.add_argument(
        '--disable-behavioral',
        action='store_true',
        help="Disable running behavioral tests. Enabled by default."
    )
    parser.add_argument(
        '--verbosity',
        type=int,
        choices=[0, 1, 2],
        default=1,
        help="Set verbosity level for test output (0, 1, or 2). Default is 1."
    )
    parser.add_argument(
        '--failfast',
        action='store_false',
        help="Stop on first failed test. Disabled by default."
    )

    # Hidden flag to disable preflight tests
    # Beware that this flag is hidden and should be used with caution
    parser.add_argument(
        '--disable-preflight',
        action='store_true',
        help=argparse.SUPPRESS
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
        main(disable_preflight=args.disable_preflight,
             disable_builtin=args.disable_builtin,
             disable_custom=args.disable_custom,
             disable_behavioral=args.disable_behavioral,
             verbosity=args.verbosity,
             failfast=args.failfast)
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
