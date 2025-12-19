#!/usr/bin/env python3

import logging
import unittest
from typing import Optional

from internal.result import ResultRunTests


def _failed(result: unittest.TestResult) -> bool:
    """Return True if the test result contains any errors or failures."""
    return bool(result.errors or result.failures)


def _run_suite(module: str, *, verbosity: int, failfast: bool) -> bool:
    """
    Run tests for `module` and return True if the suite passed.

    If `failfast` is True, abort immediately on failure.
    """
    result: Optional[unittest.TestResult] = _run_tests(module, verbosity=verbosity)

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


def _run_tests(test_directory: str, pattern: str = 'test_*.py', verbosity: int = 1) -> Optional[unittest.result.TestResult]:
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


def run(disable_preflight: bool = False,
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
