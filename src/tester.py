#!/usr/bin/python3
# -*- coding: utf-8 -*-

import logging
import os
import sys
import unittest
from typing import Final

from internal.result import ResultRunTests

APP_NAME: Final[str] = 'tester'
APP_VERSION: Final[str] = '0.1'
DESCRIPTION: Final[str] = f"{APP_NAME} ({APP_VERSION}) is a Wazuh rule and decoder testing tool."
ENCODING: Final[str] = "utf-8"


def main() -> None:

    # Create a test loader for the preflight tests
    print('Running preflight tests...')
    preflight_test_loader = unittest.TestLoader()
    # Check file permissions first
    prefligh_tests = preflight_test_loader.discover(
        'tests.preflight', pattern='test*.py')
    runner = unittest.TextTestRunner(verbosity=2)
    # Run the discovered tests
    test_result = runner.run(prefligh_tests)
    # # Print the results in a structured way
    print(ResultRunTests(test_result))

    # print('Running builtin rule tests...')
    # # Create a test loader for the rule tests
    # builtin_loader = unittest.TestLoader()
    # # Discover all test cases in the current directory matching the pattern 'test*.py'
    # builtin_rule_tests = builtin_loader.discover(
    #     'tests.builtin', pattern='test*.py')
    # # Create a test runner that will output the results to the console
    # runner = unittest.TextTestRunner(
    #     verbosity=2)
    # # Run the discovered tests
    # builtin_test_result = runner.run(builtin_rule_tests)
    # # # Print the results in a structured way
    # print(ResultRunTests(builtin_test_result))

    print('Running custom rule tests...')
    # Create a test loader for the rule tests
    custom_loader = unittest.TestLoader()
    # Discover all test cases in the current directory matching the pattern 'test*.py'
    custom_rule_tests = custom_loader.discover(
        'tests.custom', pattern='test*.py')
    # Create a test runner that will output the results to the console
    runner = unittest.TextTestRunner(
        verbosity=2)
    # Run the discovered tests
    custom_test_result = runner.run(custom_rule_tests)
    # # Print the results in a structured way
    result = ResultRunTests(custom_test_result)
    print(result.verbose_result)


def setup_logging() -> None:
    log_path = os.path.join(f'/var/ossec/logs/{APP_NAME}.log')
    logging.basicConfig(
            filename=os.path.join(log_path),
            encoding=ENCODING,
            format='%(asctime)s:%(name)s:%(levelname)s:%(message)s',
            datefmt="%Y-%m-%dT%H:%M:%S%z",
            level= logging.INFO
        )

    sys.excepthook = lambda exc_type, exc_value, exc_traceback: logging.error(
        "Unhandled exception", exc_info=(exc_type, exc_value, exc_traceback))


if __name__ == "__main__":
    try:
        setup_logging()

        logging.info(f'Starting {APP_NAME} v{APP_VERSION}')
        logging.info(DESCRIPTION)
        main()
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
