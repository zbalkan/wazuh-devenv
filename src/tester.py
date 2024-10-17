#!/usr/bin/python3
# -*- coding: utf-8 -*-
import logging
import os
import sys
from configparser import ConfigParser
from datetime import datetime, timezone
from typing import Final
import unittest

APP_NAME: Final[str] = 'tester'
APP_VERSION: Final[str] = '0.1'
DESCRIPTION: Final[str] = f"{APP_NAME} ({APP_VERSION}) is a Wazuh rule and decoder testing tool."
ENCODING: Final[str] = "utf-8"
    
def main() -> None:
    # Create a test loader
    loader = unittest.TestLoader()
    # Discover all test cases in the current directory matching the pattern 'test*.py'
    tests = loader.discover('tests', pattern='test*.py')
    # Create a test runner that will output the results to the console
    runner = unittest.TextTestRunner(verbosity=2)
    # Run the discovered tests
    runner.run(tests)


def setup_logging() -> None:
    log_path = os.path.join(f'/var/ossec/logs/{APP_NAME}.log')
    logging.basicConfig(
            filename=os.path.join(log_path),
            encoding=ENCODING,
            format='%(asctime)s:%(name)s:%(levelname)s:%(message)s',
            datefmt="%Y-%m-%dT%H:%M:%S%z",
            level= logging.INFO
        )

    excepthook = logging.error

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
        logging.error(ex, exc_info=True)
        try:
            sys.exit(1)
        except SystemExit:
            os._exit(1)