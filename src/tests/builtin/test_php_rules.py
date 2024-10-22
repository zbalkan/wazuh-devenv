#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from php.ini
class TestPhpRules(unittest.TestCase):

    def test_php_web_attack(self) -> None:
        log = '''2014/12/30 06:07:37 [error] PHP Warning: urlencode() expects parameter 1 to be string, array given in'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'nginx-errorlog')
        self.assertEqual(response.rule_id, '31411')
        self.assertEqual(response.rule_level, 6)


    def test_php_internal_error_missing_file_or_function(self) -> None:
        log = '''2014/12/30 06:07:37 [error] PHP Fatal error:  require_once() [<a href='function.require'>function.require</a>]: Failed opening required 'includes/SkinTemplate.php''''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'nginx-errorlog')
        self.assertEqual(response.rule_id, '31421')
        self.assertEqual(response.rule_level, 5)

