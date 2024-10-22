#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from test_osmatch_regex.ini
class TestTest_osmatch_regexRules(unittest.TestCase):

    def test_osmatch_test_osmatch_1_dynamic_field(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osmatch_1[12345]:test_field https://localhost GET format=json'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osmatch_1')
        self.assertEqual(response.rule_id, '999902')
        self.assertEqual(response.rule_level, 3)


    def test_osmatch_test_osmatch_1_dynamic_field_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osmatch_1[12345]:test_field https://localhost GET format=raw'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osmatch_1')
        self.assertEqual(response.rule_id, '999903')
        self.assertEqual(response.rule_level, 3)


    def test_osmatch_test_osmatch_2_regex(self) -> None:
        log = '''test_osmatch_2 test_regex regex_example_0'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osmatch_2')
        self.assertEqual(response.rule_id, '999904')
        self.assertEqual(response.rule_level, 3)


    def test_osmatch_test_osmatch_2_regex_n(self) -> None:
        log = '''test_osmatch_2 test_regex regex_example_1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osmatch_2')
        self.assertEqual(response.rule_id, '999905')
        self.assertEqual(response.rule_level, 3)


    def test_osmatch_test_osmatch_3_action(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osmatch_3[12345]:test_action action_example_1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osmatch_3')
        self.assertEqual(response.rule_id, '999906')
        self.assertEqual(response.rule_level, 3)


    def test_osmatch_test_osmatch_3_action_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osmatch_3[12345]:test_action action_example_9'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osmatch_3')
        self.assertEqual(response.rule_id, '999907')
        self.assertEqual(response.rule_level, 3)

