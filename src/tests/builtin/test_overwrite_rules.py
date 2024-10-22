#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from overwrite.ini
class TestOverwriteRules(unittest.TestCase):

    def test_do_not_match_overwritten_rule(self) -> None:
        log = '''Apr 14 13:38:51 testUser ow_test[13244]: TEST 1 - rule to be overwritten'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)


    def test_overwrite_success(self) -> None:
        log = '''Apr 14 13:38:51 testUser ow_test[13244]: TEST 1 - rule overwritten'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'ow_test')
        self.assertEqual(response.rule_id, '999911')
        self.assertEqual(response.rule_level, 12)


    def test_overwrite_success_and_child_matches_1(self) -> None:
        log = '''Apr 14 13:38:51 testUser ow_test[13244]: TEST 1 - rule overwritten'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'ow_test')
        self.assertEqual(response.rule_id, '999912')
        self.assertEqual(response.rule_level, 12)


    def test_overwrite_success_and_child_matches_2(self) -> None:
        log = '''Apr 14 13:38:51 testUser ow_test[13244]: TEST 1 - rule overwritten'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'ow_test')
        self.assertEqual(response.rule_id, '999912')
        self.assertEqual(response.rule_level, 12)


    def test_overwrite_success_and_child_matches_3(self) -> None:
        log = '''Apr 14 13:38:51 testUser ow_test[13244]: TEST 1 - rule overwritten'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'ow_test')
        self.assertEqual(response.rule_id, '999912')
        self.assertEqual(response.rule_level, 12)


    def test_overwrite_if_matched_sid_1(self) -> None:
        log = '''Apr 14 13:38:51 testUser ow_test[13244]: TEST 2 - Parent rule'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'ow_test')
        self.assertEqual(response.rule_id, '999914')
        self.assertEqual(response.rule_level, 12)


    def test_overwrite_if_matched_sid_2(self) -> None:
        log = '''Apr 14 13:38:51 testUser ow_test[13244]: TEST 2 - Parent rule'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'ow_test')
        self.assertEqual(response.rule_id, '999914')
        self.assertEqual(response.rule_level, 12)


    def test_overwrite_if_matched_sid_3(self) -> None:
        log = '''Apr 14 13:38:51 testUser ow_test[13244]: TEST 2 - Parent rule'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'ow_test')
        self.assertEqual(response.rule_id, '999914')
        self.assertEqual(response.rule_level, 12)


    def test_overwrite_if_matched_group_1(self) -> None:
        log = '''Apr 14 13:38:51 testUser ow_test[13244]: TEST 3 - Parent rule'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'ow_test')
        self.assertEqual(response.rule_id, '999917')
        self.assertEqual(response.rule_level, 12)


    def test_overwrite_if_matched_group_2(self) -> None:
        log = '''Apr 14 13:38:51 testUser ow_test[13244]: TEST 3 - Parent rule'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'ow_test')
        self.assertEqual(response.rule_id, '999917')
        self.assertEqual(response.rule_level, 12)


    def test_overwrite_if_matched_group_3(self) -> None:
        log = '''Apr 14 13:38:51 testUser ow_test[13244]: TEST 3 - Parent rule'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'ow_test')
        self.assertEqual(response.rule_id, '999917')
        self.assertEqual(response.rule_level, 12)


    def test_overwrite_&_list(self) -> None:
        log = '''May 27 14:49:04 testUser ow_test[13244]: TEST 4 - Overwrite and list test'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'ow_test')
        self.assertEqual(response.rule_id, '999918')
        self.assertEqual(response.rule_level, 5)


    def test_overwrite_&_field(self) -> None:
        log = '''Apr 14 13:38:51 testUser test_overwrite_field[13244]: Test example 'TEST5' field'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_overwrite')
        self.assertEqual(response.rule_id, '999919')
        self.assertEqual(response.rule_level, 6)


    def test_multiple_overwrite(self) -> None:
        log = '''Apr 14 13:38:51 testUser test_overwrite_field[13244]: Test example 'MULTIPLE' field'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_overwrite')
        self.assertEqual(response.rule_id, '999920')
        self.assertEqual(response.rule_level, 3)


    def test_overwrite_with_if_sid(self) -> None:
        log = '''Apr 14 13:38:51 testUser test_overwrite_field[13244]: Test example 'TEST7' field'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_overwrite')
        self.assertEqual(response.rule_id, '999922')
        self.assertEqual(response.rule_level, 3)


    def test_overwrite_with_if_level(self) -> None:
        log = '''Apr 14 13:38:51 testUser test_overwrite_field[13244]: Test example 'TEST8' field'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_overwrite')
        self.assertEqual(response.rule_id, '999924')
        self.assertEqual(response.rule_level, 3)

