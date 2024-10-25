#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from cimserver.ini
class TestCimserverRules(unittest.TestCase):

    def test_rshd_illegal_1(self) -> None:
        log = r'''
Dec 18 18:06:28 hostname cimserver[18575]: PGS17200: Authentication failed for user jones_b.
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cimserver')
        self.assertEqual(response.rule_id, '9610')
        self.assertEqual(response.rule_level, 5)


    def test_rshd_illegal_2(self) -> None:
        log = r'''
Dec 18 18:06:29 hostname vimserver[18575]: PGS17200: Authentication failed for user domain\jones_b.
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '9610')

