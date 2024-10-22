#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from rsh.ini
class TestRshRules(unittest.TestCase):

    def test_rshd_illegal_1(self) -> None:
        log = '''Dec 17 10:49:23 hostname rshd[347339]: Connection from 10.217.223.31 on illegal port'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'rshd')
        self.assertEqual(response.rule_id, '2551')
        self.assertEqual(response.rule_level, 10)


    def test_rshd_illegal_2(self) -> None:
        log = '''Dec 17 10:49:23 hostname rhsd[347339]: Connection from 10.217.223.31 on illegal port'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)

