#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from test_expr_negation_geoip.ini
class TestTest_expr_negation_geoipRules(unittest.TestCase):

    def test_expr_negation_geoip_dstgroip_1(self) -> None:
        log = '''May  1 16:17:43 wazuhUsr test_geoip[9024]: connect to 8.8.8.8 from 94.80.188.102'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation_geoip')
        self.assertEqual(response.rule_id, '999402')
        self.assertEqual(response.rule_level, 4)


    def test_expr_negation_geoip_dstgroip_2(self) -> None:
        log = '''May  1 16:17:43 wazuhUsr test_geoip[9024]: connect to 194.69.224.10 from 94.80.188.102'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation_geoip')
        self.assertEqual(response.rule_id, '999403')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_geoip_dstgroip_3(self) -> None:
        log = '''May  1 16:17:43 wazuhUsr test_geoip[9024]: connect to 200.16.16.1 from 94.80.188.102'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)


    def test_expr_negation_geoip_srcgroip_1(self) -> None:
        log = '''May  1 16:17:43 wazuhUsr test_geoip[9024]: disconnect to 94.80.188.102 from 8.8.8.8'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation_geoip')
        self.assertEqual(response.rule_id, '999400')
        self.assertEqual(response.rule_level, 4)


    def test_expr_negation_geoip_srcgroip_2(self) -> None:
        log = '''May  1 16:17:43 wazuhUsr test_geoip[9024]: disconnect to 94.80.188.102 from 194.69.224.10'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation_geoip')
        self.assertEqual(response.rule_id, '999401')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_geoip_srcgroip_3(self) -> None:
        log = '''May  1 16:17:43 wazuhUsr test_geoip[9024]: disconnect to 94.80.188.102 from 200.16.16.1'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)

