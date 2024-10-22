#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from test_pcre2_regex_geoip.ini
class TestTest_pcre2_regex_geoipRules(unittest.TestCase):

    def test_pcre2_test_pcre2_16_srcgeoip(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_16[12345]:test_srcgeoip 8.8.8.8'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_16')
        self.assertEqual(response.rule_id, '999600')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_16_srcgeoip_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_16[12345]:test_srcgeoip 194.69.224.10'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_16')
        self.assertEqual(response.rule_id, '999601')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_17_dstgeoip(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_17[12345]:test_dstgeoip 8.8.8.8'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_17')
        self.assertEqual(response.rule_id, '999602')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_17_dstgeoip_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_17[12345]:test_dstgeoip 194.69.224.10'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_17')
        self.assertEqual(response.rule_id, '999603')
        self.assertEqual(response.rule_level, 3)

