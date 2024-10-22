#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from vsftpd.ini
class TestVsftpdRules(unittest.TestCase):

    def test_connect_1(self) -> None:
        log = '''Wed Jul 27 18:32:27 2016 [pid 2] CONNECT: Client "fe80::baac:6fff:fe7d:d2e0"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'vsftpd')
        self.assertEqual(response.rule_id, '11401')
        self.assertEqual(response.rule_level, 3)


    def test_connect_2(self) -> None:
        log = '''Wed Jul 27 18:32:27 2016 [pid 2] CONNECT: Client "10.11.12.13"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'vsftpd')
        self.assertEqual(response.rule_id, '11401')
        self.assertEqual(response.rule_level, 3)


    def test_login_1(self) -> None:
        log = '''Mon Oct 24 11:32:53 2016 [pid 1] [$ALOC$] FAIL LOGIN: Client "10.55.112.101"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'vsftpd')
        self.assertEqual(response.rule_id, '11403')
        self.assertEqual(response.rule_level, 5)


    def test_login_2(self) -> None:
        log = '''Mon Oct 24 11:32:53 2016 [pid 1] [$ALOC$] FAIL LOGIN: Client "fe80::baac:6fff:fe7d:d2e0"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'vsftpd')
        self.assertEqual(response.rule_id, '11403')
        self.assertEqual(response.rule_level, 5)

