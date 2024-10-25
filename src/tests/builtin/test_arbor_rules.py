#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from arbor.ini
class TestArborRules(unittest.TestCase):

    def test_blocked_host_1(self) -> None:
        log = r'''
Sep 11 23:23:32 user arbor-networks-aps: Blocked Host: Blocked host xxx.xxx.xxx.xxx at hh:mm by Invalid Packets using TCP/23 (TELNET) destination yyy.yyy.yyy.yyy source port pppp,URL: http://web
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'arbor')
        self.assertEqual(response.rule_id, '88801')
        self.assertEqual(response.rule_level, 7)


    def test_blocked_host_2(self) -> None:
        log = r'''
Sep 11 23:23:32 user arbor-networks-aps: Blocked Host: Blocked host xxx.xxx.xxx.xxx at hh:mm by TCP SYN Flood Detection using TCP/3306 (MYSQL) destination yyy.yyy.yyy.yyy source port ppp,URL: http://web
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'arbor')
        self.assertEqual(response.rule_id, '88801')
        self.assertEqual(response.rule_level, 7)

