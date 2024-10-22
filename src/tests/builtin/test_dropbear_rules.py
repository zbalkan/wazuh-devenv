#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from dropbear.ini
class TestDropbearRules(unittest.TestCase):

    def test_dropbear_bad_password_attempt(self) -> None:
        log = '''Jan  8 16:39:33 tp.lan dropbear[14824]: Bad password attempt for 'root' from 193.219.28.149:48629'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'dropbear')
        self.assertEqual(response.rule_id, '51003')
        self.assertEqual(response.rule_level, 5)


    def test_dropbear_bad_password_attempt_for_non_existing_user(self) -> None:
        log = '''Jan  8 19:54:12 tp.lan dropbear[15197]: Login attempt for nonexistent user from 182.72.89.122:4328'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'dropbear')
        self.assertEqual(response.rule_id, '51093')
        self.assertEqual(response.rule_level, 5)


    def test_dropbear_user_successfully_logged_in_using_a_public_key(self) -> None:
        log = '''Jan  8 19:32:41 tp.lan dropbear[15165]: Pubkey auth succeeded for 'root' with key md5 78:d6:41:ca:78:37:80:88:1d:15:0a:68:91:d1:4e:ad from 10.10.10.241:51737'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'dropbear')
        self.assertEqual(response.rule_id, '51010')
        self.assertEqual(response.rule_level, 0)

