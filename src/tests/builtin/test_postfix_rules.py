#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from postfix.ini
class TestPostfixRules(unittest.TestCase):

    def test_reject_rcpt(self) -> None:
        log = '''May  8 08:26:55 mail postfix/postscreen[22055]: NOQUEUE: reject: RCPT from [157.122.148.242]:47407: 9999 text ...'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'postfix-reject')
        self.assertEqual(response.rule_id, '3300')
        self.assertEqual(response.rule_level, 0)


    def test_reject_rcpt2(self) -> None:
        log = '''May  8 08:26:55 mail postfix/postscreen[22055]: NOQUEUE: reject: RCPT from [157.122.148.242]:47407: 550 5.7.1 Service unavailable; client [157.122.148.242] blocked using bl.spamcop.net; f$'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'postfix-reject')
        self.assertEqual(response.rule_id, '3306')
        self.assertEqual(response.rule_level, 6)

