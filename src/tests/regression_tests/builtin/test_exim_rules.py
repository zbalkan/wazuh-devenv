#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from exim.ini
class TestEximRules(unittest.TestCase):

    def test_exim_auth_failure_1(self) -> None:
        log = r'''
2017-01-23 03:44:14 dovecot_login authenticator failed for (hydra) [10.101.1.18]:35686: 535 Incorrect authentication data (set_id=user)
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'windows-date-format')
        self.assertEqual(response.rule_id, '87502')
        self.assertEqual(response.rule_level, 5)


    def test_exim_auth_failure_2(self) -> None:
        log = r'''
2017-01-24 05:22:29 dovecot_plain authenticator failed for (test) [::1]:39454: 535 Incorrect authentication data (set_id=test)
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'windows-date-format')
        self.assertEqual(response.rule_id, '87502')
        self.assertEqual(response.rule_level, 5)


    def test_exim_connection(self) -> None:
        log = r'''
2017-01-24 03:09:46 SMTP connection from [10.101.1.10]:55010 (TCP/IP connection count = 1)
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'windows-date-format')
        self.assertEqual(response.rule_id, '87504')
        self.assertEqual(response.rule_level, 0)


    def test_exim_connection_lost(self) -> None:
        log = r'''
2017-01-24 02:53:13 SMTP connection from (hydra) [10.101.1.10]:53682 lost
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'windows-date-format')
        self.assertEqual(response.rule_id, '87505')
        self.assertEqual(response.rule_level, 1)


    def test_exim_syntax_protocol_error(self) -> None:
        log = r'''
2017-01-24 05:36:23 SMTP call from (000000) [::1]:39480 dropped: too many syntax or protocol errors (last command was "123")
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'windows-date-format')
        self.assertEqual(response.rule_id, '87506')
        self.assertEqual(response.rule_level, 5)


    def test_exim_protocol_synchronization_error(self) -> None:
        log = r'''
2019-10-20 11:14:38 SMTP protocol synchronization error (input sent without waiting for greeting): rejected connection from H=[134.234.45.34] input="GET / HTTP/1.1\r\nHost: 24.255.212.213:98\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:47.0) Gecko/20100101 Firefox/47.0\r\nAccept: */*\r\n"
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'windows-date-format')
        self.assertEqual(response.rule_id, '87507')
        self.assertEqual(response.rule_level, 6)


    def test_exim_unrouteable_address(self) -> None:
        log = r'''
2019-10-20 09:56:39 H=123-123-12-123.example.example.net [123.123.12.123] F=<example@example.com> rejected RCPT <example@exampley.com>: Unrouteable address
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'windows-date-format')
        self.assertEqual(response.rule_id, '87508')
        self.assertEqual(response.rule_level, 6)

