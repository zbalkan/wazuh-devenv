#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from opensmtpd.ini
class TestOpensmtpdRules(unittest.TestCase):

    def test_message_failed(self) -> None:
        log = '''Aug 14 10:15:25 junction.example.com smtpd[28882]: smtp-in: Failed command on session 1f55bdcdf16e28a3: "MAIL FROM:<root@junction.example.com>  " => 421 4.3.0: Temporary Error'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'smtpd')
        self.assertEqual(response.rule_id, '53501')
        self.assertEqual(response.rule_level, 3)


    def test_new_session(self) -> None:
        log = '''Aug 17 01:26:02 ix smtpd[22704]: smtp-in: New session 08d856b172f69c5c from host ix.example.com [local]'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'smtpd')
        self.assertEqual(response.rule_id, '53502')
        self.assertEqual(response.rule_level, 0)


    def test_message_accepted(self) -> None:
        log = '''Aug 17 01:26:02 ix smtpd[22704]: smtp-in: Accepted message 4296f490 on session 08d856b172f69c5c: from=<root@ix.example.com>, to=<ddp@ix.example.com>, size=1746, ndest=1, proto=ESMTP'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'smtpd')
        self.assertEqual(response.rule_id, '53504')
        self.assertEqual(response.rule_level, 0)


    def test_session_closed(self) -> None:
        log = '''Aug 17 01:26:02 ix smtpd[22704]: smtp-in: Closing session 08d856b172f69c5c'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'smtpd')
        self.assertEqual(response.rule_id, '53503')
        self.assertEqual(response.rule_level, 0)


    def test_disconnect(self) -> None:
        log = '''Mar  4 00:11:00 ix smtpd[22421]: smtp-in: Received disconnect from session 427e7493ebe154ae'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'smtpd')
        self.assertEqual(response.rule_id, '53500')
        self.assertEqual(response.rule_level, 0)


    def test_no_ssl(self) -> None:
        log = '''Mar  4 00:13:55 ix smtpd[22421]: smtp-in: Disconnecting session 427e7497e03518ef: IO error: No SSL error'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'smtpd')
        self.assertEqual(response.rule_id, '53507')
        self.assertEqual(response.rule_level, 2)


    def test_started_tls(self) -> None:
        log = '''Mar  4 00:13:55 ix smtpd[22421]: smtp-in: Started TLS on session 427e749c2e46f809: version=TLSv1.2, cipher=EDH-RSA-DES-CBC3-SHA, bits=112'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'smtpd')
        self.assertEqual(response.rule_id, '53500')
        self.assertEqual(response.rule_level, 0)

