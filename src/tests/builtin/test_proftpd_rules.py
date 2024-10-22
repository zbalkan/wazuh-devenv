#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from proftpd.ini
class TestProftpdRules(unittest.TestCase):

    def test_unable_to_open_incoming_connection_reason_may_vary(self) -> None:
        log = '''Jan 04 22:51:57 server proftpd[26169] server.example.net: Fatal: unable to open incoming connection: Der Socket ist nicht verbunden'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'proftpd')
        self.assertEqual(response.rule_id, '11222')
        self.assertEqual(response.rule_level, 4)


    def test_ftp_authentication_success_1(self) -> None:
        log = '''Jan 04 22:51:57 hayaletgemi proftpd[26916]: hayaletgemi (85.101.218.135[85.101.218.135]) - ANON anonymous: Login successful.'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'proftpd')
        self.assertEqual(response.rule_id, '11205')
        self.assertEqual(response.rule_level, 3)


    def test_ftp_authentication_success_2(self) -> None:
        log = '''Jan 04 22:51:57 juf01 proftpd[12564]: juf01 (pD9EE35B1.dip.t-dialin.net[217.238.53.177]) - USER jufu: Login successful'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'proftpd')
        self.assertEqual(response.rule_id, '11205')
        self.assertEqual(response.rule_level, 3)


    def test_ftp_authentication_success_3(self) -> None:
        log = '''Jan 04 22:51:57 xx.yy.zz proftpd[30362] xx.yy.zz (aa.bb.cc[aa.bb.vv.dd]): USER backup: Login successful.'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'proftpd')
        self.assertEqual(response.rule_id, '11205')
        self.assertEqual(response.rule_level, 3)


    def test_connection_refused_by_tcp_wrappers(self) -> None:
        log = '''Jan 04 22:51:57 server proftpd[2344]: refused connect from 192.168.1.2 (192.168.1.2)'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'proftpd')
        self.assertEqual(response.rule_id, '11207')
        self.assertEqual(response.rule_level, 5)


    def test_connection_denied_by_proftpd_configuration(self) -> None:
        log = '''Jan 04 22:51:57 valhalla proftpd[15181]: valhalla (crawl-66-249-66-80.googlebot.com[66.249.66.80]) - Connection from crawl-66-249-66-80.googlebot.com [66.249.66.80] denied.'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'proftpd')
        self.assertEqual(response.rule_id, '11206')
        self.assertEqual(response.rule_level, 5)


    def test_login_failed_accessing_the_ftp_server(self) -> None:
        log = '''2015-04-16 21:51:02,805 zuse proftpd[26189] zuse.domain.com (182.100.67.115[182.100.67.115]): USER root (Login failed): Incorrect password'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'proftpd')
        self.assertEqual(response.rule_id, '11204')
        self.assertEqual(response.rule_level, 5)

