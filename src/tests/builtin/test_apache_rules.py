#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from apache.ini
class TestApacheRules(unittest.TestCase):

    def test_apache_attempt_to_access_forbidden_directory_index(self) -> None:
        log = '''[error] [client 80.230.208.105] Directory index forbidden by rule: /home/'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'apache-errorlog')
        self.assertEqual(response.rule_id, '30106')
        self.assertEqual(response.rule_level, 5)


    def test_apache_code_red_attack(self) -> None:
        log = '''[error] [client 64.94.163.159] Client sent malformed Host header'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'apache-errorlog')
        self.assertEqual(response.rule_id, '30107')
        self.assertEqual(response.rule_level, 6)


    def test_apache_attempt_to_access_an_non_existent_file(self) -> None:
        log = '''[error] [client 66.31.142.16] File does not exist: /var/www/html/default.ida'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'apache-errorlog')
        self.assertEqual(response.rule_id, '30112')
        self.assertEqual(response.rule_level, 0)


    def test_apache_notice_messages_grouped(self) -> None:
        log = '''[notice] Apache configured'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'apache-errorlog')
        self.assertEqual(response.rule_id, '30103')
        self.assertEqual(response.rule_level, 0)


    def test_apache_apache_22_error_messages_grouped(self) -> None:
        log = '''[Fri Dec 13 06:59:54 2013] [error] [client 12.34.65.78] PHP Notice:'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'apache-errorlog')
        self.assertEqual(response.rule_id, '30101')
        self.assertEqual(response.rule_level, 0)


    def test_apache_apache_24_error_messages_grouped_1(self) -> None:
        log = '''[Tue Sep 30 11:30:13.262255 2014] [core:error] [pid 20101] [client 99.47.227.95:34567] AH00037: Symbolic link not allowed or link target not accessible: /usr/share/awstats/icon/mime/document.png'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'apache-errorlog')
        self.assertEqual(response.rule_id, '30301')
        self.assertEqual(response.rule_level, 0)


    def test_apache_apache_24_error_messages_grouped_2(self) -> None:
        log = '''[Tue Sep 30 12:11:21.258612 2014] [ssl:error] [pid 30473] AH02032: Hostname www.example.com provided via SNI and hostname ssl://www.example.com provided via HTTP are different'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'apache-errorlog')
        self.assertEqual(response.rule_id, '30301')
        self.assertEqual(response.rule_level, 0)


    def test_apache_apache_24_warn_messages_grouped(self) -> None:
        log = '''[Tue Sep 30 12:24:22.891366 2014] [proxy:warn] [pid 2331] [client 77.127.180.111:54082] AH01136: Unescaped URL path matched ProxyPass; ignoring unsafe nocanon, referer: http://www.easylinker.co.il/he/links.aspx?user=bguyb'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'apache-errorlog')
        self.assertEqual(response.rule_id, '30302')
        self.assertEqual(response.rule_level, 0)


    def test_apache_attempt_to_access_forbidden_file_or_directory(self) -> None:
        log = '''[Tue Sep 30 14:25:44.895897 2014] [authz_core:error] [pid 31858] [client 99.47.227.95:38870] AH01630: client denied by server configuration: /var/www/example.com/docroot/'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'apache-errorlog')
        self.assertEqual(response.rule_id, '30305')
        self.assertEqual(response.rule_level, 5)


    def test_apache_messages_grouped_1(self) -> None:
        log = '''[Thu Oct 23 15:17:55.926067 2014] [ssl:info] [pid 18838] [client 36.226.119.49:2359] AH02008: SSL library error 1 in handshake (server www.example.com:443)'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'apache-errorlog')
        self.assertEqual(response.rule_id, '30100')
        self.assertEqual(response.rule_level, 0)


    def test_apache_messages_grouped_2(self) -> None:
        log = '''[Thu Oct 23 15:17:55.926123 2014] [ssl:info] [pid 18838] SSL Library Error: error:1407609B:SSL routines:SSL23_GET_CLIENT_HELLO:https proxy request -- speaking HTTP to HTTPS port!?'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'apache-errorlog')
        self.assertEqual(response.rule_id, '30100')
        self.assertEqual(response.rule_level, 0)


    def test_apache_php_notices_in_apache_24_errorlog(self) -> None:
        log = '''[Sun Nov 23 18:49:01.713508 2014] [:error] [pid 15816] [client 141.8.147.9:51507] PHP Notice:  A non well formed numeric value encountered in /path/to/file.php on line 123'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'apache-errorlog')
        self.assertEqual(response.rule_id, '30318')
        self.assertEqual(response.rule_level, 5)

