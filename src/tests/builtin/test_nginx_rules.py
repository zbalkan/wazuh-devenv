#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from nginx.ini
class TestNginxRules(unittest.TestCase):

    def test_nginx_messages_grouped(self) -> None:
        log = r'''
2014/12/30 06:07:37 [yadda] 80:2 yadda yadda
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'nginx-errorlog')
        self.assertEqual(response.rule_id, '31300')
        self.assertEqual(response.rule_level, 0)


    def test_nginx_error_message(self) -> None:
        log = r'''
2014/12/30 06:07:37 [error] 80:2 yadda yadda
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'nginx-errorlog')
        self.assertEqual(response.rule_id, '31301')
        self.assertEqual(response.rule_level, 3)


    def test_nginx_warning_message(self) -> None:
        log = r'''
2014/12/30 06:07:37 [warn] 80:2 yadda yadda
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'nginx-errorlog')
        self.assertEqual(response.rule_id, '31302')
        self.assertEqual(response.rule_level, 3)


    def test_nginx_critical_message(self) -> None:
        log = r'''
2014/12/30 06:07:37 [crit] 80:2
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'nginx-errorlog')
        self.assertEqual(response.rule_id, '31303')
        self.assertEqual(response.rule_level, 5)


    def test_server_returned_404_reported_in_the_accesslog_1(self) -> None:
        log = r'''
2015/01/08 11:31:23 [error] 80:2 blah blah failed (2: No such file or directory)
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'nginx-errorlog')
        self.assertEqual(response.rule_id, '31310')
        self.assertEqual(response.rule_level, 0)


    def test_server_returned_404_reported_in_the_accesslog_2(self) -> None:
        log = r'''
2015/01/08 11:31:23 [error] 80:2 blah blah is not found (2: No such file or directory)
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'nginx-errorlog')
        self.assertEqual(response.rule_id, '31310')
        self.assertEqual(response.rule_level, 0)


    def test_incomplete_client_request(self) -> None:
        log = r'''
2015/01/08 11:31:23 [error] 80:2 blah blah accept() failed (53: Software caused connection abort)
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'nginx-errorlog')
        self.assertEqual(response.rule_id, '31311')
        self.assertEqual(response.rule_level, 0)


    def test_initial_401_authentication_request(self) -> None:
        log = r'''
2015/01/08 11:31:23 [error] 80:2 no user/password was provided for basic authentication
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'nginx-errorlog')
        self.assertEqual(response.rule_id, '31312')
        self.assertEqual(response.rule_level, 0)


    def test_web_authentication_failed_1(self) -> None:
        log = r'''
2015/01/08 11:31:23 [error] 80:2 yadda password mismatch, client yadda
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'nginx-errorlog')
        self.assertEqual(response.rule_id, '31315')
        self.assertEqual(response.rule_level, 5)


    def test_web_authentication_failed_2(self) -> None:
        log = r'''
2015/01/08 11:31:23 [error] 80:2 yadda was not found in yadda
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'nginx-errorlog')
        self.assertEqual(response.rule_id, '31315')
        self.assertEqual(response.rule_level, 5)


    def test_common_cache_error_when_files_were_removed(self) -> None:
        log = r'''
2015/01/08 11:31:23 [crit] 80:2 yadda yadda failed (2: No such file or directory
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'nginx-errorlog')
        self.assertEqual(response.rule_id, '31317')
        self.assertEqual(response.rule_level, 0)


    def test_invalid_uri_file_name_too_long(self) -> None:
        log = r'''
2015/01/08 11:31:23 [error] 80:2 yadda yadda failed (36: File name too long)
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'nginx-errorlog')
        self.assertEqual(response.rule_id, '31320')
        self.assertEqual(response.rule_level, 10)

