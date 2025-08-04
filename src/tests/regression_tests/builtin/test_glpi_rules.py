#!/usr/bin/env python3


# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from glpi.ini
class TestGlpiRules(unittest.TestCase):

    def test_apache_glpi_error_log(self) -> None:
        log = r'''
[Wed Jul 31 16:44:52.906254 2019] [suexec:notice] [pid 8575] AH01232: suEXEC mechanism enabled (wrapper: /usr/sbin/suexec)
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'apache-errorlog')
        self.assertEqual(response.rule_id, '30303')
        self.assertEqual(response.rule_level, 0)


    def test_web_accesslog_glpi_get_message(self) -> None:
        log = r'''
11.0.0.1 - - [31/Jul/2019:16:58:19 +0000] "GET /index.php HTTP/1.1" 200 2213 "http://11.0.0.16/install/install.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36"
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'web-accesslog')
        self.assertEqual(response.rule_id, '31108')
        self.assertEqual(response.rule_level, 0)


    def test_web_accesslog_glpi_options_message(self) -> None:
        log = r'''
::1 - - [31/Jul/2019:16:58:43 +0000] "OPTIONS * HTTP/1.0" 200 - "-" "Apache/2.4.6 (CentOS) PHP/5.6.40 (internal dummy connection)"
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'web-accesslog')
        self.assertEqual(response.rule_id, '31108')
        self.assertEqual(response.rule_level, 0)

