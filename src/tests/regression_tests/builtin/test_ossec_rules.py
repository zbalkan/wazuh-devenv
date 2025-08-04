#!/usr/bin/env python3


# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from ossec.ini
class TestOssecRules(unittest.TestCase):

    def test_ossec_active_response_add_host(self) -> None:
        log = r'''
Sat May  7 03:17:27 CDT 2011 /var/ossec/active-response/bin/host-deny.sh add - 172.16.0.1 1304756247.60385 31151
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'ar_log')
        self.assertEqual(response.rule_id, '603')
        self.assertEqual(response.rule_level, 3)


    def test_ossec_active_response_add_firewall(self) -> None:
        log = r'''
Sat May  7 03:17:27 CDT 2011 /var/ossec/active-response/bin/firewall-drop.sh add - 172.16.0.1 1304756247.60385 31151
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'ar_log')
        self.assertEqual(response.rule_id, '601')
        self.assertEqual(response.rule_level, 3)


    def test_ossec_active_response_delete_host(self) -> None:
        log = r'''
Sat May  7 03:27:57 CDT 2011 /var/ossec/active-response/bin/host-deny.sh delete - 172.16.0.1 1304756247.60385 31151
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'ar_log')
        self.assertEqual(response.rule_id, '604')
        self.assertEqual(response.rule_level, 3)


    def test_ossec_active_response_delete_firewall(self) -> None:
        log = r'''
Sat May  7 03:27:57 CDT 2011 /var/ossec/active-response/bin/firewall-drop.sh delete - 172.16.0.1 1304756247.60385 31151
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'ar_log')
        self.assertEqual(response.rule_id, '602')
        self.assertEqual(response.rule_level, 3)


    def test_ossec_logcollector_ignore_informational_messages_at_startup(self) -> None:
        log = r'''
2015/01/29 21:09:49 ossec-logcollector(1950): INFO: Analyzing file: '/var/log/httpd/error_log'.
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'ossec-logcollector')
        self.assertEqual(response.rule_id, '701')
        self.assertEqual(response.rule_level, 0)

