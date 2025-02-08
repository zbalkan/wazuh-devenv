#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from modsecurity.ini
class TestModsecurityRules(unittest.TestCase):

    def test_modsecurity_warning_messages_grouped_1(self) -> None:
        log = r'''
[Mon Feb 09 16:47:55.974089 2015] [:error] [pid 17675] [client 172.16.10.87] ModSecurity: Warning. Operator GE matched 4 at TX:outbound_anomaly_score. [file "/etc/apache2/ModSecurity/activated_rules/modsecurity_crs_60_correlation.conf"] [line "40"] [id "981205"] [msg "Outbound Anomaly Score Exceeded (score 4): The application is not available"] [hostname "172.16.10.91"] [uri "/wordpress/wp-includes/rss-functions.php"] [unique_id "VNkA238AAQEAAEULYMwAAAAA"]
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'apache-errorlog')
        self.assertEqual(response.rule_id, '30401')
        self.assertEqual(response.rule_level, 0)


    def test_modsecurity_warning_messages_grouped_2(self) -> None:
        log = r'''
[Thu Jan 22 14:33:30.959520 2015] [:error] [pid 2406] [client 172.16.10.87] ModSecurity: Warning. Pattern match "^(?i)(?:ft|htt)ps?(.*?)\\\\?+$" at ARGS:path_prefix. [file "/etc/apache2/ModSecurity/activated_rules/modsecurity_crs_40_generic_attacks.conf"] [line "160"] [id "950119"] [rev "2"] [msg "Remote File Inclusion Attack"] [data "Matched Data: http://cirt.net/rfiinc.txt? found within ARGS:path_prefix: http://cirt.net/rfiinc.txt?"] [severity "CRITICAL"] [ver "OWASP_CRS/2.2.9"] [maturity "9"] [accuracy "9"] [tag "OWASP_CRS/WEB_ATTACK/RFI"] [hostname "172.16.10.91"] [uri "/wordpress/web/BetaBlockModules//Module/Module.php"] [unique_id "VMEmWn8AAQEAAAlmdHgAAAAI"]
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'apache-errorlog')
        self.assertEqual(response.rule_id, '30401')
        self.assertEqual(response.rule_level, 0)


    def test_modsecurity_audit_log_messages_grouped_1(self) -> None:
        log = r'''
[Mon Feb 09 21:17:06.798110 2015] [:error] [pid 8608] [client 172.16.10.57] ModSecurity: Audit log: Failed writing (requested 83 bytes, written 24): No space left on device [hostname "172.16.10.91"] [uri "/403.php"] [unique_id "VNk-8n8AAQEAACGg7LEAAAAE"]
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'apache-errorlog')
        self.assertEqual(response.rule_id, '30403')
        self.assertEqual(response.rule_level, 0)


    def test_modsecurity_audit_log_messages_grouped_2(self) -> None:
        log = r'''
[Wed Feb 11 19:46:12.759594 2015] [:error] [pid 1130] [client 172.16.10.91] ModSecurity: Audit log: Failed to lock global mutex: Identifier removed [hostname "172.16.10.91"] [uri "/wordpress/wp-cron.php"] [unique_id "VNvLw38AAQEAAARqTXsAAAAD"]
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'apache-errorlog')
        self.assertEqual(response.rule_id, '30403')
        self.assertEqual(response.rule_level, 0)


    def test_modsecurity_rejected_a_query_1(self) -> None:
        log = r'''
[Mon Feb 09 16:47:55.908176 2015] [:error] [pid 17679] [client 172.16.10.91] ModSecurity: Access denied with code 403 (phase 2). Operator EQ matched 0 at REQUEST_HEADERS. [file "/etc/apache2/ModSecurity/activated_rules/modsecurity_crs_21_protocol_anomalies.conf"] [line "47"] [id "960015"] [rev "1"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/2.2.9"] [maturity "9"] [accuracy "9"] [tag "OWASP_CRS/PROTOCOL_VIOLATION/MISSING_HEADER_ACCEPT"] [tag "WASCTC/WASC-21"] [tag "OWASP_TOP_10/A7"] [tag "PCI/6.5.10"] [hostname "172.16.10.91"] [uri "/wordpress/wp-cron.php"] [unique_id "VNkA238AAQEAAEUP9hIAAAAI"]
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'apache-errorlog')
        self.assertEqual(response.rule_id, '30411')
        self.assertEqual(response.rule_level, 7)


    def test_modsecurity_rejected_a_query_2(self) -> None:
        log = r'''
[Mon Feb 09 16:47:55.973954 2015] [:error] [pid 17675] [client 172.16.10.87] ModSecurity: Access denied with code 403 (phase 4). Pattern match "^5\\\\d{2}$" at RESPONSE_STATUS. [file "/etc/apache2/ModSecurity/activated_rules/modsecurity_crs_50_outbound.conf"] [line "53"] [id "970901"] [rev "2"] [msg "The application is not available"] [data "Matched Data: 500 found within RESPONSE_STATUS: 500"] [severity "ERROR"] [ver "OWASP_CRS/2.2.9"] [maturity "9"] [accuracy "9"] [tag "WASCTC/WASC-13"] [tag "OWASP_TOP_10/A6"] [tag "PCI/6.5.6"] [hostname "172.16.10.91"] [uri "/wordpress/wp-includes/rss-functions.php"] [unique_id "VNkA238AAQEAAEULYMwAAAAA"]
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'apache-errorlog')
        self.assertEqual(response.rule_id, '30411')
        self.assertEqual(response.rule_level, 7)

