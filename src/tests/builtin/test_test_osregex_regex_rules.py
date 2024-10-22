#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from test_osregex_regex.ini
class TestTest_osregex_regexRules(unittest.TestCase):

    def test_osregex_test_osregex_realloc(self) -> None:
        log = '''Dec 25 20:45:02 MyHost osregex_realloc_test[12345]: fieldx=0 field1=1 field2=2 field3=3 field4=4 field5=5 field5=5 field6=6 field7=7 field8=8 field9=9 field10=10'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'osregex_realloc_test')
        self.assertEqual(response.rule_id, '999733')
        self.assertEqual(response.rule_level, 3)


    def test_osregex_test_osregex_3_action(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osregex_3[12345]:test_action action_example_1*'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osregex_3')
        self.assertEqual(response.rule_id, '999706')
        self.assertEqual(response.rule_level, 3)


    def test_osregex_test_osregex_3_action_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osregex_3[12345]:test_action action_example_9*'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osregex_3')
        self.assertEqual(response.rule_id, '999707')
        self.assertEqual(response.rule_level, 3)


    def test_osregex_test_osregex_4_extra_data(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osregex_4[12345]:test_extra_data extra_data_example_1*'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osregex_4')
        self.assertEqual(response.rule_id, '999708')
        self.assertEqual(response.rule_level, 3)


    def test_osregex_test_osregex_4_extra_data_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osregex_4[12345]:test_extra_data extra_data_example_9*'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osregex_4')
        self.assertEqual(response.rule_id, '999709')
        self.assertEqual(response.rule_level, 3)


    def test_osregex_test_osregex_5_id(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osregex_5[12345]:test_id id_example_1*'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osregex_5')
        self.assertEqual(response.rule_id, '999710')
        self.assertEqual(response.rule_level, 3)


    def test_osregex_test_osregex_5_id_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osregex_5[12345]:test_id id_example_9*'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osregex_5')
        self.assertEqual(response.rule_id, '999711')
        self.assertEqual(response.rule_level, 3)


    def test_osregex_test_osregex_6_location(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osregex_6[12345]:test_location'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osregex_6')
        self.assertEqual(response.rule_id, '999712')
        self.assertEqual(response.rule_level, 3)


    def test_osregex_test_osregex_6_hostname(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osregex_6[12345]:test_hostname'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osregex_6')
        self.assertEqual(response.rule_id, '999713')
        self.assertEqual(response.rule_level, 3)


    def test_osregex_test_osregex_6_program_name(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osregex_6[12345]:test_program_name'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osregex_6')
        self.assertEqual(response.rule_id, '999714')
        self.assertEqual(response.rule_level, 3)


    def test_osregex_test_osregex_7_match(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osregex_7[12345]:test_match match_example_1*'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osregex_7')
        self.assertEqual(response.rule_id, '999715')
        self.assertEqual(response.rule_level, 3)


    def test_osregex_test_osregex_7_match_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osregex_7[12345]:test_match match_example_9*'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osregex_7')
        self.assertEqual(response.rule_id, '999716')
        self.assertEqual(response.rule_level, 3)


    def test_osregex_test_osregex_8_protocol(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osregex_8[12345]:test_protocol protocol_example_1*'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osregex_8')
        self.assertEqual(response.rule_id, '999717')
        self.assertEqual(response.rule_level, 3)


    def test_osregex_test_osregex_8_protocol_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osregex_8[12345]:test_protocol protocol_example_9*'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osregex_8')
        self.assertEqual(response.rule_id, '999718')
        self.assertEqual(response.rule_level, 3)


    def test_osregex_test_osregex_9_user(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osregex_9[12345]:test_user user_example_1*'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osregex_9')
        self.assertEqual(response.rule_id, '999719')
        self.assertEqual(response.rule_level, 3)


    def test_osregex_test_osregex_9_user_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osregex_9[12345]:test_user user_example_9*'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osregex_9')
        self.assertEqual(response.rule_id, '999720')
        self.assertEqual(response.rule_level, 3)


    def test_osregex_test_osregex_10_url(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osregex_10[12345]:test_url url_example_1*'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osregex_10')
        self.assertEqual(response.rule_id, '999721')
        self.assertEqual(response.rule_level, 3)


    def test_osregex_test_osregex_10_url_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osregex_10[12345]:test_url url_example_9*'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osregex_10')
        self.assertEqual(response.rule_id, '999722')
        self.assertEqual(response.rule_level, 3)


    def test_osregex_test_osregex_11_srcport(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osregex_11[12345]:test_srcport srcport_example_1*'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osregex_11')
        self.assertEqual(response.rule_id, '999723')
        self.assertEqual(response.rule_level, 3)


    def test_osregex_test_osregex_11_srcport_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osregex_11[12345]:test_srcport srcport_example_9*'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osregex_11')
        self.assertEqual(response.rule_id, '999724')
        self.assertEqual(response.rule_level, 3)


    def test_osregex_test_osregex_12_dstport(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osregex_12[12345]:test_dstport dstport_example_1*'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osregex_12')
        self.assertEqual(response.rule_id, '999725')
        self.assertEqual(response.rule_level, 3)


    def test_osregex_test_osregex_12_dstport_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osregex_12[12345]:test_dstport dstport_example_9*'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osregex_12')
        self.assertEqual(response.rule_id, '999726')
        self.assertEqual(response.rule_level, 3)


    def test_osregex_test_osregex_13_status(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osregex_13[12345]:test_status status_example_1*'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osregex_13')
        self.assertEqual(response.rule_id, '999727')
        self.assertEqual(response.rule_level, 3)


    def test_osregex_test_osregex_13_status_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osregex_13[12345]:test_status status_example_9*'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osregex_13')
        self.assertEqual(response.rule_id, '999728')
        self.assertEqual(response.rule_level, 3)


    def test_osregex_test_osregex_14_system_name(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osregex_14[12345]:test_system_name system_name_example_1*'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osregex_14')
        self.assertEqual(response.rule_id, '999729')
        self.assertEqual(response.rule_level, 3)


    def test_osregex_test_osregex_14_system_name_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osregex_14[12345]:test_system_name system_name_example_9*'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osregex_14')
        self.assertEqual(response.rule_id, '999730')
        self.assertEqual(response.rule_level, 3)


    def test_osregex_test_osregex_15_data(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osregex_15[12345]:test_data data_example_1*'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osregex_15')
        self.assertEqual(response.rule_id, '999731')
        self.assertEqual(response.rule_level, 3)


    def test_osregex_test_osregex_15_data_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_osregex_15[12345]:test_data data_example_9*'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_osregex_15')
        self.assertEqual(response.rule_id, '999732')
        self.assertEqual(response.rule_level, 3)

