#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from test_pcre2_regex.ini
class TestTest_pcre2_regexRules(unittest.TestCase):

    def test_pcre2_test_pcre2_0_protocol(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_0[12345]:test_protocol HTTP root@192.168.0.2:1234 192.168.0.1:4321'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_0')
        self.assertEqual(response.rule_id, '999500')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_0_protocol_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_0[12345]:test_protocol QUIC root@192.168.0.2:1234 192.168.0.1:4321'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_0')
        self.assertEqual(response.rule_id, '999501')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_1_dynamic_field(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_1[12345]:test_field https://localhost GET format=json'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_1')
        self.assertEqual(response.rule_id, '999502')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_1_dynamic_field_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_1[12345]:test_field https://localhost GET format=raw'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_1')
        self.assertEqual(response.rule_id, '999503')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_2_regex(self) -> None:
        log = '''test_pcre2_2 test_regex regex_example_0'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_2')
        self.assertEqual(response.rule_id, '999504')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_2_regex_n(self) -> None:
        log = '''test_pcre2_2 test_regex regex_example_1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_2')
        self.assertEqual(response.rule_id, '999505')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_3_action(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_3[12345]:test_action action_example_1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_3')
        self.assertEqual(response.rule_id, '999506')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_3_action_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_3[12345]:test_action action_example_9'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_3')
        self.assertEqual(response.rule_id, '999507')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_4_extra_data(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_4[12345]:test_extra_data extra_data_example_1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_4')
        self.assertEqual(response.rule_id, '999508')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_4_extra_data_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_4[12345]:test_extra_data extra_data_example_9'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_4')
        self.assertEqual(response.rule_id, '999509')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_5_id(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_5[12345]:test_id id_example_1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_5')
        self.assertEqual(response.rule_id, '999510')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_5_id_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_5[12345]:test_id id_example_9'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_5')
        self.assertEqual(response.rule_id, '999511')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_6_location(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_6[12345]:test_location'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_6')
        self.assertEqual(response.rule_id, '999512')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_6_hostname(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_6[12345]:test_hostname'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_6')
        self.assertEqual(response.rule_id, '999513')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_6_program_name(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_6[12345]:test_program_name'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_6')
        self.assertEqual(response.rule_id, '999514')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_7_match(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_7[12345]:test_match match_example_1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_7')
        self.assertEqual(response.rule_id, '999515')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_7_match_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_7[12345]:test_match match_example_9'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_7')
        self.assertEqual(response.rule_id, '999516')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_8_protocol(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_8[12345]:test_protocol protocol_example_1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_8')
        self.assertEqual(response.rule_id, '999517')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_8_protocol_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_8[12345]:test_protocol protocol_example_9'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_8')
        self.assertEqual(response.rule_id, '999518')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_9_user(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_9[12345]:test_user user_example_1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_9')
        self.assertEqual(response.rule_id, '999519')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_9_user_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_9[12345]:test_user user_example_9'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_9')
        self.assertEqual(response.rule_id, '999520')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_10_url(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_10[12345]:test_url url_example_1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_10')
        self.assertEqual(response.rule_id, '999521')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_10_url_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_10[12345]:test_url url_example_9'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_10')
        self.assertEqual(response.rule_id, '999522')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_11_srcport(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_11[12345]:test_srcport srcport_example_1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_11')
        self.assertEqual(response.rule_id, '999523')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_11_srcport_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_11[12345]:test_srcport srcport_example_9'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_11')
        self.assertEqual(response.rule_id, '999524')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_12_dstport(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_12[12345]:test_dstport dstport_example_1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_12')
        self.assertEqual(response.rule_id, '999525')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_12_dstport_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_12[12345]:test_dstport dstport_example_9'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_12')
        self.assertEqual(response.rule_id, '999526')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_13_status(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_13[12345]:test_status status_example_1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_13')
        self.assertEqual(response.rule_id, '999527')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_13_status_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_13[12345]:test_status status_example_9'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_13')
        self.assertEqual(response.rule_id, '999528')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_14_system_name(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_14[12345]:test_system_name system_name_example_1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_14')
        self.assertEqual(response.rule_id, '999529')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_14_system_name_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_14[12345]:test_system_name system_name_example_9'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_14')
        self.assertEqual(response.rule_id, '999530')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_15_data(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_15[12345]:test_data data_example_1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_15')
        self.assertEqual(response.rule_id, '999531')
        self.assertEqual(response.rule_level, 3)


    def test_pcre2_test_pcre2_15_data_n(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_pcre2_15[12345]:test_data data_example_9'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_pcre2_15')
        self.assertEqual(response.rule_id, '999532')
        self.assertEqual(response.rule_level, 3)

