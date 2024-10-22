#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from test_expr_negation.ini
class TestTest_expr_negationRules(unittest.TestCase):

    def test_expr_negation_action_1(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_action wazuh-agent123@192.168.0.2:31415 HTTPS 192.168.0.1:9264 /status/isbad GET format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation')
        self.assertEqual(response.rule_id, '999300')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_action_2(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_action wazuh-agent123@192.168.0.2:31415 HTTPS 192.168.0.1:9264 /status/isbad PUT format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation')
        self.assertEqual(response.rule_id, '999301')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_action_3(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_action wazuh-agent123@192.168.0.2:31415 HTTPS 192.168.0.1:9264 /status/isbad POST format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)


    def test_expr_negation_dstip_1(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_dstip wazuh-agent123@192.168.0.2:31415 HTTPS 172.115.14.241:9264 /status/isbad GET format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation')
        self.assertEqual(response.rule_id, '999302')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_dstip_2(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_dstip wazuh-agent123@192.168.0.2:31415 HTTPS 10.0.0.1:9264 /status/isbad GET format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation')
        self.assertEqual(response.rule_id, '999303')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_dstip_3(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_dstip wazuh-agent123@192.168.0.2:31415 HTTPS 192.168.0.15:9264 /status/isbad GET format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)


    def test_expr_negation_extra_data_1(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_extra_data wazuh-agent123@192.168.0.2:31415 HTTPS 192.168.0.1:9264 /status/isbad GET format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation')
        self.assertEqual(response.rule_id, '999304')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_extra_data_2(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_extra_data wazuh-agent123@192.168.0.2:31415 HTTPS 192.168.0.1:9264 /status/isbad GET format=json content="{'msg'='test_msg'}" RESULT=success'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation')
        self.assertEqual(response.rule_id, '999305')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_extra_data_3(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_extra_data wazuh-agent123@192.168.0.2:31415 HTTPS 192.168.0.1:9264 /status/isbad GET format=json content="{'msg'='Soyez le premier'}" RESULT=success'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)


    def test_expr_negation_field_1(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_field wazuh-agent123@192.168.0.2:31415 HTTPS 192.168.0.1:9264 /status/isbad GET format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation')
        self.assertEqual(response.rule_id, '999306')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_field_2(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_field wazuh-agent123@192.168.0.2:31415 HTTPS 192.168.0.1:9264 /status/isbad GET format=raw content="msg=helloworld" RESULT=success'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation')
        self.assertEqual(response.rule_id, '999307')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_field_3(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_field wazuh-agent123@192.168.0.2:31415 HTTPS 192.168.0.1:9264 /status/isbad GET format=xml content="<msg>helloworld</msg>" RESULT=success'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)


    def test_expr_negation_hostname_1(self) -> None:
        log = '''Dec 19 17:20:08 hostname_1 test_expr_negation_predec_fields[123]: test_hostname system_name somedata'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation_predec_fields')
        self.assertEqual(response.rule_id, '999308')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_hostname_2(self) -> None:
        log = '''Dec 19 17:20:08 hostname_3 test_expr_negation_predec_fields[123]: test_hostname system_name somedata'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation_predec_fields')
        self.assertEqual(response.rule_id, '999309')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_hostname_3(self) -> None:
        log = '''Dec 19 17:20:08 hostname_2 test_expr_negation_predec_fields[123]: test_hostname system_name somedata'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)


    def test_expr_negation_id_1(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_id wazuh-agent0@192.168.0.2:31415 HTTPS 192.168.0.1:9264 /status/isbad GET format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation')
        self.assertEqual(response.rule_id, '999310')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_id_2(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_id wazuh-agent13@192.168.0.2:31415 HTTPS 192.168.0.1:9264 /status/isbad GET format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation')
        self.assertEqual(response.rule_id, '999311')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_id_3(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_id wazuh-agent999@192.168.0.2:31415 HTTPS 192.168.0.1:9264 /status/isbad GET format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)


    def test_expr_negation_location_1(self) -> None:
        log = '''Dec 19 17:20:08 hostname test_expr_negation_predec_fields[123]: test_location_1 system_name somedata'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation_predec_fields')
        self.assertEqual(response.rule_id, '999312')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_location_2(self) -> None:
        log = '''Dec 19 17:20:08 hostname test_expr_negation_predec_fields[123]: test_location_2 system_name somedata'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation_predec_fields')
        self.assertEqual(response.rule_id, '999313')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_match_1_1(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_match[12345]: test_match_1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation_match')
        self.assertEqual(response.rule_id, '999314')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_match_1_2(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_match[12345]: test_match_2'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation_match')
        self.assertEqual(response.rule_id, '999314')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_match_2_1(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_match[12345]: test_match_5'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation_match')
        self.assertEqual(response.rule_id, '999315')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_match_2_2(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_match[12345]: test_match_6'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation_match')
        self.assertEqual(response.rule_id, '999315')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_match_3_1(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_match[12345]: test_match_3'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)


    def test_expr_negation_match_3_2(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_match[12345]: test_match_4'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)


    def test_expr_negation_program_name_1(self) -> None:
        log = '''Dec 19 17:20:08 hostname test_program_name_01[123]:'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation_program_name')
        self.assertEqual(response.rule_id, '999316')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_program_name_2(self) -> None:
        log = '''Dec 19 17:20:08 hostname test_program_name_03[123]:'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation_program_name')
        self.assertEqual(response.rule_id, '999317')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_program_name_3(self) -> None:
        log = '''Dec 19 17:20:08 hostname test_program_name_02[123]:'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)


    def test_expr_negation_protocol_1(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_protocol wazuh-agent123@192.168.0.2:31415 HTTP 192.168.0.1:9264 /status/isbad GET format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation')
        self.assertEqual(response.rule_id, '999318')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_protocol_2(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_protocol wazuh-agent123@192.168.0.2:31415 QUIC 192.168.0.1:9264 /status/isbad GET format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation')
        self.assertEqual(response.rule_id, '999319')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_protocol_3(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_protocol wazuh-agent123@192.168.0.2:31415 HTTPS 192.168.0.1:9264 /status/isbad GET format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)


    def test_expr_negation_regex_1_1(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_regex[12345]: regex_id-0'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation_regex')
        self.assertEqual(response.rule_id, '999320')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_regex_1_2(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_regex[12345]: regex_id-9'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation_regex')
        self.assertEqual(response.rule_id, '999320')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_regex_2_1(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_regex[12345]: regex_id'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation_regex')
        self.assertEqual(response.rule_id, '999321')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_regex_2_2(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_regex[12345]: regex_id'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation_regex')
        self.assertEqual(response.rule_id, '999321')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_regex_3_1(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_regex[12345]: regex_id-a'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)


    def test_expr_negation_regex_3_2(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_regex[12345]: regex_id-a'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)


    def test_expr_negation_srcip_1(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_srcip wazuh-agent123@172.115.14.241:31415 HTTPS 192.168.0.1:9264 /status/isbad GET format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation')
        self.assertEqual(response.rule_id, '999322')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_srcip_2(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_srcip wazuh-agent123@10.0.0.1:31415 HTTPS 192.168.0.1:9264 /status/isbad GET format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation')
        self.assertEqual(response.rule_id, '999323')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_srcip_3(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_srcip wazuh-agent123@192.168.0.15:31415 HTTPS 192.168.0.1:9264 /status/isbad GET format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)


    def test_expr_negation_user_1(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_user ltorv-agent123@192.168.0.2:31415 HTTPS 192.168.0.1:9264 /status/isbad GET format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation')
        self.assertEqual(response.rule_id, '999324')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_user_2(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_user rstall-agent123@192.168.0.2:31415 HTTPS 192.168.0.1:9264 /status/isbad GET format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation')
        self.assertEqual(response.rule_id, '999325')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_user_3(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_user dritch-agent123@192.168.0.2:31415 HTTPS 192.168.0.1:9264 /status/isbad GET format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)


    def test_expr_negation_url_1(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_url wazuh-agent123@192.168.0.2:31415 HTTPS 192.168.0.1:9264 /admin/auth_key GET format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation')
        self.assertEqual(response.rule_id, '999326')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_url_2(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_url wazuh-agent123@192.168.0.2:31415 HTTPS 192.168.0.1:9264 /profiles/info GET format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation')
        self.assertEqual(response.rule_id, '999327')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_url_3(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_url wazuh-agent123@192.168.0.2:31415 HTTPS 192.168.0.1:9264 /resources/user_info GET format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)


    def test_expr_negation_srcport_1(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_srcport wazuh-agent123@192.168.0.2:1234 HTTPS 192.168.0.1:9264 /status/isbad GET format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation')
        self.assertEqual(response.rule_id, '999328')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_srcport_2(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_srcport wazuh-agent123@192.168.0.2:31415 HTTPS 192.168.0.1:9264 /status/isbad GET format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation')
        self.assertEqual(response.rule_id, '999329')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_srcport_3(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_srcport wazuh-agent123@192.168.0.2:4321 HTTPS 192.168.0.1:9264 /status/isbad GET format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)


    def test_expr_negation_dstport_1(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_dstport wazuh-agent123@192.168.0.2:31415 HTTPS 192.168.0.1:1234 /status/isbad GET format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation')
        self.assertEqual(response.rule_id, '999330')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_dstport_2(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_dstport wazuh-agent123@192.168.0.2:31415 HTTPS 192.168.0.1:31415 /status/isbad GET format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation')
        self.assertEqual(response.rule_id, '999331')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_dstport_3(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_dstport wazuh-agent123@192.168.0.2:31415 HTTPS 192.168.0.1:4321 /status/isbad GET format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)


    def test_expr_negation_status_1(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_status wazuh-agent123@192.168.0.2:31415 HTTPS 192.168.0.1:9264 /status/isbad GET format=json content="{'msg'='helloworld'}" RESULT=success'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation')
        self.assertEqual(response.rule_id, '999332')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_status_2(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_status wazuh-agent123@192.168.0.2:31415 HTTPS 192.168.0.1:9264 /status/isbad GET format=json content="{'msg'='helloworld'}" RESULT=unknown'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation')
        self.assertEqual(response.rule_id, '999333')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_status_3(self) -> None:
        log = '''Dec 19 17:20:08 ubuntu test_expr_negation[12345]:test_status wazuh-agent123@192.168.0.2:31415 HTTPS 192.168.0.1:9264 /status/isbad GET format=json content="{'msg'='helloworld'}" RESULT=fail'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)


    def test_expr_negation_system_name_1(self) -> None:
        log = '''Dec 19 17:20:08 hostname test_expr_negation_predec_fields[123]: test_system_name system_name_1 somedata'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation_predec_fields')
        self.assertEqual(response.rule_id, '999334')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_system_name_2(self) -> None:
        log = '''Dec 19 17:20:08 hostname test_expr_negation_predec_fields[123]: test_system_name system_name_3 somedata'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation_predec_fields')
        self.assertEqual(response.rule_id, '999335')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_system_name_3(self) -> None:
        log = '''Dec 19 17:20:08 hostname test_expr_negation_predec_fields[123]: test_system_name system_name_2 somedata'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)


    def test_expr_negation_data_1(self) -> None:
        log = '''Dec 19 17:20:08 hostname test_expr_negation_predec_fields[123]: test_data system_name data_1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation_predec_fields')
        self.assertEqual(response.rule_id, '999336')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_data_2(self) -> None:
        log = '''Dec 19 17:20:08 hostname test_expr_negation_predec_fields[123]: test_data system_name data_3'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_expr_negation_predec_fields')
        self.assertEqual(response.rule_id, '999337')
        self.assertEqual(response.rule_level, 3)


    def test_expr_negation_data_3(self) -> None:
        log = '''Dec 19 17:20:08 hostname test_expr_negation_predec_fields[123]: test_data system_name data_2'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)

