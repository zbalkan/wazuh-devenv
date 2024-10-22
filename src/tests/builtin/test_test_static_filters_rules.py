#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from test_static_filters.ini
class TestTest_static_filtersRules(unittest.TestCase):

    def test_same_fields_same_srcip_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_srcip 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999210')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_srcip_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_srcip 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999210')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_srcip_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_srcip 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999210')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_srcip_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_srcip 'Srcuser' 'User' logged from 192.168.1.90:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999210')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_srcip_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_srcip 'Srcuser' 'User' logged from 192.168.1.90:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999210')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_srcip_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_srcip 'Srcuser' 'User' logged from 192.168.1.90:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999210')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_srcip_7(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_srcip 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999210')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_dstip_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_dstip 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999212')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_dstip_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_dstip 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999212')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_dstip_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_dstip 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999212')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_dstip_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_dstip 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.0.0:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999212')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_dstip_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_dstip 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.0.0:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999212')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_dstip_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_dstip 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.0.0:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999212')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_dstip_7(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_dstip 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999212')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_srcuser_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_srcuser 'Admin' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999270')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_srcuser_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_srcuser 'Admin' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999270')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_srcuser_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_srcuser 'Admin' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999270')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_srcuser_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_srcuser 'unknown' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999270')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_srcuser_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_srcuser 'unknown' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999270')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_srcuser_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_srcuser 'unknown' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999270')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_srcuser_7(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_srcuser 'Admin' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999270')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_user_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_user 'Srcuser' 'Admin' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999214')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_user_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_user 'Srcuser' 'Admin' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999214')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_user_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_user 'Srcuser' 'Admin' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999214')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_user_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_user 'Srcuser' 'unknown' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999214')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_user_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_user 'Srcuser' 'unknown' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999214')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_user_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_user 'Srcuser' 'unknown' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999214')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_user_7(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_user 'Srcuser' 'Admin' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999214')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_srcport_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_srcport 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999216')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_srcport_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_srcport 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999216')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_srcport_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_srcport 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999216')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_srcport_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_srcport 'Srcuser' 'User' logged from 192.168.1.100:200 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999216')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_srcport_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_srcport 'Srcuser' 'User' logged from 192.168.1.100:200 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999216')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_srcport_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_srcport 'Srcuser' 'User' logged from 192.168.1.100:200 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999216')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_srcport_7(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_srcport 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999216')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_dstport_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_dstport 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999218')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_dstport_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_dstport 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999218')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_dstport_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_dstport 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999218')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_dstport_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_dstport 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:100 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999218')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_dstport_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_dstport 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:100 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999218')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_dstport_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_dstport 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:100 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999218')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_dstport_7(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_dstport 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999218')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_protocol_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_protocol 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999220')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_protocol_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_protocol 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999220')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_protocol_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_protocol 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999220')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_protocol_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_protocol 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ssh act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999220')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_protocol_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_protocol 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ssh act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999220')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_protocol_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_protocol 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ssh act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999220')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_protocol_7(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_protocol 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999220')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_action_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_action 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999222')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_action_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_action 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999222')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_action_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_action 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999222')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_action_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_action 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:install id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999222')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_action_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_action 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:install id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999222')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_action_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_action 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:install id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999222')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_action_7(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_action 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999222')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_id_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_id 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999224')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_id_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_id 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999224')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_id_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_id 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999224')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_id_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_id 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:2 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999224')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_id_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_id 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:2 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999224')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_id_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_id 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:2 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999224')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_id_7(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_id 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999224')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_url_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_url 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999226')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_url_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_url 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999226')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_url_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_url 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999226')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_url_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_url 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:wazuh dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999226')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_url_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_url 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:wazuh dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999226')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_url_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_url 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:wazuh dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999226')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_url_7(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_url 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999226')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_data_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_data 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999228')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_data_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_data 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999228')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_data_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_data 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999228')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_data_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_data 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:cesso e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999228')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_data_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_data 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:cesso e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999228')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_data_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_data 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:cesso e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999228')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_data_7(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_data 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999228')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_extra_data_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_extra_data 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999230')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_extra_data_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_extra_data 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999230')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_extra_data_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_extra_data 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999230')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_extra_data_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_extra_data 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:cesso sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999230')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_extra_data_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_extra_data 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:cesso sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999230')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_extra_data_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_extra_data 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:cesso sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999230')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_extra_data_7(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_extra_data 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999230')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_status_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_status 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999232')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_status_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_status 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999232')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_status_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_status 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999232')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_status_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_status 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:accepted systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999232')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_status_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_status 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:accepted systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999232')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_status_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_status 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:accepted systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999232')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_status_7(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_status 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999232')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_system_name_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_system_name 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999234')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_system_name_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_system_name 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999234')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_system_name_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_system_name 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999234')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_system_name_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_system_name 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system100'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999234')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_system_name_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_system_name 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system100'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999234')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_system_name_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_system_name 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system100'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999234')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_system_name_7(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_system_name 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999234')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_srcip_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_srcip 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999236')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_srcip_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_srcip 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999236')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_srcip_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_srcip 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999236')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_srcip_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_srcip 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999236')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_srcip_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_srcip 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999236')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_srcip_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_srcip 'Srcuser' 'User' logged from 192.168.0.200:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999236')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_dstip_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_dstip 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999238')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_dstip_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_dstip 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999238')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_dstip_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_dstip 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999238')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_dstip_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_dstip 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999238')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_dstip_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_dstip 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999238')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_dstip_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_dstip 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.102.60:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999238')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_srcuser_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_srcuser 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999272')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_srcuser_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_srcuser 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999272')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_srcuser_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_srcuser 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999272')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_srcuser_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_srcuser 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999272')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_srcuser_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_srcuser 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999272')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_srcuser_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_srcuser 'Unknown' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999272')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_user_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_user 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999240')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_user_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_user 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999240')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_user_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_user 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999240')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_user_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_user 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999240')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_user_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_user 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999240')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_user_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_user 'Srcuser' 'Unknown' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999240')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_src_port_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_src_port 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999242')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_src_port_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_src_port 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999242')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_src_port_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_src_port 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999242')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_src_port_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_src_port 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999242')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_src_port_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_src_port 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999242')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_src_port_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_src_port 'Srcuser' 'User' logged from 192.168.1.100:100 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999242')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_dst_port_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_dst_port 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999244')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_dst_port_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_dst_port 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999244')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_dst_port_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_dst_port 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999244')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_dst_port_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_dst_port 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999244')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_dst_port_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_dst_port 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999244')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_dst_port_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_dst_port 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:100 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999244')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_protocol_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_protocol 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999246')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_protocol_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_protocol 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999246')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_protocol_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_protocol 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999246')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_protocol_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_protocol 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999246')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_protocol_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_protocol 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999246')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_protocol_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_protocol 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:udp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999246')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_action_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_action 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999248')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_action_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_action 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999248')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_action_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_action 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999248')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_action_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_action 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999248')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_action_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_action 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999248')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_action_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_action 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:update id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999248')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_id_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_id 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999250')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_id_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_id 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999250')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_id_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_id 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999250')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_id_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_id 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999250')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_id_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_id 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999250')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_id_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_id 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:2 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999250')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_url_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_url 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999252')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_url_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_url 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999252')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_url_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_url 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999252')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_url_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_url 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999252')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_url_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_url 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999252')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_url_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_url 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:wazuh dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999252')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_data_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_data 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999254')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_data_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_data 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999254')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_data_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_data 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999254')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_data_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_data 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999254')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_data_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_data 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999254')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_data_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_data 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:data1 e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999254')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_extra_data_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_extra_data 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999256')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_extra_data_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_extra_data 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999256')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_extra_data_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_extra_data 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999256')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_extra_data_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_extra_data 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999256')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_extra_data_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_extra_data 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999256')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_extra_data_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_extra_data 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:edata1 sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999256')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_status_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_status 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999258')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_status_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_status 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999258')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_status_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_status 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999258')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_status_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_status 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999258')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_status_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_status 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999258')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_status_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_status 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:accepted systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999258')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_system_name_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_system_name 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999260')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_system_name_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_system_name 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999260')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_system_name_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_system_name 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999260')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_system_name_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_system_name 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999260')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_system_name_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_system_name 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999260')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_system_name_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_system_name 'Srcuser' 'User' logged from 192.168.1.100:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system2'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999260')
        self.assertEqual(response.rule_level, 7)

