#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from test_static_filters_geoip.ini
class TestTest_static_filters_geoipRules(unittest.TestCase):

    def test_same_fields_same_srcgeoip_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_srcgeoip 'Srcuser' 'User' logged from 2.136.147.146:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999262')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_srcgeoip_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_srcgeoip 'Srcuser' 'User' logged from 2.136.147.146:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999262')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_srcgeoip_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_srcgeoip 'Srcuser' 'User' logged from 2.136.147.146:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999262')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_srcgeoip_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_srcgeoip 'Srcuser' 'User' logged from 2.136.14.146:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999262')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_srcgeoip_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_srcgeoip 'Srcuser' 'User' logged from 2.136.14.146:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999262')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_srcgeoip_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_srcgeoip 'Srcuser' 'User' logged from 2.136.14.146:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999262')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_srcgeoip_7(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_srcgeoip 'Srcuser' 'User' logged from 2.136.147.146:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999262')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_srcgeoip_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_srcgeoip 'Srcuser' 'User' logged from 2.136.147.146:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999264')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_srcgeoip_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_srcgeoip 'Srcuser' 'User' logged from 2.136.147.146:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999264')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_srcgeoip_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_srcgeoip 'Srcuser' 'User' logged from 2.136.147.146:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999264')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_srcgeoip_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_srcgeoip 'Srcuser' 'User' logged from 2.136.147.146:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999264')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_srcgeoip_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_srcgeoip 'Srcuser' 'User' logged from 2.136.147.146:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999264')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_srcgeoip_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_srcgeoip 'Srcuser' 'User' logged from 2.136.147.146:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999264')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_srcgeoip_7(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_srcgeoip 'Srcuser' 'User' logged from 2.136.14.146:8 to 192.168.5.4:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999264')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_dstgeoip_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_dstgeoip 'Srcuser' 'User' logged from 192.168.1.100:8 to 2.136.147.146:8 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999266')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_dstgeoip_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_dstgeoip 'Srcuser' 'User' logged from 192.168.1.100:8 to 2.136.147.146:8 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999266')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_dstgeoip_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_dstgeoip 'Srcuser' 'User' logged from 192.168.1.100:8 to 2.136.147.146:8 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999266')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_dstgeoip_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_dstgeoip 'Srcuser' 'User' logged from 192.168.1.100:8 to 2.136.14.146:8 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999266')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_dstgeoip_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_dstgeoip 'Srcuser' 'User' logged from 192.168.1.100:8 to 2.136.14.146:8 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999266')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_dstgeoip_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_dstgeoip 'Srcuser' 'User' logged from 192.168.1.100:8 to 2.136.14.146:8 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999266')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_same_dstgeoip_7(self) -> None:
        log = '''Dec 19 17:20:08 User test_same_filters[12345]:Test same_dstgeoip 'Srcuser' 'User' logged from 192.168.1.100:8 to 2.136.147.146:8 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same_filters')
        self.assertEqual(response.rule_id, '999266')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_dstgeoip_1(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_dstgeoip 'Srcuser' 'User' logged from 192.168.1.100:8 to 2.136.147.146:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999268')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_dstgeoip_2(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_dstgeoip 'Srcuser' 'User' logged from 192.168.1.100:8 to 2.136.147.146:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999268')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_dstgeoip_3(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_dstgeoip 'Srcuser' 'User' logged from 192.168.1.100:8 to 2.136.147.146:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999268')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_dstgeoip_4(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_dstgeoip 'Srcuser' 'User' logged from 192.168.1.100:8 to 2.136.147.146:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999268')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_dstgeoip_5(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_dstgeoip 'Srcuser' 'User' logged from 192.168.1.100:8 to 2.136.147.146:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999268')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_dstgeoip_6(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_dstgeoip 'Srcuser' 'User' logged from 192.168.1.100:8 to 2.136.147.146:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999268')
        self.assertEqual(response.rule_level, 7)


    def test_different_fields_different_dstgeoip_7(self) -> None:
        log = '''Dec 19 17:20:08 User test_different_filters[12345]:Test different_dstgeoip 'Srcuser' 'User' logged from 192.168.1.100:8 to 2.136.14.146:20 pro:ftp act:remove id:1 url:ossec dat:huzaw e_data:hwazu sta:rejected systemname:system1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_different_filters')
        self.assertEqual(response.rule_id, '999268')
        self.assertEqual(response.rule_level, 7)

