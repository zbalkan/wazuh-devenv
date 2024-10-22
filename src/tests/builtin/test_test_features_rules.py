#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from test_features.ini
class TestTest_featuresRules(unittest.TestCase):

    def test_same_fields_1(self) -> None:
        log = '''Dec 25 20:45:02 MyHost test_same_fields[12345]: User 'admin' logged from '192.168.1.100' 5 this is the same_fields test'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same')
        self.assertEqual(response.rule_id, '999206')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_2(self) -> None:
        log = '''Dec 25 20:45:02 MyHost test_same_fields[12345]: User 'admin' logged from '192.168.1.100' 5 this is the same_fields test'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same')
        self.assertEqual(response.rule_id, '999206')
        self.assertEqual(response.rule_level, 7)


    def test_same_fields_3(self) -> None:
        log = '''Dec 25 20:45:02 MyHost test_same_fields[12345]: User 'admin' logged from '192.168.1.100' 5 this is the same_fields test'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same')
        self.assertEqual(response.rule_id, '999206')
        self.assertEqual(response.rule_level, 7)


    def test_not_same_fields_1(self) -> None:
        log = '''Dec 25 20:45:02 MyHost test_same_fields[12345]: User 'admin' logged from '192.168.1.100' 5 this is the not_same_fields test'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same')
        self.assertEqual(response.rule_id, '999208')
        self.assertEqual(response.rule_level, 7)


    def test_not_same_fields_2(self) -> None:
        log = '''Dec 25 20:45:02 MyHost test_same_fields[12345]: User 'admin' logged from '192.168.1.100' 6 this is the not_same_fields test'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same')
        self.assertEqual(response.rule_id, '999208')
        self.assertEqual(response.rule_level, 7)


    def test_not_same_fields_3(self) -> None:
        log = '''Dec 25 20:45:02 MyHost test_same_fields[12345]: User 'admin' logged from '192.168.1.100' 7 this is the not_same_fields test'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_same')
        self.assertEqual(response.rule_id, '999208')
        self.assertEqual(response.rule_level, 7)


    def test_noalert_enabled(self) -> None:
        log = '''Dec 19 17:20:08 User test_noalert[12345]:Test noalert=1'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)


    def test_noalert_disabled(self) -> None:
        log = '''Dec 19 17:20:08 User test_noalert[12345]:Test noalert=0'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_noalert')
        self.assertEqual(response.rule_id, '999274')
        self.assertEqual(response.rule_level, 3)


    def test_wrong_ifsid(self) -> None:
        log = '''Sep  5 13:14:00 User test_wrong_ifsid[12345]:Test'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'test_wrong_ifsid')
        self.assertEqual(response.rule_id, '999275')
        self.assertEqual(response.rule_level, 3)


    def test_nested_if_matched_sid_1(self) -> None:
        log = '''device="SFW" date=2000-12-01 time=17:19:06 timezone="+01" device_name="XXXX" device_id=1234567 log_id=010101010101 log_type="Firewall" log_component="Firewall Rule" log_subtype="Denied" status="Deny"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sophos-fw')
        self.assertEqual(response.rule_id, '999282')
        self.assertEqual(response.rule_level, 7)


    def test_nested_if_matched_sid_2(self) -> None:
        log = '''device="SFW" date=2000-12-01 time=17:19:06 timezone="+01" device_name="XXXX" device_id=1234567 log_id=010101010101 log_type="Firewall" log_component="Firewall Rule" log_subtype="Denied" status="Deny"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sophos-fw')
        self.assertEqual(response.rule_id, '999282')
        self.assertEqual(response.rule_level, 7)


    def test_nested_if_matched_sid_3(self) -> None:
        log = '''device="SFW" date=2000-12-01 time=17:19:06 timezone="+01" device_name="XXXX" device_id=1234567 log_id=010101010101 log_type="Firewall" log_component="Firewall Rule" log_subtype="Denied" status="Deny"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sophos-fw')
        self.assertEqual(response.rule_id, '999282')
        self.assertEqual(response.rule_level, 7)


    def test_nested_if_matched_group_1(self) -> None:
        log = '''device="SFW" date=2000-12-01 time=17:19:06 timezone="+01" device_name="XXXX" device_id=12345678 log_id=010101010101 log_type="Firewall" log_component="Firewall Rule" log_subtype="Denied" status="Deny"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sophos-fw')
        self.assertEqual(response.rule_id, '999285')
        self.assertEqual(response.rule_level, 7)


    def test_nested_if_matched_group_2(self) -> None:
        log = '''device="SFW" date=2000-12-01 time=17:19:06 timezone="+01" device_name="XXXX" device_id=12345678 log_id=010101010101 log_type="Firewall" log_component="Firewall Rule" log_subtype="Denied" status="Deny"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sophos-fw')
        self.assertEqual(response.rule_id, '999285')
        self.assertEqual(response.rule_level, 7)


    def test_nested_if_matched_group_3(self) -> None:
        log = '''device="SFW" date=2000-12-01 time=17:19:06 timezone="+01" device_name="XXXX" device_id=12345678 log_id=010101010101 log_type="Firewall" log_component="Firewall Rule" log_subtype="Denied" status="Deny"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sophos-fw')
        self.assertEqual(response.rule_id, '999285')
        self.assertEqual(response.rule_level, 7)

