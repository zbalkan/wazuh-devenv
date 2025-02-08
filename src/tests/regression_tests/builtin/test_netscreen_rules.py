#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from netscreen.ini
class TestNetscreenRules(unittest.TestCase):

    def test_firewall_configuration_changed(self) -> None:
        log = r'''
2014-05-23T10:25:58.681222-04:00 10.10.10.1 ssg5-serial: NetScreen device_id=0275112227993284  [Root]system-information-00767: System configuration saved by netscreen via web from host 10.10.10.101 to 10.10.10.1:443 by netscreen. (2014-05-23 10:58:17)
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'netscreenfw')
        self.assertEqual(response.rule_id, '4509')
        self.assertEqual(response.rule_level, 8)


    def test_firewall_policy_changed(self) -> None:
        log = r'''
2014-05-23T10:29:55.704201-04:00 10.10.10.1 ssg5-serial: NetScreen device_id=0275112227993284  [Root]system-notification-00018: Policy (5, Trust->Untrust, 10.10.10.0/24->172.16.19.0/24,ANY, Permit) was modified by netscreen via web from host 10.10.10.101 to 10.10.10.1:443. (2014-05-23 11:02:13)
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'netscreenfw')
        self.assertEqual(response.rule_id, '4508')
        self.assertEqual(response.rule_level, 8)


    def test_successfull_admin_login_to_the_netscreen_firewall(self) -> None:
        log = r'''
2014-05-23T10:39:20.681154-04:00 10.10.10.1 ssg5-serial: NetScreen device_id=0275112227993284  [Root]system-warning-00515: Management session via SSH from 10.10.10.100:0 for admin netscreen has timed out (2014-05-23 11:11:39)
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'netscreenfw')
        self.assertEqual(response.rule_id, '4507')
        self.assertEqual(response.rule_level, 8)


    def test_syn_flood(self) -> None:
        log = r'''
Jul  7 05:02:34 ssg5.17.168.192.in-addr.arpa ssg5: NetScreen device_id=ssg5  [Root]system-emergency-00005: SYN flood! From 192.168.18.53:41437 to 192.168.17.251:9612, proto TCP (zone Untrust int  ethernet0/0). Occurred 1 times. (2016-07-07 05:02:32)
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'netscreenfw')
        self.assertEqual(response.rule_id, '4560')
        self.assertEqual(response.rule_level, 3)

