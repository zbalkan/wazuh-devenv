#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from cisco_ios.ini
class TestCiscoIosRules(unittest.TestCase):

    def test_cisco_ios_ids_sig_1(self) -> None:
        log = r'''
Sep  1 10:25:29 10.10.10.1 %IPS-4-SIGNATURE: Sig:3051 Subsig:1 Sev:4 TCP Connection Window Size DoS [192.168.100.11:51654 -> 10.10.10.10:4444]
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ios')
        self.assertEqual(response.rule_id, '20100')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_ios_ids_sig_2(self) -> None:
        log = r'''
Sep  1 10:25:29 10.10.10.1 %IPS-4-SIGNATURE: Sig:3051 Subsig:1 Sev:4 TCP Connection Window Size DoS [192.168.100.11:60797 -> 10.10.10.10:80]
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ios')
        self.assertEqual(response.rule_id, '20100')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_ios_ids_sig_3(self) -> None:
        log = r'''
Sep  1 10:25:29 10.10.10.1 %IPS-4-SIGNATURE: Sig:5123 Subsig:2 Sev:5 WWW IIS Internet Printing Overflow [192.168.100.11:60797 -> 10.10.10.10:80]
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ios')
        self.assertEqual(response.rule_id, '20100')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_ios_acl_1(self) -> None:
        log = r'''
Sep  1 10:25:29 10.10.10.1 %SEC-6-IPACCESSLOGP: list 102 denied tcp 10.0.6.56(3067) -> 172.36.4.7(139), 1 packet
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ios')
        self.assertEqual(response.rule_id, '4716')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_ios_acl_2(self) -> None:
        log = r'''
Sep  1 10:25:29 10.10.10.1 %SEC-6-IPACCESSLOGP: list 199 denied tcp 10.0.61.108(1477) -> 10.0.127.20(445), 1 packet
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ios')
        self.assertEqual(response.rule_id, '4716')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_ios_acl_3(self) -> None:
        log = r'''
3924923: *Oct  6 03:32:04.114 gmt: %SEC-6-IPACCESSLOGP: list bcv_out denied tcp 10.0.3.100(50150) -> 192.168.216.1(443), 1 packet
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ios')
        self.assertEqual(response.rule_id, '4716')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_ios_acl_4(self) -> None:
        log = r'''
3924923: *Oct 6 03:32:04 mng: %SEC-6-IPACCESSLOGP: list 1111 denied tcp 10.0.3.100(50150) (Serial4/3 ) -> 192.168.216.1(443), 1 packet
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ios')
        self.assertEqual(response.rule_id, '4716')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_ios_acl_5(self) -> None:
        log = r'''
681: Aug 17 17:41:24.776 AEST: %SEC-6-IPACCESSLOGP: list 102 denied tcp 10.0.6.56(3067) -> 172.36.4.7(139), 1 packet
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ios')
        self.assertEqual(response.rule_id, '4716')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_ios_cisco_switch_1(self) -> None:
        log = r'''
4425: Aug 23 00:17:55.356: %SSH-5-SSH2_SESSION: SSH2 Session request from x.x.x.x (tty = 0) using crypto cipher 'aes-111-sdf0', hmac 'hmac-sha1' Succeeded
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ios')
        self.assertEqual(response.rule_id, '4715')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_ios_cisco_switch_2(self) -> None:
        log = r'''
4423: Aug 23 00:16:18.200: %SSH-5-SSH2_USERAUTH: User 'user' authentication for SSH2 Session from x.x.x.x (tty = 0) using crypto cipher 'aes111-sdf0', hmac 'hmac-sha1' Succeeded
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ios')
        self.assertEqual(response.rule_id, '4715')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_ios_cisco_switch_3(self) -> None:
        log = r'''
Apr 30 15:10:58: %DOT1X-5-FAIL: Authentication failed for client (Unknown MAC) on Interface Fa0/3 AuditSessionID`
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ios')
        self.assertEqual(response.rule_id, '4715')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_ios_syslog(self) -> None:
        log = r'''
2019 May 06 09:28:12 vm-ubuntu16->10.0.0.16 May 6 07:28:11 vm-ubuntu16 fortinet Apr 30 15:10:58: %DOT1X-5-FAIL: Authentication failed for client (Unknown MAC) on Interface Fa0/3 AuditSessionID
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ios')
        self.assertEqual(response.rule_id, '4715')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_ios_generic_1(self) -> None:
        log = r'''
Oct 6 03:32:02 mng: %SEC-6-IPACCESSLOGP: list 1111 denied udp xx.xxx.xx.xx(137) -> xxx.xxx.xxx.xx(137), 1 packet
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ios')
        self.assertEqual(response.rule_id, '4700')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_ios_generic_2(self) -> None:
        log = r'''
Oct 6 03:32:02 gmt: %SEC-6-IPACCESSLOGP: list bes_in denied udp xx.xxx.xx.xx(137) (GigabitEthernet0/1.6 ca5c.1da2.ba43) -> xx.xx.xx.xx(137), 1 packet
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ios')
        self.assertEqual(response.rule_id, '4700')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_ios_generic_3(self) -> None:
        log = r'''
39222: *Oct 6 03:32:02.070 mng: %SEC-6-IPACCESSLOGP: list 167 denied udp xx.xx.xx.xx(137) (GigabitEthernet0/1.6 ab9c.2a62.aa8d) -> xxx.xxx.xxx.xxx(137), 1 packet
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ios')
        self.assertEqual(response.rule_id, '4700')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_ios_error_message_1(self) -> None:
        log = r'''
00:00:46: %LINK-3-UPDOWN: Interface Port-channel1, changed state to up
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ios')
        self.assertEqual(response.rule_id, '4713')
        self.assertEqual(response.rule_level, 4)


    def test_cisco_ios_error_message_2(self) -> None:
        log = r'''
00:00:47: %LINK-3-UPDOWN: Interface GigabitEthernet0/2, changed state to up
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ios')
        self.assertEqual(response.rule_id, '4713')
        self.assertEqual(response.rule_level, 4)

