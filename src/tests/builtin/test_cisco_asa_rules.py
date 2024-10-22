#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from cisco_asa.ini
class TestCisco_asaRules(unittest.TestCase):

    def test_cisco_asa_alert_message_1(self) -> None:
        log = '''%ASA-1-505015: Module ips, application up "IPS", version "7.2(2)E4" Normal Operation'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64001')
        self.assertEqual(response.rule_level, 6)


    def test_cisco_asa_alert_message_2(self) -> None:
        log = '''%ASA-1-106101: Number of cached deny-flows for ACL log has reached limit (4096)'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64001')
        self.assertEqual(response.rule_level, 6)


    def test_cisco_asa_alert_message_3(self) -> None:
        log = '''%ASA-1-323006: Module ips experienced a data channel communication failure, data channel is DOWN.'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64001')
        self.assertEqual(response.rule_level, 6)


    def test_cisco_asa_critical_message_1(self) -> None:
        log = '''%ASA-2-106001: Inbound TCP connection denied from 111.93.241.59/54322 to 116.6.127.122/1433 flags SYN on interface outside'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64002')
        self.assertEqual(response.rule_level, 5)


    def test_cisco_asa_critical_message_2(self) -> None:
        log = '''%ASA-2-106006: Deny inbound UDP from 185.158.113.158/53306 to 116.6.127.123/53413 on interface outside'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64002')
        self.assertEqual(response.rule_level, 5)


    def test_cisco_asa_critical_message_3(self) -> None:
        log = '''%ASA-2-747011: Memory allocation Error'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64002')
        self.assertEqual(response.rule_level, 5)


    def test_cisco_asa_critical_message_4(self) -> None:
        log = '''%ASA-2-321006: System Memory usage reached 93%'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64002')
        self.assertEqual(response.rule_level, 5)


    def test_cisco_asa_error_message_1(self) -> None:
        log = '''%ASA-3-338309: The license on this ASA does not support dynamic filter updater feature'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64003')
        self.assertEqual(response.rule_level, 4)


    def test_cisco_asa_error_message_2(self) -> None:
        log = '''%ASA-3-710003: TCP access denied by ACL from 192.168.0.1/11 to outside:192.168.0.2/22'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64003')
        self.assertEqual(response.rule_level, 4)


    def test_cisco_asa_error_message_3(self) -> None:
        log = '''%ASA-3-421001: UDP flow from WLC-LAN_inside:10.233.19.92/60803 to outside:8.8.8.8/53 is dropped because application has failed'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64003')
        self.assertEqual(response.rule_level, 4)


    def test_cisco_asa_error_message_4(self) -> None:
        log = '''%ASA-3-421007: UDP flow from WLC-LAN_inside:10.233.19.92/60803 to outside:8.8.8.8/53 is skipped because application has failed'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64003')
        self.assertEqual(response.rule_level, 4)


    def test_cisco_asa_error_message_5(self) -> None:
        log = '''%ASA-3-421007: UDP flow from WLC-LAN_inside:10.233.19.92/60803 to outside:8.8.8.8/53 is skipped because application has failed'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64003')
        self.assertEqual(response.rule_level, 4)


    def test_cisco_asa_error_message_6(self) -> None:
        log = '''%ASA-3-106014: Deny inbound icmp src outside:151.80.47.231 dst outside:116.6.127.112 (type 3, code 2)'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64003')
        self.assertEqual(response.rule_level, 4)


    def test_cisco_asa_error_message_7(self) -> None:
        log = '''%ASA-3-338310: Failed to update from dynamic filter updater server https://update-manifests.ironport.com, reason: Failed to connect to updater server'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64003')
        self.assertEqual(response.rule_level, 4)


    def test_cisco_asa_error_message_8(self) -> None:
        log = '''%ASA-3-202010: PAT pool exhausted. Unable to create TCP connection from WLC-LAN_inside:10.237.52.235/40012 to outside:183.240.12.88/443'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64003')
        self.assertEqual(response.rule_level, 4)


    def test_cisco_asa_error_message_9(self) -> None:
        log = '''%ASA-3-106010: Deny inbound protocol 47 src outside:115.51.6.185 dst outside:116.6.127.120'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64003')
        self.assertEqual(response.rule_level, 4)


    def test_cisco_asa_warning_message_1(self) -> None:
        log = '''%ASA-4-313005: No matching connection for ICMP error message: icmp src WLC-LAN_inside:10.233.152.101 dst outside:8.8.8.8 (type 3, code 3) on WLC-LAN_inside interface.  Original IP payload: udp src 8.8.8.8/53 dst 10.233.152.101/62403'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64004')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_asa_warning_message_2(self) -> None:
        log = '''%ASA-4-106023: Deny tcp src inside:111.11.11.1/2143 dst YYY:172.11.1.11/139 by access-group "inside_inbound"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64004')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_asa_warning_message_3(self) -> None:
        log = '''%ASA-4-733100: Object drop rate 15 exceeded. Current burst rate is 9 per second, max configured rate is 10; Current average rate is 15 per second, max configured rate is 5; Cumulative total count is 9198'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64004')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_asa_warning_message_4(self) -> None:
        log = '''%ASA-4-338008: Dynamic Filter dropped blacklisted TCP traffic from WLC-LAN_inside:10.233.70.240/51638 (193.17.108.1/51638) to outside:198.71.232.3/80 (198.71.232.3/80), destination 198.71.232.3 resolved from dynamic list: 198.71.232.3/255.255.255.255, threat-level: very-high, category: Bot and Threat Networks'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64004')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_asa_warning_message_5(self) -> None:
        log = '''%ASA-4-500004: Invalid transport field for protocol=UDP, from 10.235.91.49/45682 to 80.98.44.227/0'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64004')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_asa_warning_message_6(self) -> None:
        log = '''%ASA-4-313009: Denied invalid ICMP code 9, for serverlan:EUCH1AAISE/38706 (EUCH1AAISE/38706) to WLC-LAN_inside:10.235.50.134/0 (10.235.50.134/0), ICMP id 295, ICMP type 8'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64004')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_asa_warning_message_7(self) -> None:
        log = '''%ASA-4-209005: Discard IP fragment set with more than 24 elements:  src = 10.235.211.237, dest = 86.29.145.200, proto = UDP, id = 48916'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64004')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_asa_warning_message_8(self) -> None:
        log = '''%ASA-4-420002: IPS requested to drop UDP packet from WLC-LAN_inside:10.235.211.237/6882 to outside:86.29.61.87/6882'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64004')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_asa_warning_message_9(self) -> None:
        log = '''%ASA-4-434002: SFR requested to drop TCP packet from outside:123.133.65.58/51115 to DMZ-SSLVPN:116.6.127.117/443'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64004')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_asa_warning_message_10(self) -> None:
        log = '''%ASA-4-313004: Denied ICMP type=0, from laddr 80.241.208.43 on interface outside to 116.6.127.116: no matching session'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64004')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_asa_warning_message_11(self) -> None:
        log = '''%ASA-4-410001: Dropped UDP DNS request from outside:139.162.126.103/46951 to DMZ-SSLVPN:143.35.126.146/53; label length 46 bytes exceeds remaining packet length limit of 17 bytes'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64004')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_asa_warning_message_12(self) -> None:
        log = '''%ASA-4-338202: Dynamic Filter monitored greylisted TCP traffic from WLC-LAN_inside:10.233.39.227/59610 (193.17.108.1/59610) to outside:152.195.32.56/443 (152.195.32.56/443), destination 152.195.32.56 resolved from dynamic list: images0.minutemediacdn.com, threat-level: very-high, category: Malware'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64004')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_asa_warning_message_13(self) -> None:
        log = '''%ASA-4-444005: Timebased license key 0x5b0349c2 0x55b93067 0x1395643 0xc48b41fb 0x373ecb2 will expire in 127 days.'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64004')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_asa_warning_message_14(self) -> None:
        log = '''%ASA-4-419002: Duplicate TCP SYN from WLC-LAN_inside:10.233.209.119/42736 to outside:192.168.0.8/52082 with different initial sequence number'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64004')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_asa_warning_message_15(self) -> None:
        log = '''%ASA-4-418001: Through-the-device packet to/from management-only network is denied: udp src DMZ:10.231.5.250/49152 dst management:143.36.200.25/161'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64004')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_asa_warning_message_16(self) -> None:
        log = '''%ASA-4-108004: ESMTP Classification: Dropped connection for ESMTP Request from WLC-LAN_inside:10.235.61.181/49536 to outside:217.76.146.62/25; matched Class 4: header line length gt 998'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64004')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_asa_warning_message_17(self) -> None:
        log = '''%ASA-4-409023: Attempting AAA Fallback method LOCAL for Authentication request for user impssnagios : Auth-server group IMPSS unreachable'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64004')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_asa_warning_message_18(self) -> None:
        log = '''%ASA-4-711004: Task ran for 435 msec, Process = DATAPATH-0-1879, PC = 0, Call stack = 0x090b0155'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64004')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_asa_warning_message_19(self) -> None:
        log = '''%ASA-4-411001: Line protocol on Interface GigabitEthernet0/0, changed state to up'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64004')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_asa_warning_message_20(self) -> None:
        log = '''%ASA-4-405003: IP address collision detected between host 1.0.0.2 at 00e0.ed27.620f and interface FAILOVER, 00e0.ed22.eb39'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64004')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_asa_warning_message_21(self) -> None:
        log = '''Oct 03 2018 17:34:08: %ASA-4-106023: Deny udp src office:1.1.1.1/3217 dst FE_xUI:Server_Windows/15000 by access-group "ACLoffice" [0x0, 0x0]'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64004')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_asa_notification_informational_message_1(self) -> None:
        log = '''%ASA-5-505002: Module ips is reloading. Please wait...'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64005')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_asa_notification_informational_message_2(self) -> None:
        log = '''%ASA-6-305012: Teardown dynamic TCP translation from WLC-LAN_inside:10.233.16.130/6890 to outside:193.17.108.1/6890 duration 0:02:32'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64005')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_asa_notification_informational_message_3(self) -> None:
        log = '''%ASA-6-305012: Teardown dynamic TCP translation from WLC-LAN_inside:10.233.16.130/6890 to outside:193.17.108.1/6890 duration 0:02:32'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64005')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_asa_notification_informational_message_4(self) -> None:
        log = '''%ASA-6-302014: Teardown TCP connection 4211 for external:171.70.168.183/53 to mgmt:192.168.1.185/1032 duration 0:00:00 bytes 526'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64005')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_asa_notification_informational_message_5(self) -> None:
        log = '''%ASA-6-302018: Teardown GRE connection 4211 from external:171.70.168.183/53 to mgmt:192.168.1.185/1032 duration 0:00:00 bytes 526'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64005')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_asa_notification_informational_message_6(self) -> None:
        log = '''%ASA-6-302021: Teardown ICMP connection 9 from outside:10.1.2.1/22 (10.1.2.1/22) to inside:10.1.1.2/53496 (10.1.1.2/53496)'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64005')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_asa_notification_informational_message_7(self) -> None:
        log = '''%ASA-6-302023: Teardown stub TCP connection for external:171.70.168.183/53 to mgmt:192.168.1.185/1032 duration 0:00:00 forwarded bytes 526 reason Conn-timeout'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64005')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_asa_notification_informational_message_8(self) -> None:
        log = '''%ASA-6-603109: Teardown PPOE Tunnel at interface, tunnel-id = 12312, remote-peer = 192.168.0.1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64005')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_asa_notification_informational_message_9(self) -> None:
        log = '''%ASA-6-305011: Built dynamic TCP translation from WLC-LAN_inside:10.235.50.55/58159 to outside:193.17.116.1/58159'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64005')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_asa_notification_informational_message_10(self) -> None:
        log = '''%ASA-6-302013: Built outbound TCP connection 9 for outside:10.1.2.1/22 (10.1.2.1/22) to inside:10.1.1.2/53496 (10.1.1.2/53496)'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64005')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_asa_notification_informational_message_11(self) -> None:
        log = '''%ASA-6-603108: Built PPTP Tunnel at interfaceex, tunnel-id = 32135, remote-peer = 192.168.0.1, virtual-interface = 3141, client-dynamic-ip = 192.168.0.2, username = userex, MPPE-key-strength = 15412'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64005')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_asa_notification_informational_message_12(self) -> None:
        log = '''%ASA-5-718060: Inbound socket select fail: context=21312'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64005')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_asa_notification_informational_message_13(self) -> None:
        log = '''%ASA-5-718062: Inbound thread is awake (context=21312)'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64005')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_asa_notification_informational_message_14(self) -> None:
        log = '''%ASA-6-106015: Deny TCP (no connection) from 192.168.0.1/11 to 192.168.0.2/22 flags tcp_flags on interface interface_name'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64005')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_asa_notification_informational_message_15(self) -> None:
        log = '''%ASA-5-304001: 192.168.200.2 Accessed URL 157.166.255.19:http://cnn.com/'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64005')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_asa_notification_informational_message_16(self) -> None:
        log = '''%ASA-5-304002: Access denied URL http://s.tbdress.com/images/favicon.ico SRC 10.69.6.39 DEST 72.21.91.19 on interface inside'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64005')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_asa_notification_informational_message_17(self) -> None:
        log = '''%ASA-5-611103: User logged out: Uname: impssnagios'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64005')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_asa_notification_informational_message_18(self) -> None:
        log = '''%ASA-6-421002: UDP flow from WLC-LAN_inside:10.233.19.92/60803 to outside:8.8.8.8/53 bypassed application checking because the protocol is not supported'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64005')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_asa_notification_informational_message_19(self) -> None:
        log = '''%ASA-5-338303: Address 184.173.97.68 (ads74271.hotwords.com) timed out. Removing rule'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64005')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_asa_notification_informational_message_20(self) -> None:
        log = '''%ASA-5-338302: Address 185.40.154.13 discovered for domain gaijin.s-2.clients.cdnnow.ru from blacklist, Adding rule'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64005')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_asa_notification_informational_message_21(self) -> None:
        log = '''%ASA-5-111010: User 'pgskyadm', running 'CLI' from IP 143.16.64.46, executed 'terminal pager 0''''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64005')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_asa_notification_informational_message_22(self) -> None:
        log = '''%ASA-5-500003: Bad TCP hdr length (hdrlen=4, pktlen=74) from 123.146.183.231/34160 to 116.6.127.118/443, flags: INVALID, on interface outside'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64005')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_asa_notification_informational_message_23(self) -> None:
        log = '''%ASA-5-771002: CLOCK: System clock set, source: NTP, IP: opbay01ntp, before: 13:44:00.021 GMT Wed Sep 20 2017, after: 13:44:11.537 GMT Wed Sep 20 2017'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64005')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_asa_debug_message(self) -> None:
        log = '''%ASA-7-609001: Built local-host Internet:200.201.202.203'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64006')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_asa_failed_login_attempt(self) -> None:
        log = '''%ASA-6-605004: Login denied from 192.168.2.10/32597 to outside:192.168.2.14/ssh for user "root"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64007')
        self.assertEqual(response.rule_level, 9)


    def test_cisco_asa_privilege_changed(self) -> None:
        log = '''%ASA-5-502103: User priv level changed: Uname: impssnagios From: 1 To: 15'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64008')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_asa_successful_login(self) -> None:
        log = '''%ASA-6-605005: Login permitted from 192.168.0.1/11 to outside:192.168.0.2/ssh for user "username"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64009')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_asa_password_mismatch_while_running_enable(self) -> None:
        log = '''%ASA-6-308001: console enable password incorrect for number tries (from 192.168.0.1)'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64010')
        self.assertEqual(response.rule_level, 9)


    def test_cisco_asa_arp_collision_detected(self) -> None:
        log = '''%ASA-4-405001: Received ARP response collision from 10.233.250.16/202d.07fc.5c1a on interface WLC-LAN_inside with existing ARP entry 10.233.250.16/0016.a421.94ef'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64011')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_asa_attempt_to_connect_from_a_blocked_shunned_ip(self) -> None:
        log = '''%ASA-4-401004 Shunned packet: 192.168.0.1 = 192.168.0.2 on interface interfacename'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64012')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_asa_connection_limit_exceeded(self) -> None:
        log = '''%ASA-7-710004: TCP connection limit exceeded from 192.168.0.1/11 to outside:192.168.0.2/22 (current connections/connection limit = 11/10)'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64013')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_asa_attack_in_progress_detected_1(self) -> None:
        log = '''%ASA-1-106022: Deny protocol connection spoof from 192.168.0.1 to 192.168.0.2 on interface interfacename.'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64017')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_asa_attack_in_progress_detected_2(self) -> None:
        log = '''%ASA-2-106017: Deny IP due to Land Attack from 193.17.108.1 to 193.17.108.1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64017')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_asa_attack_in_progress_detected_3(self) -> None:
        log = '''%ASA-2-106020: Deny IP teardrop fragment (size = 1480, offset = 0) from 10.235.224.228 to 10.235.0.1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64017')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_asa_attack_in_progress_detected_4(self) -> None:
        log = '''%ASA-1-106021: Deny protocol reverse path check from 192.168.0.1 to 192.168.0.2 on interface interfacename'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64017')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_asa_aaa_vpn_authentication_failed(self) -> None:
        log = '''%ASA-6-113005: AAA user authentication Rejected: reason = string: server = 174.143.32.22, User = user: user IP = 192.168.0.1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64018')
        self.assertEqual(response.rule_level, 5)


    def test_cisco_asa_aaa_vpn_authentication_successful(self) -> None:
        log = '''%ASA-6-113004: AAA user example Successful: server = 174.243.13.65, User = user'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64019')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_asa_aaa_vpn_user_locked_out(self) -> None:
        log = '''%ASA-6-113006: User user locked out on exceeding number successive failed authentication attempts'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64020')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_asa_the_asa_is_disallowing_new_connections(self) -> None:
        log = '''%ASA-3-201008: Disallowing new connections'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64021')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_asa_firewall_failover_pair_communication_problem_1(self) -> None:
        log = '''%ASA-1-105005: (Secondary) Lost Failover communications with mate on interface WLC-LAN_inside'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64022')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_asa_firewall_failover_pair_communication_problem_2(self) -> None:
        log = '''%ASA-1-105009: (Primary) Testing on interface interface_name Failed'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64022')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_asa_firewall_failover_pair_communication_problem_3(self) -> None:
        log = '''%ASA-1-105043: (Primary) Failover interface failed'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64022')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_asa_firewall_configuration_deleted(self) -> None:
        log = '''%ASA-5-111003: 192.168.0.1 Erase configuration'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64023')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_asa_firewall_configuration_changed_1(self) -> None:
        log = '''%ASA-5-111005: 192.168.0.1 end configuration: OK'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64024')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_asa_firewall_configuration_changed_2(self) -> None:
        log = '''%ASA-5-111004: 192.168.0.1 end configuration: FAILED'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64024')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_asa_firewall_configuration_changed_3(self) -> None:
        log = '''%ASA-5-111002: Begin configuration: 192.168.0.1 reading from device'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64024')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_asa_firewall_configuration_changed_4(self) -> None:
        log = '''%ASA-5-111007: Begin configuration: 192.168.0.1 reading from device.'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64024')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_asa_firewall_command_executed_for_accounting_only_i(self) -> None:
        log = '''%ASA-5-111008: User 'impssnagios' executed the 'enable' command.'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64025')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_asa_firewall_command_executed_for_accounting_only_ii(self) -> None:
        log = '''%ASA-7-111009: User user executed cmd:string.'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64026')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_asa_user_created_or_modified_on_the_firewall_1(self) -> None:
        log = '''%ASA-5-502101: New user added to local dbase: Uname: user Priv: privilege_level Encpass: string'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64027')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_asa_user_created_or_modified_on_the_firewall_2(self) -> None:
        log = '''%ASA-5-502102: User deleted from local dbase: Uname: user Priv: privilege_level Encpass: string'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-asa')
        self.assertEqual(response.rule_id, '64027')
        self.assertEqual(response.rule_level, 8)

