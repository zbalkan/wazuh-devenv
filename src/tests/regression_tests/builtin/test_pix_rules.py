#!/usr/bin/env python3


# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from pix.ini
class TestPixRules(unittest.TestCase):

    def test_pix1_1(self) -> None:
        log = r'''
%PIX-7-710001: TCP access requested from X.X.X.X/1292 to outside:Y.Y.Y.Y/ssh
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '4312')


    def test_pix1_2(self) -> None:
        log = r'''
%PIX-3-710003: TCP access denied by ACL from 216.39.220.130/54065 to outside:62.192.113.98/ssh
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'pix')
        self.assertEqual(response.rule_id, '4312')
        self.assertEqual(response.rule_level, 4)


    def test_pix1_3(self) -> None:
        log = r'''
%PIX-3-106010: Deny inbound tcp src outside:213.98.79.233/2620 dst dmz:213.98.254.145/135
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'pix')
        self.assertEqual(response.rule_id, '4312')
        self.assertEqual(response.rule_level, 4)


    def test_pix3_1(self) -> None:
        log = r'''
%PIX-7-710002: UDP access permitted from 33.33.33.4/943 to inside:33.33.33.15/snmp
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'pix')
        self.assertEqual(response.rule_id, '4300')
        self.assertEqual(response.rule_level, 0)


    def test_pix3_2(self) -> None:
        log = r'''
%PIX-7-710005: UDP request discarded from <public IP of 525>/4500 to outside:192.168.69.137/4500
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'pix')
        self.assertEqual(response.rule_id, '4300')
        self.assertEqual(response.rule_level, 0)


    def test_pix3_3(self) -> None:
        log = r'''
%PIX-7-710002: TCP access permitted from 10.0.0.1/60749 to db:10.0.0.2/ssh
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'pix')
        self.assertEqual(response.rule_id, '4300')
        self.assertEqual(response.rule_level, 0)


    def test_pix3_4(self) -> None:
        log = r'''
%PIX-6-106015: Deny TCP (no connection) from 161.58.238.151/110 to a.b.c.d/3782 flags RST ACK
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'pix')
        self.assertEqual(response.rule_id, '4300')
        self.assertEqual(response.rule_level, 0)


    def test_pix3_5(self) -> None:
        log = r'''
%PIX-3-106011: Deny inbound (No xlate) udp src outside:192.168.2.1/137
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'pix')
        self.assertEqual(response.rule_id, '4300')
        self.assertEqual(response.rule_level, 0)


    def test_pix3_6(self) -> None:
        log = r'''
%PIX-3-106011: Deny inbound (No xlate) tcp src inside:10.100.7.43/80 dst
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'pix')
        self.assertEqual(response.rule_id, '4300')
        self.assertEqual(response.rule_level, 0)


    def test_pix5(self) -> None:
        log = r'''
%PIX-4-106023: Deny tcp src inside:111.11.11.1/2143 dst YYY:172.11.1.11/139 by access-group "inside_inbound"
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'pix')
        self.assertEqual(response.rule_id, '4313')
        self.assertEqual(response.rule_level, 4)


    def test_pix6_1(self) -> None:
        log = r'''
%PIX-2-106006: Deny inbound UDP from ***/20031 to ***/20031 on
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'pix')
        self.assertEqual(response.rule_id, '4311')
        self.assertEqual(response.rule_level, 5)


    def test_pix6_2(self) -> None:
        log = r'''
%PIX-2-106001: Inbound TCP connection denied from 165.139.46.7/3854 to 165.189.27.70/139 flags
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'pix')
        self.assertEqual(response.rule_id, '4311')
        self.assertEqual(response.rule_level, 5)


    def test_pix8_1(self) -> None:
        log = r'''
%PIX-6-305012: Teardown dynamic UDP translation from inside:1.1.1.1/12 to outside:1.2.1.2/11 duration 0:00:11.
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'pix')
        self.assertEqual(response.rule_id, '4314')
        self.assertEqual(response.rule_level, 0)


    def test_pix8_2(self) -> None:
        log = r'''
%PIX-2-106002: protocol Connection denied by outbound list acl_ID src inside_address dest outside_address
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '4314')


    def test_pix8_3(self) -> None:
        log = r'''
%PIX-2-106002: udp connection denied by outbound list 30 src 216.53.120.62 138 dest 169.132.10.82 138
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '4314')


    def test_pix8_4(self) -> None:
        log = r'''
%PIX-4-400013 IDS:2003 ICMP redirect from 10.4.1.2 to 10.2.1.1 on interface dmz
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '4314')


    def test_pix8_5(self) -> None:
        log = r'''
%PIX-3-305005: No translation group found for icmp src outside:x.x.x.x dst inside:x.x.x.x (type 3, code 0)
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '4314')


    def test_pix8_6(self) -> None:
        log = r'''
%PIX-6-605005: Login permitted from 192.168.1.2/2953 to inside:192.168.1.1/telnet for user ""
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '4314')


    def test_pix8_7(self) -> None:
        log = r'''
%PIX-6-605004: Login denied from 192.168.2.10/32597 to outside:192.168.2.14/ssh for user "root"
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '4314')


    def test_pix8_8(self) -> None:
        log = r'''
%PIX-6-305011: Built dynamic UDP translation from inside:192.168.1.2/1026 to outside:192.168.2.14/1163
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '4314')


    def test_pix8_9(self) -> None:
        log = r'''
%PIX-6-305011: Built dynamic TCP translation from inside:192.168.1.3/54946 to outside:192.168.2.14/1033
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '4314')


    def test_pix8_10(self) -> None:
        log = r'''
%PIX-6-302015: Built outbound UDP connection 156 for outside:192.168.2.10/1514 (192.168.2.10/1514) to inside:192.168.1.2/1026 (192.168.2.14/1163)
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '4314')

