#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log, send_multiple_logs


# Converted from iptables.ini
class TestIptablesRules(unittest.TestCase):

    def test_iptables_custom_action_1(self) -> None:
        log = r'''
Feb  4 23:33:37 hostname kernel: FIREWALL_OUT IN= OUT=eth0 SRC=192.168.6.57 DST=216.161.248.225 LEN=40 TOS=0x00 PREC=0x00 TTL=64 ID=18547 DF PROTO=TCP SPT=46388 DPT=37628 WINDOW=6930 RES=0x00 ACK RST URGn=0
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4100')
        self.assertEqual(response.rule_level, 0)


    def test_iptables_custom_action_2(self) -> None:
        log = r'''
Feb  4 23:33:37 hostname kernel: IPTABLE IN=eth0 OUT= MAC=ff:ff:ff:ff:ff:ff:00:03:93:db:2e:b4:08:00 SRC=10.4.11.40 DST=255.255.255.255 LEN=180 TOS=0x00 PREC=0x00 TTL=64 ID=4753 PROTO=UDP SPT=49320 DPT=2222 LEN=160
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4100')
        self.assertEqual(response.rule_level, 0)


    def test_iptables_custom_action_3(self) -> None:
        log = r'''
Aug 17 10:03:37 myhostname kernel: SFW2-INext-DROP-DEFLT IN=eth0 OUT= MAC=00:08:02:da:c8:51:00:0f:f7:74:31:8a:08:00 SRC=1.2.3.36 DST=1.2.3.194 LEN=28 TOS=0x00 PREC=0x00 TTL=44 ID=60200 PROTO=ICMP TYPE=8 CODE=0 ID=10466 SEQ=21229
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4100')
        self.assertEqual(response.rule_level, 0)


    def test_iptables_custom_action_4(self) -> None:
        log = r'''
Aug 17 10:03:37 myhostname kernel: [4475569.016000] IN= OUT=lo SRC=192.168.2.11 DST=192.168.2.11 LEN=52 TOS=0x10 PREC=0x00 TTL=64 ID=49546 DF PROTO=TCP SPT=43068 DPT=22 WINDOW=8192 RES=0x00 ACK URGP=0
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4100')
        self.assertEqual(response.rule_level, 0)


    def test_iptables_drop(self) -> None:
        log = r'''
Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4101')
        self.assertEqual(response.rule_level, 5)


    def test_iptables_drop_frecuency_1(self) -> None:
        log = r'''
Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0
'''
        responses = send_multiple_logs([log] * 18)

        response = responses[-1]
        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_drop_frecuency_2(self) -> None:
        log = r'''
Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)
    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_drop_frecuency_3(self) -> None:
        log = r'''
Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)
    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_drop_frecuency_4(self) -> None:
        log = r'''
Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_drop_frecuency_5(self) -> None:
        log = r'''
Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_drop_frecuency_6(self) -> None:
        log = r'''
Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_drop_frecuency_7(self) -> None:
        log = r'''
Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)
    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_drop_frecuency_8(self) -> None:
        log = r'''
Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_drop_frecuency_9(self) -> None:
        log = r'''
Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_drop_frecuency_10(self) -> None:
        log = r'''
Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_drop_frecuency_11(self) -> None:
        log = r'''
Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_drop_frecuency_12(self) -> None:
        log = r'''
Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_drop_frecuency_13(self) -> None:
        log = r'''
Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_drop_frecuency_14(self) -> None:
        log = r'''
Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_drop_frecuency_15(self) -> None:
        log = r'''
Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_drop_frecuency_16(self) -> None:
        log = r'''
Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_drop_frecuency_17(self) -> None:
        log = r'''
Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_drop_frecuency_18(self) -> None:
        log = r'''
Feb  4 23:33:37 hostname kernel: DROP IN= OUT=wlan0 SRC=192.168.1.102 DST=74.125.232.52 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=5394 DF PROTO=TCP SPT=59534 DPT=443 WINDOW=501 RES=0x00 ACK PSH FIN URGP=0
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)


    def test_iptables_openwrt_drop_frecuency_1(self) -> None:
        log = r'''
Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00
'''
        responses = send_multiple_logs([log] * 18)
        response = responses[-1]
        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_openwrt_drop_frecuency_2(self) -> None:
        log = r'''
Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_openwrt_drop_frecuency_3(self) -> None:
        log = r'''
Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_openwrt_drop_frecuency_4(self) -> None:
        log = r'''
Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_openwrt_drop_frecuency_5(self) -> None:
        log = r'''
Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_openwrt_drop_frecuency_6(self) -> None:
        log = r'''
Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_openwrt_drop_frecuency_7(self) -> None:
        log = r'''
Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_openwrt_drop_frecuency_8(self) -> None:
        log = r'''
Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_openwrt_drop_frecuency_9(self) -> None:
        log = r'''
Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_openwrt_drop_frecuency_10(self) -> None:
        log = r'''
Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_openwrt_drop_frecuency_11(self) -> None:
        log = r'''
Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_openwrt_drop_frecuency_12(self) -> None:
        log = r'''
Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_openwrt_drop_frecuency_13(self) -> None:
        log = r'''
Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_openwrt_drop_frecuency_14(self) -> None:
        log = r'''
Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_openwrt_drop_frecuency_15(self) -> None:
        log = r'''
Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_openwrt_drop_frecuency_16(self) -> None:
        log = r'''
Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_openwrt_drop_frecuency_17(self) -> None:
        log = r'''
Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_iptables_openwrt_drop_frecuency_18(self) -> None:
        log = r'''
Nov 18 13:39:49 OpenWRT kernel: [10051.313745] DROP(src wan)IN=eth0 OUT= MAC=c2:56:27:73:33:cf:c4:f0:81:b0:93:24:08:00 SRC=205.205.205.205 DST=192.168.8.100 LEN=44 TOS=0x00 PREC=0x00 TTL=31 ID=8549 PROTO=TCP SPT=40952 DPT=23 WINDOW=64144 RES=0x00 SYN URGP=0 MARK=0xff00
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4151')
        self.assertEqual(response.rule_level, 10)


    def test_iptables_ufw_block_1(self) -> None:
        log = r'''
Feb  4 23:33:37 hostname kernel: [ 3529.289825] [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd SRC=254.253.252.251 DST=191.192.193.194 LEN=103 TOS=0x00 PREC=0x00 TTL=52 ID=0 DF PROTO=UDP SPT=53 DPT=36427 LEN=83
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4100')
        self.assertEqual(response.rule_level, 0)


    def test_iptables_ufw_block_2(self) -> None:
        log = r'''
Dec 26 09:05:47 server01 kernel: [126140.629122] [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd SRC=254.253.252.251 DST=191.192.193.194 LEN=52 TOS=0x02 PREC=0x00 TTL=128 ID=9209 DF PROTO=TCP SPT=17833 DPT=22 WINDOW=8192 RES=0x00 CWR ECE SYN URGP=0
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '4100')
        self.assertEqual(response.rule_level, 0)

