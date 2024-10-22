#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from paloalto.ini
class TestPaloaltoRules(unittest.TestCase):

    def test_palo_alto_generic_1(self) -> None:
        log = '''Apr 30 06:00:00 xx-xx-xx.xx 1,2020/02/09 00:00:00,00000000,SYSTEM,'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'paloalto')
        self.assertEqual(response.rule_id, '64500')
        self.assertEqual(response.rule_level, 0)


    def test_palo_alto_generic_2(self) -> None:
        log = '''Apr 30 06:00:00 xx-xx-xx.xx 1,2020/02/09 00:00:00,00000000,TRAFFIC,'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'paloalto')
        self.assertEqual(response.rule_id, '64500')
        self.assertEqual(response.rule_level, 0)


    def test_palo_alto_generic_3(self) -> None:
        log = '''Apr 30 06:00:00 xx-xx-xx.xx 1,2020/02/09 00:00:00,00000000,CONFIG,'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'paloalto')
        self.assertEqual(response.rule_id, '64500')
        self.assertEqual(response.rule_level, 0)


    def test_palo_alto_generic_4(self) -> None:
        log = '''Apr 30 06:00:00 xx-xx-xx.xx 1,2020/02/09 00:00:00,00000000,THREAT,'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'paloalto')
        self.assertEqual(response.rule_id, '64500')
        self.assertEqual(response.rule_level, 0)


    def test_palo_alto_generic_5(self) -> None:
        log = '''Apr 30 06:00:00 xx-xx-xx.xx 1,2020/02/09 00:00:00,00000000,OTHERS,'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'paloalto')
        self.assertEqual(response.rule_id, '64500')
        self.assertEqual(response.rule_level, 0)


    def test_palo_alto_severity_informational_low_1(self) -> None:
        log = '''Apr 30 06:00:00 xx-xx-xx.xx 1,2020/02/09 00:00:00,00000000,SYSTEM,general,0,2020/00/00 00:00:00,,general,,0,0,general,informational,"xxxxxxxxxxxxxxx",0000000,0x0,0,0,0,0,,XXX-XX-XX'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'paloalto')
        self.assertEqual(response.rule_id, '64501')
        self.assertEqual(response.rule_level, 2)


    def test_palo_alto_severity_informational_low_2(self) -> None:
        log = '''Apr 30 06:00:00 xx-xx-xx.xx 1,2020/02/09 00:00:00,00000000,SYSTEM,general,0,2020/00/00 00:00:00,,general,,0,0,general,low,"xxxxxxxxxxxxxxx",0000000,0x0,0,0,0,0,,XXX-XX-XX'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'paloalto')
        self.assertEqual(response.rule_id, '64501')
        self.assertEqual(response.rule_level, 2)


    def test_palo_alto_severity_medium(self) -> None:
        log = '''Apr 30 06:00:00 xx-xx-xx.xx 1,2020/02/09 00:00:00,00000000,SYSTEM,general,0,2020/00/00 00:00:00,,general,,0,0,general,medium,"xxxxxxxxxxxxxxx",0000000,0x0,0,0,0,0,,XXX-XX-XX'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'paloalto')
        self.assertEqual(response.rule_id, '64502')
        self.assertEqual(response.rule_level, 3)


    def test_palo_alto_severity_high_1(self) -> None:
        log = '''0,2021/07/12 09:46:23,321321321,THREAT,vulnerability,0,2021/07/12 09:46:00,199.195.252.165,172.30.250.61,199.195.252.165,10.20.0.19,GPS-UAT-MODULR-Web-443-OUT,,,web-browsing,vsys1,YYYYYYYYYYY,ZZZZZZZZZZZ,ethernet1/1,tunnel.2,UATH-LogForwarding,2021/07/12 09:46:00,51557,1,55094,443,55094,443,0x502000,tcp,reset-both,"getuser",DCS-2530L Unauthenticated Information Disclosure Vulnerability(90255),any,high,client-to-server,561,0xa000000000000000,United States,172.16.0.0-172.31.255.255,0,,0,,,1,,,,,,,,0,41,225,0,0,,UAT-INTERNET-FW-01,,,,,0,,0,,N/A,info-leak,AppThreat-8428-6809,0x2,0,4294967295,,"  ",dd3035a9-452f-4073-a1bc-169f4b453e6a,0,,0.0.0.0,,,,,,,,,,,,,,,,,,,,,,,,,,,0,2021-07-12T09:46:01.359+01:00,,  ,'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'paloalto')
        self.assertEqual(response.rule_id, '64503')
        self.assertEqual(response.rule_level, 5)


    def test_palo_alto_severity_high_2(self) -> None:
        log = '''Apr 30 06:00:00 xx-xx-xx.xx 1,2020/02/09 00:00:00,00000000,SYSTEM,general,0,2020/00/00 00:00:00,,general,,0,0,general,high,"xxxxxxxxxxxxxxx",0000000,0x0,0,0,0,0,,XXX-XX-XX'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'paloalto')
        self.assertEqual(response.rule_id, '64503')
        self.assertEqual(response.rule_level, 5)


    def test_palo_alto_severity_critical(self) -> None:
        log = '''Apr 30 06:00:00 xx-xx-xx.xx 1,2020/02/09 00:00:00,00000000,SYSTEM,general,0,2020/00/00 00:00:00,,general,,0,0,general,critical,"xxxxxxxxxxxxxxx",0000000,0x0,0,0,0,0,,XXX-XX-XX'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'paloalto')
        self.assertEqual(response.rule_id, '64504')
        self.assertEqual(response.rule_level, 11)


    def test_palo_alto_traffic(self) -> None:
        log = '''0,2021/07/15 11:58:58,1321564321,TRAFFIC,N/A,0,2021/07/15 11:59:02,10.210.0.84,51.11.168.232,,,DENY-ALL,,,not-applicable,vsys1,INSPECTION,INSPECTION,ethernet1/1,,AWS-PANORAMA,2021/07/15 11:59:02,0,1,500,500,0,0,0x0,udp,deny,0,0,0,1,2021/07/15 11:59:02,0,any,0,91501273,0x8000000000000000,10.0.0.0-10.255.255.255,YYYYYYYYYYYY,0,1,0,policy-deny,150,42,25,260,,P1A-GWLB-CORE-FW01,from-policy,,,0,,0,,N/A,0,0,0,0,49543e97-7c8c-44a3-bbd9-031caeb1a65e,0,0,,,,,,,,0.0.0.0,,,,,,,,,,,,,,,,,,,,,,,,,,,2021-07-15T11:59:03.547+01:00,,'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'paloalto')
        self.assertEqual(response.rule_id, '64505')
        self.assertEqual(response.rule_level, 0)


    def test_palo_alto_traffic_start(self) -> None:
        log = '''May 00 00:00:00 XXX-XX-00 1,2020/00/00 00:00:00,00000000,TRAFFIC,start,0000,2020/06/00 00:00:00,00.00.000.00,00.00.00.0,0.0.0.0,0.0.0.0,xxx-xxx_xxxx,,,xxx,xxxxx,xxxx,xxxx,xxxx.0,xxx.000,xxxxxxxx,2020/00/00 00:00:00,0000,1,0000,000,0,0,0x0,xxx,xxxx,000,000,00,0,2020/00/00 00:00:00,1,any,0,0000000,0x0,00.0.0.0-00.000.000.000,00.0.0.0-00.000.000.000,0,0,0,n/a,0,0,0,0,,xxx-xx-01,from-policy,,,0,,0,,N/A,0,0,0,0,00000-0000-00xx00-00xx-0x0x0x000xx,0'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'paloalto')
        self.assertEqual(response.rule_id, '64506')
        self.assertEqual(response.rule_level, 2)


    def test_palo_alto_traffic_end(self) -> None:
        log = '''May 00 00:00:00 XXX-XX-00 1,2020/00/00 00:00:00,00000000,TRAFFIC,end,0000,2020/06/00 00:00:00,00.00.000.00,00.00.00.0,0.0.0.0,0.0.0.0,xxx-xxx_xxxx,,,xxx,xxxxx,xxxx,xxxx,xxxx.0,xxx.000,xxxxxxxx,2020/00/00 00:00:00,0000,1,0000,000,0,0,0x0,xxx,xxxx,000,000,00,0,2020/00/00 00:00:00,1,any,0,0000000,0x0,00.0.0.0-00.000.000.000,00.0.0.0-00.000.000.000,0,0,0,n/a,0,0,0,0,,xxx-xx-01,from-policy,,,0,,0,,N/A,0,0,0,0,00000-0000-00xx00-00xx-0x0x0x000xx,0'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'paloalto')
        self.assertEqual(response.rule_id, '64507')
        self.assertEqual(response.rule_level, 2)


    def test_palo_alto_traffic_dropped_1(self) -> None:
        log = '''May 00 00:00:00 XXX-XX-00 1,2020/00/00 00:00:00,00000000,TRAFFIC,drop,0000,2020/06/00 00:00:00,00.00.000.00,00.00.00.0,0.0.0.0,0.0.0.0,xxx-xxx_xxxx,,,xxx,xxxxx,xxxx,xxxx,xxxx.0,xxx.000,xxxxxxxx,2020/00/00 00:00:00,0000,1,0000,000,0,0,0x0,xxx,xxxx,000,000,00,0,2020/00/00 00:00:00,1,any,0,0000000,0x0,00.0.0.0-00.000.000.000,00.0.0.0-00.000.000.000,0,0,0,n/a,0,0,0,0,,xxx-xx-01,from-policy,,,0,,0,,N/A,0,0,0,0,00000-0000-00xx00-00xx-0x0x0x000xx,0'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'paloalto')
        self.assertEqual(response.rule_id, '64508')
        self.assertEqual(response.rule_level, 6)


    def test_palo_alto_traffic_dropped_2(self) -> None:
        log = '''May 00 00:00:00 XXX-XX-00 1,2020/00/00 00:00:00,00000000,TRAFFIC,deny,0000,2020/06/00 00:00:00,00.00.000.00,00.00.00.0,0.0.0.0,0.0.0.0,xxx-xxx_xxxx,,,xxx,xxxxx,xxxx,xxxx,xxxx.0,xxx.000,xxxxxxxx,2020/00/00 00:00:00,0000,1,0000,000,0,0,0x0,xxx,xxxx,000,000,00,0,2020/00/00 00:00:00,1,any,0,0000000,0x0,00.0.0.0-00.000.000.000,00.0.0.0-00.000.000.000,0,0,0,n/a,0,0,0,0,,xxx-xx-01,from-policy,,,0,,0,,N/A,0,0,0,0,00000-0000-00xx00-00xx-0x0x0x000xx,0'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'paloalto')
        self.assertEqual(response.rule_id, '64508')
        self.assertEqual(response.rule_level, 6)

