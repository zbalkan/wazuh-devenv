#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from sophos_fw.ini
class TestSophos_fwRules(unittest.TestCase):

    def test_sophos_firewall_traffic_denied(self) -> None:
        log = '''device="SFW" date=2019-10-09 time=17:19:06 timezone="+08" device_name="XG210" device_id=AAAAAAAA1234567 log_id=010101010101 log_type="Firewall" log_component="Firewall Rule" log_subtype="Denied" status="Deny" priority=Information duration=0 fw_rule_id=14 policy_type=1 user_name="" user_gp="" iap=2 ips_policy_id=0 appfilter_policy_id=0 application="" application_risk=0 application_technology="" application_category="" in_interface="Port3" out_interface="Port2" src_mac=11:22:aa:bb:22:11 src_ip=11.22.33.44 src_country_code= dst_ip=44.33.22.11 dst_country_code= protocol="TCP" src_port=52667 dst_port=10051 sent_pkts=0  recv_pkts=0 sent_bytes=0 recv_bytes=0 tran_src_ip= tran_src_port=0 tran_dst_ip= tran_dst_port=0 srczonetype="" srczone="" dstzonetype="" dstzone="" dir_disp="" connid="" vconnid="" hb_health="No Heartbeat" message="" appresolvedby="Signature"th="No Heartbeat'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sophos-fw')
        self.assertEqual(response.rule_id, '70021')
        self.assertEqual(response.rule_level, 5)


    def test_sophos_firewall_traffic_allowed(self) -> None:
        log = '''device="SFW" date=2019-10-09 time=17:19:06 timezone="+08" device_name="XG210" device_id=AAAAAAAA1234567 log_id=010101010101 log_type="Firewall" log_component="Firewall Rule" log_subtype="Allowed" status="Allow" priority=Information duration=0 fw_rule_id=14 policy_type=1 user_name="" user_gp="" iap=2 ips_policy_id=0 appfilter_policy_id=0 application="" application_risk=0 application_technology="" application_category="" in_interface="Port3" out_interface="Port2" src_mac=11:22:aa:bb:22:11 src_ip=11.22.33.44 src_country_code= dst_ip=44.33.22.11 dst_country_code= protocol="TCP" src_port=52667 dst_port=10051 sent_pkts=0  recv_pkts=0 sent_bytes=0 recv_bytes=0 tran_src_ip= tran_src_port=0 tran_dst_ip= tran_dst_port=0 srczonetype="" srczone="" dstzonetype="" dstzone="" dir_disp="" connid="" vconnid="" hb_health="No Heartbeat" message="" appresolvedby="Signature"th="No Heartbeat'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sophos-fw')
        self.assertEqual(response.rule_id, '70022')
        self.assertEqual(response.rule_level, 3)


    def test_sophos_firewall_traffic_detect(self) -> None:
        log = '''device="SFW" date=2019-10-09 time=17:19:06 timezone="+08" device_name="XG210" device_id=AAAAAAAA1234567 log_id=010101010101 log_type="Firewall" log_component="Firewall Rule" log_subtype="Detected" status="Detect" priority=Information duration=0 fw_rule_id=14 policy_type=1 user_name="" user_gp="" iap=2 ips_policy_id=0 appfilter_policy_id=0 application="" application_risk=0 application_technology="" application_category="" in_interface="Port3" out_interface="Port2" src_mac=11:22:aa:bb:22:11 src_ip=11.22.33.44 src_country_code= dst_ip=44.33.22.11 dst_country_code= protocol="TCP" src_port=52667 dst_port=10051 sent_pkts=0  recv_pkts=0 sent_bytes=0 recv_bytes=0 tran_src_ip= tran_src_port=0 tran_dst_ip= tran_dst_port=0 srczonetype="" srczone="" dstzonetype="" dstzone="" dir_disp="" connid="" vconnid="" hb_health="No Heartbeat" message="" appresolvedby="Signature"th="No Heartbeat'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sophos-fw')
        self.assertEqual(response.rule_id, '70023')
        self.assertEqual(response.rule_level, 3)


    def test_sophos_firewall_traffic_drop(self) -> None:
        log = '''device="SFW" date=2019-10-09 time=17:19:06 timezone="+08" device_name="XG210" device_id=AAAAAAAA1234567 log_id=010101010101 log_type="Firewall" log_component="Firewall Rule" log_subtype="Dropped" status="Drop" priority=Information duration=0 fw_rule_id=14 policy_type=1 user_name="" user_gp="" iap=2 ips_policy_id=0 appfilter_policy_id=0 application="" application_risk=0 application_technology="" application_category="" in_interface="Port3" out_interface="Port2" src_mac=11:22:aa:bb:22:11 src_ip=11.22.33.44 src_country_code= dst_ip=44.33.22.11 dst_country_code= protocol="TCP" src_port=52667 dst_port=10051 sent_pkts=0  recv_pkts=0 sent_bytes=0 recv_bytes=0 tran_src_ip= tran_src_port=0 tran_dst_ip= tran_dst_port=0 srczonetype="" srczone="" dstzonetype="" dstzone="" dir_disp="" connid="" vconnid="" hb_health="No Heartbeat" message="" appresolvedby="Signature"th="No Heartbeat'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sophos-fw')
        self.assertEqual(response.rule_id, '70024')
        self.assertEqual(response.rule_level, 3)


    def test_sophos_firewall_traffic_clean(self) -> None:
        log = '''device="SFW" date=2019-10-09 time=17:19:06 timezone="+08" device_name="XG210" device_id=AAAAAAAA1234567 log_id=010101010101 log_type="Firewall" log_component="Firewall Rule" log_subtype="Cleaned" status="Clean" priority=Information duration=0 fw_rule_id=14 policy_type=1 user_name="" user_gp="" iap=2 ips_policy_id=0 appfilter_policy_id=0 application="" application_risk=0 application_technology="" application_category="" in_interface="Port3" out_interface="Port2" src_mac=11:22:aa:bb:22:11 src_ip=11.22.33.44 src_country_code= dst_ip=44.33.22.11 dst_country_code= protocol="TCP" src_port=52667 dst_port=10051 sent_pkts=0  recv_pkts=0 sent_bytes=0 recv_bytes=0 tran_src_ip= tran_src_port=0 tran_dst_ip= tran_dst_port=0 srczonetype="" srczone="" dstzonetype="" dstzone="" dir_disp="" connid="" vconnid="" hb_health="No Heartbeat" message="" appresolvedby="Signature"th="No Heartbeat'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sophos-fw')
        self.assertEqual(response.rule_id, '70025')
        self.assertEqual(response.rule_level, 3)


    def test_sophos_firewall_virus_detected(self) -> None:
        log = '''device="SFW" date=2019-10-09 time=17:19:06 timezone="+08" device_name="XG210" device_id=AAAAAAAA1234567 log_id=010101010101 log_type="Firewall" log_component="Firewall Rule" log_subtype="Virus" status="Virus" priority=Information duration=0 fw_rule_id=14 policy_type=1 user_name="" user_gp="" iap=2 ips_policy_id=0 appfilter_policy_id=0 application="" application_risk=0 application_technology="" application_category="" in_interface="Port3" out_interface="Port2" src_mac=11:22:aa:bb:22:11 src_ip=11.22.33.44 src_country_code= dst_ip=44.33.22.11 dst_country_code= protocol="TCP" src_port=52667 dst_port=10051 sent_pkts=0  recv_pkts=0 sent_bytes=0 recv_bytes=0 tran_src_ip= tran_src_port=0 tran_dst_ip= tran_dst_port=0 srczonetype="" srczone="" dstzonetype="" dstzone="" dir_disp="" connid="" vconnid="" hb_health="No Heartbeat" message="" appresolvedby="Signature"th="No Heartbeat'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sophos-fw')
        self.assertEqual(response.rule_id, '70026')
        self.assertEqual(response.rule_level, 7)


    def test_sophos_firewall_traffic_spam(self) -> None:
        log = '''device="SFW" date=2019-10-09 time=17:19:06 timezone="+08" device_name="XG210" device_id=AAAAAAAA1234567 log_id=010101010101 log_type="Firewall" log_component="Firewall Rule" log_subtype="Spam" status="Spam" priority=Information duration=0 fw_rule_id=14 policy_type=1 user_name="" user_gp="" iap=2 ips_policy_id=0 appfilter_policy_id=0 application="" application_risk=0 application_technology="" application_category="" in_interface="Port3" out_interface="Port2" src_mac=11:22:aa:bb:22:11 src_ip=11.22.33.44 src_country_code= dst_ip=44.33.22.11 dst_country_code= protocol="TCP" src_port=52667 dst_port=10051 sent_pkts=0  recv_pkts=0 sent_bytes=0 recv_bytes=0 tran_src_ip= tran_src_port=0 tran_dst_ip= tran_dst_port=0 srczonetype="" srczone="" dstzonetype="" dstzone="" dir_disp="" connid="" vconnid="" hb_health="No Heartbeat" message="" appresolvedby="Signature"th="No Heartbeat'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sophos-fw')
        self.assertEqual(response.rule_id, '70027')
        self.assertEqual(response.rule_level, 5)


    def test_sophos_firewall_traffic_admin(self) -> None:
        log = '''device="SFW" date=2019-10-09 time=17:19:06 timezone="+08" device_name="XG210" device_id=AAAAAAAA1234567 log_id=010101010101 log_type="Firewall" log_component="Firewall Rule" log_subtype="Admin" status="Admin" priority=Information duration=0 fw_rule_id=14 policy_type=1 user_name="" user_gp="" iap=2 ips_policy_id=0 appfilter_policy_id=0 application="" application_risk=0 application_technology="" application_category="" in_interface="Port3" out_interface="Port2" src_mac=11:22:aa:bb:22:11 src_ip=11.22.33.44 src_country_code= dst_ip=44.33.22.11 dst_country_code= protocol="TCP" src_port=52667 dst_port=10051 sent_pkts=0  recv_pkts=0 sent_bytes=0 recv_bytes=0 tran_src_ip= tran_src_port=0 tran_dst_ip= tran_dst_port=0 srczonetype="" srczone="" dstzonetype="" dstzone="" dir_disp="" connid="" vconnid="" hb_health="No Heartbeat" message="" appresolvedby="Signature"th="No Heartbeat'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sophos-fw')
        self.assertEqual(response.rule_id, '70028')
        self.assertEqual(response.rule_level, 3)


    def test_sophos_firewall_traffic_authentication(self) -> None:
        log = '''device="SFW" date=2019-10-09 time=17:19:06 timezone="+08" device_name="XG210" device_id=AAAAAAAA1234567 log_id=010101010101 log_type="Firewall" log_component="Firewall Rule" log_subtype="Authentication" status="Authentication" priority=Information duration=0 fw_rule_id=14 policy_type=1 user_name="" user_gp="" iap=2 ips_policy_id=0 appfilter_policy_id=0 application="" application_risk=0 application_technology="" application_category="" in_interface="Port3" out_interface="Port2" src_mac=11:22:aa:bb:22:11 src_ip=11.22.33.44 src_country_code= dst_ip=44.33.22.11 dst_country_code= protocol="TCP" src_port=52667 dst_port=10051 sent_pkts=0  recv_pkts=0 sent_bytes=0 recv_bytes=0 tran_src_ip= tran_src_port=0 tran_dst_ip= tran_dst_port=0 srczonetype="" srczone="" dstzonetype="" dstzone="" dir_disp="" connid="" vconnid="" hb_health="No Heartbeat" message="" appresolvedby="Signature"th="No Heartbeat'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sophos-fw')
        self.assertEqual(response.rule_id, '70029')
        self.assertEqual(response.rule_level, 5)


    def test_sophos_firewall_traffic_system(self) -> None:
        log = '''device="SFW" date=2019-10-09 time=17:19:06 timezone="+08" device_name="XG210" device_id=AAAAAAAA1234567 log_id=010101010101 log_type="Firewall" log_component="Firewall Rule" log_subtype="System" status="System" priority=Information duration=0 fw_rule_id=14 policy_type=1 user_name="" user_gp="" iap=2 ips_policy_id=0 appfilter_policy_id=0 application="" application_risk=0 application_technology="" application_category="" in_interface="Port3" out_interface="Port2" src_mac=11:22:aa:bb:22:11 src_ip=11.22.33.44 src_country_code= dst_ip=44.33.22.11 dst_country_code= protocol="TCP" src_port=52667 dst_port=10051 sent_pkts=0  recv_pkts=0 sent_bytes=0 recv_bytes=0 tran_src_ip= tran_src_port=0 tran_dst_ip= tran_dst_port=0 srczonetype="" srczone="" dstzonetype="" dstzone="" dir_disp="" connid="" vconnid="" hb_health="No Heartbeat" message="" appresolvedby="Signature"th="No Heartbeat'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sophos-fw')
        self.assertEqual(response.rule_id, '70030')
        self.assertEqual(response.rule_level, 3)

