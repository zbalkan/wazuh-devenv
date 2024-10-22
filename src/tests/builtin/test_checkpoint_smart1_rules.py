#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from checkpoint_smart1.ini
class TestCheckpoint_smart1Rules(unittest.TestCase):

    def test_checkpoint_smart1_drop_prohibit_a_packet_from_passing_send_no_response(self) -> None:
        log = '''1 2019-05-15T16:25:50Z HOSTNAME CheckPoint 19710 - [action:"Drop"; flags:"400644"; ifdir:"inbound"; ifname:"eth2"; logid:"0"; loguid:"{0x0,0x0,0x0,0x0}"; origin:"11.22.33.44"; originsicname:"CN=TR-DC-FW-INT-B-5600,O=Internet-QRO..g7hgcu"; sequencenum:"11"; time:"1557937550"; version:"5"; __policy_id_tag:"product=VPN-1 & FireWall-1[db_tag={C12F833B-77C9-3941-9B06-075E9D2A86A2};mgmt=TR-DC-VCON-2-INT;date=1557764162;policy_name=FW-INT-TR\]"; dst:"11.22.33.55"; inzone:"Internal"; layer_name:"FW-INT-TR Security"; layer_uuid:"75569106-7e80-4c4e-ab23-b0848f2cb41b"; match_id:"244"; parent_rule:"0"; rule_action:"Drop"; rule_name:"CleanUp Rule"; rule_uid:"b9d9605b-a71e-4664-a042-3fbd041b0b41"; outzone:"Internal"; product:"VPN-1 & FireWall-1"; proto:"17"; s_port:"55036"; service:"1514"; service_id:"ptos_avaya"; src:"11.22.33.77"; ]'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'checkpoint-smart1')
        self.assertEqual(response.rule_id, '64222')
        self.assertEqual(response.rule_level, 4)


    def test_checkpoint_smart1_reject_prohibit_a_packet_from_passing_send_an_icmp_destination_unreachable_back_to_the_source_host(self) -> None:
        log = '''1 2019-05-15T16:26:19Z HOSTNAME CheckPoint 19710 - [action:"Reject"; flags:"133376"; ifdir:"inbound"; ifname:"daemon"; loguid:"{0x0,0x0,0x0,0x0}"; origin:"11.22.33.44"; originsicname:"CN=TR-DC-FW-INT-B-5600,O=Internet-QRO..g7hgcu"; sequencenum:"7"; time:"1557937579"; version:"5"; community:"smartbt.cinetaca"; cookiei:"ec39c6c9c5d3669c"; dst:"11.22.33.55"; fw_subproduct:"VPN-1"; ike::"Main Mode Failed to match proposal: Transform: AES-256, SHA256, Pre-shared secret, Group 2 (1024 bit); Reason: Wrong value for: Hash Algorithm"; peer_gateway:"11.22.33.66"; reject_category:"IKE failure"; scheme::"IKE"; src:"11.22.33.77"; vpn_feature_name:"IKE"; ]'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'checkpoint-smart1')
        self.assertEqual(response.rule_id, '64223')
        self.assertEqual(response.rule_level, 9)


    def test_checkpoint_smart1_encrypt_connection_encrypted(self) -> None:
        log = '''1 2019-05-15T16:26:39Z HOSTNAME CheckPoint 19710 - [action:"Encrypt"; conn_direction:"Outgoing"; contextnum:"1"; flags:"7232772"; ifdir:"inbound"; ifname:"eth1"; logid:"0"; loguid:"{0x5cdc3dbf,0x0,0x3dff70a,0xc0000000}"; origin:"11.22.33.44"; originsicname:"CN=TR-DC-FW-INT-B-5600,O=Internet-QRO..g7hgcu"; sequencenum:"12"; time:"1557937599"; version:"5"; __policy_id_tag:"product=VPN-1 & FireWall-1[db_tag={C12F833B-77C9-3941-9B06-075E9D2A86A2};mgmt=TR-DC-VCON-2-INT;date=1557764162;policy_name=FW-INT-TR\]"; community:"vpn.tr.csn"; context_num:"1"; dst:"11.22.33.66"; fw_subproduct:"VPN-1"; hll_key:"8249302006406138919"; inzone:"Internal"; layer_name:"FW-INT-TR Security"; layer_name:"FW-INT-TR Application"; layer_uuid:"75569106-7e80-4c4e-ab23-b0848f2cb41b"; layer_uuid:"70fed639-99d5-432c-9d1e-5473a66dff08"; match_id:"142"; match_id:"16777217"; parent_rule:"0"; parent_rule:"0"; rule_action:"Accept"; rule_action:"Accept"; rule_name:"CSN"; rule_uid:"d5d708fe-3315-................'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'checkpoint-smart1')
        self.assertEqual(response.rule_id, '64224')
        self.assertEqual(response.rule_level, 2)


    def test_checkpoint_smart1_decrypt_connection_decrypted(self) -> None:
        log = '''1 2019-05-15T16:26:40Z HOSTNAME CheckPoint 19710 - [action:"Decrypt"; flags:"417028"; ifdir:"inbound"; ifname:"eth4"; logid:"0"; loguid:"{0x5cdc3dc0,0x4,0x3dff70a,0xc0000002}"; origin:"11.22.33.44"; originsicname:"CN=TR-DC-FW-INT-B-5600,O=Internet-QRO..g7hgcu"; sequencenum:"22"; time:"1557937600"; version:"5"; __policy_id_tag:"product=VPN-1 & FireWall-1[db_tag={C12F833B-77C9-3941-9B06-075E9D2A86A2};mgmt=TR-DC-VCON-2-INT;date=1557764162;policy_name=FW-INT-TR\]"; community:"safecharge.hs.triara"; dst:"11.22.33.55"; fw_subproduct:"VPN-1"; inzone:"External"; layer_name:"FW-INT-TR Security"; layer_name:"FW-INT-TR Application"; layer_uuid:"75569106-7e80-4c4e-ab23-b0848f2cb41b"; layer_uuid:"70fed639-99d5-432c-9d1e-5473a66dff08"; match_id:"127"; match_id:"33554431"; parent_rule:"0"; parent_rule:"0"; rule_action:"Accept"; rule_action:"Accept"; rule_name:"SafeCharge SEC"; rule_name:"Implicit Cleanup"; rule_uid:"7a1447ad-3f4b-4397-89d7-3adb4b5c83a5"; methods::"ESP: AES-256 + SHA256"; nat_addtnl_rulenum:"1"; nat_rulenum:"61"; outzone:"Internal"; peer_gateway:"11.22.33.77"; product:"VPN-1 & FireWall-1"; proto:"6"; s_port:"55226"; scheme::"IKE"; service:"51262"; service_id:"port_51262"; src:"11.22.33.88"; vpn_feature_name:"VPN"; xlatedport:"0"; xlatedst:"11.22.33.99"; xlatesport:"0"; xlatesrc:"0.0.0.0";'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'checkpoint-smart1')
        self.assertEqual(response.rule_id, '64225')
        self.assertEqual(response.rule_level, 2)


    def test_checkpoint_smart1_key_install_encryption_keys_were_created(self) -> None:
        log = '''1 2019-05-15T16:27:08Z HOSTNAME CheckPoint 19710 - [action:"Key Install"; flags:"133376"; ifdir:"inbound"; ifname:"daemon"; loguid:"{0x0,0x0,0x0,0x0}"; origin:"11.22.33.44"; originsicname:"CN=TR-DC-FW-INT-B-5600,O=Internet-QRO..g7hgcu"; sequencenum:"5"; time:"1557937628"; version:"5"; cookiei:"891f38892b0e6bd6"; cookier:"d71409f32c496d13"; dst:"11.22.33.55"; fw_subproduct:"VPN-1"; ike::"Informational Exchange Received Delete IKE-SA from Peer: 11.22.33.66; Cookies: 891f38892b0e6bd6-d71409f32c496d13 "; msgid:"a4bd6724"; peer_gateway:"11.22.33.77"; scheme::"IKE"; src:"11.22.33.99"; vpn_feature_name:"IKE"; ]'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'checkpoint-smart1')
        self.assertEqual(response.rule_id, '64226')
        self.assertEqual(response.rule_level, 2)


    def test_checkpoint_smart1_monitored_a_security_event_was_monitored;_however_it_was_not_blocked_due_to_the_current_configuration(self) -> None:
        log = '''1 2019-05-15T16:27:08Z HOSTNAME CheckPoint 19710 - [action:"Monitored";...'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'checkpoint-smart1')
        self.assertEqual(response.rule_id, '64227')
        self.assertEqual(response.rule_level, 4)


    def test_checkpoint_smart1_bypass_the_connection_passed_transparently_through_interspect(self) -> None:
        log = '''1 2019-05-15T16:27:08Z HOSTNAME CheckPoint 19710 - [action:"Bypass";...'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'checkpoint-smart1')
        self.assertEqual(response.rule_id, '64228')
        self.assertEqual(response.rule_level, 3)


    def test_checkpoint_smart1_flag_flags_the_connection(self) -> None:
        log = '''1 2019-05-15T16:27:08Z HOSTNAME CheckPoint 19710 - [action:"Flag";...'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'checkpoint-smart1')
        self.assertEqual(response.rule_id, '64229')
        self.assertEqual(response.rule_level, 0)


    def test_checkpoint_smart1_login_a_user_logged_into_the_system(self) -> None:
        log = '''1 2019-05-15T16:27:08Z HOSTNAME CheckPoint 19710 - [action:"Login";...'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'checkpoint-smart1')
        self.assertEqual(response.rule_id, '64230')
        self.assertEqual(response.rule_level, 3)


    def test_checkpoint_smart1_vpn_routing_the_connection_was_routed_through_the_gateway_acting_as_a_central_hub(self) -> None:
        log = '''1 2019-05-15T16:27:08Z HOSTNAME CheckPoint 19710 - [action:""; VPN routing...'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'checkpoint-smart1')
        self.assertEqual(response.rule_id, '64231')
        self.assertEqual(response.rule_level, 3)


    def test_checkpoint_smart1_deauthorize_client_authentication_logoff(self) -> None:
        log = '''1 2019-05-15T16:27:08Z HOSTNAME CheckPoint 19710 - [action:"Deauthorize";...'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'checkpoint-smart1')
        self.assertEqual(response.rule_id, '64232')
        self.assertEqual(response.rule_level, 3)


    def test_checkpoint_smart1_authorize_client_authentication_logon(self) -> None:
        log = '''1 2019-05-15T16:27:08Z HOSTNAME CheckPoint 19710 - [action:"Authorize";...'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'checkpoint-smart1')
        self.assertEqual(response.rule_id, '64233')
        self.assertEqual(response.rule_level, 3)


    def test_checkpoint_smart1_block_connection_blocked_by_interspect(self) -> None:
        log = '''1 2019-05-15T16:27:08Z HOSTNAME CheckPoint 19710 - [action:"Block";...'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'checkpoint-smart1')
        self.assertEqual(response.rule_id, '64234')
        self.assertEqual(response.rule_level, 7)


    def test_checkpoint_smart1_detect_connection_was_detected_by_interspect(self) -> None:
        log = '''1 2019-05-15T16:27:08Z HOSTNAME CheckPoint 19710 - [action:"Detect";...'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'checkpoint-smart1')
        self.assertEqual(response.rule_id, '64235')
        self.assertEqual(response.rule_level, 3)


    def test_checkpoint_smart1_inspect_connection_was_subject_to_a_configured_protections(self) -> None:
        log = '''1 2019-05-15T16:27:08Z HOSTNAME CheckPoint 19710 - [action:"Inspect";...'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'checkpoint-smart1')
        self.assertEqual(response.rule_id, '64236')
        self.assertEqual(response.rule_level, 4)


    def test_checkpoint_smart1_quarantine_the_ip_source_address_of_the_connection_was_quarantined(self) -> None:
        log = '''1 2019-05-15T16:27:08Z HOSTNAME CheckPoint 19710 - [action:"Quarantine";...'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'checkpoint-smart1')
        self.assertEqual(response.rule_id, '64237')
        self.assertEqual(response.rule_level, 7)


    def test_checkpoint_smart1_replace_malicious_code_malicious_code_in_the_connection_was_replaced(self) -> None:
        log = '''1 2019-05-15T16:27:08Z HOSTNAME CheckPoint 19710 - [action:""; Replace Malicious code ...'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'checkpoint-smart1')
        self.assertEqual(response.rule_id, '64238')
        self.assertEqual(response.rule_level, 7)


    def test_checkpoint_smart1_the_firewall_allowed_a_url(self) -> None:
        log = '''1 2019-05-15T16:27:08Z HOSTNAME CheckPoint 19710 - [action:"Allow"; flags:"133376"; ifdir:"inbound"; ifname:"daemon"; loguid:"{0x0,0x0,0x0,0x0}"; origin:"11.22.33.44"; originsicname:"CN=TR-DC-FW-INT-B-5600,O=Internet-QRO..g7hgcu"; sequencenum:"5"; time:"1557937628"; version:"5"; cookiei:"891f38892b0e6bd6"; cookier:"d71409f32c496d13"; dst:"11.22.33.55"; fw_subproduct:"VPN-1"; ike::"Informational Exchange Received Delete IKE-SA from Peer: 11.22.33.66; Cookies: 891f38892b0e6bd6-d71409f32c496d13 "; msgid:"a4bd6724"; peer_gateway:"11.22.33.77"; scheme::"IKE"; src:"11.22.33.99"; vpn_feature_name:"IKE"; ]'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'checkpoint-smart1')
        self.assertEqual(response.rule_id, '64239')
        self.assertEqual(response.rule_level, 3)

