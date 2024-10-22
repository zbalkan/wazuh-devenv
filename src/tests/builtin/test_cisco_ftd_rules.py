#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from cisco_ftd.ini
class TestCisco_ftdRules(unittest.TestCase):

    def test_cisco_ftd_high_severity_alert_1(self) -> None:
        log = '''%FTD-1-101001: (Primary) Failover cable OK.'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91501')
        self.assertEqual(response.rule_level, 7)


    def test_cisco_ftd_high_severity_alert_2(self) -> None:
        log = '''%FTD-1-101002: (Primary) Bad failover cable.'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91501')
        self.assertEqual(response.rule_level, 7)


    def test_cisco_ftd_critical_severity_alert_1(self) -> None:
        log = '''%FTD-2-106001: Inbound TCP connection denied from 192.168.1.59/port to 192.168.1.59/port flags tcp_flags on interface interface_name'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91502')
        self.assertEqual(response.rule_level, 5)


    def test_cisco_ftd_critical_severity_alert_2(self) -> None:
        log = '''%FTD-2-106002: protocol Connection denied by outbound list acl_ID src inside_address dest outside_address'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91502')
        self.assertEqual(response.rule_level, 5)


    def test_cisco_ftd_error_alert_1(self) -> None:
        log = '''%FTD-3-106010: Deny inbound protocol src [interface_name: 192.168.1.59/source_port] [([idfw_user | FQDN_string], sg_info)] dst [interface_name: 192.168.1.59/dest_port}[([idfw_user | FQDN_string], sg_info)]'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91503')
        self.assertEqual(response.rule_level, 4)


    def test_cisco_ftd_error_alert_2(self) -> None:
        log = '''%FTD-3-106011: Deny inbound (No xlate) string'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91503')
        self.assertEqual(response.rule_level, 4)


    def test_cisco_ftd_warning_alert_1(self) -> None:
        log = '''%FTD-4-106023: Deny tcp src inside:111.11.11.1/2143 dst YYY:172.11.1.11/139 by access-group "inside_inbound"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91504')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_ftd_warning_alert_2(self) -> None:
        log = '''%FTD-4-106027: Deny src [source address] dst [destination address] by access-group "access-list name".'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91504')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_ftd_notification_alerts_1(self) -> None:
        log = '''%FTD-5-106029: New reverse carrier <protocol> <ingress_ifc>:<source_addr> to <egress_ifc>:<destination_addr> overshadows existing <ingress_ifc2>:<source_addr2> to <egress_ifc2>:<destination_addr2>'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91505')
        self.assertEqual(response.rule_level, 2)


    def test_cisco_ftd_notification_alerts_2(self) -> None:
        log = '''%FTD-5-109012: Authen Session End: user 'user', sid number, elapsed number seconds'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91505')
        self.assertEqual(response.rule_level, 2)


    def test_cisco_ftd_notification_alerts_3(self) -> None:
        log = '''%FTD-6-106015: Deny TCP (no connection) from 192.168.1.59/port to 192.168.1.59/port flags tcp_flags on interface interface_name.'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91505')
        self.assertEqual(response.rule_level, 2)


    def test_cisco_ftd_notification_alerts_4(self) -> None:
        log = '''%FTD-6-106100: access-list acl_ID {permitted | denied | est-allowed} protocol interface_name/192.168.1.59(source_port)(idfw_user, sg_info) interface_name/192.168.1.59(dest_port) (idfw_user, sg_info) hit-cnt number ({first hit | number-second interval})'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91505')
        self.assertEqual(response.rule_level, 2)


    def test_cisco_ftd_debugging_alerts_1(self) -> None:
        log = '''%FTD-7-113028: Extraction of username from VPN client certificate has string. [Request num]'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91506')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_ftd_debugging_alerts_2(self) -> None:
        log = '''%FTD-7-199019: syslog'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91506')
        self.assertEqual(response.rule_level, 0)


    def test_cisco_ftd_failed_login_attempt(self) -> None:
        log = '''%FTD-6-605004: Login denied from source-address/source-port to interface:destination/service for user "username"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91507')
        self.assertEqual(response.rule_level, 9)


    def test_cisco_ftd_user_privilege_changed(self) -> None:
        log = '''%FTD-5-502103: User priv level changed: Uname: user From: privilege_level To: privilege_level'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91508')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_ftd_successful_login(self) -> None:
        log = '''%FTD-6-605005: Login permitted from source-address/source-port to interface:destination/service for user "username"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91509')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_ftd_arp_collision_detected(self) -> None:
        log = '''%FTD-4-405001: Received ARP {request | response} collision from 192.168.1.59/MAC_address on interface interface_name to 192.168.1.59/MAC_address on interface interface_name'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91510')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_ftd_attempt_to_connect_from_a_blocked_ip(self) -> None:
        log = '''%FTD-4-401004: Shunned packet: 192.168.1.59 = 192.168.1.59 on interface interface_name'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91511')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_ftd_connection_limit_exceeded(self) -> None:
        log = '''%FTD-7-710004: TCP connection limit exceeded from Src_ip/Src_port to In_name:Dest_ip/Dest_port (current connections/connection limit = Curr_conn/Conn_lmt)'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91512')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_ftd_attack_in_progress_detected_1(self) -> None:
        log = '''%FTD-6-106012: Deny IP from 192.168.1.59 to 192.168.1.59, IP options hex.'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91515')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_ftd_attack_in_progress_detected_2(self) -> None:
        log = '''%FTD-1-106022: Deny protocol connection spoof from 192.168.1.59 to 192.168.1.59 on interface interface_name'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91515')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_ftd_attack_in_progress_detected_3(self) -> None:
        log = '''%FTD-1-106021: Deny protocol reverse path check from 192.168.1.59 to 192.168.1.59 on interface interface_name'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91515')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_ftd_attack_in_progress_detected_4(self) -> None:
        log = '''%FTD-2-106017: Deny IP due to Land Attack from 192.168.1.59 to 192.168.1.59'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91515')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_ftd_attack_in_progress_detected_5(self) -> None:
        log = '''%FTD-2-106020: Deny IP teardrop fragment (size = number, offset = number) from 192.168.1.59 to 192.168.1.59'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91515')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_ftd_aaa_vpn_authentication_failed(self) -> None:
        log = '''%FTD-6-113005: AAA user authentication Rejected: reason = string: server = server_192.168.1.59, User = user: user IP = user_ip'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91516')
        self.assertEqual(response.rule_level, 5)


    def test_cisco_ftd_aaa_vpn_authentication_successful(self) -> None:
        log = '''%FTD-6-113004: AAA user aaa_type Successful: server = server_192.168.1.59, User = user'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91517')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_ftd_aaa_vpn_user_locked_out(self) -> None:
        log = '''%FTD-6-113006: User user locked out on exceeding number successive failed authentication attempts'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91518')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_ftd_disallowing_new_connections(self) -> None:
        log = '''%FTD-3-201008: Disallowing new connections.'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91519')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_ftd_firewall_failover_pair_communication_problem_1(self) -> None:
        log = '''%FTD-1-105005: (Primary) Lost Failover communications with mate on interface interface_name.'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91520')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_ftd_firewall_failover_pair_communication_problem_2(self) -> None:
        log = '''%FTD-1-105009: (Primary) Testing on interface interface_name {Passed|Failed}.'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91520')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_ftd_firewall_failover_pair_communication_problem_3(self) -> None:
        log = '''%FTD-1-105043: (Primary) Failover interface failed'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91520')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_ftd_firewall_configuration_deleted(self) -> None:
        log = '''%FTD-5-111003: 192.168.1.59 Erase configuration'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91521')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_ftd_firewall_configuration_changed_1(self) -> None:
        log = '''%FTD-5-111002: Begin configuration: 192.168.1.59 reading from device'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91522')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_ftd_firewall_configuration_changed_2(self) -> None:
        log = '''%FTD-5-111004: 192.168.1.59 end configuration: {FAILED|OK}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91522')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_ftd_firewall_configuration_changed_3(self) -> None:
        log = '''%FTD-5-111005: 192.168.1.59 end configuration: OK'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91522')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_ftd_firewall_configuration_changed_4(self) -> None:
        log = '''%FTD-5-111007: Begin configuration: 192.168.1.59 reading from device.'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91522')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_ftd_firewall_command_executed_for_accounting_only(self) -> None:
        log = '''%FTD-5-111008: User user executed the command string'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91523')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_ftd_firewall_command_executed_for_accounting(self) -> None:
        log = '''%FTD-7-111009: User user executed cmd:string'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91524')
        self.assertEqual(response.rule_level, 3)


    def test_cisco_ftd_user_created_or_modified_on_the_firewall_1(self) -> None:
        log = '''%FTD-5-502101: New user added to local dbase: Uname: user Priv: privilege_level Encpass: string'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91525')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_ftd_user_created_or_modified_on_the_firewall_2(self) -> None:
        log = '''%FTD-5-502102: User deleted from local dbase: Uname: user Priv: privilege_level Encpass: string'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91525')
        self.assertEqual(response.rule_level, 8)


    def test_cisco_ftd_ip_spoofing_attack_detected(self) -> None:
        log = '''%FTD-2-106016: Deny IP spoof from (192.168.1.59) to 192.168.1.59 on interface interface_name.'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cisco-ftd')
        self.assertEqual(response.rule_id, '91530')
        self.assertEqual(response.rule_level, 8)

