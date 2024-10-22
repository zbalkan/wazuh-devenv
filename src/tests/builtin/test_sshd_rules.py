#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from sshd.ini
class TestSshdRules(unittest.TestCase):

    def test_sshd_configuration_error_authorizedkeyscommand(self) -> None:
        log = '''Feb  9 11:44:56 someserver sshd[1234]: error: Could not stat AuthorizedKeysCommand "/usr/local/sbin/ssh-ldap-authorized_keys": No such file or directory'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5739')
        self.assertEqual(response.rule_level, 4)


    def test_ssh_connection_reset_by_peer(self) -> None:
        log = '''Feb 10 23:21:05 someserver sshd[1234]: Read error from remote host 192.168.1.1: Connection reset by peer'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5740')
        self.assertEqual(response.rule_level, 4)


    def test_ssh_connection_refused(self) -> None:
        log = '''Feb 11 06:41:50 someserver sshd[1234]: debug1: channel 5: connection failed: Connection refused'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5741')
        self.assertEqual(response.rule_level, 4)


    def test_ssh_connection_timed_out(self) -> None:
        log = '''Feb 12 17:45:09 someserver sshd[1234]: debug1: channel 3: connection failed: Connection timed out'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5742')
        self.assertEqual(response.rule_level, 4)


    def test_ssh_no_route_to_host(self) -> None:
        log = '''Jan 30 18:55:24 someserver sshd[1234]: debug1: channel 1: connection failed: No route to host'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5743')
        self.assertEqual(response.rule_level, 4)


    def test_ssh_port_forwarding_issue(self) -> None:
        log = '''Feb 13 22:54:51 someserver sshd[1234]: debug1: server_input_channel_open: failure direct-tcpip'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5744')
        self.assertEqual(response.rule_level, 4)


    def test_ssh_transport_endpoint_is_not_connected(self) -> None:
        log = '''Feb  6 12:28:17 someserver sshd[1234]: debug1: getpeername failed: Transport endpoint is not connected'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5745')
        self.assertEqual(response.rule_level, 4)


    def test_ssh_get_remote_port_failed(self) -> None:
        log = '''Feb  6 12:28:17 someserver sshd[1234]: debug1: get_remote_port failed'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5746')
        self.assertEqual(response.rule_level, 4)


    def test_ssh_bad_client_public_dh_value_1(self) -> None:
        log = '''Feb  4 23:05:57 someserver sshd[1234]: Disconnecting: bad client public DH value [preauth]'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5747')
        self.assertEqual(response.rule_level, 6)


    def test_ssh_bad_client_public_dh_value_2(self) -> None:
        log = '''Feb  4 23:05:57 someserver sshd[1234]: Disconnecting: bad client public DH value'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5747')
        self.assertEqual(response.rule_level, 6)


    def test_ssh_corrupted_mac_on_input_1(self) -> None:
        log = '''Feb 14 14:34:15 someserver sshd[1234]: Corrupted MAC on input. [preauth]'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5748')
        self.assertEqual(response.rule_level, 6)


    def test_ssh_corrupted_mac_on_input_2(self) -> None:
        log = '''Nov 22 19:24:55 server sshd[4046]: Corrupted MAC on input.'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5748')
        self.assertEqual(response.rule_level, 6)


    def test_ssh_bad_packet_length_1(self) -> None:
        log = '''Mar  4 13:34:59 someserver sshd[5396]: Bad packet length 4081586742. [preauth]'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5749')
        self.assertEqual(response.rule_level, 4)


    def test_ssh_bad_packet_length_2(self) -> None:
        log = '''Mar  4 13:34:59 someserver sshd[5396]: Bad packet length 4081586742.'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5749')
        self.assertEqual(response.rule_level, 4)


    def test_ssh_unable_to_negotiate(self) -> None:
        log = '''Mar  3 10:56:18 junction sshd[32065]: fatal: Unable to negotiate with 202.191.177.33 port 3579: no matching cipher found. Their offer: 3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc [preauth]'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5753')
        self.assertEqual(response.rule_level, 2)


    def test_ssh_no_matching_key_exchange_1(self) -> None:
        log = '''Sep 16 05:46:56 junction sshd[1961]: fatal: Unable to negotiate with 108.229.36.174: no matching key exchange method found. Their offer: diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1 [preauth]'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5752')
        self.assertEqual(response.rule_level, 2)


    def test_ssh_no_matching_key_exchange_2(self) -> None:
        log = '''Apr 18 21:27:08 web2 sshd[23484]: fatal: Unable to negotiate a key exchange method [preauth]'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5752')
        self.assertEqual(response.rule_level, 2)


    def test_invalid_user_1(self) -> None:
        log = '''2013-10-30T14:51:21.901728+01:00 srv sshd[12664]: Postponed keyboard-interactive for invalid user warez from 192.241.237.101 port 54197 ssh2 [preauth]'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5710')
        self.assertEqual(response.rule_level, 5)


    def test_invalid_user_2(self) -> None:
        log = '''2013-10-30T14:51:24.139258+01:00 srv sshd[12664]: error: PAM: User not known to the underlying authentication module for illegal user warez from 192.241.237.101'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)


    def test_invalid_user_3(self) -> None:
        log = '''2013-10-30T14:51:30.267401+01:00 srv sshd[12671]: Invalid user opcione from 192.241.237.101'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5710')
        self.assertEqual(response.rule_level, 5)


    def test_invalid_user_4(self) -> None:
        log = '''2013-10-30T14:51:30.267906+01:00 srv sshd[12671]: input_userauth_request: invalid user opcione [preauth]'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)


    def test_invalid_user_5(self) -> None:
        log = '''2020-03-23 06:47:42.801612-0700  localhost sshd[3186]: error: PAM: unknown user for illegal user badguy from 192.168.33.1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5710')
        self.assertEqual(response.rule_level, 5)


    def test_invalid_user_6(self) -> None:
        log = '''2020-03-25 08:01:34.584936-0700  localhost sshd[1551]: Failed keyboard-interactive/pam for invalid user user from 172.18.1.1 port 32982 ssh2'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5710')
        self.assertEqual(response.rule_level, 5)


    def test_invalid_user_7(self) -> None:
        log = '''2013-10-30T14:51:24.140565+01:00 srv sshd[12664]: Failed keyboard-interactive/pam for invalid user warez from 192.241.237.101 port 54197 ssh2'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5710')
        self.assertEqual(response.rule_level, 5)


    def test_invalid_user_8(self) -> None:
        log = '''2020-03-23 08:14:02.777660-0700  localhost sshd[8981]: error: PAM: authentication error for illegal user badguy from 192.168.33.1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5710')
        self.assertEqual(response.rule_level, 5)


    def test_invalid_user_9(self) -> None:
        log = '''Jul  3 21:44:07 vmi189193 sshd[26279]: Failed password for invalid user sammy from 82.202.219.155 port 51676 ssh2'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5710')
        self.assertEqual(response.rule_level, 5)


    def test_failed_to_create_session(self) -> None:
        log = '''May  4 17:48:43 collectd sshd[15044]: pam_systemd(sshd:session): Failed to create session: Access denied'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5754')
        self.assertEqual(response.rule_level, 1)


    def test_bad_authorized_keys(self) -> None:
        log = '''May  4 18:30:04 collectd sshd[15191]: Authentication refused: bad ownership or modes for file /home/ansible/.ssh/authorized_keys'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5755')
        self.assertEqual(response.rule_level, 3)


    def test_subsystem_failed(self) -> None:
        log = '''May  5 05:00:38 junction sshd[28395]: subsystem request for netconf by user checker failed, subsystem not found'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5756')
        self.assertEqual(response.rule_level, 0)


    def test_login_failed(self) -> None:
        log = '''Aug 18 07:30:25 192.168.1.5 sshd[20247]: [ID 800047 auth.notice] Failed none for root from 192.168.1.1 port 36942 ssh2'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5716')
        self.assertEqual(response.rule_level, 5)


    def test_bad_dns_1(self) -> None:
        log = '''Oct 20 12:33:07 ar-agent sshd[3433]: Address 192.168.18.54 maps to nmap.18.168.192.in-addr.arpa, but this does not map back to the address - POSSIBLE BREAK-IN ATTEMPT!'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5757')
        self.assertEqual(response.rule_level, 0)


    def test_bad_dns_2(self) -> None:
        log = '''2020-03-25 09:01:30.852002-0700  localhost sshd[11885]: Address 192.168.33.1 maps to hostname, but this does not map back to the address - POSSIBLE BREAK-IN ATTEMPT!'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5757')
        self.assertEqual(response.rule_level, 0)


    def test_max_auth_attempts_1(self) -> None:
        log = '''Dec 27 03:23:51 r1 sshd[21183]: error: maximum authentication attempts exceeded for root from 183.106.179.x port 34100 ssh2 [preauth]'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5758')
        self.assertEqual(response.rule_level, 8)


    def test_max_auth_attempts_2(self) -> None:
        log = '''2020-03-23 08:14:32.766049-0700  localhost sshd[8981]: error: maximum authentication attempts exceeded for invalid user badguy from 192.168.33.1 port 55146 ssh2 [preauth]'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5758')
        self.assertEqual(response.rule_level, 8)


    def test_max_auth_attempts_3(self) -> None:
        log = '''2020-03-23 09:58:27.102292-0700  localhost sshd[18093]: error: maximum authentication attempts exceeded for user from 192.168.33.1 port 55764 ssh2 [preauth]'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5758')
        self.assertEqual(response.rule_level, 8)


    def test_sshd_authentication_error_1(self) -> None:
        log = '''2020-03-23 09:55:42.391078-0700  localhost sshd[17329]: error: PAM: authentication error for user from 192.168.33.1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5760')
        self.assertEqual(response.rule_level, 5)


    def test_sshd_authentication_error_2(self) -> None:
        log = '''2020-03-24 08:38:42.344447-0700  localhost sshd[2519]: Failed password for user from 172.18.1.100 port 43042 ssh2'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5760')
        self.assertEqual(response.rule_level, 5)


    def test_sshd_connection_close(self) -> None:
        log = '''2020-03-24 06:07:15.245255-0700  localhost sshd[195]: Connection closed by 10.0.2.2 port 55462 [preauth]'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5722')
        self.assertEqual(response.rule_level, 0)


    def test_sshd_disconnected_from(self) -> None:
        log = '''2020-03-24 08:38:47.230409-0700  localhost sshd[2531]: Disconnected from user user 172.18.1.100 port 43042'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5761')
        self.assertEqual(response.rule_level, 0)


    def test_sshd_disconnected_from_invalid(self) -> None:
        log = '''2020-03-24 08:38:47.230409-0700  localhost sshd[2531]: Disconnected from invalid user root 172.18.1.100 port 43042'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5710')
        self.assertEqual(response.rule_level, 5)


    def test_sshd_disconnecting_invalid(self) -> None:
        log = '''2020-03-24 08:38:47.230409-0700  localhost sshd[2531]: Disconnecting invalid user root 172.18.1.100 port 43042'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5710')
        self.assertEqual(response.rule_level, 5)


    def test_sshd_insecure_connection_attempt(self) -> None:
        log = '''2020-03-24 10:32:31.672920-0700  localhost sshd[5374]: Did not receive identification string from 172.18.1.1 port 45824'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5706')
        self.assertEqual(response.rule_level, 6)


    def test_sshd_connection_reset(self) -> None:
        log = '''2020-03-25 08:23:20.933154-0700  localhost sshd[9265]: Connection reset by authenticating user user 192.168.33.1 port 51772 [preauth]'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5762')
        self.assertEqual(response.rule_level, 4)


    def test_sshd_denied_user_1(self) -> None:
        log = '''2020-03-25 07:46:15.205351-0700  localhost sshd[6738]: User root from 192.168.33.1 not allowed because not listed in AllowUsers'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5718')
        self.assertEqual(response.rule_level, 5)


    def test_sshd_denied_user_2(self) -> None:
        log = '''2020-03-31 13:15:57.368975-0700  localhost sshd[2440]: User root from 172.18.1.100 not allowed because listed in DenyUsers'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5718')
        self.assertEqual(response.rule_level, 5)


    def test_sshd_multiple_access_attempts_using_a_denied_user_1(self) -> None:
        log = '''2020-03-25 07:46:15.205351-0700  localhost sshd[6738]: User root from 192.168.33.1 not allowed because not listed in AllowUsers'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5719')
        self.assertEqual(response.rule_level, 10)


    def test_sshd_multiple_access_attempts_using_a_denied_user_2(self) -> None:
        log = '''2020-03-31 13:15:57.368975-0700  localhost sshd[2440]: User root from 172.18.1.100 not allowed because listed in DenyUsers'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5719')
        self.assertEqual(response.rule_level, 10)


    def test_sshd_multiple_access_attempts_using_a_denied_user_3(self) -> None:
        log = '''2020-03-25 07:46:15.205351-0700  localhost sshd[6738]: User root from 192.168.33.1 not allowed because not listed in AllowUsers'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5719')
        self.assertEqual(response.rule_level, 10)


    def test_sshd_multiple_access_attempts_using_a_denied_user_4(self) -> None:
        log = '''2020-03-31 13:15:57.368975-0700  localhost sshd[2440]: User root from 172.18.1.100 not allowed because listed in DenyUsers'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5719')
        self.assertEqual(response.rule_level, 10)


    def test_sshd_multiple_access_attempts_using_a_denied_user_5(self) -> None:
        log = '''2020-03-25 07:46:15.205351-0700  localhost sshd[6738]: User root from 192.168.33.1 not allowed because not listed in AllowUsers'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5719')
        self.assertEqual(response.rule_level, 10)


    def test_sshd_multiple_access_attempts_using_a_denied_user_6(self) -> None:
        log = '''2020-03-31 13:15:57.368975-0700  localhost sshd[2440]: User root from 172.18.1.100 not allowed because listed in DenyUsers'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5719')
        self.assertEqual(response.rule_level, 10)


    def test_sshd_multiple_access_attempts_using_a_denied_user_7(self) -> None:
        log = '''2020-03-25 07:46:15.205351-0700  localhost sshd[6738]: User root from 192.168.33.1 not allowed because not listed in AllowUsers'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5719')
        self.assertEqual(response.rule_level, 10)


    def test_sshd_multiple_access_attempts_using_a_denied_user_8(self) -> None:
        log = '''2020-03-31 13:15:57.368975-0700  localhost sshd[2440]: User root from 172.18.1.100 not allowed because listed in DenyUsers'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5719')
        self.assertEqual(response.rule_level, 10)


    def test_sshd_reverse_lookup_error(self) -> None:
        log = '''2020-03-25 09:18:41.510217-0700  localhost sshd[2549]: reverse mapping checking getaddrinfo for hostname [172.18.1.1] failed - POSSIBLE BREAK.'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5702')
        self.assertEqual(response.rule_level, 5)


    def test_sshd_possible_attack(self) -> None:
        log = '''2020-03-25 06:37:50.176931-0700  localhost sshd[852]: Bad protocol version identification 'ls' from 172.18.1.1 port 59920'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5701')
        self.assertEqual(response.rule_level, 8)


    def test_sshd_brute_force_rule_1(self) -> None:
        log = '''2020-03-24 08:38:42.344447-0700  localhost sshd[2519]: Failed password for user from 172.18.1.100 port 43042 ssh2'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5763')
        self.assertEqual(response.rule_level, 10)


    def test_sshd_brute_force_rule_2(self) -> None:
        log = '''2020-03-24 08:38:42.344447-0700  localhost sshd[2519]: Failed password for user from 172.18.1.100 port 43042 ssh2'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5763')
        self.assertEqual(response.rule_level, 10)


    def test_sshd_brute_force_rule_3(self) -> None:
        log = '''2020-03-24 08:38:42.344447-0700  localhost sshd[2519]: Failed password for user from 172.18.1.100 port 43042 ssh2'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5763')
        self.assertEqual(response.rule_level, 10)


    def test_sshd_brute_force_rule_4(self) -> None:
        log = '''2020-03-24 08:38:42.344447-0700  localhost sshd[2519]: Failed password for user from 172.18.1.100 port 43042 ssh2'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5763')
        self.assertEqual(response.rule_level, 10)


    def test_sshd_brute_force_rule_5(self) -> None:
        log = '''2020-03-24 08:38:42.344447-0700  localhost sshd[2519]: Failed password for user from 172.18.1.100 port 43042 ssh2'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5763')
        self.assertEqual(response.rule_level, 10)


    def test_sshd_brute_force_rule_6(self) -> None:
        log = '''2020-03-24 08:38:42.344447-0700  localhost sshd[2519]: Failed password for user from 172.18.1.100 port 43042 ssh2'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5763')
        self.assertEqual(response.rule_level, 10)


    def test_sshd_brute_force_rule_7(self) -> None:
        log = '''2020-03-24 08:38:42.344447-0700  localhost sshd[2519]: Failed password for user from 172.18.1.100 port 43042 ssh2'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5763')
        self.assertEqual(response.rule_level, 10)


    def test_sshd_brute_force_rule_8(self) -> None:
        log = '''2020-03-24 08:38:42.344447-0700  localhost sshd[2519]: Failed password for user from 172.18.1.100 port 43042 ssh2'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5763')
        self.assertEqual(response.rule_level, 10)


    def test_sshd_brute_force_rule_2_1(self) -> None:
        log = '''May 29 11:31:00 vagrant sshd[30016]: Invalid user user from 212.64.151.233'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5712')
        self.assertEqual(response.rule_level, 10)


    def test_sshd_brute_force_rule_2_2(self) -> None:
        log = '''May 29 11:31:00 vagrant sshd[30016]: Invalid user user from 212.64.151.233'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5712')
        self.assertEqual(response.rule_level, 10)


    def test_sshd_brute_force_rule_2_3(self) -> None:
        log = '''May 29 11:31:00 vagrant sshd[30016]: Invalid user user from 212.64.151.233'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5712')
        self.assertEqual(response.rule_level, 10)


    def test_sshd_brute_force_rule_2_4(self) -> None:
        log = '''May 29 11:31:00 vagrant sshd[30016]: Invalid user user from 212.64.151.233'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5712')
        self.assertEqual(response.rule_level, 10)


    def test_sshd_brute_force_rule_2_5(self) -> None:
        log = '''May 29 11:31:00 vagrant sshd[30016]: Invalid user user from 212.64.151.233'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5712')
        self.assertEqual(response.rule_level, 10)


    def test_sshd_brute_force_rule_2_6(self) -> None:
        log = '''May 29 11:31:00 vagrant sshd[30016]: Invalid user user from 212.64.151.233'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5712')
        self.assertEqual(response.rule_level, 10)


    def test_sshd_brute_force_rule_2_7(self) -> None:
        log = '''May 29 11:31:00 vagrant sshd[30016]: Invalid user user from 212.64.151.233'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5712')
        self.assertEqual(response.rule_level, 10)


    def test_sshd_brute_force_rule_2_8(self) -> None:
        log = '''May 29 11:31:00 vagrant sshd[30016]: Invalid user user from 212.64.151.233'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_id, '5712')
        self.assertEqual(response.rule_level, 10)

