#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from openvpn_ldap.ini
class TestOpenvpn_ldapRules(unittest.TestCase):

    def test_openvpn_ldap_bind_failed(self) -> None:
        log = '''Jan 28 14:25:49 VPN-SERVER-05892 openvpn: LDAP bind failed: Invalid credentials (80090308: LdapErr: DSID-55555555, comment: AcceptSecurityContext error, data 775, v3839)'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'openvpn')
        self.assertEqual(response.rule_id, '81805')
        self.assertEqual(response.rule_level, 5)


    def test_openvpn_ldap_logon_failure(self) -> None:
        log = '''Jan 28 14:25:49 VPN-SERVER-05892 openvpn: Incorrect password supplied for LDAP DN "CN=Harry T. Hacker,OU=business unit,OU=department,DC=domain,DC=com"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'openvpn')
        self.assertEqual(response.rule_id, '81806')
        self.assertEqual(response.rule_level, 5)

