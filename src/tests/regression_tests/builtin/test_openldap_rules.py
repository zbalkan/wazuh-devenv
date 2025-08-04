#!/usr/bin/env python3


# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from openldap.ini
class TestOpenldapRules(unittest.TestCase):

    def test_openldap_generic_1(self) -> None:
        log = r'''
Jan 11 09:26:57 hostname slapd[20872]: conn=999999 op=0 BIND dn="uid=example,ou=People,dc=example,dc=com" method=128
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'openldap')
        self.assertEqual(response.rule_id, '2507')
        self.assertEqual(response.rule_level, 0)


    def test_openldap_generic_2(self) -> None:
        log = r'''
Jan 11 09:26:57 hostname slapd[20872]: conn=999999 op=0 RESULT tag=97 err=49 text=
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'openldap')
        self.assertEqual(response.rule_id, '2507')
        self.assertEqual(response.rule_level, 0)


    def test_openldap_generic_3(self) -> None:
        log = r'''
Jan 11 09:26:57 hostname slapd[20872]: conn=999999 op=1 BIND dn="uid=example,ou=People,dc=example,dc=com" method=128
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'openldap')
        self.assertEqual(response.rule_id, '2507')
        self.assertEqual(response.rule_level, 0)


    def test_openldap_generic_4(self) -> None:
        log = r'''
Jan 11 09:26:57 hostname slapd[20872]: conn=999999 op=1 RESULT tag=97 err=0 text=
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'openldap')
        self.assertEqual(response.rule_id, '2507')
        self.assertEqual(response.rule_level, 0)


    def test_openldap_generic_5(self) -> None:
        log = r'''
Jan 11 09:26:57 hostname slapd[20872]: conn=999999 op=2 UNBIND
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'openldap')
        self.assertEqual(response.rule_id, '2507')
        self.assertEqual(response.rule_level, 0)


    def test_openldap_generic_6(self) -> None:
        log = r'''
Jan 11 09:26:57 hostname slapd[20872]: conn=999999 fd=64
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'openldap')
        self.assertEqual(response.rule_id, '2507')
        self.assertEqual(response.rule_level, 0)


    def test_openldap_connection_open_1(self) -> None:
        log = r'''
Jan 11 09:26:57 hostname slapd[20872]: conn=999999 fd=64 ACCEPT from IP=10.10.248.27:33957 (IP=10.10.241.77:389)
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'openldap')
        self.assertEqual(response.rule_id, '2508')
        self.assertEqual(response.rule_level, 3)


    def test_openldap_connection_open_2(self) -> None:
        log = r'''
Oct  2 19:51:22 example slapd[30864]: conn=1068 fd=19 ACCEPT from IP=192.168.0.2:59800 (IP=0.0.0.0:636)
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'openldap')
        self.assertEqual(response.rule_id, '2508')
        self.assertEqual(response.rule_level, 3)


    def test_openldap_connection_open_3(self) -> None:
        log = r'''
Feb 11 20:12:27 ldap slapd[13129]: conn=15098 fd=23 ACCEPT from IP=[fda2:3ab6:adf4:aa2a::0]:45242 (IP=[::]:389)
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'openldap')
        self.assertEqual(response.rule_id, '2508')
        self.assertEqual(response.rule_level, 3)

