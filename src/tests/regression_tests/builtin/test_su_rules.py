#!/usr/bin/env python3


# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from su.ini
class TestSuRules(unittest.TestCase):

    def test_su_failed_(self) -> None:
        log = r'''
Apr 27 15:22:23 niban su[2921936]: failed: ttyq4 changing from ldap to root
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'su')
        self.assertEqual(response.rule_id, '5302')
        self.assertEqual(response.rule_level, 9)


    def test_su_bad_pass(self) -> None:
        log = r'''
Apr 27 15:22:23 niban su[234]: BAD SU ger to fwmaster on /dev/ttyp0
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'su')
        self.assertEqual(response.rule_id, '5301')
        self.assertEqual(response.rule_level, 5)

    @unittest.skip("This should be passing")
    def test_su_pam_auth_fail_1(self) -> None:
        log = r'''
Apr 27 15:22:23 niban su(pam_unix)[23164]: authentication failure; logname= uid=1342 euid=0 tty= ruser=dcid rhost=  user=osaudit
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '5503')

    @unittest.skip("This should be passing")
    def test_su_pam_auth_fail_2(self) -> None:
        log = r'''
Apr 27 15:22:23 niban su(pam_unix)[2298]: authentication failure; logname= uid=1342 euid=0 tty= ruser=dcid rhost=  user=root
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '5503')


    def test_su_work_fts(self) -> None:
        log = r'''
Apr 22 17:51:51 enigma su: dcid to root on /dev/ttyp1
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'su')
        self.assertEqual(response.rule_id, '5305')
        self.assertEqual(response.rule_level, 4)

