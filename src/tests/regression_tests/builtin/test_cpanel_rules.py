#!/usr/bin/env python3


# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from cpanel.ini
class TestCpanelRules(unittest.TestCase):

    def test_successful_login_1(self) -> None:
        log = r'''
[2016-04-18 13:07:02 -0400] info [cpsrvd] 10.1.5.19 - root - SUCCESS LOGIN whostmgrd
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '11007')


    def test_successful_login_2(self) -> None:
        log = r'''
[2016-04-18 13:07:15 -0400] info [cpsrvd] 10.1.5.19 - reseller (possessor: root) - SUCCESS LOGIN cpaneld
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '11007')


    def test_successful_login_3(self) -> None:
        log = r'''
[2016-04-18 13:08:27 -0400] info [cpsrvd] 10.1.5.19 - emailaccount@reseller.com (possessor: reseller) - SUCCESS LOGIN webmaild
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '11007')


    def test_cpanel_attacks(self) -> None:
        log = r'''
[2017-01-25 06:01:10 -0500] info [cpsrvd] 10.1.5.19 - test "POST /login/?login_only=1 HTTP/1.1" FAILED LOGIN cpaneld: invalid cpanel user test (loadcpdata failed)
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '11001')


    def test_cpanel_attacks_2(self) -> None:
        log = r'''
[2016-11-18 09:32:19 +0000] info [cpsrvd] 10.1.5.19 - admin "POST /login/?login_only=1 HTTP/1.1" FAILED LOGIN whostmgrd: user password hash is missing from system (user probably does not exist)
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '11000')


    def test_successful_login_2(self) -> None:
        log = r'''
[2016-04-18 13:07:02 +0400] info [cpsrvd] 10.1.5.19 - root - SUCCESS LOGIN whostmgrd
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '11006')


    def test_session_purge(self) -> None:
        log = r'''
[2017-01-25 06:15:38 -0500] info [cpsrvd] 10.1.5.19 PURGE root:Nmm4xzhSpA2Sddv3 logout
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '11009')

