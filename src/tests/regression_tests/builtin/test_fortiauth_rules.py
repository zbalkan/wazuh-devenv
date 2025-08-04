#!/usr/bin/env python3


# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from fortiauth.ini
class TestFortiauthRules(unittest.TestCase):

    def test_fortiauth_pending_authentication(self) -> None:
        log = r'''
2021-07-08T11:01:06-03:00 XXX.XXX.XXX.XXX db[32167]:  category="Event" subcategory="Authentication" typeid=20299 level="information" user="user2" nas="XXX.XXX.XXX.XXX" action="Authentication" status="Pending" Remote RADIUS user authentication partially done, remote server expecting challenge response
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortiauth')
        self.assertEqual(response.rule_id, '44732')
        self.assertEqual(response.rule_level, 4)


    def test_fortiauth_failed_authentication(self) -> None:
        log = r'''
2021-07-08T11:00:56-03:00 XXX.XXX.XXX.XXX db[31013]:  category="Event" subcategory="Authentication" typeid=20001 level="information" user="user1" nas="XXX.XXX.XXX.XXX" action="Authentication" status="Failed" Remote RADIUS user authentication with invalid token
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortiauth')
        self.assertEqual(response.rule_id, '44733')
        self.assertEqual(response.rule_level, 7)


    def test_fortiauth_successful_authentication(self) -> None:
        log = r'''
2021-07-08T11:00:56-03:00 XXX.XXX.XXX.XXX db[31013]:  category="Event" subcategory="Authentication" typeid=20001 level="information" user="user1" nas="XXX.XXX.XXX.XXX" action="Authentication" status="Success" Remote RADIUS user authentication with no token successful
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortiauth')
        self.assertEqual(response.rule_id, '44734')
        self.assertEqual(response.rule_level, 3)


    def test_fortiauth_info_event(self) -> None:
        log = r'''
2021-07-08T11:01:03-03:00 XXX.XXX.XXX.XXX db[32167]:  category="Event" subcategory="System" typeid=30101 level="information" user="admin" nas="" action="" status="" RADIUS server running in full edition
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortiauth')
        self.assertEqual(response.rule_id, '44735')
        self.assertEqual(response.rule_level, 4)

