#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from macos.ini
class TestMacosRules(unittest.TestCase):

    def test_application_has_been_granted_permission_to_service_at_time(self) -> None:
        log = r'''
2023-01-23 03:22:26.410246-0800  localhost tccd[1030]: [com.apple.TCC:access] Update Access Record: kTCCServiceMicrophone for us.zoom.xos to Allowed at 1674472946 (2023-01-23 11:22:26 +0000)
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'macOS_tccd')
        self.assertEqual(response.rule_id, '89600')
        self.assertEqual(response.rule_level, 5)


    def test_application_has_been_denied_permission_to_service_at_time(self) -> None:
        log = r'''
2023-01-23 03:22:29.290427-0800  localhost tccd[1030]: [com.apple.TCC:access] Update Access Record: kTCCServiceMicrophone for us.zoom.xos to Denied at 1674472949 (2023-01-23 11:22:29 +0000)
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'macOS_tccd')
        self.assertEqual(response.rule_id, '89601')
        self.assertEqual(response.rule_level, 5)


    def test_screen_unlocked_with_userid_userid(self) -> None:
        log = r'''
2023-01-23 03:14:00.792511-0800  localhost loginwindow[156]: [com.apple.loginwindow.logging:Standard] -[SessionAgentNotificationCenter sendBSDNotification:forUserID:] | sendBSDNotification: com.apple.sessionagent.screenIsUnlocked, with userID:501
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'macOS_loginwindow')
        self.assertEqual(response.rule_id, '89602')
        self.assertEqual(response.rule_level, 3)


    def test_screen_locked(self) -> None:
        log = r'''
2023-04-12 01:36:42.792314-0700  localhost loginwindow[155]: [com.apple.loginwindow.logging:Standard] -[SessionAgentNotificationCenter sendBSDNotification:forUserID:] | sendBSDNotification: com.apple.sessionagent.screenIsLocked, with userID:501
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'macOS_loginwindow')
        self.assertEqual(response.rule_id, '89603')
        self.assertEqual(response.rule_level, 3)


    def test_user_logoff(self) -> None:
        log = r'''
2023-04-20 11:01:00.364465+0200  localhost sessionlogoutd[6119]: (loginsupport) [com.apple.sessionlogoutd:SLOD_General] -[SessionLogoutd continueLogoutAfterDelayOptionsComplete]:456:      sessionlogoutd telling session agent, logout is complete.
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'macOS_sessionlogoutd')
        self.assertEqual(response.rule_id, '89604')
        self.assertEqual(response.rule_level, 3)


    def test_user_login(self) -> None:
        log = r'''
2023-04-20 11:16:56.849437+0200  localhost loginwindow[9143]: [com.apple.loginwindow.logging:Standard] -[SessionAgentNotificationCenter sendDistributedNotification:forUserID:] | sendDistributedNotification: com.apple.sessionDidLogin, with userID:501
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'macOS_loginwindow')
        self.assertEqual(response.rule_id, '89605')
        self.assertEqual(response.rule_level, 3)


    def test_attempt_to_connect_to_screen_sharing_with_username_dstuser_from_ip_address_failed(self) -> None:
        log = r'''
2023-01-23 03:32:35.380619-0800  localhost screensharingd[3535]: Authentication: FAILED :: User Name: macos :: Viewer Address: 192.168.56.128 :: Type: DH
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'macOS_screensharingd')
        self.assertEqual(response.rule_id, '89606')
        self.assertEqual(response.rule_level, 5)


    def test_attempt_to_connect_to_screen_sharing_with_username_dstuser_from_ip_address_succeeded(self) -> None:
        log = r'''
2023-01-23 03:32:42.775333-0800  localhost screensharingd[3535]: Authentication: SUCCEEDED :: User Name: macos :: Viewer Address: 192.168.56.128 :: Type: N/A
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'macOS_screensharingd')
        self.assertEqual(response.rule_id, '89607')
        self.assertEqual(response.rule_level, 3)


    def test_session_sessionid_has_been_created(self) -> None:
        log = r'''
2023-04-04 14:28:51.146384-0300  localhost securityd[122]: [com.apple.securityd:SecServer] 0x7f9289a19240 Session 71803 created, uid:501 sessionId:71803
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'macOS_securityd')
        self.assertEqual(response.rule_id, '89608')
        self.assertEqual(response.rule_level, 3)


    def test_session_sessionid_has_been_destroyed(self) -> None:
        log = r'''
2023-01-23 03:26:38.517706-0800  localhost securityd[129]: [com.apple.securityd:SecServer] 0x7fae6a535710 Session 3495 destroyed
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'macOS_securityd')
        self.assertEqual(response.rule_id, '89609')
        self.assertEqual(response.rule_level, 3)


    def test_plus_symbol_on_timestamp(self) -> None:
        log = r'''
2023-04-13 22:02:51.837266+0200  localhost loginwindow[164]: [com.apple.loginwindow.logging:Standard] -[SessionAgentNotificationCenter sendBSDNotification:forUserID:] | sendBSDNotification: com.apple.sessionagent.screenIsLocked, with userID:501
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'macOS_loginwindow')
        self.assertEqual(response.rule_id, '89603')
        self.assertEqual(response.rule_level, 3)

