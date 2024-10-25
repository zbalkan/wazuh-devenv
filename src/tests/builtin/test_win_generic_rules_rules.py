#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from win-generic_rules.ini
class TestWinGenericRulesRules(unittest.TestCase):

    def test_ts_gateway_login_success(self) -> None:
        log = r'''
{"win":{"system":{"providerName":"Microsoft-Windows-TerminalServices-Gateway","providerGuid":"{4D5AE6A1-C7B8-3E6D-B840-4D8029342E1B}","eventID":"200","version":"0","level":"4","task":"2","opcode":"30","keywords":"0x4020000001000000","systemTime":"2023-01-25T20:56:39.141308000Z","eventRecordID":"84771","processID":"4672","threadID":"1996","channel":"Microsoft-Windows-TerminalServices-Gateway/Operational","computer":"server.domain.com","severityValue":"INFORMATION","message":"The user \"DOM\\user\", on client computer \"172.16.63.71\", met connection authorization policy requirements and was therefore authorized to access the RD Gateway server. The authentication method used was: \"NTLM\" and connection protocol used: \"HTTP\"."},"eventInfo":{"username":"DOM\\user","ipAddress":"172.16.93.71","authType":"NTLM","connectionProtocol":"HTTP","errorCode":"0"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '64105')
        self.assertEqual(response.rule_level, 3)

