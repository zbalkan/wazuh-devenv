#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from sysmon_eid_8.ini
class TestSysmon_eid_8Rules(unittest.TestCase):

    def test_possible_code_injection_on_explorerexe(self) -> None:
        log = '''{"win":{"eventdata":{"targetProcessGuid":"{4dc16835-8ca1-60f5-99cb-100000000000}","targetProcessId":"5052","startAddress":"0x0000000002630000","utcTime":"2021-07-19 15:56:08.048","ruleName":"technique_id=T1055,technique_name=Process Injection","sourceProcessId":"5016","sourceImage":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","newThreadId":"5492","sourceProcessGuid":"{4dc16835-8df4-60f5-367c-340000000000}","targetImage":"C:\\\\Windows\\\\explorer.exe"},"system":{"eventID":"8","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"CreateRemoteThread detected:\r\nRuleName: technique_id=T1055,technique_name=Process Injection\r\nUtcTime: 2021-07-19 15:56:08.048\r\nSourceProcessGuid: {4dc16835-8df4-60f5-367c-340000000000}\r\nSourceProcessId: 5016\r\nSourceImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nTargetProcessGuid: {4dc16835-8ca1-60f5-99cb-100000000000}\r\nTargetProcessId: 5052\r\nTargetImage: C:\\Windows\\explorer.exe\r\nNewThreadId: 5492\r\nStartAddress: 0x0000000002630000\r\nStartModule: -\r\nStartFunction: -\"","version":"2","systemTime":"2021-07-19T15:56:08.0602748Z","eventRecordID":"275938","threadID":"3736","computer":"hrmanager.ExchangeTest.com","task":"8","processID":"2420","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92400')
        self.assertEqual(response.rule_level, 12)


    def test_possible_code_injection_on_mstscexe(self) -> None:
        log = '''{"win":{"eventdata":{"targetProcessGuid":"{4dc16835-13d3-615e-a46d-620000000000}","targetProcessId":"4620","startAddress":"0x000001DC199F0000","utcTime":"2021-10-06 21:24:08.946","ruleName":"technique_id=T1055,technique_name=Process Injection","sourceProcessId":"5108","sourceImage":"C:\\\\Windows\\\\explorer.exe","newThreadId":"1696","sourceProcessGuid":"{4dc16835-0ceb-615e-5eda-090000000000}","targetImage":"C:\\\\Windows\\\\System32\\\\mstsc.exe"},"system":{"eventID":"8","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"CreateRemoteThread detected:\r\nRuleName: technique_id=T1055,technique_name=Process Injection\r\nUtcTime: 2021-10-06 21:24:08.946\r\nSourceProcessGuid: {4dc16835-0ceb-615e-5eda-090000000000}\r\nSourceProcessId: 5108\r\nSourceImage: C:\\Windows\\explorer.exe\r\nTargetProcessGuid: {4dc16835-13d3-615e-a46d-620000000000}\r\nTargetProcessId: 4620\r\nTargetImage: C:\\Windows\\System32\\mstsc.exe\r\nNewThreadId: 1696\r\nStartAddress: 0x000001DC199F0000\r\nStartModule: -\r\nStartFunction: -\"","version":"2","systemTime":"2021-10-06T21:24:08.9461786Z","eventRecordID":"449981","threadID":"3376","computer":"hrmanager.ExchangeTest.com","task":"8","processID":"2480","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92401')
        self.assertEqual(response.rule_level, 12)


    def test_possible_code_injection_on_synchostexe(self) -> None:
        log = '''{ "win": { "eventdata": { "targetProcessGuid": "{94f48244-7831-6169-8c00-000000001b00}", "targetProcessId": "5516", "startAddress": "0x0000000002D91120", "utcTime": "2021-10-15 12:46:41.416", "ruleName": "technique_id=T1055,technique_name=Process Injection", "sourceProcessId": "5372", "sourceImage": "C:\\\\Users\\\\Public\\\\AccountingIQ.exe", "newThreadId": "5524", "sourceProcessGuid": "{94f48244-782d-6169-8900-000000001b00}", "targetImage": "C:\\\\Windows\\\\SysWOW64\\\\SyncHost.exe" }, "system": { "eventID": "8", "keywords": "0x8000000000000000", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "level": "4", "channel": "Microsoft-Windows-Sysmon/Operational", "opcode": "0", "message": "\"CreateRemoteThread detected:\r\nRuleName: technique_id=T1055,technique_name=Process Injection\r\nUtcTime: 2021-10-15 12:46:41.416\r\nSourceProcessGuid: {94f48244-782d-6169-8900-000000001b00}\r\nSourceProcessId: 5372\r\nSourceImage: C:\\Users\\Public\\AccountingIQ.exe\r\nTargetProcessGuid: {94f48244-7831-6169-8c00-000000001b00}\r\nTargetProcessId: 5516\r\nTargetImage: C:\\Windows\\SysWOW64\\SyncHost.exe\r\nNewThreadId: 5524\r\nStartAddress: 0x0000000002D91120\r\nStartModule: -\r\nStartFunction: -\"", "version": "2", "systemTime": "2021-10-15T12:46:41.5602188Z", "eventRecordID": "55995", "threadID": "3584", "computer": "accounting.xrisbarney.local", "task": "8", "processID": "2192", "severityValue": "INFORMATION", "providerName": "Microsoft-Windows-Sysmon" } } }'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92402')
        self.assertEqual(response.rule_level, 3)


    def test_possible_code_injection_on_lsassexe_possible_credential_dumping(self) -> None:
        log = '''{ "win": { "eventdata": { "targetProcessGuid": "{94f48244-0aee-6177-0c00-000000002300}", "targetProcessId": "600", "startAddress": "0x000001F727DE0000", "utcTime": "2021-10-25 16:21:35.166", "ruleName": "technique_id=T1055,technique_name=Process Injection", "sourceProcessId": "5000", "sourceImage": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe", "newThreadId": "1016", "sourceProcessGuid": "{94f48244-c73d-6176-4302-000000002300}", "targetImage": "C:\\\\Windows\\\\system32\\\\lsass.exe" }, "system": { "eventID": "8", "keywords": "0x8000000000000000", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "level": "4", "channel": "Microsoft-Windows-Sysmon/Operational", "opcode": "0", "message": "\"CreateRemoteThread detected:\r\nRuleName: technique_id=T1055,technique_name=Process Injection\r\nUtcTime: 2021-10-25 16:21:35.166\r\nSourceProcessGuid: {94f48244-c73d-6176-4302-000000002300}\r\nSourceProcessId: 5000\r\nSourceImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nTargetProcessGuid: {94f48244-0aee-6177-0c00-000000002300}\r\nTargetProcessId: 600\r\nTargetImage: C:\\Windows\\system32\\lsass.exe\r\nNewThreadId: 1016\r\nStartAddress: 0x000001F727DE0000\r\nStartModule: -\r\nStartFunction: -\"", "version": "2", "systemTime": "2021-10-25T16:21:35.1717366Z", "eventRecordID": "116149", "threadID": "3124", "computer": "apt29w1.xrisbarney.local", "task": "8", "processID": "2292", "severityValue": "INFORMATION", "providerName": "Microsoft-Windows-Sysmon" } } }'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92403')
        self.assertEqual(response.rule_level, 12)

