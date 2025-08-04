#!/usr/bin/env python3


# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from sysmon_eid_13.ini
class TestSysmonEid13Rules(unittest.TestCase):

    def test_added_registry_content_to_be_executed_on_next_logon(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Windows\\\\system32\\\\msi.exe","targetObject":"HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Java-Update","processGuid":"{4dc16835-4977-60ef-dac9-5b0000000000}","processId":"4692","utcTime":"2021-07-14 20:30:47.841","ruleName":"technique_id=T1547.001,technique_name=Registry Run Keys / Start Folder","details":"C:\\\\Users\\\\Public\\\\Java-Update","eventType":"SetValue"},"system":{"eventID":"13","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Registry value set:\r\nRuleName: technique_id=T1547.001,technique_name=Registry Run Keys / Start Folder\r\nEventType: SetValue\r\nUtcTime: 2021-07-14 20:30:47.841\r\nProcessGuid: {4dc16835-4977-60ef-dac9-5b0000000000}\r\nProcessId: 4692\r\nImage: C:\\Windows\\system32\\reg.exe\r\nTargetObject: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Java-Update\r\nDetails: C:\\Users\\Public\\\"","version":"2","systemTime":"2021-07-14T20:30:47.8486552Z","eventRecordID":"28692","threadID":"1272","computer":"cfo.ExchangeTest.com","task":"13","processID":"5364","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92300')
        self.assertEqual(response.rule_level, 0)


    def test_suspicious_file_extension_detected_in_registry_asep(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Windows\\\\system32\\\\reg.exe","targetObject":"HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Java-Update","processGuid":"{4dc16835-4977-60ef-dac9-5b0000000000}","processId":"4692","utcTime":"2021-07-14 20:30:47.841","ruleName":"technique_id=T1547.001,technique_name=Registry Run Keys / Start Folder","details":"C:\\\\Users\\\\Public\\\\Java-Update.vbs","eventType":"SetValue"},"system":{"eventID":"13","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Registry value set:\r\nRuleName: technique_id=T1547.001,technique_name=Registry Run Keys / Start Folder\r\nEventType: SetValue\r\nUtcTime: 2021-07-14 20:30:47.841\r\nProcessGuid: {4dc16835-4977-60ef-dac9-5b0000000000}\r\nProcessId: 4692\r\nImage: C:\\Windows\\system32\\reg.exe\r\nTargetObject: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Java-Update\r\nDetails: C:\\Users\\Public\\Java-Update.vbs\"","version":"2","systemTime":"2021-07-14T20:30:47.8486552Z","eventRecordID":"28692","threadID":"1272","computer":"cfo.ExchangeTest.com","task":"13","processID":"5364","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92301')
        self.assertEqual(response.rule_level, 12)


    def test_registry_entry_to_be_executed_on_next_logon_was_modified_using_command_line_application_regexe(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Windows\\\\system32\\\\reg.exe","targetObject":"HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Java-Update","processGuid":"{4dc16835-4977-60ef-dac9-5b0000000000}","processId":"4692","utcTime":"2021-07-14 20:30:47.841","ruleName":"technique_id=T1547.001,technique_name=Registry Run Keys / Start Folder","details":"C:\\\\Users\\\\Public\\\\Java-Update","eventType":"SetValue"},"system":{"eventID":"13","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Registry value set:\r\nRuleName: technique_id=T1547.001,technique_name=Registry Run Keys / Start Folder\r\nEventType: SetValue\r\nUtcTime: 2021-07-14 20:30:47.841\r\nProcessGuid: {4dc16835-4977-60ef-dac9-5b0000000000}\r\nProcessId: 4692\r\nImage: C:\\Windows\\system32\\reg.exe\r\nTargetObject: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Java-Update\r\nDetails: C:\\Users\\Public\\Java-Update.vbs\"","version":"2","systemTime":"2021-07-14T20:30:47.8486552Z","eventRecordID":"28692","threadID":"1272","computer":"cfo.ExchangeTest.com","task":"13","processID":"5364","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92302')
        self.assertEqual(response.rule_level, 6)


    def test_vnc_to_be_executed_from_currentversionrun(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Program Files\\\\TightVNC\\\\tvnserver.exe","targetObject":"HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\tvncontrol","processGuid":"{4dc16835-04d7-60fa-f781-340000000000}","processId":"7112","utcTime":"2021-07-22 23:52:55.282","ruleName":"technique_id=T1547.001,technique_name=Registry Run Keys / Start Folder","details":"\\\"C:\\\\Program Files\\\\TightVNC\\\\tvnserver.exe\\\" -controlservice -slave","eventType":"SetValue"},"system":{"eventID":"13","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Registry value set:\r\nRuleName: technique_id=T1547.001,technique_name=Registry Run Keys / Start Folder\r\nEventType: SetValue\r\nUtcTime: 2021-07-22 23:52:55.282\r\nProcessGuid: {4dc16835-04d7-60fa-f781-340000000000}\r\nProcessId: 7112\r\nImage: C:\\Program Files\\TightVNC\\tvnserver.exe\r\nTargetObject: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\tvncontrol\r\nDetails: \"C:\\Program Files\\TightVNC\\tvnserver.exe\" -controlservice -slave\"","version":"2","systemTime":"2021-07-22T23:52:55.2860207Z","eventRecordID":"302406","threadID":"3456","computer":"hrmanager.ExchangeTest.com","task":"13","processID":"2320","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92303')
        self.assertEqual(response.rule_level, 12)


    def test_fodhelper_uac_bypass_evidence(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","targetObject":"HKU\\\\S-1-5-21-887924094-598891991-956377308-1146_Classes\\\\ms-settings\\\\shell\\\\open\\\\command\\\\(Default)","processGuid":"{4dc16835-0124-6141-fb02-000000006500}","processId":"7152","utcTime":"2021-09-14 20:08:06.921","details":"cmd.exe /C C:\\\\Users\\\\kmitnick.FINANCIAL\\\\AppData\\\\Roaming\\\\TransbaseOdbcDriver\\\\smrs.exe &gt; C:\\\\Users\\\\kmitnick.financial\\\\AppData\\\\Roaming\\\\TransbaseOdbcDriver\\\\MGsCOxPSNK.txt","eventType":"SetValue"},"system":{"eventID":"13","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Registry value set:\r\nRuleName: -\r\nEventType: SetValue\r\nUtcTime: 2021-09-14 20:08:06.921\r\nProcessGuid: {4dc16835-0124-6141-fb02-000000006500}\r\nProcessId: 7152\r\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nTargetObject: HKU\\S-1-5-21-887924094-598891991-956377308-1146_Classes\\ms-settings\\shell\\open\\command\\(Default)\r\nDetails: cmd.exe /C C:\\Users\\kmitnick.FINANCIAL\\AppData\\Roaming\\TransbaseOdbcDriver\\smrs.exe > C:\\Users\\kmitnick.financial\\AppData\\Roaming\\TransbaseOdbcDriver\\MGsCOxPSNK.txt\"","version":"2","systemTime":"2021-09-14T20:08:06.9235444Z","eventRecordID":"360356","threadID":"3756","computer":"hrmanager.ExchangeTest.com","task":"13","processID":"2664","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92305')
        self.assertEqual(response.rule_level, 12)


    def test_powershell_adds_to_registry_uac_bypass_key(self) -> None:
        log = r'''
{ "win": { "eventdata": { "image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe", "targetObject": "HKU\\\\S-1-5-21-184966080-802066075-2268707989-1001_Classes\\\\Folder\\\\shell\\\\open\\\\command\\\\DelegateExecute", "processGuid": "{94f48244-b463-616e-5201-000000001900}", "processId": "3112", "utcTime": "2021-10-19 12:06:02.871", "details": "(Empty)", "eventType": "SetValue" }, "system": { "eventID": "13", "keywords": "0x8000000000000000", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "level": "4", "channel": "Microsoft-Windows-Sysmon/Operational", "opcode": "0", "message": "\"Registry value set:\r\nRuleName: -\r\nEventType: SetValue\r\nUtcTime: 2021-10-19 12:06:02.871\r\nProcessGuid: {94f48244-b463-616e-5201-000000001900}\r\nProcessId: 3112\r\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nTargetObject: HKU\\S-1-5-21-184966080-802066075-2268707989-1001_Classes\\Folder\\shell\\open\\command\\DelegateExecute\r\nDetails: (Empty)\"", "version": "2", "systemTime": "2021-10-19T12:06:02.8755420Z", "eventRecordID": "48409", "threadID": "3932", "computer": "apt29w1.xrisbarney.local", "task": "13", "processID": "2340", "severityValue": "INFORMATION", "providerName": "Microsoft-Windows-Sysmon" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92306')
        self.assertEqual(response.rule_level, 12)


    def test_new_service_created_in_registry(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Windows\\\\system32\\\\services.exe","targetObject":"HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\javamtsup\\\\ImagePath","processGuid":"{4dc16835-4447-6177-0b00-000000006b00}","processId":"636","utcTime":"2021-10-25 20:24:46.463","details":"C:\\\\Windows\\\\System32\\\\javamtsup.exe","eventType":"SetValue"},"system":{"eventID":"13","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Registry value set:\r\nRuleName: -\r\nEventType: SetValue\r\nUtcTime: 2021-10-25 20:24:46.463\r\nProcessGuid: {4dc16835-4447-6177-0b00-000000006b00}\r\nProcessId: 636\r\nImage: C:\\Windows\\system32\\services.exe\r\nTargetObject: HKLM\\System\\CurrentControlSet\\Services\\javamtsup\\ImagePath\r\nDetails: C:\\Windows\\System32\\javamtsup.exe\"","version":"2","systemTime":"2021-10-25T20:24:46.4658681Z","eventRecordID":"409331","threadID":"3812","computer":"hrmanager.ExchangeTest.com","task":"13","processID":"2368","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92307')
        self.assertEqual(response.rule_level, 3)


    def test_possible_com_hijacking_evidence_found_in_registry(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\reg.exe","targetObject":"HKLM\\\\SOFTWARE\\\\CurrentControlSet\\\\Classes\\\\CLSID\\\\{B5F8350B-0548-48B1-A6EE-88BD00B4A5E8}\\\\LocalServer32","processGuid":"{4dc16835-c471-645e-0701-000000002000}","processId":"4140","utcTime":"2023-05-12 22:57:53.526","ruleName":"technique_id=T1543,technique_name=Service Creation","details":"C::\\\\windows\\\\calc.exe","eventType":"SetValue","user":"EXCHANGETEST\\\\AtomicRed"},"system":{"eventID":"13","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","version":"2","systemTime":"2023-05-12T22:57:53.5273376Z","eventRecordID":"232330","threadID":"3064","computer":"cfo.ExchangeTest.com","task":"13","processID":"2156","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92308')
        self.assertEqual(response.rule_level, 3)


    def test_com_hijacking_evidence_found_in_registry(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\reg.exe","targetObject":"HKLM\\\\SOFTWARE\\\\CurrentControlSet\\\\Classes\\\\CLSID\\\\{B5F8350B-0548-48B1-A6EE-88BD00B4A5E8}\\\\LocalServer32","processGuid":"{4dc16835-c471-645e-0701-000000002000}","processId":"4140","utcTime":"2023-05-12 22:57:53.526","ruleName":"technique_id=T1543,technique_name=Service Creation","details":"C::\\\\Users:\\\\AtomicRed:\\\\AppData:\\\\Local\\\\Temp\\\\calc.exe","eventType":"SetValue","user":"EXCHANGETEST\\\\AtomicRed"},"system":{"eventID":"13","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","version":"2","systemTime":"2023-05-12T22:57:53.5273376Z","eventRecordID":"232330","threadID":"3064","computer":"cfo.ExchangeTest.com","task":"13","processID":"2156","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92309')
        self.assertEqual(response.rule_level, 15)

