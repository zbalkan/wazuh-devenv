#!/usr/bin/env python3


# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from sysmon_eid_11.ini
class TestSysmonEid11Rules(unittest.TestCase):

    def test_scripting_file_created_under_system_or_user_folder(self) -> None:
        log = r'''
{ "win": { "eventdata": { "image": "C:\\\\Users\\\\st9\\\\AppData\\\\Local\\\\adb156.exe", "processGuid": "{50263ab4-3306-6154-5101-000000000d00}", "processId": "6988", "utcTime": "2021-09-29 10:09:46.298", "targetFilename": "C:\\\\Users\\\\st9\\\\AppData\\\\Local\\\\stager.ps1", "ruleName": "technique_id=T1059.001,technique_name=PowerShell", "creationUtcTime": "2021-09-29 10:09:46.298" }, "system": { "eventID": "11", "keywords": "0x8000000000000000", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "level": "4", "channel": "Microsoft-Windows-Sysmon/Operational", "opcode": "0", "message": "\"File created:\r\nRuleName: technique_id=T1059.001,technique_name=PowerShell\r\nUtcTime: 2021-09-29 10:09:46.298\r\nProcessGuid: {50263ab4-3306-6154-5101-000000000d00}\r\nProcessId: 6988\r\nImage: C:\\Users\\st9\\AppData\\Local\\adb156.exe\r\nTargetFilename: C:\\Users\\st9\\AppData\\Local\\stager.ps1\r\nCreationUtcTime: 2021-09-29 10:09:46.298\"", "version": "2", "systemTime": "2021-09-29T10:09:46.3002205Z", "eventRecordID": "18277", "threadID": "3400", "computer": "DESKTOP-P45R1DM", "task": "11", "processID": "2384", "severityValue": "INFORMATION", "providerName": "Microsoft-Windows-Sysmon" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92200')
        self.assertEqual(response.rule_level, 6)


    def test_possible_abuse_of_windows_admin_shares_by_binary_dropped_in_windows_root_folder_by_system_process(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"System","processGuid":"{86107A5D-0B6A-60D6-EB03-000000000000}","processId":"4","utcTime":"2021-06-25 18:09:57.530","targetFilename":"C:\\\\Windows\\\\tiny.exe","creationUtcTime":"2021-06-24 23:36:43.555"},"system":{"eventID":"11","keywords":"0x8000000000000000","providerGuid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"File created:\r\nRuleName: -\r\nUtcTime: 2021-06-25 18:09:57.530\r\nProcessGuid: {86107A5D-0B6A-60D6-EB03-000000000000}\r\nProcessId: 4\r\nImage: System\r\nTargetFilename: C:\\Windows\\tiny.exe\r\nCreationUtcTime: 2021-06-24 23:36:43.555\"","version":"2","systemTime":"2021-06-25T18:09:57.530600200Z","eventRecordID":"647283","threadID":"3784","computer":"bankdc.ExchangeTest.com","task":"11","processID":"2620","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92218')
        self.assertEqual(response.rule_level, 6)


    def test_executable_file_created_by_powershell(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","processGuid":"{4dc16835-1e3a-6157-a82a-160000000000}","processId":"7644","utcTime":"2021-10-01 14:48:12.284","targetFilename":"C:\\\\Users\\\\AtomicRed\\\\samcat.exe","creationUtcTime":"2021-10-01 14:48:12.284"},"system":{"eventID":"11","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"File created:\r\nRuleName: -\r\nUtcTime: 2021-10-01 14:48:12.284\r\nProcessGuid: {4dc16835-1e3a-6157-a82a-160000000000}\r\nProcessId: 7644\r\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nTargetFilename: C:\\Users\\AtomicRed\\AppData\\Local\\samcat.exe\r\nCreationUtcTime: 2021-10-01 14:48:12.284\"","version":"2","systemTime":"2021-10-01T14:48:12.2895098Z","eventRecordID":"403833","threadID":"3916","computer":"hrmanager.ExchangeTest.com","task":"11","processID":"2440","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92203')
        self.assertEqual(response.rule_level, 6)


    def test_powershell_process_created_executable_file_in_appdata_temp_folder(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","processGuid":"{4dc16835-3136-609c-2c01-000000003b00}","processId":"1488","utcTime":"2021-05-12 19:53:22.467","targetFilename":"C:\\\\Users\\\\AtomicRed\\\\AppData\\\\Roaming\\\\TransbaseOdbcDriver\\\\pscp.exe","creationUtcTime":"2021-05-12 19:53:22.467"},"system":{"eventID":"11","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"File created:\r\nRuleName: -\r\nUtcTime: 2021-05-12 19:53:22.467\r\nProcessGuid: {4dc16835-3136-609c-2c01-000000003b00}\r\nProcessId: 1488\r\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nTargetFilename: C:\\Users\\AtomicRed\\AppData\\Roaming\\TransbaseOdbcDriver\\pscp.exe\r\nCreationUtcTime: 2021-05-12 19:53:22.467\"","version":"2","systemTime":"2021-05-12T19:53:22.4784997Z","eventRecordID":"198839","threadID":"3320","computer":"hrmanager.ExchangeTest.com","task":"11","processID":"2080","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92204')
        self.assertEqual(response.rule_level, 9)


    def test_dll_file_created_by_printer_spool_service(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Windows\\\\System32\\\\spoolsv.exe","processGuid":"{4dc16835-6534-60ec-92a4-010000000000}","processId":"1912","utcTime":"2021-07-12 15:58:13.001","targetFilename":"C:\\\\Windows\\\\System32\\\\spool\\\\drivers\\\\x64\\\\3\\\\New\\\\mimispoolbis.dll","ruleName":"technique_id=T1047,technique_name=File System Permissions Weakness","creationUtcTime":"2021-07-12 15:58:13.001"},"system":{"eventID":"11","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"File created:\r\nRuleName: technique_id=T1047,technique_name=File System Permissions Weakness\r\nUtcTime: 2021-07-12 15:58:13.001\r\nProcessGuid: {4dc16835-6534-60ec-92a4-010000000000}\r\nProcessId: 1912\r\nImage: C:\\Windows\\System32\\spoolsv.exe\r\nTargetFilename: C:\\Windows\\System32\\spool\\drivers\\x64\\3\\New\\mimispoolbis.dll\r\nCreationUtcTime: 2021-07-12 15:58:13.001\"","version":"2","systemTime":"2021-07-12T15:58:13.0067714Z","eventRecordID":"267528","threadID":"3548","computer":"hrmanager.ExchangeTest.com","task":"11","processID":"2092","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92206')
        self.assertEqual(response.rule_level, 12)


    def test_binary_file_dropped_in_userspublic_folder(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Windows\\\\system32\\\\cmd.exe","processGuid":"{4dc16835-41b5-60ef-7a00-000000001100}","processId":"2860","utcTime":"2021-07-14 20:21:04.678","targetFilename":"C:\\\\Users\\\\Public\\\\Java-Update.vbs","creationUtcTime":"2021-07-14 20:21:04.678"},"system":{"eventID":"11","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"File created:\r\nRuleName: -\r\nUtcTime: 2021-07-14 20:21:04.678\r\nProcessGuid: {4dc16835-41b5-60ef-7a00-000000001100}\r\nProcessId: 2860\r\nImage: C:\\Windows\\system32\\cmd.exe\r\nTargetFilename: C:\\Users\\Public\\Java-Update.vbs\r\nCreationUtcTime: 2021-07-14 20:21:04.678\"","version":"2","systemTime":"2021-07-14T20:21:04.6849507Z","eventRecordID":"28558","threadID":"1272","computer":"cfo.ExchangeTest.com","task":"11","processID":"5364","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92207')
        self.assertEqual(response.rule_level, 12)


    def test_binary_file_dropped_in_userspublic_folder_via_ssh(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Windows\\\\System32\\\\OpenSSH\\\\scp.exe","processGuid":"{4dc16835-44ed-60ef-bdc3-4d0000000000}","processId":"3144","utcTime":"2021-07-14 20:11:27.810","targetFilename":"C:\\\\Users\\\\Public\\\\Java-Update.exe","creationUtcTime":"2021-07-14 20:03:07.766"},"system":{"eventID":"11","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"File created:\r\nRuleName: -\r\nUtcTime: 2021-07-14 20:11:27.810\r\nProcessGuid: {4dc16835-44ed-60ef-bdc3-4d0000000000}\r\nProcessId: 3144\r\nImage: C:\\Windows\\System32\\OpenSSH\\scp.exe\r\nTargetFilename: C:\\Users\\Public\\Java-Update.exe\r\nCreationUtcTime: 2021-07-14 20:03:07.766\"","version":"2","systemTime":"2021-07-14T20:11:27.8528377Z","eventRecordID":"28453","threadID":"1272","computer":"cfo.ExchangeTest.com","task":"11","processID":"5364","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92208')
        self.assertEqual(response.rule_level, 15)


    def test_executable_file_dropped_in_folder_commonly_used_by_malware(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","processGuid":"{4dc16835-8df4-60f5-367c-340000000000}","processId":"5016","utcTime":"2021-07-19 14:39:32.595","targetFilename":"C:\\\\Users\\\\AtomicRed\\\\AppData\\\\Local\\\\Temp\\\\DefenderUpgradeExec.exe","creationUtcTime":"2021-07-19 14:39:32.595"},"system":{"eventID":"11","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"File created:\r\nRuleName: -\r\nUtcTime: 2021-07-19 14:39:32.595\r\nProcessGuid: {4dc16835-8df4-60f5-367c-340000000000}\r\nProcessId: 5016\r\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nTargetFilename: C:\\Users\\AtomicRed\\AppData\\Local\\Temp\\DefenderUpgradeExec.exe\r\nCreationUtcTime: 2021-07-19 14:39:32.595\"","version":"2","systemTime":"2021-07-19T14:39:32.6032653Z","eventRecordID":"274778","threadID":"3736","computer":"hrmanager.ExchangeTest.com","task":"11","processID":"2420","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92213')
        self.assertEqual(response.rule_level, 15)


    def test_drop_binary_in_public_folder_1(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Windows\\\\system32\\\\cmd.exe","processGuid":"{4dc16835-41b5-60ef-7a00-000000001100}","processId":"2860","utcTime":"2021-07-14 20:21:04.678","targetFilename":"C:\\\\Users\\\\Public\\\\Java-Update.vbs","creationUtcTime":"2021-07-14 20:21:04.678"},"system":{"eventID":"11","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"File created:\r\nRuleName: -\r\nUtcTime: 2021-07-14 20:21:04.678\r\nProcessGuid: {4dc16835-41b5-60ef-7a00-000000001100}\r\nProcessId: 2860\r\nImage: C:\\Windows\\system32\\cmd.exe\r\nTargetFilename: C:\\Users\\Public\\Java-Update.vbs\r\nCreationUtcTime: 2021-07-14 20:21:04.678\"","version":"2","systemTime":"2021-07-14T20:21:04.6849507Z","eventRecordID":"28558","threadID":"1272","computer":"cfo.ExchangeTest.com","task":"11","processID":"5364","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92207')
        self.assertEqual(response.rule_level, 12)


    def test_drop_binary_in_public_folder_2(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","processGuid":"{4dc16835-00b8-60fa-0056-290000000000}","processId":"4564","utcTime":"2021-07-22 23:37:02.829","targetFilename":"C:\\\\Users\\\\Public\\\\tightvnc-2.8.27-gpl-setup-64bit.msi","ruleName":"technique_id=T1047,technique_name=File System Permissions Weakness","creationUtcTime":"2021-07-22 23:37:02.829"},"system":{"eventID":"11","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"File created:\r\nRuleName: technique_id=T1047,technique_name=File System Permissions Weakness\r\nUtcTime: 2021-07-22 23:37:02.829\r\nProcessGuid: {4dc16835-00b8-60fa-0056-290000000000}\r\nProcessId: 4564\r\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nTargetFilename: C:\\Users\\Public\\tightvnc-2.8.27-gpl-setup-64bit.msi\r\nCreationUtcTime: 2021-07-22 23:37:02.829\"","version":"2","systemTime":"2021-07-22T23:37:02.8319616Z","eventRecordID":"302090","threadID":"3456","computer":"hrmanager.ExchangeTest.com","task":"11","processID":"2320","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92207')
        self.assertEqual(response.rule_level, 12)


    def test_drop_reg_in_public_folder(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","processGuid":"{4dc16835-00b8-60fa-0056-290000000000}","processId":"4564","utcTime":"2021-07-22 23:40:12.626","targetFilename":"C:\\\\Users\\\\Public\\\\vnc-settings.reg","ruleName":"technique_id=T1047,technique_name=File System Permissions Weakness","creationUtcTime":"2021-07-22 23:40:12.626"},"system":{"eventID":"11","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"File created:\r\nRuleName: technique_id=T1047,technique_name=File System Permissions Weakness\r\nUtcTime: 2021-07-22 23:40:12.626\r\nProcessGuid: {4dc16835-00b8-60fa-0056-290000000000}\r\nProcessId: 4564\r\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nTargetFilename: C:\\Users\\Public\\vnc-settings.reg\r\nCreationUtcTime: 2021-07-22 23:40:12.626\"","version":"2","systemTime":"2021-07-22T23:40:12.6279906Z","eventRecordID":"302217","threadID":"3456","computer":"hrmanager.ExchangeTest.com","task":"11","processID":"2320","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92209')
        self.assertEqual(response.rule_level, 6)


    def test_powershell_process_created_scripting_file_in_appdata_temp_folder(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","processGuid":"{4dc16835-fc27-6140-8277-6d0000000000}","processId":"6760","utcTime":"2021-09-14 19:49:13.528","targetFilename":"C:\\\\Users\\\\AtomicRed\\\\AppData\\\\Roaming\\\\TransbaseOdbcDriver\\\\rad353F7.ps1","ruleName":"technique_id=T1059.001,technique_name=PowerShell","creationUtcTime":"2021-09-14 19:49:13.528"},"system":{"eventID":"11","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"File created:\r\nRuleName: technique_id=T1059.001,technique_name=PowerShell\r\nUtcTime: 2021-09-14 19:49:13.528\r\nProcessGuid: {4dc16835-fc27-6140-8277-6d0000000000}\r\nProcessId: 6760\r\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nTargetFilename: C:\\Users\\AtomicRed\\AppData\\Roaming\\TransbaseOdbcDriver\\rad353F7.ps1\r\nCreationUtcTime: 2021-09-14 19:49:13.528\"","version":"2","systemTime":"2021-09-14T19:49:13.5617693Z","eventRecordID":"358727","threadID":"3756","computer":"hrmanager.ExchangeTest.com","task":"11","processID":"2664","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92201')
        self.assertEqual(response.rule_level, 9)


    def test_office_application_creates_suspicious_file(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Program Files (x86)\\\\Microsoft Office\\\\root\\\\Office16\\\\WINWORD.EXE","processGuid":"{4dc16835-7c76-614b-61d5-620000000000}","processId":"5100","utcTime":"2021-09-22 19:42:23.518","targetFilename":"C:\\\\Users\\\\ATOMIC~2\\\\AppData\\\\Local\\\\Temp\\\\{99EF3796-053F-4BF8-8F8B-4D350422FBF4}\\\\unprotected.lnk","ruleName":"technique_id=T1187,technique_name=Forced Authentication","creationUtcTime":"2021-09-22 19:42:23.518"},"system":{"eventID":"11","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"File created:\r\nRuleName: technique_id=T1187,technique_name=Forced Authentication\r\nUtcTime: 2021-09-22 19:42:23.518\r\nProcessGuid: {4dc16835-7c76-614b-61d5-620000000000}\r\nProcessId: 5100\r\nImage: C:\\Program Files (x86)\\Microsoft Office\\root\\Office16\\WINWORD.EXE\r\nTargetFilename: C:\\Users\\ATOMIC~2\\AppData\\Local\\Temp\\{99EF3796-053F-4BF8-8F8B-4D350422FBF4}\\unprotected.lnk\r\nCreationUtcTime: 2021-09-22 19:42:23.518\"","version":"2","systemTime":"2021-09-22T19:42:23.5713065Z","eventRecordID":"379112","threadID":"3560","computer":"hrmanager.ExchangeTest.com","task":"11","processID":"2736","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92214')
        self.assertEqual(response.rule_level, 15)


    def test_mshta_creates_executable_file(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Windows\\\\SysWOW64\\\\mshta.exe","processGuid":"{4dc16835-8cdf-614b-90f6-cf0000000000}","processId":"7736","utcTime":"2021-09-22 20:06:57.538","targetFilename":"C:\\\\Users\\\\AtomicRed\\\\AppData\\\\Local\\\\adb156.exe","creationUtcTime":"2021-09-22 20:06:57.538"},"system":{"eventID":"11","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"File created:\r\nRuleName: -\r\nUtcTime: 2021-09-22 20:06:57.538\r\nProcessGuid: {4dc16835-8cdf-614b-90f6-cf0000000000}\r\nProcessId: 7736\r\nImage: C:\\Windows\\SysWOW64\\mshta.exe\r\nTargetFilename: C:\\Users\\AtomicRed\\AppData\\Local\\adb156.exe\r\nCreationUtcTime: 2021-09-22 20:06:57.538\"","version":"2","systemTime":"2021-09-22T20:06:57.5392545Z","eventRecordID":"385282","threadID":"3560","computer":"hrmanager.ExchangeTest.com","task":"11","processID":"2736","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92215')
        self.assertEqual(response.rule_level, 12)


    def test_powershellexe_created_a_temporary_file_under_system_folder(self) -> None:
        log = r'''
{ "win": { "eventdata": { "image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe", "processGuid": "{94f48244-3a4f-6164-e701-000000001200}", "processId": "5968", "utcTime": "2021-10-11 13:21:30.556", "targetFilename": "C:\\\\Windows\\\\Temp\\\\sdbE376.tmp", "ruleName": "technique_id=T1047,technique_name=File System Permissions Weakness", "creationUtcTime": "2021-10-11 13:21:30.556" }, "system": { "eventID": "11", "keywords": "0x8000000000000000", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "level": "4", "channel": "Microsoft-Windows-Sysmon/Operational", "opcode": "0", "message": "\"File created:\r\nRuleName: technique_id=T1047,technique_name=File System Permissions Weakness\r\nUtcTime: 2021-10-11 13:21:30.556\r\nProcessGuid: {94f48244-3a4f-6164-e701-000000001200}\r\nProcessId: 5968\r\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nTargetFilename: C:\\Windows\\Temp\\sdbE376.tmp\r\nCreationUtcTime: 2021-10-11 13:21:30.556\"", "version": "2", "systemTime": "2021-10-11T13:21:30.5650949Z", "eventRecordID": "5736", "threadID": "4792", "computer": "accounting.xrisbarney.local", "task": "11", "processID": "6116", "severityValue": "INFORMATION", "providerName": "Microsoft-Windows-Sysmon" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92216')
        self.assertEqual(response.rule_level, 0)


    def test_wineventdataimage_created_a_new_scripting_file_under_user_data_folder(self) -> None:
        log = r'''
{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"11","version":"2","level":"4","task":"11","opcode":"0","keywords":"0x8000000000000000","systemTime":"2021-04-28T20:11:55.0310966Z","eventRecordID":"144500","processID":"2204","threadID":"3300","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-2QKFOBA","severityValue":"INFORMATION","message":"\"File created:\r\nRuleName: -\r\nUtcTime: 2021-04-28 20:11:55.021\r\nProcessGuid: {4dc16835-c189-6089-a003-000000002e00}\r\nProcessId: 6876\r\nImage: C:\\Windows\\system32\\cscript.exe\r\nTargetFilename: C:\\Users\\AtomicRedTeamTest\\AppData\\Roaming\\TransbaseOdbcDriver\\starter.vbs\r\nCreationUtcTime: 2021-04-28 20:11:55.021\""},"eventdata":{"utcTime":"2021-04-28 20:11:55.021","processGuid":"{4dc16835-c189-6089-a003-000000002e00}","processId":"6876","image":"C:\\\\Windows\\\\system32\\\\cscript.exe","targetFilename":"C:\\\\Users\\\\AtomicRedTeamTest\\\\AppData\\\\Roaming\\\\TransbaseOdbcDriver\\\\starter.vbs","creationUtcTime":"2021-04-28 20:11:55.021"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92201')
        self.assertEqual(response.rule_level, 9)


    def test_binary_dropped_in_windows_root_folder_by_wineventdataimage_process_possible_abuse_of_windows_admin_shares(self) -> None:
        log = r'''
{ "win": { "eventdata": { "image": "C:\\\\Windows\\\\PAExec-5544-HOTELMANAGER.exe", "processGuid": "{94f48244-9c1f-6164-7000-000000001f00}", "processId": "5928", "utcTime": "2021-10-11 20:18:41.400", "targetFilename": "C:\\\\Windows\\\\hollow.exe", "creationUtcTime": "2021-10-11 20:18:41.400" }, "system": { "eventID": "11", "keywords": "0x8000000000000000", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "level": "4", "channel": "Microsoft-Windows-Sysmon/Operational", "opcode": "0", "message": "\"File created:\r\nRuleName: -\r\nUtcTime: 2021-10-11 20:18:41.400\r\nProcessGuid: {94f48244-9c1f-6164-7000-000000001f00}\r\nProcessId: 5928\r\nImage: C:\\Windows\\PAExec-5544-HOTELMANAGER.exe\r\nTargetFilename: C:\\Windows\\hollow.exe\r\nCreationUtcTime: 2021-10-11 20:18:41.400\"", "version": "2", "systemTime": "2021-10-11T20:18:41.4882783Z", "eventRecordID": "48671", "threadID": "3248", "computer": "itadmin.xrisbarney.local", "task": "11", "processID": "2284", "severityValue": "INFORMATION", "providerName": "Microsoft-Windows-Sysmon" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92202')
        self.assertEqual(response.rule_level, 6)


    def test_possible_dll_search_order_hijack_by_dll_created_in_windows_root_folder(self) -> None:
        log = r'''
{ "win": { "eventdata": { "image": "C:\\\\Windows\\\\system32\\\\svchost.exe", "processGuid": "{94f48244-c3c1-615e-a700-000000001a00}", "processId": "4540", "utcTime": "2021-10-07 09:55:44.346", "targetFilename": "C:\\\\Windows\\\\SysWOW64\\\\srrstr.dll", "ruleName": "technique_id=T1044,technique_name=File System Permissions Weakness", "creationUtcTime": "2021-10-06 17:15:37.512" }, "system": { "eventID": "11", "keywords": "0x8000000000000000", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "level": "4", "channel": "Microsoft-Windows-Sysmon/Operational", "opcode": "0", "message": "\"File created:\r\nRuleName: technique_id=T1044,technique_name=File System Permissions Weakness\r\nUtcTime: 2021-10-07 09:55:44.346\r\nProcessGuid: {94f48244-c3c1-615e-a700-000000001a00}\r\nProcessId: 4540\r\nImage: C:\\Windows\\system32\\svchost.exe\r\nTargetFilename: C:\\Windows\\SysWOW64\\srrstr.dll\r\nCreationUtcTime: 2021-10-06 17:15:37.512\"", "version": "2", "systemTime": "2021-10-07T09:55:44.3962611Z", "eventRecordID": "16546", "threadID": "2836", "computer": "itadmin.xrisbarney.local", "task": "11", "processID": "2400", "severityValue": "INFORMATION", "providerName": "Microsoft-Windows-Sysmon" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92219')
        self.assertEqual(response.rule_level, 6)


    def test_suspicious_file_compression_activity_in_userspublic_folder(self) -> None:
        log = r'''
{ "win": { "eventdata": { "image": "C:\\\\Users\\\\Public\\\\7za.exe", "processGuid": "{94f48244-7a43-6169-d200-000000001b00}", "processId": "6124", "utcTime": "2021-10-15 12:56:05.057", "targetFilename": "C:\\\\Users\\\\Public\\\\log.7z", "ruleName": "technique_id=T1047,technique_name=File System Permissions Weakness", "creationUtcTime": "2021-10-15 12:56:05.025" }, "system": { "eventID": "11", "keywords": "0x8000000000000000", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "level": "4", "channel": "Microsoft-Windows-Sysmon/Operational", "opcode": "0", "message": "\"File created:\r\nRuleName: technique_id=T1047,technique_name=File System Permissions Weakness\r\nUtcTime: 2021-10-15 12:56:05.057\r\nProcessGuid: {94f48244-7a43-6169-d200-000000001b00}\r\nProcessId: 6124\r\nImage: C:\\Users\\Public\\7za.exe\r\nTargetFilename: C:\\Users\\Public\\log.7z\r\nCreationUtcTime: 2021-10-15 12:56:05.025\"", "version": "2", "systemTime": "2021-10-15T12:56:05.0584806Z", "eventRecordID": "56626", "threadID": "3584", "computer": "accounting.xrisbarney.local", "task": "11", "processID": "2192", "severityValue": "INFORMATION", "providerName": "Microsoft-Windows-Sysmon" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92210')
        self.assertEqual(response.rule_level, 6)


    def test_suspicious_executable_file_creation_by_rundll32_wineventdatatargetfilename(self) -> None:
        log = r'''
{ "win": { "eventdata": { "image": "C:\\\\Windows\\\\SysWOW64\\\\rundll32.exe", "processGuid": "{94f48244-7831-6169-8d00-000000001b00}", "processId": "5532", "utcTime": "2021-10-15 12:54:47.338", "targetFilename": "C:\\\\Users\\\\Public\\\\7za.exe", "creationUtcTime": "2021-10-15 12:54:47.338" }, "system": { "eventID": "11", "keywords": "0x8000000000000000", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "level": "4", "channel": "Microsoft-Windows-Sysmon/Operational", "opcode": "0", "message": "\"File created:\r\nRuleName: -\r\nUtcTime: 2021-10-15 12:54:47.338\r\nProcessGuid: {94f48244-7831-6169-8d00-000000001b00}\r\nProcessId: 5532\r\nImage: C:\\Windows\\SysWOW64\\rundll32.exe\r\nTargetFilename: C:\\Users\\Public\\7za.exe\r\nCreationUtcTime: 2021-10-15 12:54:47.338\"", "version": "2", "systemTime": "2021-10-15T12:54:47.3395921Z", "eventRecordID": "56604", "threadID": "3584", "computer": "accounting.xrisbarney.local", "task": "11", "processID": "2192", "severityValue": "INFORMATION", "providerName": "Microsoft-Windows-Sysmon" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92211')
        self.assertEqual(response.rule_level, 14)


    def test_a_screensaver_executable_created_a_file(self) -> None:
        log = r'''
{ "win": { "eventdata": { "image": "C:\\\\Users\\\\chris\\\\Desktop\\\\‮cod.3aka3.scr", "processGuid": "{94f48244-aa65-616e-1001-000000001900}", "processId": "4396", "utcTime": "2021-10-19 12:04:04.091", "targetFilename": "C:\\\\Users\\\\chris\\\\Downloads\\\\monkey.png", "creationUtcTime": "2021-10-19 12:04:04.091" }, "system": { "eventID": "11", "keywords": "0x8000000000000000", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "level": "4", "channel": "Microsoft-Windows-Sysmon/Operational", "opcode": "0", "message": "\"File created:\r\nRuleName: -\r\nUtcTime: 2021-10-19 12:04:04.091\r\nProcessGuid: {94f48244-aa65-616e-1001-000000001900}\r\nProcessId: 4396\r\nImage: C:\\Users\\chris\\Desktop\\‮cod.3aka3.scr\r\nTargetFilename: C:\\Users\\chris\\Downloads\\monkey.png\r\nCreationUtcTime: 2021-10-19 12:04:04.091\"", "version": "2", "systemTime": "2021-10-19T12:04:04.0952681Z", "eventRecordID": "48331", "threadID": "3932", "computer": "apt29w1.xrisbarney.local", "task": "11", "processID": "2340", "severityValue": "INFORMATION", "providerName": "Microsoft-Windows-Sysmon" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92221')
        self.assertEqual(response.rule_level, 3)


    def test_suspicious_file_compression_activity_by_powershell_wineventdatatargetfilename(self) -> None:
        log = r'''
{ "win": { "eventdata": { "image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe", "processGuid": "{1f43d37e-6816-6170-cf00-000000001300}", "processId": "1040", "utcTime": "2021-10-20 19:18:11.149", "targetFilename": "C:\\\\Users\\\\adminuser\\\\Downloads\\\\SysinternalsSuite.zip", "creationUtcTime": "2021-10-20 19:18:11.149" }, "system": { "eventID": "11", "keywords": "0x8000000000000000", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "level": "4", "channel": "Microsoft-Windows-Sysmon/Operational", "opcode": "0", "message": "\"File created:\r\nRuleName: -\r\nUtcTime: 2021-10-20 19:18:11.149\r\nProcessGuid: {1f43d37e-6816-6170-cf00-000000001300}\r\nProcessId: 1040\r\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nTargetFilename: C:\\Users\\adminuser\\Downloads\\SysinternalsSuite.zip\r\nCreationUtcTime: 2021-10-20 19:18:11.149\"", "version": "2", "systemTime": "2021-10-20T19:18:11.1682906Z", "eventRecordID": "37037", "threadID": "1096", "computer": "Workstation1.dc.local", "task": "11", "processID": "2352", "severityValue": "INFORMATION", "providerName": "Microsoft-Windows-Sysmon" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92212')
        self.assertEqual(response.rule_level, 14)


    def test_an_executable_accesschkexe_created_a_password_dump_file_in_a_system_directory(self) -> None:
        log = r'''
{ "win": { "eventdata": { "image": "C:\\\\Program Files\\\\SysinternalsSuite\\\\accesschk.exe", "processGuid": "{94f48244-d740-6176-a002-000000002300}", "processId": "3944", "utcTime": "2021-10-25 16:11:44.247", "targetFilename": "C:\\\\Windows\\\\SysWOW64\\\\passwordsDB", "ruleName": "technique_id=T1044,technique_name=File System Permissions Weakness", "creationUtcTime": "2021-10-25 16:11:44.247" }, "system": { "eventID": "11", "keywords": "0x8000000000000000", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "level": "4", "channel": "Microsoft-Windows-Sysmon/Operational", "opcode": "0", "message": "\"File created:\r\nRuleName: technique_id=T1044,technique_name=File System Permissions Weakness\r\nUtcTime: 2021-10-25 16:11:44.247\r\nProcessGuid: {94f48244-d740-6176-a002-000000002300}\r\nProcessId: 3944\r\nImage: C:\\Program Files\\SysinternalsSuite\\accesschk.exe\r\nTargetFilename: C:\\Windows\\SysWOW64\\passwordsDB\r\nCreationUtcTime: 2021-10-25 16:11:44.247\"", "version": "2", "systemTime": "2021-10-25T16:11:44.2546222Z", "eventRecordID": "115607", "threadID": "3124", "computer": "apt29w1.xrisbarney.local", "task": "11", "processID": "2292", "severityValue": "INFORMATION", "providerName": "Microsoft-Windows-Sysmon" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92222')
        self.assertEqual(response.rule_level, 3)


    def test_pfx_file_created(self) -> None:
        log = r'''
{ "win": { "eventdata": { "image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe", "processGuid": "{94f48244-c7dc-6176-4902-000000002300}", "processId": "6140", "utcTime": "2021-10-25 15:18:14.930", "targetFilename": "C:\\\\Users\\\\chris\\\\Downloads\\\\vxupoe2e.je0.pfx", "creationUtcTime": "2021-10-25 15:18:14.914" }, "system": { "eventID": "11", "keywords": "0x8000000000000000", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "level": "4", "channel": "Microsoft-Windows-Sysmon/Operational", "opcode": "0", "message": "\"File created:\r\nRuleName: -\r\nUtcTime: 2021-10-25 15:18:14.930\r\nProcessGuid: {94f48244-c7dc-6176-4902-000000002300}\r\nProcessId: 6140\r\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nTargetFilename: C:\\Users\\chris\\Downloads\\vxupoe2e.je0.pfx\r\nCreationUtcTime: 2021-10-25 15:18:14.914\"", "version": "2", "systemTime": "2021-10-25T15:18:14.9388560Z", "eventRecordID": "115039", "threadID": "3124", "computer": "apt29w1.xrisbarney.local", "task": "11", "processID": "2292", "severityValue": "INFORMATION", "providerName": "Microsoft-Windows-Sysmon" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92224')
        self.assertEqual(response.rule_level, 6)


    def test_powershell_process_created_pfx_file_possible_private_key_or_certificate_exportation(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","processGuid":"{4dc16835-0fe5-6177-dc4d-4a0000000000}","processId":"3132","utcTime":"2021-10-25 20:36:29.391","targetFilename":"C:\\\\ProgramData\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\StartUp\\\\hostui.lnk","ruleName":"technique_id=T1187,technique_name=Forced Authentication","creationUtcTime":"2021-10-25 20:34:09.949"},"system":{"eventID":"11","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"File created:\r\nRuleName: technique_id=T1187,technique_name=Forced Authentication\r\nUtcTime: 2021-10-25 20:36:29.391\r\nProcessGuid: {4dc16835-0fe5-6177-dc4d-4a0000000000}\r\nProcessId: 3132\r\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nTargetFilename: C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\hostui.lnk\r\nCreationUtcTime: 2021-10-25 20:34:09.949\"","version":"2","systemTime":"2021-10-25T20:36:29.3930991Z","eventRecordID":"409602","threadID":"3812","computer":"hrmanager.ExchangeTest.com","task":"11","processID":"2368","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92226')
        self.assertEqual(response.rule_level, 14)


    def test_binary_created_in_windows_root_folder_by_winrm_process(self) -> None:
        log = r'''
{ "win": { "eventdata": { "image": "C:\\\\Windows\\\\system32\\\\wsmprovhost.exe", "processGuid": "{4ead7fc4-8063-6182-0901-000000001600}", "processId": "4760", "utcTime": "2021-11-03 12:35:43.597", "targetFilename": "C:\\\\Windows\\\\System32\\\\m.exe", "creationUtcTime": "2021-11-03 12:35:43.597" }, "system": { "eventID": "11", "keywords": "0x8000000000000000", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "level": "4", "channel": "Microsoft-Windows-Sysmon/Operational", "opcode": "0", "message": "\"File created:\r\nRuleName: -\r\nUtcTime: 2021-11-03 12:35:43.597\r\nProcessGuid: {4ead7fc4-8063-6182-0901-000000001600}\r\nProcessId: 4760\r\nImage: C:\\Windows\\system32\\wsmprovhost.exe\r\nTargetFilename: C:\\Windows\\System32\\m.exe\r\nCreationUtcTime: 2021-11-03 12:35:43.597\"", "version": "2", "systemTime": "2021-11-03T12:35:43.614137300Z", "eventRecordID": "148780", "threadID": "2136", "computer": "hoteldc.xrisbarney.local", "task": "11", "processID": "2376", "severityValue": "INFORMATION", "providerName": "Microsoft-Windows-Sysmon" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92220')
        self.assertEqual(response.rule_level, 6)


    def test_powershell_process_created_an_executable_file_in_windows_root_folder(self) -> None:
        log = r'''
{ "win": { "eventdata": { "image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe", "processGuid": "{94f48244-81af-6180-6e01-000000002100}", "processId": "5740", "utcTime": "2021-11-02 00:09:22.912", "targetFilename": "C:\\\\Windows\\\\System32\\\\m.exe", "creationUtcTime": "2021-11-02 00:09:22.867" }, "system": { "eventID": "11", "keywords": "0x8000000000000000", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "level": "4", "channel": "Microsoft-Windows-Sysmon/Operational", "opcode": "0", "message": "\"File created:\r\nRuleName: -\r\nUtcTime: 2021-11-02 00:09:22.912\r\nProcessGuid: {94f48244-81af-6180-6e01-000000002100}\r\nProcessId: 5740\r\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nTargetFilename: C:\\Windows\\System32\\m.exe\r\nCreationUtcTime: 2021-11-02 00:09:22.867\"", "version": "2", "systemTime": "2021-11-02T00:09:22.9938867Z", "eventRecordID": "210136", "threadID": "3608", "computer": "apt29w2.xrisbarney.local", "task": "11", "processID": "2332", "severityValue": "INFORMATION", "providerName": "Microsoft-Windows-Sysmon" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92205')
        self.assertEqual(response.rule_level, 9)


    def test_curl_process_created_an_dll_binary(self) -> None:
        log = r'''
{ "win": { "eventdata": { "image": "C:\\\\Windows\\\\system32\\\\curl.exe", "processGuid": "{94f48244-a252-618a-c800-000000002900}", "processId": "2832", "utcTime": "2021-11-09 16:31:21.765", "targetFilename": "C:\\\\Users\\\\itadmin\\\\Desktop\\\\compile.dll", "creationUtcTime": "2021-11-09 16:31:21.765" }, "system": { "eventID": "11", "keywords": "0x8000000000000000", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "level": "4", "channel": "Microsoft-Windows-Sysmon/Operational", "opcode": "0", "message": "\"File created:\r\nRuleName: -\r\nUtcTime: 2021-11-09 16:31:21.765\r\nProcessGuid: {94f48244-a252-618a-c800-000000002900}\r\nProcessId: 2832\r\nImage: C:\\Windows\\system32\\curl.exe\r\nTargetFilename: C:\\Users\\itadmin\\Desktop\\compile.dll\r\nCreationUtcTime: 2021-11-09 16:31:21.765\"", "version": "2", "systemTime": "2021-11-09T16:31:21.7703251Z", "eventRecordID": "213867", "threadID": "3060", "computer": "apt29w1.xrisbarney.local", "task": "11", "processID": "2468", "severityValue": "INFORMATION", "providerName": "Microsoft-Windows-Sysmon" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92227')
        self.assertEqual(response.rule_level, 6)

