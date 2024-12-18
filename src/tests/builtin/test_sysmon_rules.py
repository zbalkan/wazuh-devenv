#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from sysmon.ini
class TestSysmonRules(unittest.TestCase):

    def test_sysmon_eventid1_suspicious_svchost_process(self) -> None:
        log = r'''
2014 Dec 20 09:29:47 WinEvtLog: Microsoft-Windows-Sysmon/Operational: INFORMATION(1): Microsoft-Windows-Sysmon: SYSTEM: NT AUTHORITY: WIN-U93G48C7BOP: Process Create:  UtcTime: 12/20/2014 2:29 PM  ProcessGuid: {00000000-87DB-5495-0000-001045F25A00}  ProcessId: 3048  Image: C:\Windows\system32\svchost.exe  CommandLine: "C:\Windows\system32\NOTEPAD.EXE" C:\Users\Administrator\Desktop\ossec.log  User: WIN-U93G48C7BOP\Administrator  LogonGuid: {00000000-84B8-5494-0000-0020CB330200}  LogonId: 0x233CB  TerminalSessionId: 1  IntegrityLevel: High  HashType: SHA1  Hash: 9FEF303BEDF8430403915951564E0D9888F6F365  ParentProcessGuid: {00000000-84B9-5494-0000-0010BE4A0200}  ParentProcessId: 848  ParentImage: C:\Windows\Explorer.EXE  ParentCommandLine: C:\Windows\Explorer.EXE
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'windows')
        self.assertEqual(response.rule_id, '184666')
        self.assertEqual(response.rule_level, 12)


    def test_sysmon_eventid1_non_suspicious_svchost_process(self) -> None:
        log = r'''
2014 Dec 20 09:29:47 WinEvtLog: Microsoft-Windows-Sysmon/Operational: INFORMATION(1): Microsoft-Windows-Sysmon: SYSTEM: NT AUTHORITY: WIN-U93G48C7BOP: Process Create:  UtcTime: 12/20/2014 12:15 PM  ProcessGuid: {00000000-87DB-5495-0000-001045F25A00}  ProcessId: 3048  Image: C:\Windows\system32\svchost.exe  CommandLine: "C:\windows\system32\svchost.exe -k defragsvc"  User: NT AUTHORITY\SYSTEM  LogonGuid: {00000000-84B8-5494-0000-0020CB330200}  LogonId: 0x233CB  TerminalSessionId: 1  IntegrityLevel: High  HashType: SHA1  Hash: 9FEF303BEDF8430403915951564E0D9888F6F365  ParentProcessGuid: {00000000-84B9-5494-0000-0010BE4A0200}  ParentProcessId: 848  ParentImage: C:\Windows\System32\services.exe  ParentCommandLine: C:\Windows\System32\services.exe
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'windows')
        self.assertEqual(response.rule_id, '184667')
        self.assertEqual(response.rule_level, 0)


    def test_windows_event(self) -> None:
        log = r'''
2013 Oct 09 17:09:04 WinEvtLog: Application: INFORMATION(1): My Script: (no user): no domain: demo1.foo.example.com: test
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'windows')
        self.assertEqual(response.rule_id, '18101')
        self.assertEqual(response.rule_level, 0)


    def test_sysmon_eventid_1(self) -> None:
        log = r'''
{"win":{"eventdata":{"originalFileName":"Wmiprvse.exe","image":"C:\\\\Windows\\\\System32\\\\wbem\\\\WmiPrvSE.exe","product":"Microsoft® Windows® Operating System","parentProcessGuid":"{00000000-0000-0000-0000-000000000000}","description":"WMI Provider Host","logonGuid":"{4dc16835-1309-6130-e403-000000000000}","processGuid":"{4dc16835-eaa5-612f-d04e-830000000000}","logonId":"0x3e4","parentProcessId":"720","processId":"3552","currentDirectory":"C:\\\\Windows\\\\system32\\\\","utcTime":"2021-09-01 21:03:33.317","hashes":"SHA1=3EA7CC066317AC45F963C2227C4C7C50AA16EB7C,MD5=60FF40CFD7FB8FE41EE4FE9AE5FE1C51,SHA256=2198A7B58BCCB758036B969DDAE6CC2ECE07565E2659A7C541A313A0492231A3,IMPHASH=B71CB3AC5C352BEC857C940CBC95F0F3","ruleName":"technique_id=T1047,technique_name=Windows Management Instrumentation","company":"Microsoft Corporation","commandLine":"C:\\\\Windows\\\\system32\\\\wbem\\\\wmiprvse.exe -secured -Embedding","integrityLevel":"System","fileVersion":"10.0.19041.546 (WinBuild.160101.0800)","user":"NT AUTHORITY\\\\NETWORK SERVICE","terminalSessionId":"0"},"system":{"eventID":"1","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Process Create:\r\nRuleName: technique_id=T1047,technique_name=Windows Management Instrumentation\r\nUtcTime: 2021-09-01 21:03:33.317\r\nProcessGuid: {4dc16835-eaa5-612f-d04e-830000000000}\r\nProcessId: 3552\r\nImage: C:\\Windows\\System32\\wbem\\WmiPrvSE.exe\r\nFileVersion: 10.0.19041.546 (WinBuild.160101.0800)\r\nDescription: WMI Provider Host\r\nProduct: Microsoft® Windows® Operating System\r\nCompany: Microsoft Corporation\r\nOriginalFileName: Wmiprvse.exe\r\nCommandLine: C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding\r\nCurrentDirectory: C:\\Windows\\system32\\\r\nUser: NT AUTHORITY\\NETWORK SERVICE\r\nLogonGuid: {4dc16835-1309-6130-e403-000000000000}\r\nLogonId: 0x3E4\r\nTerminalSessionId: 0\r\nIntegrityLevel: System\r\nHashes: SHA1=3EA7CC066317AC45F963C2227C4C7C50AA16EB7C,MD5=60FF40CFD7FB8FE41EE4FE9AE5FE1C51,SHA256=2198A7B58BCCB758036B969DDAE6CC2ECE07565E2659A7C541A313A0492231A3,IMPHASH=B71CB3AC5C352BEC857C940CBC95F0F3\r\nParentProcessGuid: {00000000-0000-0000-0000-000000000000}\r\nParentProcessId: 720\r\nParentImage: -\r\nParentCommandLine: -\"","version":"5","systemTime":"2021-09-01T21:03:33.3185950Z","eventRecordID":"351608","threadID":"3644","computer":"hrmanager.ExchangeTest.com","task":"1","processID":"2516","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '61603')
        self.assertEqual(response.rule_level, 0)


    def test_sysmon_eventid_2(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Users\\\\ATOMIC~1\\\\AppData\\\\Local\\\\Temp\\\\{B280E7B6-1E83-4F12-8EDA-F1AB03DBFEC5}\\\\.cr\\\\dotnet-sdk-5.0.200-win-x64.exe","processGuid":"{4dc16835-7d51-6042-1801-000000001100}","processId":"3788","utcTime":"2021-03-05 18:50:12.790","targetFilename":"C:\\\\Users\\\\ATOMIC~1\\\\AppData\\\\Local\\\\Temp\\\\{015C7FBB-55E8-4F48-A734-CEC83D0AB3A2}\\\\AspNetCoreSharedFramework_x64","previousCreationUtcTime":"2021-03-05 18:50:12.774","ruleName":"technique_id=T1099,technique_name=Timestomp","creationUtcTime":"2021-01-23 20:57:42.000"},"system":{"eventID":"2","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"File creation time changed:\r\nRuleName: technique_id=T1099,technique_name=Timestomp\r\nUtcTime: 2021-03-05 18:50:12.790\r\nProcessGuid: {4dc16835-7d51-6042-1801-000000001100}\r\nProcessId: 3788\r\nImage: C:\\Users\\ATOMIC~1\\AppData\\Local\\Temp\\{B280E7B6-1E83-4F12-8EDA-F1AB03DBFEC5}\\.cr\\dotnet-sdk-5.0.200-win-x64.exe\r\nTargetFilename: C:\\Users\\ATOMIC~1\\AppData\\Local\\Temp\\{015C7FBB-55E8-4F48-A734-CEC83D0AB3A2}\\AspNetCoreSharedFramework_x64\r\nCreationUtcTime: 2021-01-23 20:57:42.000\r\nPreviousCreationUtcTime: 2021-03-05 18:50:12.774\"","version":"5","systemTime":"2021-03-05T18:50:12.8065118Z","eventRecordID":"49656","threadID":"2180","computer":"DESKTOP-2QKFOBA","task":"2","processID":"2128","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '61604')
        self.assertEqual(response.rule_level, 0)


    def test_sysmon_eventid_3(self) -> None:
        log = r'''
{"win":{"eventdata":{"destinationPort":"7010","image":"C:\\\\Users\\\\Public\\\\super_scary.exe","sourcePort":"49747","initiated":"true","destinationIp":"192.168.0.4","protocol":"tcp","processGuid":"{4dc16835-b1a4-6112-d917-2f0000000000}","sourceIp":"192.168.0.121","processId":"1320","utcTime":"2021-08-10 17:04:40.816","ruleName":"technique_id=T1036,technique_name=Masquerading","destinationIsIpv6":"false","user":"EXCHANGETEST\\\\AtomicRed","sourceIsIpv6":"false"},"system":{"eventID":"3","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Network connection detected:\r\nRuleName: technique_id=T1036,technique_name=Masquerading\r\nUtcTime: 2021-08-10 17:04:40.816\r\nProcessGuid: {4dc16835-b1a4-6112-d917-2f0000000000}\r\nProcessId: 1320\r\nImage: C:\\Users\\Public\\super_scary.exe\r\nUser: EXCHANGETEST\\AtomicRed\r\nProtocol: tcp\r\nInitiated: true\r\nSourceIsIpv6: false\r\nSourceIp: 192.168.0.121\r\nSourceHostname: -\r\nSourcePort: 49747\r\nSourcePortName: -\r\nDestinationIsIpv6: false\r\nDestinationIp: 192.168.0.4\r\nDestinationHostname: -\r\nDestinationPort: 7010\r\nDestinationPortName: -\"","version":"5","systemTime":"2021-08-10T17:04:41.8691945Z","eventRecordID":"328239","threadID":"3444","computer":"hrmanager.ExchangeTest.com","task":"3","processID":"2312","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '61605')
        self.assertEqual(response.rule_level, 0)


    def test_sysmon_eventid_4(self) -> None:
        log = r'''
{"win":{"eventdata":{"schemaVersion":"4.70","utcTime":"2021-08-13 20:59:07.499","state":"Started","version":"13.22"},"system":{"eventID":"4","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Sysmon service state changed:\r\nUtcTime: 2021-08-13 20:59:07.499\r\nState: Started\r\nVersion: 13.22\r\nSchemaVersion: 4.70\"","version":"3","systemTime":"2021-08-13T20:59:07.4999128Z","eventRecordID":"342247","threadID":"4260","computer":"hrmanager.ExchangeTest.com","task":"4","processID":"2668","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '61606')
        self.assertEqual(response.rule_level, 0)


    def test_sysmon_eventid_5(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Users\\\\AtomicRed\\\\AppData\\\\Local\\\\Microsoft\\\\OneDrive\\\\OneDrive.exe","processGuid":"{4dc16835-dd35-6116-07a7-0c0000000000}","processId":"5764","utcTime":"2021-08-13 22:27:05.281"},"system":{"eventID":"5","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Process terminated:\r\nRuleName: -\r\nUtcTime: 2021-08-13 22:27:05.281\r\nProcessGuid: {4dc16835-dd35-6116-07a7-0c0000000000}\r\nProcessId: 5764\r\nImage: C:\\Users\\AtomicRed\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\"","version":"3","systemTime":"2021-08-13T22:27:05.2840390Z","eventRecordID":"346832","threadID":"4260","computer":"hrmanager.ExchangeTest.com","task":"5","processID":"2668","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '61607')
        self.assertEqual(response.rule_level, 0)


    def test_sysmon_eventid_6(self) -> None:
        log = r'''
{"win":{"eventdata":{"signatureStatus":"Valid","signature":"Oracle Corporation","utcTime":"2021-08-14 00:58:34.609","hashes":"SHA1=A33768C126545B2A5A1DB905D9F5E8ECC44074E1,MD5=52CA9687FFD4F6C5AA9C92A98BA3B319,SHA256=98535D8A486B339759CC73CF2E002E54EC887B0533ADD7064063B32A81C46F34,IMPHASH=DA88E590C5D4C95F6149672355A98A6B","imageLoaded":"C:\\\\Windows\\\\System32\\\\drivers\\\\VBoxWddm.sys","signed":"true"},"system":{"eventID":"6","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Driver loaded:\r\nRuleName: -\r\nUtcTime: 2021-08-14 00:58:34.609\r\nImageLoaded: C:\\Windows\\System32\\drivers\\VBoxWddm.sys\r\nHashes: SHA1=A33768C126545B2A5A1DB905D9F5E8ECC44074E1,MD5=52CA9687FFD4F6C5AA9C92A98BA3B319,SHA256=98535D8A486B339759CC73CF2E002E54EC887B0533ADD7064063B32A81C46F34,IMPHASH=DA88E590C5D4C95F6149672355A98A6B\r\nSigned: true\r\nSignature: Oracle Corporation\r\nSignatureStatus: Valid\"","version":"4","systemTime":"2021-08-13T20:59:08.2957992Z","eventRecordID":"342329","threadID":"4272","computer":"hrmanager.ExchangeTest.com","task":"6","processID":"2668","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '61608')
        self.assertEqual(response.rule_level, 0)


    def test_sysmon_eventid_7(self) -> None:
        log = r'''
{"win":{"eventdata":{"originalFileName":"wmiutils.dll","image":"C:\\\\Windows\\\\System32\\\\wbem\\\\WmiApSrv.exe","product":"Microsoft® Windows® Operating System","signature":"Microsoft Windows","imageLoaded":"C:\\\\Windows\\\\System32\\\\wbem\\\\wmiutils.dll","description":"WMI","signed":"true","signatureStatus":"Valid","processGuid":"{4dc16835-eaa5-612f-2d82-830000000000}","processId":"3952","utcTime":"2021-09-01 21:03:33.996","hashes":"SHA1=C509BA56FBC9CED227B85C2120CC3168EC06266B,MD5=02AE3EA0E5F0C12724802768D3970E8A,SHA256=1287470AB7A43A3A01FCFCE8EF5A4EF62ADACE1388E6E2172E0D9698C364C9B3,IMPHASH=0D31E6D27B954AD879CB4DF742982F1A","ruleName":"technique_id=T1047,technique_name=Windows Management Instrumentation","company":"Microsoft Corporation","fileVersion":"10.0.19041.1081 (WinBuild.160101.0800)"},"system":{"eventID":"7","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Image loaded:\r\nRuleName: technique_id=T1047,technique_name=Windows Management Instrumentation\r\nUtcTime: 2021-09-01 21:03:33.996\r\nProcessGuid: {4dc16835-eaa5-612f-2d82-830000000000}\r\nProcessId: 3952\r\nImage: C:\\Windows\\System32\\wbem\\WmiApSrv.exe\r\nImageLoaded: C:\\Windows\\System32\\wbem\\wmiutils.dll\r\nFileVersion: 10.0.19041.1081 (WinBuild.160101.0800)\r\nDescription: WMI\r\nProduct: Microsoft® Windows® Operating System\r\nCompany: Microsoft Corporation\r\nOriginalFileName: wmiutils.dll\r\nHashes: SHA1=C509BA56FBC9CED227B85C2120CC3168EC06266B,MD5=02AE3EA0E5F0C12724802768D3970E8A,SHA256=1287470AB7A43A3A01FCFCE8EF5A4EF62ADACE1388E6E2172E0D9698C364C9B3,IMPHASH=0D31E6D27B954AD879CB4DF742982F1A\r\nSigned: true\r\nSignature: Microsoft Windows\r\nSignatureStatus: Valid\"","version":"3","systemTime":"2021-09-01T21:03:33.9977500Z","eventRecordID":"351623","threadID":"3644","computer":"hrmanager.ExchangeTest.com","task":"7","processID":"2516","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '61609')
        self.assertEqual(response.rule_level, 0)


    def test_sysmon_eventid_8(self) -> None:
        log = r'''
{"win":{"eventdata":{"targetProcessGuid":"{4dc16835-25ac-6114-0900-000000006000}","targetProcessId":"552","startAddress":"0xFFFFD91F60CF20D0","utcTime":"2021-08-11 18:03:53.072","ruleName":"technique_id=T1055,technique_name=Process Injection","sourceProcessId":"948","sourceImage":"C:\\\\Windows\\\\system32\\\\dwm.exe","newThreadId":"6576","sourceProcessGuid":"{4dc16835-25ad-6114-1100-000000006000}","targetImage":"&lt;unknown process&gt;"},"system":{"eventID":"8","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"CreateRemoteThread detected:\r\nRuleName: technique_id=T1055,technique_name=Process Injection\r\nUtcTime: 2021-08-11 18:03:53.072\r\nSourceProcessGuid: {4dc16835-25ad-6114-1100-000000006000}\r\nSourceProcessId: 948\r\nSourceImage: C:\\Windows\\system32\\dwm.exe\r\nTargetProcessGuid: {4dc16835-25ac-6114-0900-000000006000}\r\nTargetProcessId: 552\r\nTargetImage: <unknown process>\r\nNewThreadId: 6576\r\nStartAddress: 0xFFFFD91F60CF20D0\r\nStartModule: -\r\nStartFunction: -\"","version":"2","systemTime":"2021-08-11T18:03:53.1714235Z","eventRecordID":"339976","threadID":"3620","computer":"hrmanager.ExchangeTest.com","task":"8","processID":"2368","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '61610')
        self.assertEqual(response.rule_level, 0)


    def test_sysmon_eventid_10(self) -> None:
        log = r'''
{"win":{"eventdata":{"sourceThreadId":"4436","grantedAccess":"0x3a84","targetProcessGUID":"{4dc16835-ded5-612f-d02d-770000000000}","targetProcessId":"6788","utcTime":"2021-09-01 20:13:11.375","ruleName":"technique_id=T1036,technique_name=Masquerading","sourceProcessId":"4844","sourceImage":"C:\\\\Windows\\\\TEMP\\\\E7559ABC-5904-4E4C-94E4-D210ACC05431\\\\MpSigStub.exe","targetImage":"C:\\\\Windows\\\\SoftwareDistribution\\\\Download\\\\Install\\\\updateplatform.exe","sourceProcessGUID":"{4dc16835-ded7-612f-ec71-770000000000}","callTrace":"C:\\\\Windows\\\\SYSTEM32\\\\ntdll.dll+9d0d4|C:\\\\Windows\\\\System32\\\\KERNELBASE.dll+249ee|C:\\\\Windows\\\\TEMP\\\\E7559ABC-5904-4E4C-94E4-D210ACC05431\\\\MpSigStub.exe+6b38b|C:\\\\Windows\\\\TEMP\\\\E7559ABC-5904-4E4C-94E4-D210ACC05431\\\\MpSigStub.exe+1a487|C:\\\\Windows\\\\TEMP\\\\E7559ABC-5904-4E4C-94E4-D210ACC05431\\\\MpSigStub.exe+1beab|C:\\\\Windows\\\\TEMP\\\\E7559ABC-5904-4E4C-94E4-D210ACC05431\\\\MpSigStub.exe+1bb01|C:\\\\Windows\\\\TEMP\\\\E7559ABC-5904-4E4C-94E4-D210ACC05431\\\\MpSigStub.exe+1ccf2|C:\\\\Windows\\\\TEMP\\\\E7559ABC-5904-4E4C-94E4-D210ACC05431\\\\MpSigStub.exe+e89f|C:\\\\Windows\\\\TEMP\\\\E7559ABC-5904-4E4C-94E4-D210ACC05431\\\\MpSigStub.exe+8b95c|C:\\\\Windows\\\\System32\\\\KERNEL32.DLL+17034|C:\\\\Windows\\\\SYSTEM32\\\\ntdll.dll+52651"},"system":{"eventID":"10","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Process accessed:\r\nRuleName: technique_id=T1036,technique_name=Masquerading\r\nUtcTime: 2021-09-01 20:13:11.375\r\nSourceProcessGUID: {4dc16835-ded7-612f-ec71-770000000000}\r\nSourceProcessId: 4844\r\nSourceThreadId: 4436\r\nSourceImage: C:\\Windows\\TEMP\\E7559ABC-5904-4E4C-94E4-D210ACC05431\\MpSigStub.exe\r\nTargetProcessGUID: {4dc16835-ded5-612f-d02d-770000000000}\r\nTargetProcessId: 6788\r\nTargetImage: C:\\Windows\\SoftwareDistribution\\Download\\Install\\updateplatform.exe\r\nGrantedAccess: 0x3A84\r\nCallTrace: C:\\Windows\\SYSTEM32\\ntdll.dll+9d0d4|C:\\Windows\\System32\\KERNELBASE.dll+249ee|C:\\Windows\\TEMP\\E7559ABC-5904-4E4C-94E4-D210ACC05431\\MpSigStub.exe+6b38b|C:\\Windows\\TEMP\\E7559ABC-5904-4E4C-94E4-D210ACC05431\\MpSigStub.exe+1a487|C:\\Windows\\TEMP\\E7559ABC-5904-4E4C-94E4-D210ACC05431\\MpSigStub.exe+1beab|C:\\Windows\\TEMP\\E7559ABC-5904-4E4C-94E4-D210ACC05431\\MpSigStub.exe+1bb01|C:\\Windows\\TEMP\\E7559ABC-5904-4E4C-94E4-D210ACC05431\\MpSigStub.exe+1ccf2|C:\\Windows\\TEMP\\E7559ABC-5904-4E4C-94E4-D210ACC05431\\MpSigStub.exe+e89f|C:\\Windows\\TEMP\\E7559ABC-5904-4E4C-94E4-D210ACC05431\\MpSigStub.exe+8b95c|C:\\Windows\\System32\\KERNEL32.DLL+17034|C:\\Windows\\SYSTEM32\\ntdll.dll+52651\"","version":"3","systemTime":"2021-09-01T20:13:11.3897320Z","eventRecordID":"180086","threadID":"3140","computer":"cfo.ExchangeTest.com","task":"10","processID":"2400","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '61612')
        self.assertEqual(response.rule_level, 0)


    def test_sysmon_eventid_11(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Windows\\\\System32\\\\svchost.exe","processGuid":"{4dc16835-130a-6130-1800-000000006300}","processId":"424","utcTime":"2021-09-01 21:03:43.372","targetFilename":"C:\\\\Windows\\\\Prefetch\\\\WMIPRVSE.EXE-1628051C.pf","ruleName":"technique_id=T1047,technique_name=File System Permissions Weakness","creationUtcTime":"2021-02-23 17:48:15.536"},"system":{"eventID":"11","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"File created:\r\nRuleName: technique_id=T1047,technique_name=File System Permissions Weakness\r\nUtcTime: 2021-09-01 21:03:43.372\r\nProcessGuid: {4dc16835-130a-6130-1800-000000006300}\r\nProcessId: 424\r\nImage: C:\\Windows\\System32\\svchost.exe\r\nTargetFilename: C:\\Windows\\Prefetch\\WMIPRVSE.EXE-1628051C.pf\r\nCreationUtcTime: 2021-02-23 17:48:15.536\"","version":"2","systemTime":"2021-09-01T21:03:43.3733588Z","eventRecordID":"351624","threadID":"3644","computer":"hrmanager.ExchangeTest.com","task":"11","processID":"2516","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '61613')
        self.assertEqual(response.rule_level, 0)


    def test_sysmon_eventid_12(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Windows\\\\system32\\\\wbem\\\\wmiprvse.exe","targetObject":"HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\Windows Workflow Foundation 4.0.0.0\\\\Linkage","processGuid":"{4dc16835-dab9-612f-5c76-040000000000}","processId":"3124","utcTime":"2021-09-01 21:03:33.507","ruleName":"technique_id=T1543,technique_name=Service Creation","eventType":"CreateKey"},"system":{"eventID":"12","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Registry object added or deleted:\r\nRuleName: technique_id=T1543,technique_name=Service Creation\r\nEventType: CreateKey\r\nUtcTime: 2021-09-01 21:03:33.507\r\nProcessGuid: {4dc16835-dab9-612f-5c76-040000000000}\r\nProcessId: 3124\r\nImage: C:\\Windows\\system32\\wbem\\wmiprvse.exe\r\nTargetObject: HKLM\\System\\CurrentControlSet\\Services\\Windows Workflow Foundation 4.0.0.0\\Linkage\"","version":"2","systemTime":"2021-09-01T21:03:33.5134169Z","eventRecordID":"351619","threadID":"3644","computer":"hrmanager.ExchangeTest.com","task":"12","processID":"2516","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '61614')
        self.assertEqual(response.rule_level, 0)


    def test_sysmon_eventid_13(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Windows\\\\System32\\\\svchost.exe","targetObject":"HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\NcbService\\\\NCBKapiNlmCache\\\\9\\\\Value","processGuid":"{4dc16835-130a-6130-1800-000000006300}","processId":"424","utcTime":"2021-09-01 20:58:03.282","ruleName":"technique_id=T1543,technique_name=Service Creation","details":"Binary Data","eventType":"SetValue"},"system":{"eventID":"13","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Registry value set:\r\nRuleName: technique_id=T1543,technique_name=Service Creation\r\nEventType: SetValue\r\nUtcTime: 2021-09-01 20:58:03.282\r\nProcessGuid: {4dc16835-130a-6130-1800-000000006300}\r\nProcessId: 424\r\nImage: C:\\Windows\\System32\\svchost.exe\r\nTargetObject: HKLM\\System\\CurrentControlSet\\Services\\NcbService\\NCBKapiNlmCache\\9\\Value\r\nDetails: Binary Data\"","version":"2","systemTime":"2021-09-01T20:58:03.2841583Z","eventRecordID":"351550","threadID":"3644","computer":"hrmanager.ExchangeTest.com","task":"13","processID":"2516","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '61615')
        self.assertEqual(response.rule_level, 0)


    def test_sysmon_eventid_15(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Windows\\\\Explorer.EXE","processGuid":"{4dc16835-dc72-612f-591d-0a0000000000}","processId":"4480","contents":"[ZoneTransfer]  ZoneId=3  ReferrerUrl=C:\\\\Users\\\\AtomicRed\\\\Downloads\\\\katz_trunk.zip","utcTime":"2021-09-01 20:39:01.347","targetFilename":"C:\\\\Users\\\\AtomicRed\\\\Downloads\\\\katz_trunk\\\\x64\\\\spool.dll:Zone.Identifier","ruleName":"technique_id=T1089,technique_name=Drive-by Compromise","creationUtcTime":"2021-08-11 00:22:58.000","hash":"SHA1=66B6C5EBA4BAEF803C9344763711DDEF70B5CCCD,MD5=9876DC6D155D58377D83FF94EC83FBA4,SHA256=07C83F0BF8F8A855CFD77B7E8F2014B8D808D14354B8CE540C2A9B0DF11AE367,IMPHASH=00000000000000000000000000000000"},"system":{"eventID":"15","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"File stream created:\r\nRuleName: technique_id=T1089,technique_name=Drive-by Compromise\r\nUtcTime: 2021-09-01 20:39:01.347\r\nProcessGuid: {4dc16835-dc72-612f-591d-0a0000000000}\r\nProcessId: 4480\r\nImage: C:\\Windows\\Explorer.EXE\r\nTargetFilename: C:\\Users\\AtomicRed\\Downloads\\katz_trunk\\x64\\spool.dll:Zone.Identifier\r\nCreationUtcTime: 2021-08-11 00:22:58.000\r\nHash: SHA1=66B6C5EBA4BAEF803C9344763711DDEF70B5CCCD,MD5=9876DC6D155D58377D83FF94EC83FBA4,SHA256=07C83F0BF8F8A855CFD77B7E8F2014B8D808D14354B8CE540C2A9B0DF11AE367,IMPHASH=00000000000000000000000000000000\r\nContents: [ZoneTransfer]  ZoneId=3  ReferrerUrl=C:\\Users\\AtomicRed\\Downloads\\katz_trunk.zip  \"","version":"2","systemTime":"2021-09-01T20:39:01.3623659Z","eventRecordID":"182584","threadID":"3140","computer":"cfo.ExchangeTest.com","task":"15","processID":"2400","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '61617')
        self.assertEqual(response.rule_level, 0)


    def test_sysmon_eventid_16(self) -> None:
        log = r'''
{"win":{"eventdata":{"configuration":"C:\\\\Users\\\\AtomicRed\\\\Downloads\\\\sysmon\\\\Sysmonjune22\\\\sysmonconfig.xml","utcTime":"2021-07-20 19:32:20.396","configurationFileHash":"SHA256=EFCDCF4315ACFDDAD6060A246CBE0115D8F49591B0535A2990F2101A67B7155C"},"system":{"eventID":"16","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Sysmon config state changed:\r\nUtcTime: 2021-07-20 19:32:20.396\r\nConfiguration: C:\\Users\\AtomicRed\\Downloads\\sysmon\\Sysmonjune22\\sysmonconfig.xml\r\nConfigurationFileHash: SHA256=EFCDCF4315ACFDDAD6060A246CBE0115D8F49591B0535A2990F2101A67B7155C\"","version":"3","systemTime":"2021-07-20T19:32:20.4013153Z","eventRecordID":"279041","threadID":"5780","computer":"hrmanager.ExchangeTest.com","task":"16","processID":"3688","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '61644')
        self.assertEqual(response.rule_level, 0)


    def test_sysmon_eventid_17(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Windows\\\\system32\\\\sihost.exe","processGuid":"{4dc16835-dc71-612f-8335-090000000000}","processId":"1596","utcTime":"2021-09-01 20:23:42.451","eventType":"CreatePipe","pipeName":"\\\\AppContracts_x0A30B754-BF6E-423F-99E4-96AF8B5BD189y"},"system":{"eventID":"17","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Pipe Created:\r\nRuleName: -\r\nEventType: CreatePipe\r\nUtcTime: 2021-09-01 20:23:42.451\r\nProcessGuid: {4dc16835-dc71-612f-8335-090000000000}\r\nProcessId: 1596\r\nPipeName: \\AppContracts_x0A30B754-BF6E-423F-99E4-96AF8B5BD189y\r\nImage: C:\\Windows\\system32\\sihost.exe\"","version":"1","systemTime":"2021-09-01T20:23:42.4560267Z","eventRecordID":"181769","threadID":"3140","computer":"cfo.ExchangeTest.com","task":"17","processID":"2400","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '61645')
        self.assertEqual(response.rule_level, 0)


    def test_sysmon_eventid_19(self) -> None:
        log = r'''
{"win":{"eventdata":{"utcTime":"2021-03-01 20:53:46.257","query":" \\\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime &gt;= 240 AND TargetInstance.SystemUpTime &lt; 325\\\"","name":" \\\"AtomicRedTeam-WMIPersistence-Example\\\"","ruleName":"technique_id=T1047,technique_name=Windows Management Instrumentation","eventType":"WmiFilterEvent","eventNamespace":" \\\"root\\\\\\\\CimV2\\\"","operation":"Created","user":"DESKTOP-2QKFOBA\\\\AtomicRedTeamTest"},"system":{"eventID":"19","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"WmiEventFilter activity detected:\r\nRuleName: technique_id=T1047,technique_name=Windows Management Instrumentation\r\nEventType: WmiFilterEvent\r\nUtcTime: 2021-03-01 20:53:46.257\r\nOperation: Created\r\nUser: DESKTOP-2QKFOBA\\AtomicRedTeamTest\r\nEventNamespace:  \"root\\\\CimV2\"\r\nName:  \"AtomicRedTeam-WMIPersistence-Example\"\r\nQuery:  \"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325\"\"","version":"3","systemTime":"2021-03-01T20:53:46.2650847Z","eventRecordID":"33057","threadID":"6368","computer":"DESKTOP-2QKFOBA","task":"19","processID":"2368","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '61647')
        self.assertEqual(response.rule_level, 0)


    def test_sysmon_eventid_20(self) -> None:
        log = r'''
{"win":{"eventdata":{"utcTime":"2021-03-01 20:53:46.273","name":" \\\"AtomicRedTeam-WMIPersistence-Example\\\"","destination":" \\\"C:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\notepad.exe\\\"","ruleName":"technique_id=T1047,technique_name=Windows Management Instrumentation","eventType":"WmiConsumerEvent","type":"Other","operation":"Created","user":"DESKTOP-2QKFOBA\\\\AtomicRedTeamTest"},"system":{"eventID":"20","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"WmiEventConsumer activity detected:\r\nRuleName: technique_id=T1047,technique_name=Windows Management Instrumentation\r\nEventType: WmiConsumerEvent\r\nUtcTime: 2021-03-01 20:53:46.273\r\nOperation: Created\r\nUser: DESKTOP-2QKFOBA\\AtomicRedTeamTest\r\nName:  \"AtomicRedTeam-WMIPersistence-Example\"\r\nType: Command Line\r\nDestination:  \"C:\\\\Windows\\\\System32\\\\notepad.exe\"\"","version":"3","systemTime":"2021-03-01T20:53:46.2783291Z","eventRecordID":"33059","threadID":"6368","computer":"DESKTOP-2QKFOBA","task":"20","processID":"2368","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '61648')
        self.assertEqual(response.rule_level, 0)


    def test_sysmon_eventid_21(self) -> None:
        log = r'''
{"win":{"eventdata":{"filter":" \\\"\\\\\\\\\\\\\\\\.\\\\\\\\ROOT\\\\\\\\subscription:__EventFilter.Name=\\\\\\\"AtomicRedTeam-WMIPersistence-Example\\\\\\\"\\\"","utcTime":"2021-03-01 20:53:46.570","ruleName":"technique_id=T1047,technique_name=Windows Management Instrumentation","eventType":"WmiBindingEvent","operation":"Created","user":"DESKTOP-2QKFOBA\\\\AtomicRedTeamTest","consumer":" \\\"\\\\\\\\\\\\\\\\.\\\\\\\\ROOT\\\\\\\\subscription:CommandLineEventConsumer.Name=\\\\\\\"AtomicRedTeam-WMIPersistence-Example\\\\\\\"\\\""},"system":{"eventID":"21","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"WmiEventConsumerToFilter activity detected:\r\nRuleName: technique_id=T1047,technique_name=Windows Management Instrumentation\r\nEventType: WmiBindingEvent\r\nUtcTime: 2021-03-01 20:53:46.570\r\nOperation: Created\r\nUser: DESKTOP-2QKFOBA\\AtomicRedTeamTest\r\nConsumer:  \"\\\\\\\\.\\\\ROOT\\\\subscription:CommandLineEventConsumer.Name=\\\"AtomicRedTeam-WMIPersistence-Example\\\"\"\r\nFilter:  \"\\\\\\\\.\\\\ROOT\\\\subscription:__EventFilter.Name=\\\"AtomicRedTeam-WMIPersistence-Example\\\"\"\"","version":"3","systemTime":"2021-03-01T20:53:46.5721127Z","eventRecordID":"33060","threadID":"6368","computer":"DESKTOP-2QKFOBA","task":"21","processID":"2368","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '61649')
        self.assertEqual(response.rule_level, 0)


    def test_sysmon_eventid_22(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Program Files (x86)\\\\Microsoft\\\\Edge\\\\Application\\\\msedge.exe","processGuid":"{4dc16835-e4b7-612f-d002-000000001900}","queryStatus":"0","processId":"2412","utcTime":"2021-09-01 20:40:24.039","queryName":"img-s-msn-com.akamaized.net","queryResults":"type:  5 a1834.dspg2.akamai.net;181.30.131.40;181.30.131.42;"},"system":{"eventID":"22","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Dns query:\r\nRuleName: -\r\nUtcTime: 2021-09-01 20:40:24.039\r\nProcessGuid: {4dc16835-e4b7-612f-d002-000000001900}\r\nProcessId: 2412\r\nQueryName: img-s-msn-com.akamaized.net\r\nQueryStatus: 0\r\nQueryResults: type:  5 a1834.dspg2.akamai.net;181.30.131.40;181.30.131.42;\r\nImage: C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\"","version":"5","systemTime":"2021-09-01T20:40:34.8860064Z","eventRecordID":"182667","threadID":"1592","computer":"cfo.ExchangeTest.com","task":"22","processID":"2400","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '61650')
        self.assertEqual(response.rule_level, 0)


    def test_sysmon_eventid_23(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Windows\\\\System32\\\\poqexec.exe","archived":"true","processGuid":"{4dc16835-e584-612f-baba-cc0000000000}","processId":"1960","utcTime":"2021-09-01 20:41:48.604","targetFilename":"C:\\\\Windows\\\\SysWOW64\\\\WsmRes.dll","hashes":"SHA1=7B494AB968B305F969F7F86630FBB06CFDED6C76,MD5=0A09CEDE529A4A71A37D4BB8F40EF55C,SHA256=99B69B8C2D5020F2F8BFF7951CD79F01CD97294F84053D5EB42B3A7C66CBA347,IMPHASH=00000000000000000000000000000000","isExecutable":"true","user":"NT AUTHORITY\\\\SYSTEM"},"system":{"eventID":"23","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"File Delete archived:\r\nRuleName: -\r\nUtcTime: 2021-09-01 20:41:48.604\r\nProcessGuid: {4dc16835-e584-612f-baba-cc0000000000}\r\nProcessId: 1960\r\nUser: NT AUTHORITY\\SYSTEM\r\nImage: C:\\Windows\\System32\\poqexec.exe\r\nTargetFilename: C:\\Windows\\SysWOW64\\WsmRes.dll\r\nHashes: SHA1=7B494AB968B305F969F7F86630FBB06CFDED6C76,MD5=0A09CEDE529A4A71A37D4BB8F40EF55C,SHA256=99B69B8C2D5020F2F8BFF7951CD79F01CD97294F84053D5EB42B3A7C66CBA347,IMPHASH=00000000000000000000000000000000\r\nIsExecutable: true\r\nArchived: true\"","version":"5","systemTime":"2021-09-01T20:41:48.6048977Z","eventRecordID":"183596","threadID":"3140","computer":"cfo.ExchangeTest.com","task":"23","processID":"2400","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '61651')
        self.assertEqual(response.rule_level, 0)


    def test_sysmon_eventid_25(self) -> None:
        log = r'''
{"win":{"eventdata":{"image":"C:\\\\Windows\\\\System32\\\\wbem\\\\WMIADAP.exe","processGuid":"{4dc16835-ddfd-6116-5a0b-1d0000000000}","processId":"352","utcTime":"2021-08-13 21:02:53.207","type":"Image is locked for access"},"system":{"eventID":"25","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Process Tampering:\r\nRuleName: -\r\nUtcTime: 2021-08-13 21:02:53.207\r\nProcessGuid: {4dc16835-ddfd-6116-5a0b-1d0000000000}\r\nProcessId: 352\r\nImage: C:\\Windows\\System32\\wbem\\WMIADAP.exe\r\nType: Image is locked for access\"","version":"5","systemTime":"2021-08-13T21:02:53.2085459Z","eventRecordID":"343354","threadID":"4260","computer":"hrmanager.ExchangeTest.com","task":"25","processID":"2668","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '61653')
        self.assertEqual(response.rule_level, 0)


    def test_sysmon_eventid_255(self) -> None:
        log = r'''
{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"255","version":"5","level":"4","task":"22","opcode":"0","keywords":"0x8000000000000000","systemTime":"2022-10-14T10:19:22.7373425Z","eventRecordID":"271","processID":"2624","threadID":"3544","channel":"Microsoft-Windows-Sysmon/Operational","computer":"EC2AMAZ-N9OLJ1L","severityValue":"INFORMATION","message":"\"Dns query:\r\nRuleName: -\r\nUtcTime: 2022-10-14 10:19:19.391\r\nProcessGuid: {3bd4f97a-3636-6349-6500-000000009800}\r\nProcessId: 2820\r\nQueryName: ssm.us-east-1.amazonaws.com\r\nQueryStatus: 0\r\nQueryResults: ::ffff:52.119.198.91;\r\nImage: C:\\Program Files\\Amazon\\SSM\\ssm-agent-worker.exe\r\nUser: NT AUTHORITY\\SYSTEM\""},"eventdata":{"utcTime":"2022-10-14 10:19:19.391","processGuid":"{3bd4f97a-3636-6349-6500-000000009800}","processId":"2820","queryName":"ssm.us-east-1.amazonaws.com","queryStatus":"0","queryResults":"::ffff:52.119.198.91;","image":"C:\\\\Program Files\\\\Amazon\\\\SSM\\\\ssm-agent-worker.exe","user":"NT AUTHORITY\\\\SYSTEM"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '61655')
        self.assertEqual(response.rule_level, 0)

