#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from windows_baseline_intrusion_detection.ini
class TestWindows_baseline_intrusion_detectionRules(unittest.TestCase):

    def test_app_locker_allowed_exe_execution(self) -> None:
        log = '''{"win":{"system":{"eventID":"8002","keywords":"0x8000000000000000","providerGuid":"{cbda4dbf-8d5d-4f69-9578-be14aa540d22}","level":"4","channel":"Microsoft-Windows-AppLocker/EXE and DLL","opcode":"0","message":"\"%SYSTEM32%\\TASKHOSTW.EXE was allowed to run.\"","version":"0","systemTime":"2022-08-10T23:40:50.0608494Z","eventRecordID":"48","threadID":"5880","computer":"hrmanager.ExchangeTest.com","task":"0","processID":"1260","severityValue":"INFORMATION","providerName":"Microsoft-Windows-AppLocker"},"ruleAndFileData":{"targetProcessId":"3736","ruleNameLength":"54","policyName":"Exe","policyNameLength":"3","filePath":"%SYSTEM32%\\\\TASKHOSTW.EXE","fullFilePathLength":"33","filePathLength":"24","fileHashLength":"0","targetLogonId":"0x35718c","ruleSddl":"D:(XA;;FX;;;S-1-1-0;(APPID://PATH Contains \\\"%WINDIR%\\\\*\\\"))","fqbnLength":"1","ruleName":"(Default Rule) All files located in the Windows folder","fullFilePath":"C:\\\\Windows\\\\system32\\\\taskhostw.exe","ruleId":"{a61c8b2c-a319-4cd0-9690-d2177cad7b51}","ruleSddlLength":"57","targetUser":"S-1-5-21-887924094-598891991-956377308-1146"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '67011')
        self.assertEqual(response.rule_level, 3)


    def test_app_locker_would_block_exe_execution(self) -> None:
        log = '''{"win":{"system":{"eventID":"8003","keywords":"0x8000000000000000","providerGuid":"{cbda4dbf-8d5d-4f69-9578-be14aa540d22}","level":"2","channel":"Microsoft-Windows-AppLocker/EXE and DLL","opcode":"0","message":"\"%OSDRIVE%\\X\\NPP.8.4.1.INSTALLER.X64.EXE was prevented from running.\"","version":"0","systemTime":"2022-08-10T23:36:47.5675660Z","eventRecordID":"46","threadID":"5072","computer":"hrmanager.ExchangeTest.com","task":"0","processID":"3128","severityValue":"WARNING","providerName":"Microsoft-Windows-AppLocker"},"ruleAndFileData":{"targetProcessId":"2804","ruleNameLength":"14","policyName":"Exe","policyNameLength":"3","filePath":"%OSDRIVE%\\\\X\\\\NPP.8.4.1.INSTALLER.X64.EXE","fullFilePathLength":"32","filePathLength":"39","fileHashLength":"0","targetLogonId":"0x35718c","ruleSddl":"D:(XD;;FX;;;S-1-1-0;(APPID://PATH Contains \\\"%OSDRIVE%\\\\X\\\\*\\\"))","fqbnLength":"1","ruleName":"Execute from x","fullFilePath":"C:\\\\x\\\\npp.8.4.1.Installer.x64.exe","ruleId":"{519e1be7-3ebe-4679-b282-94b611c4b06f}","ruleSddlLength":"60","targetUser":"S-1-5-21-887924094-598891991-956377308-1146"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '67012')
        self.assertEqual(response.rule_level, 3)


    def test_app_locker_blocked_exe_execution(self) -> None:
        log = '''{"win":{"system":{"eventID":"8004","keywords":"0x8000000000000000","providerGuid":"{cbda4dbf-8d5d-4f69-9578-be14aa540d22}","level":"2","channel":"Microsoft-Windows-AppLocker/EXE and DLL","opcode":"0","message":"\"%OSDRIVE%\\X\\NPP.8.4.1.INSTALLER.X64.EXE was prevented from running.\"","version":"0","systemTime":"2022-08-10T23:36:47.5675660Z","eventRecordID":"46","threadID":"5072","computer":"hrmanager.ExchangeTest.com","task":"0","processID":"3128","severityValue":"ERROR","providerName":"Microsoft-Windows-AppLocker"},"ruleAndFileData":{"targetProcessId":"2804","ruleNameLength":"14","policyName":"Exe","policyNameLength":"3","filePath":"%OSDRIVE%\\\\X\\\\NPP.8.4.1.INSTALLER.X64.EXE","fullFilePathLength":"32","filePathLength":"39","fileHashLength":"0","targetLogonId":"0x35718c","ruleSddl":"D:(XD;;FX;;;S-1-1-0;(APPID://PATH Contains \\\"%OSDRIVE%\\\\X\\\\*\\\"))","fqbnLength":"1","ruleName":"Execute from x","fullFilePath":"C:\\\\x\\\\npp.8.4.1.Installer.x64.exe","ruleId":"{519e1be7-3ebe-4679-b282-94b611c4b06f}","ruleSddlLength":"60","targetUser":"S-1-5-21-887924094-598891991-956377308-1146"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '67013')
        self.assertEqual(response.rule_level, 3)


    def test_task_scheduler_create_task(self) -> None:
        log = '''{"win":{"eventdata":{"taskName":"\\\\test-task","userContext":"S-1-5-18"},"system":{"eventID":"106","keywords":"0x8000000000000000","providerGuid":"{de7b24ea-73c8-4a09-985d-5bdadcfa9017}","level":"4","channel":"Microsoft-Windows-TaskScheduler/Operational","opcode":"0","message":"\"User \"S-1-5-18\"  registered Task Scheduler task \"\\test-task\"\"","version":"0","systemTime":"2022-08-11T20:31:40.4825154Z","eventRecordID":"60201","threadID":"6112","computer":"hrmanager.ExchangeTest.com","task":"106","processID":"1104","severityValue":"INFORMATION","providerName":"Microsoft-Windows-TaskScheduler"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '67014')
        self.assertEqual(response.rule_level, 3)


    def test_task_scheduler_delete_task(self) -> None:
        log = '''{"win":{"eventdata":{"taskName":"\\\\test-task","userName":"EXCHANGETEST\\\\AtomicRed"},"system":{"eventID":"141","keywords":"0x8000000000000000","providerGuid":"{de7b24ea-73c8-4a09-985d-5bdadcfa9017}","level":"4","channel":"Microsoft-Windows-TaskScheduler/Operational","opcode":"0","message":"\"User \"EXCHANGETEST\\AtomicRed\"  deleted Task Scheduler task \"\\test-task\"\"","version":"0","systemTime":"2022-08-11T20:39:10.7871630Z","eventRecordID":"60210","threadID":"4656","computer":"hrmanager.ExchangeTest.com","task":"141","processID":"1104","severityValue":"INFORMATION","providerName":"Microsoft-Windows-TaskScheduler"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '67015')
        self.assertEqual(response.rule_level, 3)


    def test_task_scheduler_disable_task(self) -> None:
        log = '''{"win":{"eventdata":{"taskName":"\\\\test-task","userName":"System"},"system":{"eventID":"142","keywords":"0x8000000000000000","providerGuid":"{de7b24ea-73c8-4a09-985d-5bdadcfa9017}","level":"4","channel":"Microsoft-Windows-TaskScheduler/Operational","opcode":"0","message":"\"User \"System\"  disabled Task Scheduler task \"\\test-task\"\"","version":"0","systemTime":"2022-08-11T20:38:37.2298208Z","eventRecordID":"60209","threadID":"5576","computer":"hrmanager.ExchangeTest.com","task":"142","processID":"1104","severityValue":"INFORMATION","providerName":"Microsoft-Windows-TaskScheduler"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '67016')
        self.assertEqual(response.rule_level, 3)


    def test_create_service(self) -> None:
        log = '''{"win":{"eventdata":{"serviceType":"user mode service","accountName":"LocalSystem","imagePath":"C:\\\\nssm-2.24-101-g897c7ad\\\\win64\\\\nssm.exe","startType":"auto start","serviceName":"shoulddelete"},"system":{"eventID":"7045","eventSourceName":"Service Control Manager","keywords":"0x8080000000000000","providerGuid":"{555908d1-a6d7-4695-8e1e-26931d2012f4}","level":"4","channel":"System","opcode":"0","message":"\"A service was installed in the system.\r\n\r\nService Name:  shoulddelete\r\nService File Name:  C:\\nssm-2.24-101-g897c7ad\\win64\\nssm.exe\r\nService Type:  user mode service\r\nService Start Type:  auto start\r\nService Account:  LocalSystem\"","version":"0","systemTime":"2022-08-11T23:44:28.9085059Z","eventRecordID":"15753","threadID":"536","computer":"hrmanager.ExchangeTest.com","task":"0","processID":"620","severityValue":"INFORMATION","providerName":"Service Control Manager"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '61138')
        self.assertEqual(response.rule_level, 5)


    def test_terminal_services_connect(self) -> None:
        log = '''{"win":{"eventdata":{"accountDomain":"EXCHANGETEST","logonID":"0xa197f3","accountName":"AtomicRed","clientName":"DESKTOP-K8SKTTJ","sessionName":"RDP-Tcp#9","clientAddress":"192.168.0.115"},"system":{"eventID":"4778","keywords":"0x8020000000000000","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","level":"0","channel":"Security","opcode":"0","message":"\"A session was reconnected to a Window Station.\r\n\r\nSubject:\r\n\tAccount Name:\t\tAtomicRed\r\n\tAccount Domain:\t\tEXCHANGETEST\r\n\tLogon ID:\t\t0xA197F3\r\n\r\nSession:\r\n\tSession Name:\t\tRDP-Tcp#9\r\n\r\nAdditional Information:\r\n\tClient Name:\t\tDESKTOP-K8SKTTJ\r\n\tClient Address:\t\t192.168.0.115\r\n\r\nThis event is generated when a user reconnects to an existing Terminal Services session, or when a user switches to an existing desktop using Fast User Switching.\"","version":"0","systemTime":"2022-08-12T18:49:06.0784840Z","eventRecordID":"1254999","threadID":"1500","computer":"hrmanager.ExchangeTest.com","task":"12551","processID":"672","severityValue":"AUDIT_SUCCESS","providerName":"Microsoft-Windows-Security-Auditing"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '60108')
        self.assertEqual(response.rule_level, 3)


    def test_terminal_services_disconnect(self) -> None:
        log = '''{"win":{"eventdata":{"accountDomain":"EXCHANGETEST","logonID":"0xa197f3","accountName":"AtomicRed","clientName":"DESKTOP-K8SKTTJ","sessionName":"RDP-Tcp#9","clientAddress":"192.168.0.115"},"system":{"eventID":"4779","keywords":"0x8020000000000000","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","level":"0","channel":"Security","opcode":"0","message":"\"A session was disconnected from a Window Station.\r\n\r\nSubject:\r\n\tAccount Name:\t\tAtomicRed\r\n\tAccount Domain:\t\tEXCHANGETEST\r\n\tLogon ID:\t\t0xA197F3\r\n\r\nSession:\r\n\tSession Name:\t\tRDP-Tcp#9\r\n\r\nAdditional Information:\r\n\tClient Name:\t\tDESKTOP-K8SKTTJ\r\n\tClient Address:\t\t192.168.0.115\r\n\r\n\r\nThis event is generated when a user disconnects from an existing Terminal Services session, or when a user switches away from an existing desktop using Fast User Switching.\"","version":"0","systemTime":"2022-08-12T18:57:45.7437245Z","eventRecordID":"1255021","threadID":"7564","computer":"hrmanager.ExchangeTest.com","task":"12551","processID":"672","severityValue":"AUDIT_SUCCESS","providerName":"Microsoft-Windows-Security-Auditing"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '60108')
        self.assertEqual(response.rule_level, 3)


    def test_network_share_object_access_without_ipc$_and_netlogon_shares(self) -> None:
        log = '''{"win":{"eventdata":{"subjectLogonId":"0x17880fe","subjectUserSid":"S-1-5-21-887924094-598891991-956377308-1146","ipPort":"60366","subjectDomainName":"EXCHANGETEST","shareLocalPath":"\\\\??\\\\C:\\\\Users\\\\AtomicRed\\\\Documents","ipAddress":"192.168.0.115","accessList":"%%4416","accessMask":"0x1","shareName":"\\\\\\\\*\\\\Documents","subjectUserName":"AtomicRed","objectType":"File"},"system":{"eventID":"5140","keywords":"0x8020000000000000","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","level":"0","channel":"Security","opcode":"0","message":"\"A network share object was accessed.\r\n\t\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-21-887924094-598891991-956377308-1146\r\n\tAccount Name:\t\tAtomicRed\r\n\tAccount Domain:\t\tEXCHANGETEST\r\n\tLogon ID:\t\t0x17880FE\r\n\r\nNetwork Information:\t\r\n\tObject Type:\t\tFile\r\n\tSource Address:\t\t192.168.0.115\r\n\tSource Port:\t\t60366\r\n\t\r\nShare Information:\r\n\tShare Name:\t\t\\\\*\\Documents\r\n\tShare Path:\t\t\\??\\C:\\Users\\AtomicRed\\Documents\r\n\r\nAccess Request Information:\r\n\tAccess Mask:\t\t0x1\r\n\tAccesses:\t\tReadData (or ListDirectory)\r\n\t\t\t\t\r\n\"","version":"1","systemTime":"2022-08-12T19:43:57.7974347Z","eventRecordID":"1280841","threadID":"6540","computer":"hrmanager.ExchangeTest.com","task":"12808","processID":"4","severityValue":"AUDIT_SUCCESS","providerName":"Microsoft-Windows-Security-Auditing"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '67017')
        self.assertEqual(response.rule_level, 3)


    def test_network_share_object_access_with_ipc$_and_netlogon_shares(self) -> None:
        log = '''{"win":{"eventdata":{"subjectLogonId":"0x17880fe","subjectUserSid":"S-1-5-21-887924094-598891991-956377308-1146","ipPort":"60366","subjectDomainName":"EXCHANGETEST","ipAddress":"192.168.0.115","accessList":"%%4416","accessMask":"0x1","shareName":"\\\\\\\\*\\\\IPC$","subjectUserName":"AtomicRed","objectType":"File"},"system":{"eventID":"5140","keywords":"0x8020000000000000","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","level":"0","channel":"Security","opcode":"0","message":"\"A network share object was accessed.\r\n\t\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-21-887924094-598891991-956377308-1146\r\n\tAccount Name:\t\tAtomicRed\r\n\tAccount Domain:\t\tEXCHANGETEST\r\n\tLogon ID:\t\t0x17880FE\r\n\r\nNetwork Information:\t\r\n\tObject Type:\t\tFile\r\n\tSource Address:\t\t192.168.0.115\r\n\tSource Port:\t\t60366\r\n\t\r\nShare Information:\r\n\tShare Name:\t\t\\\\*\\IPC$\r\n\tShare Path:\t\t\r\n\r\nAccess Request Information:\r\n\tAccess Mask:\t\t0x1\r\n\tAccesses:\t\tReadData (or ListDirectory)\r\n\t\t\t\t\r\n\"","version":"1","systemTime":"2022-08-12T19:43:57.7965891Z","eventRecordID":"1280840","threadID":"6540","computer":"hrmanager.ExchangeTest.com","task":"12808","processID":"4","severityValue":"AUDIT_SUCCESS","providerName":"Microsoft-Windows-Security-Auditing"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '67017')
        self.assertEqual(response.rule_level, 3)


    def test_change_system_date(self) -> None:
        log = '''{"win":{"eventdata":{"subjectLogonId":"0x3e7","previousTime":"2022-08-13T19:48:08.1093244Z","subjectUserSid":"S-1-5-18","processId":"0x654","processName":"C:\\\\Windows\\\\System32\\\\VBoxService.exe","subjectDomainName":"EXCHANGETEST","newTime":"2022-08-12T19:48:16.4640000Z","subjectUserName":"HRMANAGER$"},"system":{"eventID":"4616","keywords":"0x8020000000000000","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","level":"0","channel":"Security","opcode":"0","message":"\"The system time was changed.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tHRMANAGER$\r\n\tAccount Domain:\t\tEXCHANGETEST\r\n\tLogon ID:\t\t0x3E7\r\n\r\nProcess Information:\r\n\tProcess ID:\t0x654\r\n\tName:\t\tC:\\Windows\\System32\\VBoxService.exe\r\n\r\nPrevious Time:\t\t‎2022‎-‎08‎-‎13T19:48:08.109324400Z\r\nNew Time:\t\t‎2022‎-‎08‎-‎12T19:48:16.464000000Z\r\n\r\nThis event is generated when the system time is changed. It is normal for the Windows Time Service, which runs with System privilege, to change the system time on a regular basis. Other system time changes may be indicative of attempts to tamper with the computer.\"","version":"1","systemTime":"2022-08-12T19:48:16.4643388Z","eventRecordID":"1281495","threadID":"9916","computer":"hrmanager.ExchangeTest.com","task":"12288","processID":"4","severityValue":"AUDIT_SUCCESS","providerName":"Microsoft-Windows-Security-Auditing"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '60132')
        self.assertEqual(response.rule_level, 5)


    def test_shutdown_initiate_requests(self) -> None:
        log = '''{"win":{"eventdata":{"param7":"EXCHANGETEST\\\\AtomicRed","param5":"power off","param6":"testing events","param3":"Other (Planned)","param4":"0x85000000","param1":"wininit.exe (HRMANAGER)","param2":"HRMANAGER"},"system":{"eventID":"1074","eventSourceName":"User32","keywords":"0x8080000000000000","providerGuid":"{b0aa8734-56f7-41cc-b2f4-de228e98b946}","level":"4","channel":"System","opcode":"0","message":"\"The process wininit.exe (HRMANAGER) has initiated the power off of computer HRMANAGER on behalf of user EXCHANGETEST\\AtomicRed for the following reason: Other (Planned)\r\n Reason Code: 0x85000000\r\n Shutdown Type: power off\r\n Comment: testing events\"","version":"0","systemTime":"2022-08-12T19:52:25.8264794Z","eventRecordID":"15957","threadID":"464","computer":"hrmanager.ExchangeTest.com","task":"0","processID":"448","severityValue":"INFORMATION","providerName":"User32"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '67018')
        self.assertEqual(response.rule_level, 3)


    def test_applocker_packaged_ui_execution_allowed(self) -> None:
        log = '''{"win":{"system":{"eventID":"8020","keywords":"0x2000000000000000","providerGuid":"{cbda4dbf-8d5d-4f69-9578-be14aa540d22}","level":"2","channel":"Microsoft-Windows-AppLocker/Packaged app-Execution","opcode":"0","message":"\"\\??\\C:\\Program Files\\WindowsApps\\5319275A.WhatsAppDesktop_2.2228.14.0_x64__cv1g1gvanyjgm\\app\\WhatsApp.exe was prevented from running.\"","version":"0","systemTime":"2022-08-16T18:39:16.1843343Z","eventRecordID":"41","threadID":"4120","computer":"hrmanager.ExchangeTest.com","task":"0","processID":"1276","severityValue":"INFORMATION","providerName":"Microsoft-Windows-AppLocker"},"ruleAndFileData":{"targetProcessId":"5788","package":"\\\\??\\\\C:\\\\Program Files\\\\WindowsApps\\\\5319275A.WhatsAppDesktop_2.2228.14.0_x64__cv1g1gvanyjgm\\\\app\\\\WhatsApp.exe","ruleNameLength":"44","policyName":"Appx","policyNameLength":"4","fqbn":"CN=24803D75-212C-471A-BC57-9EF86AB91435\\\\5319275A.WHATSAPPDESKTOP\\\\WHATSAPP\\\\2.2228.14.00","ruleSddl":"D:(XD;;FX;;;S-1-1-0;((Exists APPID://FQBN) &amp;&amp; ((APPID://FQBN) &gt;= ({\\\"CN=24803D75-212C-471A-BC57-9EF86AB91435\\\\5319275A.WHATSAPPDESKTOP\\\\*\\\",0}))))","fqbnLength":"86","ruleName":"5319275A.WhatsAppDesktop, from WhatsApp Inc.","packageLength":"105","ruleId":"{a480952c-a710-4d92-b9a3-2fbff7c12866}","ruleSddlLength":"142","targetUser":"S-1-5-21-887924094-598891991-956377308-1146"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '67019')
        self.assertEqual(response.rule_level, 3)


    def test_applocker_packaged_ui_execution_would_block(self) -> None:
        log = '''{"win":{"system":{"eventID":"8021","keywords":"0x2000000000000000","providerGuid":"{cbda4dbf-8d5d-4f69-9578-be14aa540d22}","level":"2","channel":"Microsoft-Windows-AppLocker/Packaged app-Execution","opcode":"0","message":"\"\\??\\C:\\Program Files\\WindowsApps\\5319275A.WhatsAppDesktop_2.2228.14.0_x64__cv1g1gvanyjgm\\app\\WhatsApp.exe was prevented from running.\"","version":"0","systemTime":"2022-08-16T18:39:16.1843343Z","eventRecordID":"41","threadID":"4120","computer":"hrmanager.ExchangeTest.com","task":"0","processID":"1276","severityValue":"WARNING","providerName":"Microsoft-Windows-AppLocker"},"ruleAndFileData":{"targetProcessId":"5788","package":"\\\\??\\\\C:\\\\Program Files\\\\WindowsApps\\\\5319275A.WhatsAppDesktop_2.2228.14.0_x64__cv1g1gvanyjgm\\\\app\\\\WhatsApp.exe","ruleNameLength":"44","policyName":"Appx","policyNameLength":"4","fqbn":"CN=24803D75-212C-471A-BC57-9EF86AB91435\\\\5319275A.WHATSAPPDESKTOP\\\\WHATSAPP\\\\2.2228.14.00","ruleSddl":"D:(XD;;FX;;;S-1-1-0;((Exists APPID://FQBN) &amp;&amp; ((APPID://FQBN) &gt;= ({\\\"CN=24803D75-212C-471A-BC57-9EF86AB91435\\\\5319275A.WHATSAPPDESKTOP\\\\*\\\",0}))))","fqbnLength":"86","ruleName":"5319275A.WhatsAppDesktop, from WhatsApp Inc.","packageLength":"105","ruleId":"{a480952c-a710-4d92-b9a3-2fbff7c12866}","ruleSddlLength":"142","targetUser":"S-1-5-21-887924094-598891991-956377308-1146"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '67020')
        self.assertEqual(response.rule_level, 3)


    def test_applocker_packaged_ui_execution_blocked(self) -> None:
        log = '''{"win":{"system":{"eventID":"8022","keywords":"0x2000000000000000","providerGuid":"{cbda4dbf-8d5d-4f69-9578-be14aa540d22}","level":"2","channel":"Microsoft-Windows-AppLocker/Packaged app-Execution","opcode":"0","message":"\"\\??\\C:\\Program Files\\WindowsApps\\5319275A.WhatsAppDesktop_2.2228.14.0_x64__cv1g1gvanyjgm\\app\\WhatsApp.exe was prevented from running.\"","version":"0","systemTime":"2022-08-16T18:39:16.1843343Z","eventRecordID":"41","threadID":"4120","computer":"hrmanager.ExchangeTest.com","task":"0","processID":"1276","severityValue":"ERROR","providerName":"Microsoft-Windows-AppLocker"},"ruleAndFileData":{"targetProcessId":"5788","package":"\\\\??\\\\C:\\\\Program Files\\\\WindowsApps\\\\5319275A.WhatsAppDesktop_2.2228.14.0_x64__cv1g1gvanyjgm\\\\app\\\\WhatsApp.exe","ruleNameLength":"44","policyName":"Appx","policyNameLength":"4","fqbn":"CN=24803D75-212C-471A-BC57-9EF86AB91435\\\\5319275A.WHATSAPPDESKTOP\\\\WHATSAPP\\\\2.2228.14.00","ruleSddl":"D:(XD;;FX;;;S-1-1-0;((Exists APPID://FQBN) &amp;&amp; ((APPID://FQBN) &gt;= ({\\\"CN=24803D75-212C-471A-BC57-9EF86AB91435\\\\5319275A.WHATSAPPDESKTOP\\\\*\\\",0}))))","fqbnLength":"86","ruleName":"5319275A.WhatsAppDesktop, from WhatsApp Inc.","packageLength":"105","ruleId":"{a480952c-a710-4d92-b9a3-2fbff7c12866}","ruleSddlLength":"142","targetUser":"S-1-5-21-887924094-598891991-956377308-1146"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '67021')
        self.assertEqual(response.rule_level, 3)


    def test_local_logons_without_network_or_service_events(self) -> None:
        log = '''{"win":{"eventdata":{"subjectLogonId":"0x3e7","subjectDomainName":"EXCHANGETEST","targetLinkedLogonId":"0x24cf93a","impersonationLevel":"%%1833","ipAddress":"127.0.0.1","authenticationPackageName":"Negotiate","workstationName":"HRMANAGER","targetLogonId":"0x24cfb29","logonProcessName":"User32","logonGuid":"{00000000-0000-0000-0000-000000000000}","targetUserName":"AtomicRed","keyLength":"0","elevatedToken":"%%1843","subjectUserSid":"S-1-5-18","processId":"0x4fc","processName":"C:\\\\Windows\\\\System32\\\\svchost.exe","ipPort":"0","targetDomainName":"EXCHANGETEST","targetUserSid":"S-1-5-21-887924094-598891991-956377308-1146","virtualAccount":"%%1843","logonType":"11","subjectUserName":"HRMANAGER$"},"system":{"eventID":"4624","keywords":"0x8020000000000000","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","level":"0","channel":"Security","opcode":"0","message":"\"An account was successfully logged on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tHRMANAGER$\r\n\tAccount Domain:\t\tEXCHANGETEST\r\n\tLogon ID:\t\t0x3E7\r\n\r\nLogon Information:\r\n\tLogon Type:\t\t11\r\n\tRestricted Admin Mode:\t-\r\n\tVirtual Account:\t\tNo\r\n\tElevated Token:\t\tNo\r\n\r\nImpersonation Level:\t\tImpersonation\r\n\r\nNew Logon:\r\n\tSecurity ID:\t\tS-1-5-21-887924094-598891991-956377308-1146\r\n\tAccount Name:\t\tAtomicRed\r\n\tAccount Domain:\t\tEXCHANGETEST\r\n\tLogon ID:\t\t0x24CFB29\r\n\tLinked Logon ID:\t\t0x24CF93A\r\n\tNetwork Account Name:\t-\r\n\tNetwork Account Domain:\t-\r\n\tLogon GUID:\t\t{00000000-0000-0000-0000-000000000000}\r\n\r\nProcess Information:\r\n\tProcess ID:\t\t0x4fc\r\n\tProcess Name:\t\tC:\\Windows\\System32\\svchost.exe\r\n\r\nNetwork Information:\r\n\tWorkstation Name:\tHRMANAGER\r\n\tSource Network Address:\t127.0.0.1\r\n\tSource Port:\t\t0\r\n\r\nDetailed Authentication Information:\r\n\tLogon Process:\t\tUser32 \r\n\tAuthentication Package:\tNegotiate\r\n\tTransited Services:\t-\r\n\tPackage Name (NTLM only):\t-\r\n\tKey Length:\t\t0\r\n\r\nThis event is generated when a logon session is created. It is generated on the computer that was accessed.\r\n\r\nThe subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\r\n\r\nThe logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).\r\n\r\nThe New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.\r\n\r\nThe network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\r\n\r\nThe impersonation level field indicates the extent to which a process in the logon session can impersonate.\r\n\r\nThe authentication information fields provide detailed information about this specific logon request.\r\n\t- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.\r\n\t- Transited services indicate which intermediate services have participated in this logon request.\r\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\r\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.\"","version":"2","systemTime":"2022-08-16T19:12:59.3843446Z","eventRecordID":"1430969","threadID":"8232","computer":"hrmanager.ExchangeTest.com","task":"12544","processID":"716","severityValue":"AUDIT_SUCCESS","providerName":"Microsoft-Windows-Security-Auditing"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '67022')
        self.assertEqual(response.rule_level, 3)


    def test_clear_audit_logs(self) -> None:
        log = '''{"win":{"system":{"eventID":"1102","keywords":"0x4020000000000000","providerGuid":"{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}","level":"4","channel":"Security","opcode":"0","message":"\"The audit log was cleared.\r\nSubject:\r\n\tSecurity ID:\tS-1-5-21-887924094-598891991-956377308-1146\r\n\tAccount Name:\tAtomicRed\r\n\tDomain Name:\tEXCHANGETEST\r\n\tLogon ID:\t0x98D819\"","version":"0","systemTime":"2022-08-16T20:21:22.6597339Z","eventRecordID":"1443557","threadID":"7204","computer":"hrmanager.ExchangeTest.com","task":"104","processID":"740","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Eventlog"},"logFileCleared":{"subjectLogonId":"0x98d819","subjectUserSid":"S-1-5-21-887924094-598891991-956377308-1146","subjectDomainName":"EXCHANGETEST","subjectUserName":"AtomicRed"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '63103')
        self.assertEqual(response.rule_level, 5)


    def test_clear_logs(self) -> None:
        log = '''{"win":{"system":{"eventID":"104","keywords":"0x8000000000000000","providerGuid":"{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}","level":"4","channel":"System","opcode":"0","message":"\"The Microsoft-Windows-AppLocker/Packaged app-Execution log file was cleared.\"","version":"0","systemTime":"2022-08-16T19:33:39.4783921Z","eventRecordID":"16408","threadID":"9036","computer":"hrmanager.ExchangeTest.com","task":"104","processID":"740","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Eventlog"},"logFileCleared":{"subjectDomainName":"EXCHANGETEST","channel":"Microsoft-Windows-AppLocker/Packaged app-Execution","subjectUserName":"AtomicRed"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '63104')
        self.assertEqual(response.rule_level, 5)


    def test_user_initiated_logoff(self) -> None:
        log = '''{"win":{"eventdata":{"targetLogonId":"0xa197f3","targetUserName":"AtomicRed","targetDomainName":"EXCHANGETEST","targetUserSid":"S-1-5-21-887924094-598891991-956377308-1146"},"system":{"eventID":"4647","keywords":"0x8020000000000000","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","level":"0","channel":"Security","opcode":"0","message":"\"User initiated logoff:\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-21-887924094-598891991-956377308-1146\r\n\tAccount Name:\t\tAtomicRed\r\n\tAccount Domain:\t\tEXCHANGETEST\r\n\tLogon ID:\t\t0xA197F3\r\n\r\nThis event is generated when a logoff is initiated. No further user-initiated activity can occur. This event can be interpreted as a logoff event.\"","version":"0","systemTime":"2022-08-12T19:52:58.2306502Z","eventRecordID":"1284279","threadID":"6972","computer":"hrmanager.ExchangeTest.com","task":"12545","processID":"672","severityValue":"AUDIT_SUCCESS","providerName":"Microsoft-Windows-Security-Auditing"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '60137')
        self.assertEqual(response.rule_level, 3)


    def test_local_logons_without_network_or_service_events_(self) -> None:
        log = '''{"win":{"eventdata":{"subjectLogonId":"0x3e7","subjectDomainName":"EXCHANGETEST","targetLinkedLogonId":"0x282141f","impersonationLevel":"%%1833","ipAddress":"127.0.0.1","authenticationPackageName":"Negotiate","workstationName":"HRMANAGER","targetLogonId":"0x2821d60","logonProcessName":"User32","logonGuid":"{00000000-0000-0000-0000-000000000000}","targetUserName":"AtomicRed","keyLength":"0","elevatedToken":"%%1843","subjectUserSid":"S-1-5-18","processId":"0x4fc","processName":"C:\\\\Windows\\\\System32\\\\svchost.exe","ipPort":"0","targetDomainName":"EXCHANGETEST","targetUserSid":"S-1-5-21-887924094-598891991-956377308-1146","virtualAccount":"%%1843","logonType":"11","subjectUserName":"HRMANAGER$"},"system":{"eventID":"4624","keywords":"0x8020000000000000","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","level":"0","channel":"Security","opcode":"0","message":"\"An account was successfully logged on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tHRMANAGER$\r\n\tAccount Domain:\t\tEXCHANGETEST\r\n\tLogon ID:\t\t0x3E7\r\n\r\nLogon Information:\r\n\tLogon Type:\t\t11\r\n\tRestricted Admin Mode:\t-\r\n\tVirtual Account:\t\tNo\r\n\tElevated Token:\t\tNo\r\n\r\nImpersonation Level:\t\tImpersonation\r\n\r\nNew Logon:\r\n\tSecurity ID:\t\tS-1-5-21-887924094-598891991-956377308-1146\r\n\tAccount Name:\t\tAtomicRed\r\n\tAccount Domain:\t\tEXCHANGETEST\r\n\tLogon ID:\t\t0x2821D60\r\n\tLinked Logon ID:\t\t0x282141F\r\n\tNetwork Account Name:\t-\r\n\tNetwork Account Domain:\t-\r\n\tLogon GUID:\t\t{00000000-0000-0000-0000-000000000000}\r\n\r\nProcess Information:\r\n\tProcess ID:\t\t0x4fc\r\n\tProcess Name:\t\tC:\\Windows\\System32\\svchost.exe\r\n\r\nNetwork Information:\r\n\tWorkstation Name:\tHRMANAGER\r\n\tSource Network Address:\t127.0.0.1\r\n\tSource Port:\t\t0\r\n\r\nDetailed Authentication Information:\r\n\tLogon Process:\t\tUser32 \r\n\tAuthentication Package:\tNegotiate\r\n\tTransited Services:\t-\r\n\tPackage Name (NTLM only):\t-\r\n\tKey Length:\t\t0\r\n\r\nThis event is generated when a logon session is created. It is generated on the computer that was accessed.\r\n\r\nThe subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\r\n\r\nThe logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).\r\n\r\nThe New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.\r\n\r\nThe network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\r\n\r\nThe impersonation level field indicates the extent to which a process in the logon session can impersonate.\r\n\r\nThe authentication information fields provide detailed information about this specific logon request.\r\n\t- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.\r\n\t- Transited services indicate which intermediate services have participated in this logon request.\r\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\r\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.\"","version":"2","systemTime":"2022-08-16T20:02:37.9423951Z","eventRecordID":"1440430","threadID":"1160","computer":"hrmanager.ExchangeTest.com","task":"12544","processID":"716","severityValue":"AUDIT_SUCCESS","providerName":"Microsoft-Windows-Security-Auditing"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '67022')
        self.assertEqual(response.rule_level, 3)


    def test_user_logoff_for_all_non_network_logon_sessions(self) -> None:
        log = '''{"win":{"eventdata":{"targetLogonId":"0x282141f","targetUserName":"AtomicRed","targetDomainName":"EXCHANGETEST","targetUserSid":"S-1-5-21-887924094-598891991-956377308-1146","logonType":"2"},"system":{"eventID":"4634","keywords":"0x8020000000000000","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","level":"0","channel":"Security","opcode":"0","message":"\"An account was logged off.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-21-887924094-598891991-956377308-1146\r\n\tAccount Name:\t\tAtomicRed\r\n\tAccount Domain:\t\tEXCHANGETEST\r\n\tLogon ID:\t\t0x282141F\r\n\r\nLogon Type:\t\t\t2\r\n\r\nThis event is generated when a logon session is destroyed. It may be positively correlated with a logon event using the Logon ID value. Logon IDs are only unique between reboots on the same computer.\"","version":"0","systemTime":"2022-08-16T20:02:37.9865361Z","eventRecordID":"1440437","threadID":"1160","computer":"hrmanager.ExchangeTest.com","task":"12545","processID":"716","severityValue":"AUDIT_SUCCESS","providerName":"Microsoft-Windows-Security-Auditing"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '67023')
        self.assertEqual(response.rule_level, 3)


    def test_service_logon_events_if_the_user_account_isnt_localsystem_networkservice_localservice(self) -> None:
        log = '''{"win":{"eventdata":{"subjectLogonId":"0x3e7","subjectDomainName":"EXCHANGETEST","targetLinkedLogonId":"0x282141f","impersonationLevel":"%%1833","ipAddress":"127.0.0.1","authenticationPackageName":"Negotiate","workstationName":"HRMANAGER","targetLogonId":"0x2821d60","logonProcessName":"User32","logonGuid":"{00000000-0000-0000-0000-000000000000}","targetUserName":"AtomicRed","keyLength":"0","elevatedToken":"%%1843","subjectUserSid":"S-1-5-18","processId":"0x4fc","processName":"C:\\\\Windows\\\\System32\\\\svchost.exe","ipPort":"0","targetDomainName":"EXCHANGETEST","targetUserSid":"S-1-5-21-887924094-598891991-956377308-1146","virtualAccount":"%%1843","logonType":"5","subjectUserName":"HRMANAGER$"},"system":{"eventID":"4624","keywords":"0x8020000000000000","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","level":"0","channel":"Security","opcode":"0","message":"\"An account was successfully logged on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tHRMANAGER$\r\n\tAccount Domain:\t\tEXCHANGETEST\r\n\tLogon ID:\t\t0x3E7\r\n\r\nLogon Information:\r\n\tLogon Type:\t\t11\r\n\tRestricted Admin Mode:\t-\r\n\tVirtual Account:\t\tNo\r\n\tElevated Token:\t\tNo\r\n\r\nImpersonation Level:\t\tImpersonation\r\n\r\nNew Logon:\r\n\tSecurity ID:\t\tS-1-5-21-887924094-598891991-956377308-1146\r\n\tAccount Name:\t\tAtomicRed\r\n\tAccount Domain:\t\tEXCHANGETEST\r\n\tLogon ID:\t\t0x2821D60\r\n\tLinked Logon ID:\t\t0x282141F\r\n\tNetwork Account Name:\t-\r\n\tNetwork Account Domain:\t-\r\n\tLogon GUID:\t\t{00000000-0000-0000-0000-000000000000}\r\n\r\nProcess Information:\r\n\tProcess ID:\t\t0x4fc\r\n\tProcess Name:\t\tC:\\Windows\\System32\\svchost.exe\r\n\r\nNetwork Information:\r\n\tWorkstation Name:\tHRMANAGER\r\n\tSource Network Address:\t127.0.0.1\r\n\tSource Port:\t\t0\r\n\r\nDetailed Authentication Information:\r\n\tLogon Process:\t\tUser32 \r\n\tAuthentication Package:\tNegotiate\r\n\tTransited Services:\t-\r\n\tPackage Name (NTLM only):\t-\r\n\tKey Length:\t\t0\r\n\r\nThis event is generated when a logon session is created. It is generated on the computer that was accessed.\r\n\r\nThe subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\r\n\r\nThe logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).\r\n\r\nThe New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.\r\n\r\nThe network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\r\n\r\nThe impersonation level field indicates the extent to which a process in the logon session can impersonate.\r\n\r\nThe authentication information fields provide detailed information about this specific logon request.\r\n\t- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.\r\n\t- Transited services indicate which intermediate services have participated in this logon request.\r\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\r\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.\"","version":"2","systemTime":"2022-08-16T20:02:37.9423951Z","eventRecordID":"1440430","threadID":"1160","computer":"hrmanager.ExchangeTest.com","task":"12544","processID":"716","severityValue":"AUDIT_SUCCESS","providerName":"Microsoft-Windows-Security-Auditing"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '67024')
        self.assertEqual(response.rule_level, 3)


    def test_service_logon_events_if_the_user_is_networkservice(self) -> None:
        log = '''{"win":{"eventdata":{"subjectLogonId":"0x3e7","subjectDomainName":"EXCHANGETEST","targetLinkedLogonId":"0x282141f","impersonationLevel":"%%1833","ipAddress":"127.0.0.1","authenticationPackageName":"Negotiate","workstationName":"HRMANAGER","targetLogonId":"0x2821d60","logonProcessName":"User32","logonGuid":"{00000000-0000-0000-0000-000000000000}","targetUserName":"AtomicRed","keyLength":"0","elevatedToken":"%%1843","subjectUserSid":"S-1-5-18","processId":"0x4fc","processName":"C:\\\\Windows\\\\System32\\\\svchost.exe","ipPort":"0","targetDomainName":"EXCHANGETEST","targetUserSid":"S-1-5-19","virtualAccount":"%%1843","logonType":"5","subjectUserName":"HRMANAGER$"},"system":{"eventID":"4624","keywords":"0x8020000000000000","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","level":"0","channel":"Security","opcode":"0","message":"\"An account was successfully logged on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tHRMANAGER$\r\n\tAccount Domain:\t\tEXCHANGETEST\r\n\tLogon ID:\t\t0x3E7\r\n\r\nLogon Information:\r\n\tLogon Type:\t\t11\r\n\tRestricted Admin Mode:\t-\r\n\tVirtual Account:\t\tNo\r\n\tElevated Token:\t\tNo\r\n\r\nImpersonation Level:\t\tImpersonation\r\n\r\nNew Logon:\r\n\tSecurity ID:\t\tS-1-5-21-887924094-598891991-956377308-1146\r\n\tAccount Name:\t\tAtomicRed\r\n\tAccount Domain:\t\tEXCHANGETEST\r\n\tLogon ID:\t\t0x2821D60\r\n\tLinked Logon ID:\t\t0x282141F\r\n\tNetwork Account Name:\t-\r\n\tNetwork Account Domain:\t-\r\n\tLogon GUID:\t\t{00000000-0000-0000-0000-000000000000}\r\n\r\nProcess Information:\r\n\tProcess ID:\t\t0x4fc\r\n\tProcess Name:\t\tC:\\Windows\\System32\\svchost.exe\r\n\r\nNetwork Information:\r\n\tWorkstation Name:\tHRMANAGER\r\n\tSource Network Address:\t127.0.0.1\r\n\tSource Port:\t\t0\r\n\r\nDetailed Authentication Information:\r\n\tLogon Process:\t\tUser32 \r\n\tAuthentication Package:\tNegotiate\r\n\tTransited Services:\t-\r\n\tPackage Name (NTLM only):\t-\r\n\tKey Length:\t\t0\r\n\r\nThis event is generated when a logon session is created. It is generated on the computer that was accessed.\r\n\r\nThe subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\r\n\r\nThe logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).\r\n\r\nThe New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.\r\n\r\nThe network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\r\n\r\nThe impersonation level field indicates the extent to which a process in the logon session can impersonate.\r\n\r\nThe authentication information fields provide detailed information about this specific logon request.\r\n\t- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.\r\n\t- Transited services indicate which intermediate services have participated in this logon request.\r\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\r\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.\"","version":"2","systemTime":"2022-08-16T20:02:37.9423951Z","eventRecordID":"1440430","threadID":"1160","computer":"hrmanager.ExchangeTest.com","task":"12544","processID":"716","severityValue":"AUDIT_SUCCESS","providerName":"Microsoft-Windows-Security-Auditing"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '60106')
        self.assertEqual(response.rule_level, 3)


    def test_network_create_share(self) -> None:
        log = '''{"win":{"eventdata":{"subjectLogonId":"0x3e7","subjectUserSid":"S-1-5-18","subjectDomainName":"EXCHANGETEST","shareLocalPath":"C:\\\\Users\\\\AtomicRed\\\\Documents","shareName":"\\\\\\\\*\\\\Documents","subjectUserName":"HRMANAGER$"},"system":{"eventID":"5142","keywords":"0x8020000000000000","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","level":"0","channel":"Security","opcode":"0","message":"\"A network share object was added.\r\n\t\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tHRMANAGER$\r\n\tAccount Domain:\t\tEXCHANGETEST\r\n\tLogon ID:\t\t0x3E7\r\n\r\nShare Information:\t\r\n\tShare Name:\t\t\\\\*\\Documents\r\n\tShare Path:\t\tC:\\Users\\AtomicRed\\Documents\"","version":"0","systemTime":"2022-08-17T17:24:47.1026768Z","eventRecordID":"1464569","threadID":"2144","computer":"hrmanager.ExchangeTest.com","task":"12808","processID":"4","severityValue":"AUDIT_SUCCESS","providerName":"Microsoft-Windows-Security-Auditing"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '67025')
        self.assertEqual(response.rule_level, 3)


    def test_network_delete_share(self) -> None:
        log = '''{"win":{"eventdata":{"subjectLogonId":"0x3e7","subjectUserSid":"S-1-5-18","subjectDomainName":"EXCHANGETEST","shareLocalPath":"C:\\\\Users\\\\AtomicRed\\\\Documents","shareName":"\\\\\\\\*\\\\Documents","subjectUserName":"HRMANAGER$"},"system":{"eventID":"5144","keywords":"0x8020000000000000","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","level":"0","channel":"Security","opcode":"0","message":"\"A network share object was deleted.\r\n\t\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tHRMANAGER$\r\n\tAccount Domain:\t\tEXCHANGETEST\r\n\tLogon ID:\t\t0x3E7\r\n\r\nShare Information:\t\r\n\tShare Name:\t\t\\\\*\\Documents\r\n\tShare Path:\t\tC:\\Users\\AtomicRed\\Documents\"","version":"0","systemTime":"2022-08-17T17:24:47.1026768Z","eventRecordID":"1464569","threadID":"2144","computer":"hrmanager.ExchangeTest.com","task":"12808","processID":"4","severityValue":"AUDIT_SUCCESS","providerName":"Microsoft-Windows-Security-Auditing"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '67026')
        self.assertEqual(response.rule_level, 3)


    def test_process_create(self) -> None:
        log = '''{"win":{"eventdata":{"subjectLogonId":"0x3e7","parentProcessName":"C:\\\\Windows\\\\System32\\\\svchost.exe","subjectDomainName":"EXCHANGETEST","tokenElevationType":"%%1938","newProcessId":"0x1b50","mandatoryLabel":"S-1-16-8192","newProcessName":"C:\\\\Windows\\\\System32\\\\dllhost.exe","targetLogonId":"0x2749b2","targetUserName":"AtomicRed","subjectUserSid":"S-1-5-18","processId":"0x32c","targetDomainName":"EXCHANGETEST","targetUserSid":"S-1-5-21-887924094-598891991-956377308-1146","subjectUserName":"HRMANAGER$"},"system":{"eventID":"4688","keywords":"0x8020000000000000","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","level":"0","channel":"Security","opcode":"0","message":"\"A new process has been created.\r\n\r\nCreator Subject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tHRMANAGER$\r\n\tAccount Domain:\t\tEXCHANGETEST\r\n\tLogon ID:\t\t0x3E7\r\n\r\nTarget Subject:\r\n\tSecurity ID:\t\tS-1-5-21-887924094-598891991-956377308-1146\r\n\tAccount Name:\t\tAtomicRed\r\n\tAccount Domain:\t\tEXCHANGETEST\r\n\tLogon ID:\t\t0x2749B2\r\n\r\nProcess Information:\r\n\tNew Process ID:\t\t0x1b50\r\n\tNew Process Name:\tC:\\Windows\\System32\\dllhost.exe\r\n\tToken Elevation Type:\t%%1938\r\n\tMandatory Label:\t\tS-1-16-8192\r\n\tCreator Process ID:\t0x32c\r\n\tCreator Process Name:\tC:\\Windows\\System32\\svchost.exe\r\n\tProcess Command Line:\t\r\n\r\nToken Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy.\r\n\r\nType 1 is a full token with no privileges removed or groups disabled.  A full token is only used if User Account Control is disabled or if the user is the built-in Administrator account or a service account.\r\n\r\nType 2 is an elevated token with no privileges removed or groups disabled.  An elevated token is used when User Account Control is enabled and the user chooses to start the program using Run as administrator.  An elevated token is also used when an application is configured to always require administrative privilege or to always require maximum privilege, and the user is a member of the Administrators group.\r\n\r\nType 3 is a limited token with administrative privileges removed and administrative groups disabled.  The limited token is used when User Account Control is enabled, the application does not require administrative privilege, and the user does not choose to start the program using Run as administrator.\"","version":"2","systemTime":"2022-08-17T17:51:34.4951868Z","eventRecordID":"1483720","threadID":"2012","computer":"hrmanager.ExchangeTest.com","task":"13312","processID":"4","severityValue":"AUDIT_SUCCESS","providerName":"Microsoft-Windows-Security-Auditing"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '67027')
        self.assertEqual(response.rule_level, 3)


    def test_special_privileges_admin_equivalent_access_assigned_to_new_logon_excluding_localsystem(self) -> None:
        log = '''{"win":{"eventdata":{"subjectLogonId":"0x274983","subjectUserSid":"S-1-5-21-887924094-598891991-956377308-1146","subjectDomainName":"EXCHANGETEST","privilegeList":"SeSecurityPrivilege     SeTakeOwnershipPrivilege     SeLoadDriverPrivilege     SeBackupPrivilege     SeRestorePrivilege     SeDebugPrivilege     SeSystemEnvironmentPrivilege     SeImpersonatePrivilege     SeDelegateSessionUserImpersonatePrivilege","subjectUserName":"AtomicRed"},"system":{"eventID":"4672","keywords":"0x8020000000000000","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","level":"0","channel":"Security","opcode":"0","message":"\"Special privileges assigned to new logon.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-21-887924094-598891991-956377308-1146\r\n\tAccount Name:\t\tAtomicRed\r\n\tAccount Domain:\t\tEXCHANGETEST\r\n\tLogon ID:\t\t0x274983\r\n\r\nPrivileges:\t\tSeSecurityPrivilege\r\n\t\t\tSeTakeOwnershipPrivilege\r\n\t\t\tSeLoadDriverPrivilege\r\n\t\t\tSeBackupPrivilege\r\n\t\t\tSeRestorePrivilege\r\n\t\t\tSeDebugPrivilege\r\n\t\t\tSeSystemEnvironmentPrivilege\r\n\t\t\tSeImpersonatePrivilege\r\n\t\t\tSeDelegateSessionUserImpersonatePrivilege\"","version":"0","systemTime":"2022-08-17T17:31:21.6380750Z","eventRecordID":"1471357","threadID":"756","computer":"hrmanager.ExchangeTest.com","task":"12548","processID":"704","severityValue":"AUDIT_SUCCESS","providerName":"Microsoft-Windows-Security-Auditing"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '67028')
        self.assertEqual(response.rule_level, 3)


    def test_log_attempted_ts_connect_to_remote_serverm(self) -> None:
        log = '''{"win":{"eventdata":{"name":"Server Name","customLevel":"Info","value":"192.168.0.115"},"system":{"eventID":"1024","keywords":"0x4000000000000000","providerGuid":"{28aa95bb-d444-4719-a36f-40462168127e}","level":"4","channel":"Microsoft-Windows-TerminalServices-RDPClient/Operational","opcode":"10","message":"\"RDP ClientActiveX is trying to connect to the server (192.168.0.115)\"","version":"0","systemTime":"2022-08-17T21:39:01.1874960Z","eventRecordID":"8","threadID":"3772","computer":"hrmanager.ExchangeTest.com","task":"101","processID":"4508","severityValue":"INFORMATION","providerName":"Microsoft-Windows-TerminalServices-ClientActiveXCore"}}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '67029')
        self.assertEqual(response.rule_level, 3)

