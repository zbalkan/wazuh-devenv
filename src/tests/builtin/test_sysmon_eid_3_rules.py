#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from sysmon_eid_3.ini
class TestSysmonEid3Rules(unittest.TestCase):

    def test_powershell_process_communicating_over_tcp(self) -> None:
        log = r'''
{"win":{"eventdata":{"destinationPort":"8080","image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","sourcePort":"50152","initiated":"true","destinationIp":"192.168.0.4","protocol":"tcp","processGuid":"{4dc16835-e854-6116-9224-950000000000}","sourceIp":"192.168.0.121","processId":"5888","utcTime":"2021-08-13 21:47:01.587","ruleName":"technique_id=T1059.001,technique_name=PowerShell","destinationIsIpv6":"false","user":"EXCHANGETEST\\\\AtomicRed","sourceIsIpv6":"false"},"system":{"eventID":"3","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Network connection detected:\r\nRuleName: technique_id=T1059.001,technique_name=PowerShell\r\nUtcTime: 2021-08-13 21:47:01.587\r\nProcessGuid: {4dc16835-e854-6116-9224-950000000000}\r\nProcessId: 5888\r\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nUser: EXCHANGETEST\\AtomicRed\r\nProtocol: tcp\r\nInitiated: true\r\nSourceIsIpv6: false\r\nSourceIp: 192.168.0.121\r\nSourceHostname: -\r\nSourcePort: 50152\r\nSourcePortName: -\r\nDestinationIsIpv6: false\r\nDestinationIp: 192.168.0.4\r\nDestinationHostname: -\r\nDestinationPort: 8080\r\nDestinationPortName: -\"","version":"5","systemTime":"2021-08-13T21:47:02.6323067Z","eventRecordID":"346207","threadID":"3316","computer":"hrmanager.ExchangeTest.com","task":"3","processID":"2668","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92101')
        self.assertEqual(response.rule_level, 0)


    def test_dcom_rpc_activity_from_powershell_process(self) -> None:
        log = r'''
{"win":{"eventdata":{"destinationPort":"135","image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","sourcePort":"49815","initiated":"true","destinationIp":"192.168.0.57","protocol":"tcp","processGuid":"{4dc16835-60aa-6094-3701-000000003800}","sourceIp":"192.168.0.121","processId":"1852","utcTime":"2021-05-06 21:35:16.032","ruleName":"technique_id=T1059.001,technique_name=PowerShell","destinationIsIpv6":"false","user":"EXCHANGETEST\\\\Administrator","sourceIsIpv6":"false"},"system":{"eventID":"3","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Network connection detected:\r\nRuleName: technique_id=T1059.001,technique_name=PowerShell\r\nUtcTime: 2021-05-06 21:35:16.032\r\nProcessGuid: {4dc16835-60aa-6094-3701-000000003800}\r\nProcessId: 1852\r\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nUser: EXCHANGETEST\\Administrator\r\nProtocol: tcp\r\nInitiated: true\r\nSourceIsIpv6: false\r\nSourceIp: 192.168.0.121\r\nSourceHostname: -\r\nSourcePort: 49815\r\nSourcePortName: -\r\nDestinationIsIpv6: false\r\nDestinationIp: 192.168.0.57\r\nDestinationHostname: -\r\nDestinationPort: 135\r\nDestinationPortName: -\"","version":"5","systemTime":"2021-05-06T21:35:17.0534150Z","eventRecordID":"185918","threadID":"2944","computer":"hrmanager.ExchangeTest.com","task":"3","processID":"2140","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92102')
        self.assertEqual(response.rule_level, 6)


    def test_ldap_activity_from_powershell_process(self) -> None:
        log = r'''
{"win":{"eventdata":{"destinationPort":"389","image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","sourcePort":"56704","initiated":"true","destinationIp":"192.168.0.57","protocol":"tcp","processGuid":"{4dc16835-5bcf-6091-b801-000000003500}","sourceIp":"192.168.0.121","processId":"5912","utcTime":"2021-05-04 15:04:59.139","ruleName":"technique_id=T1059.001,technique_name=PowerShell","destinationIsIpv6":"false","user":"EXCHANGETEST\\\\AtomicRed","sourceIsIpv6":"false"},"system":{"eventID":"3","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Network connection detected:\r\nRuleName: technique_id=T1059.001,technique_name=PowerShell\r\nUtcTime: 2021-05-04 15:04:59.139\r\nProcessGuid: {4dc16835-5bcf-6091-b801-000000003500}\r\nProcessId: 5912\r\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nUser: EXCHANGETEST\\AtomicRed\r\nProtocol: tcp\r\nInitiated: true\r\nSourceIsIpv6: false\r\nSourceIp: 192.168.0.121\r\nSourceHostname: -\r\nSourcePort: 56704\r\nSourcePortName: -\r\nDestinationIsIpv6: false\r\nDestinationIp: 192.168.0.57\r\nDestinationHostname: -\r\nDestinationPort: 389\r\nDestinationPortName: -\"","version":"5","systemTime":"2021-05-04T15:05:00.3201980Z","eventRecordID":"169292","threadID":"3052","computer":"hrmanager.ExchangeTest.com","task":"3","processID":"2432","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92103')
        self.assertEqual(response.rule_level, 6)


    def test_possible_suspicious_access_to_windows_admin_shares(self) -> None:
        log = r'''
{ "win": { "eventdata": { "destinationPort": "135", "image": "C:\\\\Users\\\\itadmin\\\\AppData\\\\Local\\\\paexec.exe", "sourcePort": "49610", "initiated": "true", "destinationIp": "172.20.10.12", "protocol": "tcp", "processGuid": "{94f48244-7eff-6164-5203-000000001b00}", "sourceIp": "172.20.10.9", "processId": "1672", "utcTime": "2021-10-11 17:44:24.000", "ruleName": "technique_id=T1036,technique_name=Masquerading", "destinationIsIpv6": "false", "user": "XRISBARNEY\\\\itadmin", "sourceIsIpv6": "false" }, "system": { "eventID": "3", "keywords": "0x8000000000000000", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "level": "4", "channel": "Microsoft-Windows-Sysmon/Operational", "opcode": "0", "message": "\"Network connection detected:\r\nRuleName: technique_id=T1036,technique_name=Masquerading\r\nUtcTime: 2021-10-11 17:44:24.000\r\nProcessGuid: {94f48244-7eff-6164-5203-000000001b00}\r\nProcessId: 1672\r\nImage: C:\\Users\\itadmin\\AppData\\Local\\paexec.exe\r\nUser: XRISBARNEY\\itadmin\r\nProtocol: tcp\r\nInitiated: true\r\nSourceIsIpv6: false\r\nSourceIp: 172.20.10.9\r\nSourceHostname: -\r\nSourcePort: 49610\r\nSourcePortName: -\r\nDestinationIsIpv6: false\r\nDestinationIp: 172.20.10.12\r\nDestinationHostname: -\r\nDestinationPort: 135\r\nDestinationPortName: -\"", "version": "5", "systemTime": "2021-10-11T18:14:25.9773023Z", "eventRecordID": "325975", "threadID": "3616", "computer": "hotelmanager.xrisbarney.local", "task": "3", "processID": "2456", "severityValue": "INFORMATION", "providerName": "Microsoft-Windows-Sysmon" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92105')
        self.assertEqual(response.rule_level, 3)


    def test_windows_system_process_activity_over_smb_port(self) -> None:
        log = r'''
{"win":{"eventdata":{"destinationPort":"445","image":"System","sourcePort":"51970","initiated":"false","destinationIp":"192.168.0.57","protocol":"tcp","processGuid":"{86107A5D-0B6A-60D6-EB03-000000000000}","sourceIp":"192.168.0.218","processId":"4","utcTime":"2021-06-25 18:34:36.226","destinationPortName":"microsoft-ds","ruleName":"technique_id=T1021.002,technique_name=Remote Services: SMB/Windows Admin Shares","destinationIsIpv6":"false","user":"NT AUTHORITY\\\\SYSTEM","sourceIsIpv6":"false"},"system":{"eventID":"3","keywords":"0x8000000000000000","providerGuid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Network connection detected:\r\nRuleName: technique_id=T1021.002,technique_name=Remote Services: SMB/Windows Admin Shares\r\nUtcTime: 2021-06-25 18:34:36.226\r\nProcessGuid: {86107A5D-0B6A-60D6-EB03-000000000000}\r\nProcessId: 4\r\nImage: System\r\nUser: NT AUTHORITY\\SYSTEM\r\nProtocol: tcp\r\nInitiated: false\r\nSourceIsIpv6: false\r\nSourceIp: 192.168.0.218\r\nSourceHostname: -\r\nSourcePort: 51970\r\nSourcePortName: -\r\nDestinationIsIpv6: false\r\nDestinationIp: 192.168.0.57\r\nDestinationHostname: -\r\nDestinationPort: 445\r\nDestinationPortName: microsoft-ds\"","version":"5","systemTime":"2021-06-25T18:34:37.376008800Z","eventRecordID":"658731","threadID":"3792","computer":"bankdc.ExchangeTest.com","task":"3","processID":"2620","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92106')
        self.assertEqual(response.rule_level, 3)


    def test_script_generated_suspicious_network_activity_over_tcp_protocol(self) -> None:
        log = r'''
{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"3","version":"5","level":"4","task":"3","opcode":"0","keywords":"0x8000000000000000","systemTime":"2021-04-28T20:12:51.1096098Z","eventRecordID":"144535","processID":"2204","threadID":"2944","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-2QKFOBA","severityValue":"INFORMATION","message":"\"Network connection detected:\r\nRuleName: technique_id=T1202,technique_name=Indirect Command Execution\r\nUtcTime: 2021-04-28 20:12:52.061\r\nProcessGuid: {4dc16835-c18b-6089-a503-000000002e00}\r\nProcessId: 2488\r\nImage: C:\\Windows\\System32\\wscript.exe\r\nUser: DESKTOP-2QKFOBA\\AtomicRedTeamTest\r\nProtocol: tcp\r\nInitiated: true\r\nSourceIsIpv6: false\r\nSourceIp: 192.168.0.121\r\nSourceHostname: -\r\nSourcePort: 52094\r\nSourcePortName: -\r\nDestinationIsIpv6: false\r\nDestinationIp: 192.168.0.4\r\nDestinationHostname: -\r\nDestinationPort: 443\r\nDestinationPortName: -\""},"eventdata":{"ruleName":"technique_id=T1202,technique_name=Indirect Command Execution","utcTime":"2021-04-28 20:12:52.061","processGuid":"{4dc16835-c18b-6089-a503-000000002e00}","processId":"2488","image":"C:\\\\Windows\\\\System32\\\\wscript.exe","user":"DESKTOP-2QKFOBA\\\\AtomicRedTeamTest","protocol":"tcp","initiated":"true","sourceIsIpv6":"false","sourceIp":"192.168.0.121","sourcePort":"52094","destinationIsIpv6":"false","destinationIp":"192.168.0.4","destinationPort":"443"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92107')
        self.assertEqual(response.rule_level, 4)


    def test_rdp_port_network_activity(self) -> None:
        log = r'''
{"win":{"eventdata":{"destinationPort":"3389","image":"C:\\\\Windows\\\\System32\\\\svchost.exe","sourcePort":"54642","initiated":"false","destinationIp":"192.168.0.121","protocol":"tcp","processGuid":"{4dc16835-fe80-60ee-d322-300000000000}","sourceIp":"192.168.0.57","processId":"5836","utcTime":"2021-07-14 15:44:40.699","ruleName":"technique_id=T1021,technique_name=Remote Services","destinationIsIpv6":"false","user":"NT AUTHORITY\\\\NETWORK SERVICE","sourceIsIpv6":"false"},"system":{"eventID":"3","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Network connection detected:\r\nRuleName: technique_id=T1021,technique_name=Remote Services\r\nUtcTime: 2021-07-14 15:44:40.699\r\nProcessGuid: {4dc16835-fe80-60ee-d322-300000000000}\r\nProcessId: 5836\r\nImage: C:\\Windows\\System32\\svchost.exe\r\nUser: NT AUTHORITY\\NETWORK SERVICE\r\nProtocol: tcp\r\nInitiated: false\r\nSourceIsIpv6: false\r\nSourceIp: 192.168.0.57\r\nSourceHostname: -\r\nSourcePort: 54642\r\nSourcePortName: -\r\nDestinationIsIpv6: false\r\nDestinationIp: 192.168.0.121\r\nDestinationHostname: -\r\nDestinationPort: 3389\r\nDestinationPortName: -\"","version":"5","systemTime":"2021-07-14T15:44:42.0974780Z","eventRecordID":"271706","threadID":"3068","computer":"hrmanager.ExchangeTest.com","task":"3","processID":"2112","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92108')
        self.assertEqual(response.rule_level, 0)


    def test_loopback_ip_rdp_port_network_activity(self) -> None:
        log = r'''
{"win":{"eventdata":{"destinationPort":"3389","image":"C:\\\\Windows\\\\System32\\\\svchost.exe","sourcePort":"25387","initiated":"false","destinationIp":"0:0:0:0:0:0:0:1","protocol":"tcp","processGuid":"{86107A5D-6C0C-60DF-04DD-600100000000}","sourceIp":"0:0:0:0:0:0:0:1","processId":"7728","sourceHostname":"bankdc.ExchangeTest.com","utcTime":"2021-07-02 20:19:28.870","destinationPortName":"ms-wbt-server","ruleName":"technique_id=T1021,technique_name=Remote Services","destinationIsIpv6":"true","user":"NT AUTHORITY\\\\NETWORK SERVICE","destinationHostname":"bankdc.ExchangeTest.com","sourceIsIpv6":"true"},"system":{"eventID":"3","keywords":"0x8000000000000000","providerGuid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Network connection detected:\r\nRuleName: technique_id=T1021,technique_name=Remote Services\r\nUtcTime: 2021-07-02 20:19:28.870\r\nProcessGuid: {86107A5D-6C0C-60DF-04DD-600100000000}\r\nProcessId: 7728\r\nImage: C:\\Windows\\System32\\svchost.exe\r\nUser: NT AUTHORITY\\NETWORK SERVICE\r\nProtocol: tcp\r\nInitiated: false\r\nSourceIsIpv6: true\r\nSourceIp: 0:0:0:0:0:0:0:1\r\nSourceHostname: bankdc.ExchangeTest.com\r\nSourcePort: 25387\r\nSourcePortName: -\r\nDestinationIsIpv6: true\r\nDestinationIp: 0:0:0:0:0:0:0:1\r\nDestinationHostname: bankdc.ExchangeTest.com\r\nDestinationPort: 3389\r\nDestinationPortName: ms-wbt-server\"","version":"5","systemTime":"2021-07-02T20:19:29.969938200Z","eventRecordID":"1122514","threadID":"3504","computer":"bankdc.ExchangeTest.com","task":"3","processID":"2528","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92109')
        self.assertEqual(response.rule_level, 15)


    def test_left_to_right_override_binary_does_network_connection(self) -> None:
        log = r'''
{"win":{"eventdata":{"destinationPort":"1234","image":"C:\\\\Users\\\\AtomicRed\\\\Downloads\\\\cod.3aka3.scr2\\\\cod.scr\\\\‭‭‮cod.abaf.scr","sourcePort":"57275","initiated":"true","destinationIp":"192.168.0.4","protocol":"tcp","processGuid":"{4dc16835-c80d-6171-29c3-300100000000}","sourceIp":"192.168.0.121","processId":"7100","utcTime":"2021-10-21 20:05:36.768","ruleName":"technique_id=T1036,technique_name=Masquerading","destinationIsIpv6":"false","user":"EXCHANGETEST\\\\AtomicRed","sourceIsIpv6":"false"},"system":{"eventID":"3","keywords":"0x8000000000000000","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","level":"4","channel":"Microsoft-Windows-Sysmon/Operational","opcode":"0","message":"\"Network connection detected:\r\nRuleName: technique_id=T1036,technique_name=Masquerading\r\nUtcTime: 2021-10-21 20:05:36.768\r\nProcessGuid: {4dc16835-c80d-6171-29c3-300100000000}\r\nProcessId: 7100\r\nImage: C:\\Users\\AtomicRed\\Downloads\\cod.3aka3.scr2\\cod.scr\\‭‭‮cod.abaf.scr\r\nUser: EXCHANGETEST\\AtomicRed\r\nProtocol: tcp\r\nInitiated: true\r\nSourceIsIpv6: false\r\nSourceIp: 192.168.0.121\r\nSourceHostname: -\r\nSourcePort: 57275\r\nSourcePortName: -\r\nDestinationIsIpv6: false\r\nDestinationIp: 192.168.0.4\r\nDestinationHostname: -\r\nDestinationPort: 1234\r\nDestinationPortName: -\"","version":"5","systemTime":"2021-10-21T20:05:37.9825478Z","eventRecordID":"397063","threadID":"3712","computer":"hrmanager.ExchangeTest.com","task":"3","processID":"2296","severityValue":"INFORMATION","providerName":"Microsoft-Windows-Sysmon"}}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92104')
        self.assertEqual(response.rule_level, 15)


    def test_detected_winrm_activity(self) -> None:
        log = r'''
{ "win": { "eventdata": { "destinationPort": "5985", "image": "&lt;unknown process&gt;", "sourcePort": "58411", "initiated": "false", "destinationIp": "192.168.0.101", "protocol": "tcp", "processGuid": "{4ead7fc4-b197-6182-eb03-000000000000}", "sourceIp": "192.168.0.107", "processId": "4", "utcTime": "2021-11-03 12:28:20.757", "ruleName": "technique_id=T1021.006,technique_name=Windows Remote Management", "destinationIsIpv6": "false", "sourceIsIpv6": "false" }, "system": { "eventID": "3", "keywords": "0x8000000000000000", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "level": "4", "channel": "Microsoft-Windows-Sysmon/Operational", "opcode": "0", "message": "\"Network connection detected:\r\nRuleName: technique_id=T1021.006,technique_name=Windows Remote Management\r\nUtcTime: 2021-11-03 12:28:20.757\r\nProcessGuid: {4ead7fc4-b197-6182-eb03-000000000000}\r\nProcessId: 4\r\nImage: <unknown process>\r\nUser: -\r\nProtocol: tcp\r\nInitiated: false\r\nSourceIsIpv6: false\r\nSourceIp: 192.168.0.107\r\nSourceHostname: -\r\nSourcePort: 58411\r\nSourcePortName: -\r\nDestinationIsIpv6: false\r\nDestinationIp: 192.168.0.101\r\nDestinationHostname: -\r\nDestinationPort: 5985\r\nDestinationPortName: -\"", "version": "5", "systemTime": "2021-11-03T12:28:20.286619200Z", "eventRecordID": "148171", "threadID": "248", "computer": "hoteldc.xrisbarney.local", "task": "3", "processID": "2376", "severityValue": "INFORMATION", "providerName": "Microsoft-Windows-Sysmon" } } }
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92110')
        self.assertEqual(response.rule_level, 4)

