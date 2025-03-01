#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from mcafee_epo.ini
class TestMcafeeEpoRules(unittest.TestCase):

    def test_mcafee_epo(self) -> None:
        log = r'''
2019-07-03T13:49:44.0Z RH1WVEPO1 EPOEvents - EventFwd [agentInfo@3401 tenantId="1" bpsId="1" tenantGUID="{00000000-0000-0000-0000-000000000000}" tenantNodePath="1\2"] ﻿<?xml version="1.0"encoding="UTF-8"?><EPOevent><MachineInfo><MachineName>WAW-URSZULAL1</MachineName><AgentGUID>{11f929ca-65ce-11e9-2e63-34e6d73c4809}</AgentGUID><IPAddress>10.150.10.237</IPAddress><OSName>Windows 10 Workstation</OSName><UserName>SYSTEM</UserName><TimeZoneBias>-120</TimeZoneBias><RawMACAddress>34e6d73c4809</RawMACAddress></MachineInfo><SoftwareInfo ProductName="McAfee Endpoint Security" ProductVersion="10.6.1.1128" ProductFamily="TVD"><CommonFields><Analyzer>ENDP_AM_1060</Analyzer><AnalyzerName>McAfee Endpoint Security</AnalyzerName><AnalyzerVersion>10.6.1.1128</AnalyzerVersion><AnalyzerHostName>WAW-URSZULAL1</AnalyzerHostName><AnalyzerDetectionMethod>Self Protection</AnalyzerDetectionMethod></CommonFields><Event><EventID>1092</EventID><Severity>0</Severity><GMTTime>2019-07-03T13:42:03</GMTTime><CommonFields><ThreatCategory>hip.registry</ThreatCategory><ThreatEventID>1092</ThreatEventID><ThreatName>Threat Prevention - Protect McAfee core registry keys and values</ThreatName><ThreatType>IDS_THREAT_TYPE_VALUE_SP</ThreatType><DetectedUTC>2019-07-03T13:42:03</DetectedUTC><ThreatActionTaken>blocked</ThreatActionTaken><ThreatHandled>True</ThreatHandled><SourceUserName>VERIFONE\UrszulaL1</SourceUserName><SourceProcessName>IEXPLORE.EXE</SourceProcessName><TargetHostName>WAW-URSZULAL1</TargetHostName><TargetUserName>SYSTEM</TargetUserName><TargetFileName>HKCU\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXT\SETTINGS\{7DB2D5A0-7241-4E79-B68D-6309F01C5231}\</TargetFileName><ThreatSeverity>6</ThreatSeverity></CommonFields><CustomFields target="EPExtendedEventMT"><BladeName>IDS_BLADE_NAME_SPB</BladeName><AnalyzerContentVersion>10.6.0000</AnalyzerContentVersion><AnalyzerContentCreationDate>2016-02-17T10:02:00Z</AnalyzerContentCreationDate><AnalyzerRuleName>IDS_SP_TP_RULE_PROTECT_MCAFEE_REG_KEY_VAL</AnalyzerRuleName><SourceProcessHash>c6e2e43dc922be346dbe3636d8711d5b</SourceProcessHash><SourceProcessSigned>True</SourceProcessSigned><SourceProcessSigner>C=US, S=WASHINGTON, L=REDMOND, O=MICROSOFT CORPORATION, OU=MOPR, CN=MICROSOFT CORPORATION</SourceProcessSigner><SourceProcessTrusted>True</SourceProcessTrusted><SourceFilePath>C:\PROGRAM FILES\INTERNET EXPLORER</SourceFilePath><SourceFileSize>824584</SourceFileSize><SourceModifyTime>2018-03-30  06:50:19</SourceModifyTime><SourceAccessTime>2019-04-24  09:09:52</SourceAccessTime><SourceCreateTime>2019-04-24  09:09:52</SourceCreateTime><TargetName> </TargetName><TargetPath>HKCU\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXT\SETTINGS\{7DB2D5A0-7241-4E79-B68D-6309F01C5231}\</TargetPath><TargetSigned>False</TargetSigned><TargetTrusted>False</TargetTrusted><AttackVectorType>4</AttackVectorType><DurationBeforeDetection>6071531</DurationBeforeDetection><NaturalLangDescription>IDS_NATURAL_LANG_DESC_DETECTION_APSP_1|TargetPath=HKCU\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXT\SETTINGS\{7DB2D5A0-7241-4E79-B68D-6309F01C5231}\|AnalyzerRuleName=IDS_SP_TP_RULE_PROTECT_MCAFEE_REG_KEY_VAL|SourceProcessName=IEXPLORE.EXE|SourceUserName=VERIFONE\UrszulaL1</NaturalLangDescription><AccessRequested>IDS_AAC_REQ_CREATE</AccessRequested></CustomFields></Event></SoftwareInfo></EPOevent>
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'mcafee-epo2')
        self.assertEqual(response.rule_id, '65501')
        self.assertEqual(response.rule_level, 3)

