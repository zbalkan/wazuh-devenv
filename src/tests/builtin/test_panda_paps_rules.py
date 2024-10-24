#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from panda_paps.ini
class TestPanda_papsRules(unittest.TestCase):

    def test_panda_paps_alert_message_received(self) -> None:
        log = '''LEEF:1.0|Panda Security|paps|02.47.00.0000|registrym|sev=1	devTime=2019-05-09 22:03:58.692466	devTimeFormat=yyyy-MM-dd HH:mm:ss.SSS	usrName=SYSTEM	domain=NT AUTHORITY	src=192.168.0.8	identSrc=192.168.0.8	identHostName=13_2595_43	HostName=13_2595_43	MUID=6C6A0D57714FE5B6D72BA0EC0E46D71B	Op=ModifyExeKey	Hash=E60A27AAEB184AABD9C92C513B27F98A	DriveType=Fixed	Path=PROGRAM_FILES_COMMONX86|\Quest\Privilege Manager\Client\CSEHost.exe	ValidSig=true	Company=Quest Software Inc.	Broken=false	ImageType=EXE 32	ExeType=Unknown	Prevalence=Medium	PrevLastDay=Low	Cat=Goodware	MWName=	TargetPath=3|PROGRAM_FILES_COMMONX86|\Quest\Privilege Manager\Client\GPEEventMsgFile.dll	RegKey=\REGISTRY\MACHINE\SYSTEM\ControlSet001\services\eventlog\Application\GPE Alert?EventMessageFile'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'paps')
        self.assertEqual(response.rule_id, '64201')
        self.assertEqual(response.rule_level, 7)


    def test_panda_paps_low_severity_event_detected(self) -> None:
        log = '''LEEF:1.0|Panda Security|paps|02.47.00.0000|registrym|sev=3	devTime=2019-05-09 22:01:23.255825	devTimeFormat=yyyy-MM-dd HH:mm:ss.SSS	usrName=SYSTEM	domain=NT AUTHORITY	src=10.255.44.11	identSrc=10.255.44.11	identHostName=44_CCO_11	HostName=44_CCO_11	MUID=D877F2C4C4000A9BF39F1710CA787291	Op=ModifyExeKey	Hash=F6494E7C35B6514A3AD74E27435F3141	DriveType=Fixed	Path=PROGRAM_FILESX86|\LANDesk\LDClient\hips\LDSecSvc64.EXE	ValidSig=true	Company=LANDESK Software, Inc. and its affiliates.	Broken=false	ImageType=EXE 64	ExeType=Unknown	Prevalence=Low	PrevLastDay=Low	Cat=Goodware	MWName=	TargetPath=3|PROGRAM_FILESX86|\LANDesk\LDClient\LDdrives.exe'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'paps')
        self.assertEqual(response.rule_id, '64202')
        self.assertEqual(response.rule_level, 4)


    def test_panda_paps_medium_severity_event_detected(self) -> None:
        log = '''LEEF:1.0|Panda Security|paps|02.47.00.0000|registrym|sev=5	devTime=2019-05-09 22:01:23.255825	devTimeFormat=yyyy-MM-dd HH:mm:ss.SSS	usrName=SYSTEM	domain=NT AUTHORITY	src=10.255.44.11	identSrc=10.255.44.11	identHostName=44_CCO_11	HostName=44_CCO_11	MUID=D877F2C4C4000A9BF39F1710CA787291	Op=ModifyExeKey	Hash=F6494E7C35B6514A3AD74E27435F3141	DriveType=Fixed	Path=PROGRAM_FILESX86|\LANDesk\LDClient\hips\LDSecSvc64.EXE	ValidSig=true	Company=LANDESK Software, Inc. and its affiliates.	Broken=false	ImageType=EXE 64	ExeType=Unknown	Prevalence=Low	PrevLastDay=Low	Cat=Goodware	MWName=	TargetPath=3|PROGRAM_FILESX86|\LANDesk\LDClient\LDdrives.exe'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'paps')
        self.assertEqual(response.rule_id, '64203')
        self.assertEqual(response.rule_level, 4)


    def test_panda_paps_high_severity_event_detected(self) -> None:
        log = '''LEEF:1.0|Panda Security|paps|02.47.00.0000|registrym|sev=7	devTime=2019-05-09 22:01:23.255825	devTimeFormat=yyyy-MM-dd HH:mm:ss.SSS	usrName=SYSTEM	domain=NT AUTHORITY	src=10.255.44.11	identSrc=10.255.44.11	identHostName=44_CCO_11	HostName=44_CCO_11	MUID=D877F2C4C4000A9BF39F1710CA787291	Op=ModifyExeKey	Hash=F6494E7C35B6514A3AD74E27435F3141	DriveType=Fixed	Path=PROGRAM_FILESX86|\LANDesk\LDClient\hips\LDSecSvc64.EXE	ValidSig=true	Company=LANDESK Software, Inc. and its affiliates.	Broken=true	ImageType=EXE 64	ExeType=Unknown	Prevalence=Low	PrevLastDay=Low	Cat=Goodware	MWName=	TargetPath=3|PROGRAM_FILESX86|\LANDesk\LDClient\LDdrives.exe'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'paps')
        self.assertEqual(response.rule_id, '64204')
        self.assertEqual(response.rule_level, 12)


    def test_panda_paps_very_high_severity_event_detected(self) -> None:
        log = '''LEEF:1.0|Panda Security|paps|02.47.00.0000|registrym|sev=9	devTime=2019-05-09 22:01:23.255825	devTimeFormat=yyyy-MM-dd HH:mm:ss.SSS	usrName=SYSTEM	domain=NT AUTHORITY	src=10.255.44.11	identSrc=10.255.44.11	identHostName=44_CCO_11	HostName=44_CCO_11	MUID=D877F2C4C4000A9BF39F1710CA787291	Op=ModifyExeKey	Hash=F6494E7C35B6514A3AD74E27435F3141	DriveType=Fixed	Path=PROGRAM_FILESX86|\LANDesk\LDClient\hips\LDSecSvc64.EXE	ValidSig=true	Company=LANDESK Software, Inc. and its affiliates.	Broken=true	ImageType=EXE 64	ExeType=Unknown	Prevalence=Low	PrevLastDay=Low	Cat=Goodware	MWName=	TargetPath=3|PROGRAM_FILESX86|\LANDesk\LDClient\LDdrives.exe'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'paps')
        self.assertEqual(response.rule_id, '64205')
        self.assertEqual(response.rule_level, 14)


    def test_panda_paps_the_child_process_is_corrupted_or_defective(self) -> None:
        log = '''LEEF:1.0|Panda Security|paps|02.47.00.0000|exec|sev=1	devTime=2019-05-09 22:07:36.130735	devTimeFormat=yyyy-MM-dd HH:mm:ss.SSS	usrName=hsmartin	domain=PROSAMX	src=10.255.16.21	identSrc=10.255.16.21	identHostName=16_2470_21	HostName=16_2470_21	MUID=577C98BB9DC2523C1AEDE584FCAF1615	Op=Exec	ParentHash=7E160844D950765356C84BCBCFBF1DEE	ParentDriveType=Fixed	ParentPath=PROGRAM_FILESX86|\Google\Chrome\Application\chrome.exe	ParentValidSig=true	ParentCompany=Google Inc.	ParentBroken=false	ParentImageType=EXE 64	ParentExeType=Unknown	ParentPrevalence=High	ParentPrevLastDay=Low	ParentCat=Goodware	ParentMWName=	ChildHash=7E160844D950765356C84BCBCFBF1DEE	ChildDriveType=Fixed	ChildPath=PROGRAM_FILESX86|\Google\Chrome\Application\chrome.exe	ChildValidSig=true	ChildCompany=Google Inc.	ChildBroken=true	ChildImageType=EXE 64	ChildExeType=Unknown	ChildPrevalence=High	ChildPrevLastDay=Low	ChildCat=Goodware	ChildMWName=	OCS_Exec=true	OCS_Name=Google Chrome	OCS_Version=71.0.3578.80	Params="C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --type\=renderer --field-trial-handle\=1716,6504423765877186287,9579056321151338165,131072 --service-pipe-token\=11343697476573359606 --lang\=es --extension-process --enable-offline-auto-reload --enable-offline-auto-reload-visible-only --device-scale-factor\=1 --num-raster-threads\=4 --enable-main-frame-before-activation --service-request-channel-token\=11343697476573359606 --renderer-client-id\=629 --no-v8-untrusted-code-mitigations --mojo-platform-channel-handle\=17588 /prefetch:1	ToastResult=	Action=Allow	ServiceLevel=Learning	WinningTech=Cloud	DetId=0'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'paps')
        self.assertEqual(response.rule_id, '64206')
        self.assertEqual(response.rule_level, 7)


    def test_panda_paps_the_parent_process_is_corrupted_or_defective(self) -> None:
        log = '''LEEF:1.0|Panda Security|paps|02.47.00.0000|createdir|sev=1	devTime=2019-05-09 21:59:51.410364	devTimeFormat=yyyy-MM-dd HH:mm:ss.SSS	usrName=SYSTEM	domain=NT AUTHORITY	src=10.255.16.21	identSrc=10.255.16.21	identHostName=16_2470_21	HostName=16_2470_21	MUID=577C98BB9DC2523C1AEDE584FCAF1615	Op=CreateDir	ParentHash=C05A19A38D7D203B738771FD1854656F	ParentDriveType=Fixed	ParentPath=SYSTEM|\spoolsv.exe	ParentValidSig=	ParentCompany=Microsoft Corporation	ParentBroken=true	ParentImageType=EXE 64	ParentExeType=Unknown	ParentPrevalence=High	ParentPrevLastDay=Low	ParentCat=Goodware	ParentMWName=	ChildHash=	ChildDriveType=Fixed	ChildPath=SYSTEM|\spool\V4Dirs\5F1D9A23-55FC-420A-84EC-E78F46C362E2	ChildValidSig=	ChildCompany=	ChildBroken=	ChildImageType=	ChildExeType=	ChildPrevalence=	ChildPrevLastDay=	ChildCat=Unknown	ChildMWName=	OCS_Exec=false	OCS_Name=	OCS_Version=	Params=	ToastResult=	Action=Allow	ServiceLevel=Learning	WinningTech=Unknown	DetId=0'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'paps')
        self.assertEqual(response.rule_id, '64207')
        self.assertEqual(response.rule_level, 7)


    def test_panda_paps_a_file_is_corrupted_or_defective(self) -> None:
        log = '''LEEF:1.0|Panda Security|paps|02.47.00.0000|registrym|sev=1	devTime=2019-05-09 22:01:23.255825	devTimeFormat=yyyy-MM-dd HH:mm:ss.SSS	usrName=SYSTEM	domain=NT AUTHORITY	src=10.255.44.11	identSrc=10.255.44.11	identHostName=44_CCO_11	HostName=44_CCO_11	MUID=D877F2C4C4000A9BF39F1710CA787291	Op=ModifyExeKey	Hash=F6494E7C35B6514A3AD74E27435F3141	DriveType=Fixed	Path=PROGRAM_FILESX86|\LANDesk\LDClient\hips\LDSecSvc64.EXE	ValidSig=true	Company=LANDESK Software, Inc. and its affiliates.	Broken=true	ImageType=EXE 64	ExeType=Unknown	Prevalence=Low	PrevLastDay=Low	Cat=Goodware	MWName=	TargetPath=3|PROGRAM_FILESX86|\LANDesk\LDClient\LDdrives.exe'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'paps')
        self.assertEqual(response.rule_id, '64208')
        self.assertEqual(response.rule_level, 7)

