#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from fireeye.ini
class TestFireeyeRules(unittest.TestCase):

    def test_fireeye(self) -> None:
        log = r'''
Sep  9 00:31:10 192.168.1.1 cef: CEF:0|FireEye|????|7.9.3.616878|MC|YYYY|7|rt=Sep 09 2017 00:31:23 UTC src=192.168.1.2 cn3La...=tcp dst=192.168.1.2 cs5Lab...
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cef-fireeye')
        self.assertEqual(response.rule_id, '150101')
        self.assertEqual(response.rule_level, 7)


    def test_fireeye_malicious_script(self) -> None:
        log = r'''
Aug 25 17:22:01 usa001 cef: CEF:0|fireeye|hx|3.5.1|IOC Hit Found|IOC Hit Found|10|rt=Aug 25 2017 17:22:01 UTC dvchost=usa001 categoryDeviceGroup=/IDS categoryDeviceType=Forensic Investigation categoryObject=/Host cs1Label=Host Agent Cert Hash cs1=DOdxxxuqM dst=192.168.1.2 dmac=d8-d0-d3-d8-d8-d8 dhost=XXXXXXXXXX-XX dntdom=NA deviceCustomDate1Label=Agent Last Audit deviceCustomDate1=Aug 25 2017 17:18:04 UTC cs2Label=FireEye Agent Version cs2=21.33.7 cs5Label=Target GMT Offset cs5=-PT4H cs6Label=Target OS cs6=Windows 7 Enterprise 7601 Service Pack 1 externalId=82xxx51 start=Aug 25 2017 17:17:34 UTC categoryOutcome=/Success categorySignificance=/Compromise categoryBehavior=/Found cs7Label=Resolution cs7=ALERT cs8Label=Alert Types cs8=exc act=Detection IOC Hit msg=Host XXXXXXXXXX-XX IOC compromise alert categoryTupleDescription=A Detection IOC found a compromise indication. cs4Label=IOC Name cs4=MALICIOUS SCRIPT CONTENT A (METHODOLOGY) categoryTechnique=Alert
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cef-fireeye')
        self.assertEqual(response.rule_id, '150102')
        self.assertEqual(response.rule_level, 7)


    def test_fireeye_malware_callback(self) -> None:
        log = r'''
Sep  9 00:31:10 192.168.1.1 cef: CEF:0|FireEye|MPS|7.9.3.616878|MC|malware-callback|7|rt=Sep 09 2017 00:31:23 UTC src=192.168.1.1 cn3Label=cncPort cn3=1080 cn2Label=sid cn2=xxxxxxxx requestMethod=GET proto=tcp dst=192.168.1.2 cs5Label=cncHost cs5=192.168.1.1 spt=xxxxxx cs4Label=link cs4=https://192.168.1.1/event_stream/events_for_bot?ev_id\=xxxxx&lms_iden\=002xxxCBA smac=a0:a8:a3:af:ac:a4 cn1Label=vlan cn1=0 dpt=1080 externalId=xxxxx dvc=192.168.1.2 act=notified cs6Label=channel cs6=GET /api.php?sk\=strategy HTTP/1.1::~~uid: 1xxx5::~~self_pname: com.shinymobi.app.funweather::~~manuFacturer: leimin::~~rom_avl: 343xxx792::~~resolution: 480x854::~~net: WIFI::~~lang: es::~~androidid: c0axxx871::~~time: Fri Sep 08 19:31:02 CDT 2017::~~mc: d8:d5:d7:d7:df:d6::~~ext_tol: 395xxx512::~~sdk: 19::~~vcode: 40022::~~app: DollarGetter_lg2::~~os: 1::~~gaid: 4xxxb-9xxx0-4xxx0-9xxx8-1cxxx1b::~~apis: F:SP_V:40022::~~s_nation: mx::~~vendor: zhxingch::~~imei: 35xxx21::~~cpu: 1300000::~~a_location: /
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'cef-fireeye')
        self.assertEqual(response.rule_id, '150101')
        self.assertEqual(response.rule_level, 7)

