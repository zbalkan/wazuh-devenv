#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from exchange.ini
class TestExchangeRules(unittest.TestCase):

    def test_ms_exchange_possible_proxylogon_vulnerability_exploitation_cve_2021_26855(self) -> None:
        log = r'''
2021-04-06T14:54:34.255Z,61d2c86f-f9bb-456d-88c0-3529172510ac,15,0,847,30,,Ecp,192.168.0.60,/ecp/lkO.js,,FBA,False,,,ServerInfo~Admin@WIN-03FGEGKLSPR:444/ecp/DDI/DDIService.svc/GetList?reqId=1615583487987&schema=VirtualDirectory&msExchEcpCanary=Sw7TsEblh0O9yAO2zOMLYYjmrzSe-tgIeEyMoR9keCLkC8uBhZ54ExFEhXKulvSv9x5C62ymOnE.&a=,Mozilla/5.0,192.168.0.127,WIN-03FGEGKLSPR,200,200,,POST,Proxy,win-03fgegklspr,41.42.31996.000,CrossRegion,X-BEResource-Cookie,,,,159,598,1,,0,0,,0,,0,,0,0,6375,0,0,1,0,6378,0,0,0,6380,0,6378,1,2,2,6380,,,CorrelationID=<empty>;BeginRequest=2021-04-06T14:54:27.880Z;ProxyState-Run=None;BeginGetRequestStream=2021-04-06T14:54:27.880Z;OnRequestStreamReady=2021-04-06T14:54:27.880Z;BeginGetResponse=2021-04-06T14:54:27.880Z;OnResponseReady=2021-04-06T14:54:34.255Z;EndGetResponse=2021-04-06T14:54:34.255Z;ProxyState-Complete=ProxyResponseData;,
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'HTTPProxyLog')
        self.assertEqual(response.rule_id, '91002')
        self.assertEqual(response.rule_level, 12)


    def test_ms_exchange_possible_proxylogon_vulnerability_exploitation_cve_2021_27065(self) -> None:
        log = r"""
2021-04-06T14:54:38.677Z,WIN-03FGEGKLSPR,ECP.Request,"S:TIME=4365;S:SID=3a5d3a0b-a544-4d5c-9b1d-3d33d4968b48;'S:CMD=Set-OabVirtualDirectory.ExternalUrl=''http://o/#<sanitized>bad code goes here</sanitized>''.Identity=''87fc3593-ca62-4d08-93bd-782275d33c1''';S:REQID=;S:URL=/ecp/DDI/DDIService.svc/SetObject?schema=OABVirtualDirectory&msExchEcpCanary=MALCOD.&a=%5D:444/ecp/lkO.js;S:EX=;S:ACTID=c3f8f7e0-9817-46da-9ed4-fe575da51fbd;S:RS=0;S:BLD=15.0.847.32
"""
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'ECPServerLog')
        self.assertEqual(response.rule_id, '91003')
        self.assertEqual(response.rule_level, 12)

