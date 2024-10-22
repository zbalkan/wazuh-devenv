#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from owlh.ini
class TestOwlhRules(unittest.TestCase):

    def test_ssh(self) -> None:
        log = '''{"ts":1573747292.658982,"uid":"Crpk2p1rt6idRtb2Fi","id.orig_h":"10.0.2.2","id.orig_p":45398,"id.resp_h":"10.0.2.15","id.resp_p":22,"version":2,"auth_attempts":0,"client":"SSH-2.0-OpenSSH_7.9p1 Ubuntu-10","bro_engine":"SSH"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '66001')
        self.assertEqual(response.rule_level, 5)


    def test_ssl(self) -> None:
        log = '''{"ts":1573804908.676001,"uid":"C4XJwR30xeMnOdUnm9","id.orig_h":"10.0.0.1","id.orig_p":56980,"id.resp_h":"10.0.0.5","id.resp_p":443,"resumed":false,"established":false,"bro_engine":"SSL"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '66002')
        self.assertEqual(response.rule_level, 5)


    def test_dns(self) -> None:
        log = '''{"ts":1573747600.751717,"uid":"C5KJdi3dcFfrbKjPb2","id.orig_h":"10.0.2.15","id.orig_p":48469,"id.resp_h":"10.0.2.3","id.resp_p":53,"proto":"udp","trans_id":44048,"query":"archive.ubuntu.com","rcode":0,"rcode_name":"NOERROR","AA":false,"TC":false,"RD":false,"RA":true,"Z":0,"answers":["91.189.88.173","91.189.88.174","91.189.88.24","91.189.88.162","91.189.88.149","91.189.88.31"],"TTLs":[60.0,60.0,60.0,60.0,60.0,60.0],"rejected":false,"bro_engine":"DNS"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '66003')
        self.assertEqual(response.rule_level, 5)


    def test_conn(self) -> None:
        log = '''{"ts":1573747285.572531,"uid":"CGosDF2j8tJOWH3lCa","id.orig_h":"10.0.2.2","id.orig_p":45338,"id.resp_h":"10.0.2.15","id.resp_p":22,"proto":"tcp","duration":1.794416904449463,"orig_bytes":456,"resp_bytes":0,"conn_state":"SH","local_orig":true,"local_resp":true,"missed_bytes":0,"history":"DcAcF","orig_pkts":28,"orig_ip_bytes":1576,"resp_pkts":0,"resp_ip_bytes":0,"bro_engine":"CONN"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '66004')
        self.assertEqual(response.rule_level, 5)

