#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from vuln_detector.ini
class TestVuln_detectorRules(unittest.TestCase):

    def test_cve_removed_1(self) -> None:
        log = '''{"vulnerability":{"package":{"name":"ncurses","version":"5.9-14.20130511.el7_4","architecture":"x86_64"},"cve":"CVE-2019-17594", "status":"Solved", "reference":"fb783b1c771a643f81259a93248e7f61e9a4a597"}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '23502')
        self.assertEqual(response.rule_level, 3)


    def test_cve_removed_2(self) -> None:
        log = '''{"vulnerability":{"package":{"name":"ncurses","version":"5.9-14.20130511.el7_4","architecture":"x86_64"},"cve":"", "status":"Solved", "reference":"fb783b1c771a643f81259a93248e7f61e9a4a597"}}'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)

