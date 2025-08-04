#!/usr/bin/env python3


# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from pfsense.ini
class TestPfsenseRules(unittest.TestCase):

    def test_pfsense_firewall_generic(self) -> None:
        log = r'''
Jan 22 18:34:00 filterlog: 65,,,0,vmx1,match,pass,out,4,0x0,,63,21011,0,none,1,icmp,56,192.168.105.11,192.168.105.1,datalength=36
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'pf')
        self.assertEqual(response.rule_id, '87700')
        self.assertEqual(response.rule_level, 0)


    def test_pfsense_firewall_drop_event(self) -> None:
        log = r'''
Nov  8 12:37:34 pfSense filterlog: 5,,,1000102433,em0,match,block,in,4,0x0,,128,24677,0,none,17,udp,186,10.9.0.119,10.9.0.255,17500,17600,166
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'pf')
        self.assertEqual(response.rule_id, '87701')
        self.assertEqual(response.rule_level, 5)

