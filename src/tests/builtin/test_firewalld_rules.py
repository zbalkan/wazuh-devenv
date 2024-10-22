#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from firewalld.ini
class TestFirewalldRules(unittest.TestCase):

    def test_incorrect_chain_target_match(self) -> None:
        log = '''Jul 18 10:51:43 localhost firewalld: 2014-07-18 10:51:43 ERROR: '/sbin/iptables -D INPUT_ZONES -t filter -i enp1s0 -g IN_public' failed: iptables: No chain/target/match by that name.'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)


    def test_incorrect_chain_target_match(self) -> None:
        log = '''Jul 18 10:51:43 localhost firewalld: 2014-07-18 10:51:43 ERROR: COMMAND_FAILED: '/sbin/iptables -D INPUT_ZONES -t filter -i enp1s0 -g IN_public' failed: iptables: No chain/target/match by that name.'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)


    def test_firewalld_zone_already_set(self) -> None:
        log = '''Jul 18 11:04:51 localhost firewalld: 2014-07-18 11:04:51 ERROR: ZONE_ALREADY_SET'''
        response = send_log(log)

        self.assertNotEqual(response.status, LogtestStatus.RuleMatch)

