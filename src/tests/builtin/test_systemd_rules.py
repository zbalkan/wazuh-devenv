#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from systemd.ini
class TestSystemdRules(unittest.TestCase):

    def test_stale_file_handle(self) -> None:
        log = '''Jul 19 07:28:02 localhost systemd: Failed to mark scope session-1024.scope as abandoned : Stale file handle'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'systemd')
        self.assertEqual(response.rule_id, '40701')
        self.assertEqual(response.rule_level, 0)


    def test_system_time_changed(self) -> None:
        log = '''Aug 13 13:20:58 master systemd: Time has been changed'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'systemd')
        self.assertEqual(response.rule_id, '40705')
        self.assertEqual(response.rule_level, 5)

