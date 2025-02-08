#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from mailscanner.ini
class TestMailscannerRules(unittest.TestCase):

    @unittest.skip("This should be passing")
    def test_update_phishing(self) -> None:
        log = r'''
Feb 14 06:29:39 hostname update.bad.phishing.sites: Phishing bad sites list updated
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '3752')

