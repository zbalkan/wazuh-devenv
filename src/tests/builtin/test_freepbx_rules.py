#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from freepbx.ini
class TestFreepbxRules(unittest.TestCase):

    def test_freepbx_1(self) -> None:
        log = '''[2019-07-25 14:29:19] Asterisk 15.7.3 built by root @ centos-7-31 on a x86_64 running Linux on 2019-07-25 14:15:02 UTC'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'FreePBX')
        self.assertEqual(response.rule_id, '70007')
        self.assertEqual(response.rule_level, 3)


    def test_freepbx_2(self) -> None:
        log = '''[2019-Jul-25 14:28:31] [INFO] (libraries/modulefunctions.class.php:2083) - Generating CSS...Done'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'FreePBX')
        self.assertEqual(response.rule_id, '70005')
        self.assertEqual(response.rule_level, 3)


    def test_freepbx_3(self) -> None:
        log = '''May 19 00:22:05 freepbx-a pacemakerd[1310]:   notice: crm_add_logfile: Additional logging available in /var/log/cluster/corosync.log'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'FreePBX')
        self.assertEqual(response.rule_id, '70008')
        self.assertEqual(response.rule_level, 3)


    def test_freepbx_4(self) -> None:
        log = '''[2019-07-25 14:58:54] ERROR[21763] config_options.c: Unable to load config file 'cel.conf''''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'FreePBX')
        self.assertEqual(response.rule_id, '70001')
        self.assertEqual(response.rule_level, 5)


    def test_freepbx_5(self) -> None:
        log = '''[npm-cache] [INFO] [npm] hash of /var/www/html/admin/modules/pm2/node/package.json: fa2348032788d5067b56972347177c79'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'FreePBX')
        self.assertEqual(response.rule_id, '70006')
        self.assertEqual(response.rule_level, 3)


    def test_freepbx_6(self) -> None:
        log = '''[2019-Jul-25 14:28:32] [freepbx.INFO]: Deprecated way to add Console commands, adding console commands this way can have negative performance impacts. Please use module.xml. See: https://wiki.freepbx.org/display/FOP/Adding+fwconsole+commands [] []'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'FreePBX')
        self.assertEqual(response.rule_id, '70005')
        self.assertEqual(response.rule_level, 3)

