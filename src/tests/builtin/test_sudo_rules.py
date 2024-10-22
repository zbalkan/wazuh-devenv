#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from sudo.ini
class TestSudoRules(unittest.TestCase):

    def test_sudo_all_1(self) -> None:
        log = '''Apr 27 15:22:23 niban sudo:     dcid : TTY=pts/4 ; PWD=/home/dcid ; USER=root ; COMMAND=/usr/bin/tail /var/log/snort/alert.fast'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sudo')
        self.assertEqual(response.rule_id, '5403')
        self.assertEqual(response.rule_level, 4)


    def test_sudo_all_2(self) -> None:
        log = '''Apr 14 10:59:01 enigma sudo:     dcid : TTY=ttyp3 ; PWD=/home/dcid/ossec-hids.0.1a/src/analysisd ; USER=root ; COMMAND=/bin/cp -pr ../../bin/addagent ../../bin/osaudit-logaudit ../../bin/ossec-execd ../../bin/ossec-logcollector ../../bin/ossec-maild ../../bin/ossec-remoted /var/ossec/bin'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sudo')
        self.assertEqual(response.rule_id, '5403')
        self.assertEqual(response.rule_level, 4)


    def test_sudo_all_3(self) -> None:
        log = '''Apr 19 14:52:02 enigma sudo:     dcid : TTY=ttyp3 ; PWD=/var/www/alex ; USER=root ; COMMAND=/sbin/chown dcid.dcid .'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sudo')
        self.assertEqual(response.rule_id, '5403')
        self.assertEqual(response.rule_level, 4)


    def test_sudo_all_4(self) -> None:
        log = '''Dec 30 19:36:11 rheltest sudo: cplummer : TTY=pts/2 ; PWD=/home/cplummer1 ; USER=root ; TSID=0000UM ; COMMAND=/bin/bash'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sudo')
        self.assertEqual(response.rule_id, '5403')
        self.assertEqual(response.rule_level, 4)


    def test_failed_attempt_to_run_sudo(self) -> None:
        log = '''Jun 25 15:51:13 precise32 sudo:     mike : 1 incorrect password attempt ; TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/ls'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sudo')
        self.assertEqual(response.rule_id, '5401')
        self.assertEqual(response.rule_level, 5)


    def test_first_time_user_executed_sudo(self) -> None:
        log = '''Jun 25 15:48:21 precise32 sudo:  mike : TTY=pts/0 ; PWD=/home/vagrant ; USER=root ; COMMAND=/bin/su -'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sudo')
        self.assertEqual(response.rule_id, '5403')
        self.assertEqual(response.rule_level, 4)


    def test_3_incorrect_password_attempts(self) -> None:
        log = '''Jun 25 16:15:45 precise32 sudo:     mike : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/ls'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sudo')
        self.assertEqual(response.rule_id, '5404')
        self.assertEqual(response.rule_level, 10)


    def test_unauthorized_user(self) -> None:
        log = '''Apr 13 08:36:31 ix sudo:     ddp2 : user NOT in sudoers ; TTY=ttypZ ; PWD=/home/ddp2 ; USER=root ; COMMAND=/bin/ls'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'sudo')
        self.assertEqual(response.rule_id, '5405')
        self.assertEqual(response.rule_level, 5)

