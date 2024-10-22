#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from apparmor.ini
class TestApparmorRules(unittest.TestCase):

    def test_ignore_allowed_or_status(self) -> None:
        log = '''Jun 24 10:35:29 hostname kernel: [49787.970285] audit: type=1400 audit(1403598929.839:88986): apparmor="ALLOWED" operation="getattr" profile="/usr/sbin/dovecot//null-1//null-2//null-4a6" name="/home/admin/mails/new/" pid=19973 comm="imap" requested_mask="r" denied_mask="r" fsuid=1003 ouid=1003'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '52001')
        self.assertEqual(response.rule_level, 0)


    def test_apparmor_allowed_or_status(self) -> None:
        log = '''Jun 23 20:46:15 hostname kernel: [   11.103248] audit: type=1400 audit(1403549175.177:2): apparmor="STATUS" operation="profile_load" name="/sbin/klogd" pid=2185 comm="apparmor_parser"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '52001')
        self.assertEqual(response.rule_level, 0)


    def test_apparmor_denied(self) -> None:
        log = '''Jul 14 11:03:47 hostname kernel: [ 8665.951930] type=1400 audit(1405328627.702:54): apparmor="DENIED" operation="open" profile="/usr/bin/evince" name="/etc/xfce4/defaults.list" pid=16418 comm="evince" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '52002')
        self.assertEqual(response.rule_level, 3)


    def test_apparmor_denied_mknod_operation(self) -> None:
        log = '''Jun 16 17:37:39 hostname kernel: [891880.587989] audit: type=1400 audit(1314853822.672:33649): apparmor="DENIED" operation="mknod" parent=27250 profile="/usr/lib/apache2/mpm-prefork/apache2//example.com" name="/usr/share/wordpress/1114140474e5f13bea68a4.tmp" pid=27289 comm="apache2" requested_mask="c" denied_mask="c" fsuid=33 ouid=33'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '52004')
        self.assertEqual(response.rule_level, 4)


    def test_apparmor_denied_exec_operation(self) -> None:
        log = '''Jun 16 17:37:39 hostname kernel: [891880.587989] audit: type =1400 audit(1315353795.331:33657): apparmor="DENIED" operation="exec" parent=14952 profile="/usr/lib/apache2/mpm-prefork/apache2//example.com" name="/usr/lib/sm.bin/sendmail" pid=14953 comm="sh" requested_mask="x" denied_mask="x" fsuid=33 ouid=0'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '52003')
        self.assertEqual(response.rule_level, 5)

