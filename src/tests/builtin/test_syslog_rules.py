#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from syslog.ini
class TestSyslogRules(unittest.TestCase):

    @unittest.skip("This should be passing")
    def test_uninteresting_nouveau_error(self) -> None:
        log = r'''
Jul 18 09:21:57 localhost kernel: nouveau E[  PGRAPH][0000:0f:00.0] DATA_ERROR BEGIN_END_ACTIVE
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '2944')

    @unittest.skip("This should be passing")
    def test_uninteresting_nouveau_error_2(self) -> None:
        log = r'''
Jul 18 09:21:57 localhost kernel: nouveau E[  PGRAPH][0000:0f:00.0]  DATA_ERROR
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '2944')

    @unittest.skip("This should be passing")
    def test_incorrect_chain_target_match(self) -> None:
        log = r'''
Jul 18 10:51:43 localhost NetworkManager[1366]: <warn> (enp1s0) firewall zone remove failed: (32) COMMAND_FAILED: '/sbin/iptables -D INPUT_ZONES -t filter -i enp1s0 -g IN_public' failed: iptables: No chain/target/match by that name.
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '2941')

    @unittest.skip("This should be passing")
    def test_rsyslog_may_be_dropping_messages_due_to_rate_limiting(self) -> None:
        log = r'''
Feb  5 13:07:52 plugh rsyslogd-2177: imuxsock begins to drop messages from pid 12105 due to rate-limiting
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '2945')

    @unittest.skip("This should be passing")
    def test_non_standard_syslog_ng_format_with_year(self) -> None:
        log = r'''
2015 Nov 13 13:40:01 ether rsyslogd-2177: imuxsock begins to drop messages from pid 17840 due to rate-limiting
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '2945')

    @unittest.skip("This should be passing")
    def test_useradd_failed(self) -> None:
        log = r'''
May  4 18:21:10 collectd useradd[15178]: failed adding user 'ansible', data deleted
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '5905')

