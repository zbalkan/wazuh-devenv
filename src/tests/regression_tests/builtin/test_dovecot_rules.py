#!/usr/bin/env python3


# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from dovecot.ini
class TestDovecotRules(unittest.TestCase):

    def test_auth_failed_1(self) -> None:
        log = r'''
Dec 19 06:21:06 ny dovecot: imap-login: Disconnected (auth failed, 7 attempts in 111 secs): user=<thousands>, method=PLAIN, rip=109.201.200.201, lip=67.205.141.203, session=<+hgd5vxDBMZtycjJ>
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'dovecot')
        self.assertEqual(response.rule_id, '9705')
        self.assertEqual(response.rule_level, 5)


    def test_auth_failed_2(self) -> None:
        log = r'''
Jan 11 03:45:09 hostname dovecot: auth-worker(default): sql(username,1.2.3.4): unknown user
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'dovecot')
        self.assertEqual(response.rule_id, '9705')
        self.assertEqual(response.rule_level, 5)


    def test_auth_failed_3(self) -> None:
        log = r'''
Jan 11 03:42:09 hostname dovecot: auth(default): pam(user@example.com,1.2.3.4): pam_authenticate() failed: User not known to the underlying authentication module
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'dovecot')
        self.assertEqual(response.rule_id, '9705')
        self.assertEqual(response.rule_level, 5)


    def test_dovecot_is_starting(self) -> None:
        log = r'''
Jun 17 10:15:24 hostname dovecot: Dovecot v1.2.rc3 starting up (core dumps disabled)
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'dovecot')
        self.assertEqual(response.rule_id, '9703')
        self.assertEqual(response.rule_level, 3)


    def test_fatal_error_1(self) -> None:
        log = r'''
Jun 17 10:15:24 hostname dovecot: Fatal: auth(default): Support not compiled in for passdb driver 'ldap'
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'dovecot')
        self.assertEqual(response.rule_id, '9704')
        self.assertEqual(response.rule_level, 2)


    def test_fatal_error_2(self) -> None:
        log = r'''
Jun 17 10:15:24 hostname dovecot: Fatal: Auth process died too early - shutting down
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'dovecot')
        self.assertEqual(response.rule_id, '9704')
        self.assertEqual(response.rule_level, 2)


    def test_user_authentication_failure(self) -> None:
        log = r'''
Jun 23 15:04:05 Info: imap-login: Login: user=<username>, method=PLAIN, rip=1.2.3.4, lip=1.2.3.5 Authentication Failure:
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'dovecot-info')
        self.assertEqual(response.rule_id, '9770')
        self.assertEqual(response.rule_level, 0)


    def test_dovecot_auth_failed(self) -> None:
        log = r'''
Jan 11 03:42:09 hostname dovecot: auth-worker(default): sql(user@example.com,1.2.3.4): Password mismatch
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'dovecot')
        self.assertEqual(response.rule_id, '9702')
        self.assertEqual(response.rule_level, 5)


    def test_xxx_nothing_1(self) -> None:
        log = r'''
Jan 07 14:46:28 Warn: auth(default): userdb(username,::ffff:127.0.0.1): user not found from userdb
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '1002')


    def test_xxx_nothing_2(self) -> None:
        log = r'''
May 31 09:43:57 Info: pop3-login: Aborted login (1 authentication attempts): user=<username>, method=PLAIN, rip=::ffff:1.2.3.4, lip=::ffff:1.2.3.5, secured
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '1002')


    def test_xxx_unknown_1002(self) -> None:
        log = r'''
Mar 13 15:25:07 Info: auth(default): pam(user@example.com,::ffff:1.2.3.4): pam_authenticate() failed: User not known to the underlying authentication module
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'dovecot-info')
        self.assertEqual(response.rule_id, '9771')
        self.assertEqual(response.rule_level, 5)


    def test_session_disconnected(self) -> None:
        log = r'''
Jul  4 17:30:51 hostname dovecot[2992]: pop3-login: Disconnected: rip=1.2.3.4, lip=1.2.3.5
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'dovecot')
        self.assertEqual(response.rule_id, '9706')
        self.assertEqual(response.rule_level, 3)


    def test_aborted_login(self) -> None:
        log = r'''
Jan 30 09:37:55 hostname dovecot: pop3-login: Aborted login: user=<username>, method=PLAIN, rip=::ffff:1.2.3.4, lip=::ffff:1.2.3.5
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'dovecot')
        self.assertEqual(response.rule_id, '9707')
        self.assertEqual(response.rule_level, 5)


    def test_xxx_logged_out(self) -> None:
        log = r'''
Jun 23 15:04:06 Info: IMAP(username): Disconnected: Logged out bytes=59/566
'''
        response = send_log(log)

        self.assertNotEqual(response.rule_id, '1002')


    def test_unknown_user(self) -> None:
        log = r'''
Mar 13 15:25:07 Info: auth(default): passwd-file(user@example.com,::ffff:1.2.3.4): unknown user
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'dovecot-info')
        self.assertEqual(response.rule_id, '9771')
        self.assertEqual(response.rule_level, 5)

