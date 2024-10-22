#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from auditd.ini
class TestAuditdRules(unittest.TestCase):

    def test_auditd_daemon_start_resume(self) -> None:
        log = '''type=DAEMON_RESUME msg=audit(1300385209.456:8846): auditd resuming logging, sending auid=? pid=? subj=? res=success'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80701')
        self.assertEqual(response.rule_level, 1)


    def test_auditd_daemon_start_resume_failed(self) -> None:
        log = '''type=DAEMON_START msg=audit(1450875964.131:8728): auditd start, ver=2.4 format=raw kernel=3.16.0-4-amd64 auid=4294967295 pid=1437 res=failed'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80702')
        self.assertEqual(response.rule_level, 10)


    def test_auditd_daemon_end(self) -> None:
        log = '''type=DAEMON_END msg=audit(1450876093.165:8729): auditd normal halt, sending auid=0 pid=1 subj= res=success'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80703')
        self.assertEqual(response.rule_level, 10)


    def test_auditd_daemon_abort(self) -> None:
        log = '''type=DAEMON_ABORT msg=audit(1339336882.189:9206): auditd error halt, auid=4294967295 pid=3095 res=failed'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80704')
        self.assertEqual(response.rule_level, 10)


    def test_auditd_configuration_changed_1(self) -> None:
        log = '''type=CONFIG_CHANGE msg=audit(1368831799.081:466947): auid=4294967295 ses=4294967295 op="remove rule" path="/path/to/my/bin0" key=(null) list=4 res=1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80705')
        self.assertEqual(response.rule_level, 3)


    def test_auditd_configuration_changed_2(self) -> None:
        log = '''type=DAEMON_CONFIG msg=audit(1264985324.554:4915): auditd error getting hup info - no change, sending auid=? pid=? subj=? res=failed'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80705')
        self.assertEqual(response.rule_level, 3)


    def test_auditd_device_enables_promiscuous_mode(self) -> None:
        log = '''type=ANOM_PROMISCUOUS msg=audit(1390181243.575:738): dev=vethDvSeyL prom=256 old_prom=256 auid=4294967295 uid=0 gid=0 ses=4294967295'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80710')
        self.assertEqual(response.rule_level, 10)


    def test_auditd_process_ended_abnormally(self) -> None:
        log = '''type=ANOM_ABEND msg=audit(1222174623.498:608): auid=4294967295 uid=0 gid=7 ses=4294967295 subj=system_u:system_r:cupsd_t:s0-s0:c0.c1023 pid=7192 comm="ipp" sig=11'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80711')
        self.assertEqual(response.rule_level, 10)


    def test_auditd_execution_of_a_file_ended_abnormally(self) -> None:
        log = '''type=ANOM_EXEC msg=audit(1222174623.498:608): user pid=12965 uid=1 auid=2 ses=1 msg='op=PAM:unix_chkpwd acct="snap" exe="/sbin/unix_chkpwd" (hostname=?, addr=?, terminal=pts/0 res=failed)''''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80712')
        self.assertEqual(response.rule_level, 10)


    def test_auditd_file_is_made_executable(self) -> None:
        log = '''type=ANOM_MK_EXEC msg=audit(1234567890.123:1234): Text'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80713')
        self.assertEqual(response.rule_level, 7)


    def test_auditd_file_or_a_directory_access_ended_abnormally(self) -> None:
        log = '''type=ANOM_ACCESS_FS msg=audit(1234567890.123:1234): Text'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80714')
        self.assertEqual(response.rule_level, 8)


    def test_auditd_failure_of_the_abstract_machine_test_utility_amtu_detected(self) -> None:
        log = '''type=ANOM_AMTU_FAIL msg=audit(1234567890.123:1234): Text'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80715')
        self.assertEqual(response.rule_level, 8)


    def test_auditd_maximum_amount_of_discretionary_access_control_dac_or_mandatory_access_control_mac_failures_reached(self) -> None:
        log = '''type=ANOM_MAX_DAC msg=audit(1234567890.123:1234): Text'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80716')
        self.assertEqual(response.rule_level, 8)


    def test_auditd_role_based_access_control_rbac_failure_detected_1(self) -> None:
        log = '''type=ANOM_AMTU_FAIL msg=audit(1234567890.123:1234): Text'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80717')
        self.assertEqual(response.rule_level, 8)


    def test_auditd_role_based_access_control_rbac_failure_detected_2(self) -> None:
        log = '''type=ANOM_RBAC_INTEGRITY_FAIL msg=audit(1234567890.123:1234): Text'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80717')
        self.assertEqual(response.rule_level, 8)


    def test_auditd_user_space_account_addition_ended_abnormally(self) -> None:
        log = '''type=ANOM_ADD_ACCT msg=audit(1450770603.209:3300446): Text'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80718')
        self.assertEqual(response.rule_level, 3)


    def test_auditd_user_space_account_deletion_ended_abnormally(self) -> None:
        log = '''type=ANOM_DEL_ACCT msg=audit(1450770603.209:3300446): Text'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80719')
        self.assertEqual(response.rule_level, 3)


    def test_auditd_user_space_account_modification_ended_abnormally(self) -> None:
        log = '''type=ANOM_MOD_ACCT msg=audit(1450770603.209:3300446): Text'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80720')
        self.assertEqual(response.rule_level, 3)


    def test_auditd_user_becomes_root(self) -> None:
        log = '''type=ANOM_ROOT_TRANS msg=audit(1450770603.209:3300446): Text'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80721')
        self.assertEqual(response.rule_level, 10)


    def test_auditd_account_login_attempt_ended_abnormally(self) -> None:
        log = '''type=ANOM_LOGIN_ACCT msg=audit(1450770603.209:3300446): Text'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80722')
        self.assertEqual(response.rule_level, 5)


    def test_auditd_limit_of_failed_login_attempts_reached(self) -> None:
        log = '''type=ANOM_LOGIN_FAILURES msg=audit(1450770603.209:3300446): Text'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80723')
        self.assertEqual(response.rule_level, 5)


    def test_auditd_login_attempt_from_a_forbidden_location(self) -> None:
        log = '''type=ANOM_LOGIN_LOCATION msg=audit(1450770603.209:3300446): Text'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80724')
        self.assertEqual(response.rule_level, 5)


    def test_auditd_login_attempt_reached_the_maximum_amount_of_concurrent_sessions(self) -> None:
        log = '''type=ANOM_LOGIN_SESSIONS msg=audit(1450770603.209:3300446): Text'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80725')
        self.assertEqual(response.rule_level, 4)


    def test_auditd_login_attempt_is_made_at_a_time_when_it_is_prevented(self) -> None:
        log = '''type=ANOM_LOGIN_TIME msg=audit(1450770603.209:3300446): Text'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80726')
        self.assertEqual(response.rule_level, 5)


    def test_auditd_selinux_permission_check(self) -> None:
        log = '''type=AVC msg=audit(1226270358.848:238): avc:  denied  { write } for  pid=13349 comm="certwatch" name="cache" dev=dm-0 ino=218171 scontext=system_u:system_r:certwatch_t:s0 tcontext=system_u:object_r:var_t:s0 tclass=dir'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80730')
        self.assertEqual(response.rule_level, 3)


    def test_auditd_selinux_mode_enforcing_permissive_off_is_changed(self) -> None:
        log = '''type=MAC_STATUS msg=audit(1336836093.835:406): enforcing=1 old_enforcing=0 auid=0 ses=2'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80731')
        self.assertEqual(response.rule_level, 10)


    def test_auditd_selinux_error_1(self) -> None:
        log = '''type=SELINUX_ERR msg=audit(1311948547.151:138): op=security_compute_av reason=bounds scontext=system_u:system_r:anon_webapp_t:s0-s0:c0,c100,c200 tcontext=system_u:object_r:security_t:s0 tclass=dir perms=ioctl,read,lock'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80732')
        self.assertEqual(response.rule_level, 10)


    def test_auditd_selinux_error_2(self) -> None:
        log = '''type=USER_SELINUX_ERR msg=audit(1311948547.151:138): Text'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80732')
        self.assertEqual(response.rule_level, 10)


    def test_auditd_replay_attack_detected(self) -> None:
        log = '''type=CRYPTO_REPLAY_USER msg=audit(1234567890.123:1234): Text'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80740')
        self.assertEqual(response.rule_level, 12)


    def test_auditd_group_id_changed(self) -> None:
        log = '''type=CHGRP_ID msg=audit(1450770603.209:3300446): Text'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80741')
        self.assertEqual(response.rule_level, 5)


    def test_auditd_user_id_changed(self) -> None:
        log = '''type=CHUSER_ID msg=audit(1450770603.209:3300446): Text'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80742')
        self.assertEqual(response.rule_level, 5)


    def test_audit_created_$auditfilename_1(self) -> None:
        log = '''type=SYSCALL msg=audit(1479982525.380:50): arch=c000003e syscall=2 success=yes exit=3 a0=7ffedc40d83b a1=941 a2=1b6 a3=7ffedc40cce0 items=2 ppid=432 pid=3333 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=2 comm="touch" exe="/bin/touch" key="audit-wazuh-w" type=CWD msg=audit(1479982525.380:50):  cwd="/var/log/audit" type=PATH msg=audit(1479982525.380:50): item=0 name="/var/log/audit/tmp_directory1/" inode=399849 dev=ca:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT type=PATH msg=audit(1479982525.380:50): item=1 name="/var/log/audit/tmp_directory1/malware.py" inode=399852 dev=ca:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=CREATE type=PROCTITLE msg=audit(1479982525.380:50): proctitle=746F756368002F7661722F6C6F672F61756469742F746D705F6469726563746F7279312F6D616C776172652E7079'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80790')
        self.assertEqual(response.rule_level, 3)


    def test_audit_created_$auditfilename_2(self) -> None:
        log = '''node=localhost type=SYSCALL msg=audit(1479982525.380:50): arch=c000003e syscall=2 success=yes exit=3 a0=7ffedc40d83b a1=941 a2=1b6 a3=7ffedc40cce0 items=2 ppid=432 pid=3333 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=2 comm="touch" exe="/bin/touch" key="audit-wazuh-w" type=CWD msg=audit(1479982525.380:50):  cwd="/var/log/audit" type=PATH msg=audit(1479982525.380:50): item=0 name="/var/log/audit/tmp_directory1/" inode=399849 dev=ca:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT type=PATH msg=audit(1479982525.380:50): item=1 name="/var/log/audit/tmp_directory1/malware.py" inode=399852 dev=ca:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=CREATE type=PROCTITLE msg=audit(1479982525.380:50): proctitle=746F756368002F7661722F6C6F672F61756469742F746D705F6469726563746F7279312F6D616C776172652E7079'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80790')
        self.assertEqual(response.rule_level, 3)


    def test_audit_passwd_was_used_to_lock_an_account(self) -> None:
        log = '''type=ACCT_LOCK msg=audit(1630937849.448:891): pid=4171 uid=0 auid=1000 ses=3 subj=unconfined_u:unconfined_r:passwd_t:s0-s0:c0.c1023 msg='op=locked-password id=1001 exe="/usr/bin/passwd" hos>'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80793')
        self.assertEqual(response.rule_level, 8)


    def test_audit_passwd_was_used_to_unlock_an_account(self) -> None:
        log = '''type=ACCT_UNLOCK msg=audit(1630937871.591:892): pid=4172 uid=0 auid=1000 ses=3 subj=unconfined_u:unconfined_r:passwd_t:s0-s0:c0.c1023 msg='op=unlocked-password id=1001 exe="/usr/bin/passwd">'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'auditd')
        self.assertEqual(response.rule_id, '80794')
        self.assertEqual(response.rule_level, 8)

