#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from fortimail.ini
class TestFortimailRules(unittest.TestCase):

    def test_fortimail_informational_message(self) -> None:
        log = r'''
2021-07-08T13:45:20.966330-03:00 10.132.128.10 date=2021-07-08 time=13:45:21.846 device_id=XXXXXXXX log_id=0200027993 type=statistics pri=information  session_id="168GjLEk027992-16027992" client_name="" client_ip="11.22.33.44" client_cc="ZZ" dst_ip="12.34.56.78" from="noreply@domain.com" hfrom="noreply@domain.com" to="user@gmail.com" polid="2:2:5:SYSTEM" domain="HHHHHHHH" mailer="mta" resolved="FAIL" src_type="int" direction="out" virus="" disposition="Accept" classifier="Not Spam" message_length="23951" subject="Subject of the message" message_id="896710244.116204.16257.Mail@lnk2489" recv_time="" notif_delay="0" scan_time="0.008128" xfer_time="0.005643" srcfolder="" read_status=""
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortimail-like')
        self.assertEqual(response.rule_id, '44641')
        self.assertEqual(response.rule_level, 0)


    def test_fortimail_an_administrator_successfully_logged_in_using_the_web_based_manager_or_cli(self) -> None:
        log = r'''
date=2012-08-17 time=12:26:41 device_id=FE100C3909600504 log_id=0001001623 type=kevent subtype=admin pri=information user=admin ui=GUI(172.20.120.26) action=login status=success reason=none msg="User admin login successfully from GUI (172.20.120.26)"
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortimail-like')
        self.assertEqual(response.rule_id, '44649')
        self.assertEqual(response.rule_level, 3)


    def test_fortimail_heartbeat_related_activities(self) -> None:
        log = r'''
date=2012-08-09 time=10:30:31 device_id=FE100C3909600504 log_id=0004001036 type=kevent subtype=ha pri=notice user=ha ui=ha action=none status=success msg="hahbd: heart beat status changed to primary-hearbeat-port1=FAILED;secondary-hearbeat-port2=OK"
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortimail-like')
        self.assertEqual(response.rule_id, '44696')
        self.assertEqual(response.rule_level, 3)


    def test_fortimail_the_file_contains_the_specified_virus(self) -> None:
        log = r'''
date=2012-07-24 time=17:07:42 device_id=FE100C3909600504 log_id=0100000924 type=virus subtype=infected pri=information from="syntax@www.ca" to="user2@1.ca" src=172.20.140.94 session_id="q6OL7fsQ018870-q6OL7fsR018870" msg="The file inline-16-69.dat is infected with EICAR_TEST_FILE."
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortimail-like')
        self.assertEqual(response.rule_id, '44718')
        self.assertEqual(response.rule_level, 3)


    def test_fortimail_spam_related_events(self) -> None:
        log = r'''
date=2012-07-20 time=14:33:26 device_id=FE100C3909600504 log_id=0300000924 type=spam pri=information session_id="q6KIXPZe008097-q6KIXPZf008097" client_name="[172.20.140.94]" dst_ip="172.20.140.92" endpoint="" from="syntax@www.ca" to="user1@1.ca" subject="Email with wd, excel, and rtf test" msg="Detected by BannedWord test"
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortimail-like')
        self.assertEqual(response.rule_id, '44719')
        self.assertEqual(response.rule_level, 3)


    def test_fortimail_fortimail_encrypted_or_decrypted_an_email(self) -> None:
        log = r'''
date=2012-08-09 time=10:45:27 device_id=FE100C3909600504 log_id=0400005355 type=encrypt pri=information session_id="q79EiV8S007017-q79EiV8T0070170001474" msg="User user1@1.ca read secure message, id:'q79EiV8S007017-q79EiV8T0070170001474', sent from: 'user2@2.ca', subject: 'ppt file'"
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortimail-like')
        self.assertEqual(response.rule_id, '44720')
        self.assertEqual(response.rule_level, 3)

