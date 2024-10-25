#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log, send_multiple_logs


# Converted from nextcloud.ini
class TestNextcloudRules(unittest.TestCase):

    def test_nextcloud_brute_force_1(self) -> None:
        log = r'''
{"reqId":"XaQ6ehNN-waxXQIsoJHOSgAAAAE","level":2,"time":"October 14, 2019 09:06:02","remoteAddr":"127.0.0.1","user":"--","app":"core","method":"POST","url":"\/index.php\/login","message":"Login failed: 'admin' (Remote IP: '10.3.2.2')","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}
'''
        responses = send_multiple_logs([log] * 8)
        response = responses[-1]
        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '88203')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_nextcloud_brute_force_2(self) -> None:
        log = r'''
{"reqId":"XaQ6ehNN-waxXQIsoJHOSgAAAAE","level":2,"time":"October 14, 2019 09:06:02","remoteAddr":"127.0.0.1","user":"--","app":"core","method":"POST","url":"\/index.php\/login","message":"Login failed: 'admin' (Remote IP: '10.3.2.2')","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '88203')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_nextcloud_brute_force_3(self) -> None:
        log = r'''
{"reqId":"XaQ6ehNN-waxXQIsoJHOSgAAAAE","level":2,"time":"October 14, 2019 09:06:02","remoteAddr":"127.0.0.1","user":"--","app":"core","method":"POST","url":"\/index.php\/login","message":"Login failed: 'admin' (Remote IP: '10.3.2.2')","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '88203')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_nextcloud_brute_force_4(self) -> None:
        log = r'''
{"reqId":"XaQ6ehNN-waxXQIsoJHOSgAAAAE","level":2,"time":"October 14, 2019 09:06:02","remoteAddr":"127.0.0.1","user":"--","app":"core","method":"POST","url":"\/index.php\/login","message":"Login failed: 'admin' (Remote IP: '10.3.2.2')","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '88203')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_nextcloud_brute_force_5(self) -> None:
        log = r'''
{"reqId":"XaQ6ehNN-waxXQIsoJHOSgAAAAE","level":2,"time":"October 14, 2019 09:06:02","remoteAddr":"127.0.0.1","user":"--","app":"core","method":"POST","url":"\/index.php\/login","message":"Login failed: 'admin' (Remote IP: '10.3.2.2')","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '88203')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_nextcloud_brute_force_6(self) -> None:
        log = r'''
{"reqId":"XaQ6ehNN-waxXQIsoJHOSgAAAAE","level":2,"time":"October 14, 2019 09:06:02","remoteAddr":"127.0.0.1","user":"--","app":"core","method":"POST","url":"\/index.php\/login","message":"Login failed: 'admin' (Remote IP: '10.3.2.2')","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '88203')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_nextcloud_brute_force_7(self) -> None:
        log = r'''
{"reqId":"XaQ6ehNN-waxXQIsoJHOSgAAAAE","level":2,"time":"October 14, 2019 09:06:02","remoteAddr":"127.0.0.1","user":"--","app":"core","method":"POST","url":"\/index.php\/login","message":"Login failed: 'admin' (Remote IP: '10.3.2.2')","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '88203')
        self.assertEqual(response.rule_level, 10)

    @unittest.skip("This is a frequency test. Consolidated in the first one.")
    def test_nextcloud_brute_force_8(self) -> None:
        log = r'''
{"reqId":"XaQ6ehNN-waxXQIsoJHOSgAAAAE","level":2,"time":"October 14, 2019 09:06:02","remoteAddr":"127.0.0.1","user":"--","app":"core","method":"POST","url":"\/index.php\/login","message":"Login failed: 'admin' (Remote IP: '10.3.2.2')","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '88203')
        self.assertEqual(response.rule_level, 10)


    def test_nextcloud_logout_successful(self) -> None:
        log = r'''
{"reqId":"XaCAfP1v4@1xpIqlElMIVgAAAAk","level":1,"time":"October 11, 2019 13:15:40","remoteAddr":"127.0.0.1","user":"admin","app":"admin_audit","method":"GET","url":"\/index.php\/logout?requesttoken=RPYdKvrWwtB859EZQyfK%2F2DIu5l7HAqMrrNlcMzKoaM%3D%3AFLdvYq6atZJKgeFgEUSglQql0fsQaCHD68EjFKicleg%3D","message":"Logout occurred","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '88210')
        self.assertEqual(response.rule_level, 3)


    def test_nextcloud_authentication_successful(self) -> None:
        log = r'''
{"reqId":"XaQ6fxNN-waxXQIsoJHOTQAAAAE","level":1,"time":"October 14, 2019 09:06:07","remoteAddr":"127.0.0.1","user":"admin","app":"admin_audit","method":"POST","url":"\/index.php\/login?user=admin","message":"Login successful: \"admin\"","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '88211')
        self.assertEqual(response.rule_level, 3)


    def test_nextcloud_authentication_failed(self) -> None:
        log = r'''
{"reqId":"XaQ6ehNN-waxXQIsoJHOSgAAAAE","level":2,"time":"October 14, 2019 09:06:02","remoteAddr":"127.0.0.1","user":"--","app":"core","method":"POST","url":"\/index.php\/login","message":"Login failed: 'admin' (Remote IP: '10.3.2.2')","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '88212')
        self.assertEqual(response.rule_level, 6)


    def test_nextcloud_file_accessed(self) -> None:
        log = r'''
{"reqId":"XaCDUP1v4@1xpIqlElMIaQAAAAk","level":1,"time":"October 11, 2019 13:27:44","remoteAddr":"127.0.0.1","user":"admin","app":"admin_audit","method":"GET","url":"\/remote.php\/webdav\/Nextcloud%20Manual.pdf","message":"File accessed: \"\/Nextcloud Manual.pdf\"","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '88213')
        self.assertEqual(response.rule_level, 3)


    def test_nextcloud_file_created(self) -> None:
        log = r'''
{"reqId":"XaCDuMT03XAQReilx1Z76QAAAAU","level":1,"time":"October 11, 2019 13:29:28","remoteAddr":"127.0.0.1","user":"admin","app":"admin_audit","method":"PUT","url":"\/remote.php\/webdav\/logo.jpg","message":"File created: \"\/\/logo.jpg\"","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '88214')
        self.assertEqual(response.rule_level, 3)


    def test_nextcloud_file_deleted(self) -> None:
        log = r'''
{"reqId":"XaCDX3wkGUtETLC8cVWzdwAAAAI","level":1,"time":"October 11, 2019 13:27:59","remoteAddr":"127.0.0.1","user":"admin","app":"admin_audit","method":"DELETE","url":"\/remote.php\/dav\/files\/admin\/logo.png","message":"File deleted: \"\/logo.png\"","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '88215')
        self.assertEqual(response.rule_level, 3)


    def test_nextcloud_preview_accessed(self) -> None:
        log = r'''
{"reqId":"XaCCwMT03XAQReilx1Z75gAAAAU","level":1,"time":"October 11, 2019 13:25:20","remoteAddr":"127.0.0.1","user":"admin","app":"admin_audit","method":"GET","url":"\/index.php\/core\/preview?fileId=1780&x=1920&y=1080&a=true","message":"Preview accessed: \"\/logo.png\" (width: \"1920\", height: \"1080\" crop: \"\", mode: \"fill\")","userAgent":"Mozilla\/5.0 (X11; Linux x86_64) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/77.0.3865.120 Safari\/537.36","version":"16.0.5.1","@source":"NextCloud"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '88216')
        self.assertEqual(response.rule_level, 3)

