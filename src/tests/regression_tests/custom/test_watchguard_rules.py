import unittest

import internal.logtest as lt


# TODO: Rename the class
class LocalRules(unittest.TestCase):

    def test_rule_110000(self) -> None:
        logs = [
            r'''2025-11-21T00:28:01.556323+00:00 D1-ROM1-FW-A 80D802B41D509 D1-ROM1-FW firewall: msg_id="3000-0148" Allow Collector Firebox 73 udp 20 64 10.x.x.x 208.x.x.x 46616 53  geo_dst="USA" record_type="AAAA" question="mail.mydomain.com"  (DNS-00)''',
            r'''2025-11-21T00:28:01.556528+00:00 D1-ROM1-FW-A 80D802B41D509 D1-ROM1-FW firewall: msg_id="3000-0148" Deny WAN - Aruba Firebox 40 tcp 20 239 194.x.x.x 209.x.x.x 41277 591 offset 5 S 1497867397 win 4  geo_src="BGR"  geo_dst="ITA" flags="SR" duration="0" sent_pkts="1" rcvd_pkts="0" sent_bytes="40" rcvd_bytes="0"  (Unhandled External Packet-00)''',
            r'''2025-11-21T00:28:01.946033+00:00 D1-ROM1-FW-A 80D802B41D509 D1-ROM1-FW https-proxy[4148]: msg_id="2CFF-0000" Allow Collector WAN - Aruba tcp 10.x.x.x 213.x.x.x 42018 443 msg="HTTPS Request" proxy_act="Default-HTTPS-Client" tls_profile="TLS-Client-HTTPS.Standard" ...'''
        ]

        responses = lt.send_multiple_logs(logs)

        for response in responses:
            self.assertEqual(response.status, lt.LogtestStatus.RuleMatch)
            self.assertIn('Watchguard', response.rule_groups)  # type: ignore

    def test_rule_110001(self) -> None:
        log = r'''2025-11-21T00:28:01.556528+00:00 D1-ROM1-FW-A 80D802B41D509 D1-ROM1-FW firewall: msg_id="3000-0148" Deny WAN - Aruba Firebox 40 tcp 20 239 194.x.x.x 209.x.x.x 41277 591 offset 5 S 1497867397 win 4  geo_src="BGR"  geo_dst="ITA" flags="SR" duration="0" sent_pkts="1" rcvd_pkts="0" sent_bytes="40" rcvd_bytes="0"  (Unhandled External Packet-00)'''
        response = lt.send_log(log)

        self.assertEqual(response.status, lt.LogtestStatus.RuleMatch)
        self.assertEqual(response.rule_id, '110001')
        self.assertEqual(response.rule_level, 5)
        self.assertEqual(response.rule_description, "Packet Was Denied.")
        self.assertIn('Watchguard', response.rule_groups)  # type: ignore

    def test_rule_110002(self) -> None:
        log = r'''2025-11-21T00:28:01.556323+00:00 D1-ROM1-FW-A 80D802B41D509 D1-ROM1-FW firewall: msg_id="3000-0148" Allow Collector Firebox 73 udp 20 64 10.x.x.x 208.x.x.x 46616 53  geo_dst="USA" record_type="AAAA" question="mail.mydomain.com"  (DNS-00)'''
        response = lt.send_log(log)

        self.assertEqual(response.status, lt.LogtestStatus.RuleMatch)
        self.assertEqual(response.rule_id, '110002')
        self.assertEqual(response.rule_level, 5)
        self.assertEqual(response.rule_description, "Packet Was Allowed.")
        self.assertIn('Watchguard', response.rule_groups)  # type: ignore
