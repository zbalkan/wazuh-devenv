

import unittest
from lib.logtest import send_log

class TestCustomSSHRules(unittest.TestCase):

    def test_failed_login(self) -> None:
        log = 'Jun 30 23:58:38 debian sshd[13444]: Failed password for root from 112.85.42.146 port 56969 ssh2'
        response = send_log(log)
    
        self.assertEqual(response.decoder, 'sshd')
        self.assertEqual(response.rule_description, 'sshd: authentication failed.')
        self.assertEqual(response.rule_id, '5760')
        self.assertEqual(response.rule_level, '5')
        self.assertEqual(response.get_data_field(['dstuser']), 'root')
        self.assertEqual(response.get_data_field(['srcport']), '56969')
        self.assertEqual(response.get_data_field(['srcip']), '112.85.42.146')
        self.assertIn('syslog', response.rule_groups)
        self.assertIn('sshd', response.rule_groups)
        self.assertIn('authentication_failed', response.rule_groups)
        
        # Other tests
