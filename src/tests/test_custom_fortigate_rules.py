#!/usr/bin/python3
# -*- coding: utf-8 -*-
import unittest
from internal.logtest import send_log

class TestCustomFortigateRules(unittest.TestCase):

    def test_failed_login(self) -> None:
        log = 'date=2019-10-10 time=17:01:31 devname="FG111E-INFT2"'
        response = send_log(log)
    
        self.assertEqual(response.decoder, 'fortigate-custom')
        self.assertEqual(response.rule_description,
                         'Fortigate messages grouped.')
        self.assertEqual(response.rule_id, '222000')
        self.assertEqual(response.rule_level, 3)
        self.assertEqual(response.get_data_field(['date']), '2019-10-10')
        self.assertEqual(response.get_data_field(['time']), '17:01:31')
        self.assertEqual(response.get_data_field(['devname']), 'FG111E-INFT2')
        self.assertIn('custom', response.rule_groups)
        self.assertIn('fortigate', response.rule_groups)

        
        # Other tests
