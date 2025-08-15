#!/usr/bin/python3

import unittest

from internal.logtest import LogtestStatus, send_log


class TestCustomFortigateRules(unittest.TestCase):

    def test_basic_log(self) -> None:
        log = 'date=2019-10-10 time=17:01:31 devname="FG111E-INFT2"'
        response = send_log(log)

        # Test the response

        # Ensure there is a rule match
        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        # Ensure there is a decoder matching
        self.assertEqual(response.decoder, 'fortigate-custom')

        # Ensure the rule information is descriptive
        self.assertEqual(response.rule_description,
                         'Fortigate messages grouped.')

        # Use an availabe rule ID
        self.assertEqual(response.rule_id, '222000')

        # Ensure the rule level is correct
        self.assertEqual(response.rule_level, 3)

        # Ensure the parsed data is correct
        self.assertEqual(
            response.get_dynamic_field_value('date'), '2019-10-10')
        self.assertEqual(response.get_dynamic_field_value('time'), '17:01:31')
        self.assertEqual(response.get_dynamic_field_value(
            'devname'), 'FG111E-INFT2')

        # Ensure the rule groups are correct
        self.assertIn('custom', response.rule_groups)
        self.assertIn('fortigate', response.rule_groups)
