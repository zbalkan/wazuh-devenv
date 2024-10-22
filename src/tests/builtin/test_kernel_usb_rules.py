#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from kernel_usb.ini
class TestKernel_usbRules(unittest.TestCase):

    def test_kernel_usb_attach_usb(self) -> None:
        log = '''Mar 23 15:04:52 manager kernel: usb 1-1: New USB device found, idVendor=0930, idProduct=6544'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '81101')
        self.assertEqual(response.rule_level, 3)


    def test_kernel_usb_attach_usb_with_kernel_id(self) -> None:
        log = '''Mar 23 15:04:52 manager kernel: [62828.333722] usb 1-1: New USB device found, idVendor=0930, idProduct=6544'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '81101')
        self.assertEqual(response.rule_level, 3)


    def test_kernel_usb_attach_usb_with_kernel_id_and_blank_spaces(self) -> None:
        log = '''Mar 15 23:14:34 manager kernel: [ 195.634715] usb 1-1: New USB device found, idVendor=0bda, idProduct=568a, bcdDevice=65.10'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '81101')
        self.assertEqual(response.rule_level, 3)


    def test_kernel_usb_disconnect_usb(self) -> None:
        log = '''Mar 23 15:05:23 manager kernel: usb 1-1: USB disconnect, device number 2'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '81102')
        self.assertEqual(response.rule_level, 3)


    def test_kernel_usb_disconnect_usb_with_kernel_id(self) -> None:
        log = '''Mar 23 15:05:23 manager kernel: [62859.373865] usb 1-1: USB disconnect, device number 2'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '81102')
        self.assertEqual(response.rule_level, 3)


    def test_kernel_usb_disconnect_usb_with_kernel_id_and_blank_spaces(self) -> None:
        log = '''Mar 23 15:05:23 manager kernel: [  259.373865] usb 1-1: USB disconnect, device number 2'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'kernel')
        self.assertEqual(response.rule_id, '81102')
        self.assertEqual(response.rule_level, 3)

