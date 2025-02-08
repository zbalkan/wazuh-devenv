#!/usr/bin/python3
# -*- coding: utf-8 -*-
import os
import subprocess
import unittest

from internal.logtest import LOGTEST_SOCKET, WazuhSocket


class TestWazuhService(unittest.TestCase):

    def test_1_wazuh_service_exists(self) -> None:
        if_systemctl = os.path.exists('/etc/systemd/system/wazuh-manager.service')
        if_initd = os.path.exists('/etc/init.d/wazuh-manager')
        self.assertTrue(if_systemctl or if_initd)

    def test_2_logtest_socket_exists(self) -> None:
        assert os.path.exists(LOGTEST_SOCKET)

    def test_3_wazuh_service_running(self) -> None:
        # Run the pgrep command with -fl to match the process name and show the full command line
        result = subprocess.run(['pgrep', '-fl', 'wazuh-analysisd'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)

        # Check if any output was returned, meaning processes were found
        self.assertNotEqual(result.stdout, '')

    def test_4_logtest_socket_open(self) -> None:
        socket = WazuhSocket(LOGTEST_SOCKET)
        self.assertTrue(socket.is_socket_open())
