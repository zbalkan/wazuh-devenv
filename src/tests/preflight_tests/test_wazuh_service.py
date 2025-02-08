#!/usr/bin/python3

import os
import shutil
import subprocess
import unittest

from internal.logtest import LOGTEST_SOCKET, WazuhSocket


class TestWazuhService(unittest.TestCase):

    def test_1_wazuh_service_exists(self) -> None:
        with_systemd: bool = shutil.which("systemctl") is not None and run_command(
            ["systemctl", "list-unit-files", "wazuh-manager.service"])
        with_service = shutil.which("service") is not None and run_command(["service", "--status-all"]) and run_command(["bash", "-c", "service --status-all | grep -q wazuh-manager"])

        self.assertTrue(with_systemd or with_service)

    def test_2_logtest_socket_exists(self) -> None:
        assert os.path.exists(LOGTEST_SOCKET)

    def test_3_wazuh_service_running(self) -> None:
        running: bool = run_command(['pgrep', '-fl', 'wazuh-analysisd'])
        self.assertTrue(running)

    def test_4_logtest_socket_open(self) -> None:
        socket = WazuhSocket(LOGTEST_SOCKET)
        self.assertTrue(socket.is_socket_open())


def run_command(cmd) -> bool:
    """Runs a shell command and returns True if it executes successfully."""
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False
