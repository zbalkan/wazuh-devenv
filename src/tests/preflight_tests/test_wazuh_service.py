#!/usr/bin/python3

import os
import shutil
import subprocess
import unittest

from internal.logtest import LOGTEST_SOCKET, _WazuhLogtestHelpers


class TestWazuhService(unittest.TestCase):

    def test_1_wazuh_service_exists(self) -> None:
        with_systemd: bool = shutil.which("systemctl") is not None and run_command(
            ["systemctl", "list-unit-files", "wazuh-manager.service"])
        with_service = shutil.which("service") is not None and run_command(
            ["service", "--status-all"]) and run_command(["bash", "-c", "service --status-all | grep -q wazuh-manager"])

        self.assertTrue(expr=with_systemd or with_service,
                        msg="Wazuh service not found")

    def test_2_logtest_socket_exists(self) -> None:
        self.assertTrue(os.path.exists(LOGTEST_SOCKET),
                        msg="Wazuh logtest socket not found")

    def test_3_wazuh_service_running(self) -> None:
        running: bool = run_command(['pgrep', '-fl', 'wazuh-analysisd'])
        self.assertTrue(expr=running, msg="Wazuh service is not running")

    def test_4_logtest_socket_open(self) -> None:
        self.assertTrue(_WazuhLogtestHelpers.is_socket_open(),
                        msg="Wazuh logtest socket is not open")


def run_command(cmd: list[str]) -> bool:
    """Runs a shell command and returns True if it executes successfully."""
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False
