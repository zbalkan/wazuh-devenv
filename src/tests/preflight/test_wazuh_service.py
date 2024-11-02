#!/usr/bin/python3
# -*- coding: utf-8 -*-
import os
import subprocess
import pytest
from internal.logtest import LOGTEST_SOCKET, WazuhSocket


def test_wazuh_service_exists() -> None:
    """Check if Wazuh service exists in systemd or init.d."""
    if_systemctl = os.path.exists('/etc/systemd/system/wazuh-manager.service')
    if_initd = os.path.exists('/etc/init.d/wazuh-manager')
    assert if_systemctl or if_initd, "Wazuh service is not installed."


def test_logtest_socket_exists() -> None:
    """Verify that the logtest socket exists."""
    assert os.path.exists(
        LOGTEST_SOCKET), f"Logtest socket not found at {LOGTEST_SOCKET}"


def test_wazuh_service_running() -> None:
    """Check if Wazuh service is running."""
    result = subprocess.run(
        ['pgrep', '-fl', 'wazuh-analysisd'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False
    )
    assert result.stdout != '', "Wazuh analysisd process is not running."


def test_logtest_socket_open() -> None:
    """Verify that the logtest socket is open."""
    socket = WazuhSocket(LOGTEST_SOCKET)
    assert socket.is_socket_open(), "Logtest socket is not open."
