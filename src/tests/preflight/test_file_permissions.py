#!/usr/bin/python3
# -*- coding: utf-8 -*-
import grp
import os
import pwd
import stat
import pytest


def get_file_permissions(file_path):
    """Retrieve file permissions, owner, and group of a file."""
    # Check if the file exists
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    # Get file's actual stat info
    file_stat = os.stat(file_path)

    # Get actual file mode (permissions)
    permissions = stat.S_IMODE(file_stat.st_mode)

    # Get actual owner and group names
    owner = pwd.getpwuid(file_stat.st_uid).pw_name
    group = grp.getgrgid(file_stat.st_gid).gr_name

    return permissions, owner, group


@pytest.fixture
def file_permissions_data():
    """Fixture for commonly used paths and expected values."""
    return {
        "rules_path": "./rules",
        "decoders_path": "./decoders",
        "expected_permissions": 0o660,  # Example: rw-rw----
        "expected_owner": "wazuh",
        "expected_group": "wazuh"
    }


def test_rules_folder_exists(file_permissions_data):
    # Test if the rules folder exists
    assert os.path.exists(file_permissions_data["rules_path"]), \
        f"File not found: {file_permissions_data['rules_path']}"


def test_decoders_folder_exists(file_permissions_data):
    # Test if the decoders folder exists
    assert os.path.exists(file_permissions_data["decoders_path"]), \
        f"File not found: {file_permissions_data['decoders_path']}"


def test_rule_permissions(file_permissions_data):
    # Check permissions, owner, and group for files in the rules path
    for root, _, files in os.walk(file_permissions_data["rules_path"]):
        for file in files:
            path = os.path.join(root, file)
            permissions, owner, group = get_file_permissions(path)

            # Assert file permissions, owner, and group
            assert permissions == file_permissions_data["expected_permissions"], \
                f"Permissions for {path} are {oct(permissions)}, expected {oct(file_permissions_data['expected_permissions'])}"
            assert owner == file_permissions_data["expected_owner"], \
                f"Owner for {path} is {owner}, expected {file_permissions_data['expected_owner']}"
            assert group == file_permissions_data["expected_group"], \
                f"Group for {path} is {group}, expected {file_permissions_data['expected_group']}"


def test_decoder_permissions(file_permissions_data):
    # Check permissions, owner, and group for files in the decoders path
    for root, _, files in os.walk(file_permissions_data["decoders_path"]):
        for file in files:
            path = os.path.join(root, file)
            permissions, owner, group = get_file_permissions(path)

            # Assert file permissions, owner, and group
            assert permissions == file_permissions_data["expected_permissions"], \
                f"Permissions for {path} are {oct(permissions)}, expected {oct(file_permissions_data['expected_permissions'])}"
            assert owner == file_permissions_data["expected_owner"], \
                f"Owner for {path} is {owner}, expected {file_permissions_data['expected_owner']}"
            assert group == file_permissions_data["expected_group"], \
                f"Group for {path} is {group}, expected {file_permissions_data['expected_group']}"
