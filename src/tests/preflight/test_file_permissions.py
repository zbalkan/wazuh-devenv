#!/usr/bin/python3
# -*- coding: utf-8 -*-
import grp
import os
import pwd
import stat
import unittest


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


class TestFilePermissions(unittest.TestCase):
    def setUp(self) -> None:
        # Define the file path and expected values
        self.rules_path = "./rules"
        self.decoders_path = "./decoders"
        self.expected_permissions = 0o660  # Example: rwxr-xr-x
        self.expected_owner = "wazuh"       # Expected owner
        self.expected_group = "wazuh"       # Expected group

    def test_rules_folder_exists(self) -> None:
        # Test if the file exists
        self.assertTrue(os.path.exists(self.rules_path),
                        f"File not found: {self.rules_path}")

    def test_decoders_folder_exists(self) -> None:
        # Test if the file exists
        self.assertTrue(os.path.exists(self.decoders_path),
                        f"File not found: {self.decoders_path}")

    def test_rule_permissions(self) -> None:

        for root, dirs, files in os.walk(self.rules_path):
            for file in files:
                path: str = os.path.join(root, file)

                # Test file permissions, owner, and group
                permissions, owner, group = get_file_permissions(path)

                # Assert that the permissions are correct
                self.assertEqual(permissions, self.expected_permissions,
                                f"Permissions for {path} are {oct(permissions)}, expected {oct(self.expected_permissions)}")

                # Assert that the owner is correct
                self.assertEqual(owner, self.expected_owner,
                                f"Owner for {path} is {owner}, expected {self.expected_owner}")

                # Assert that the group is correct
                self.assertEqual(group, self.expected_group,
                                f"Group for {path} is {group}, expected {self.expected_group}")

    def test_decoder_permissions(self) -> None:

        for root, dirs, files in os.walk(self.decoders_path):
            for file in files:
                path: str = os.path.join(root, file)

                # Test file permissions, owner, and group
                permissions, owner, group = get_file_permissions(path)

                # Assert that the permissions are correct
                self.assertEqual(permissions, self.expected_permissions,
                                 f"Permissions for {path} are {oct(permissions)}, expected {oct(self.expected_permissions)}")

                # Assert that the owner is correct
                self.assertEqual(owner, self.expected_owner,
                                 f"Owner for {path} is {owner}, expected {self.expected_owner}")

                # Assert that the group is correct
                self.assertEqual(group, self.expected_group,
                                 f"Group for {path} is {group}, expected {self.expected_group}")
