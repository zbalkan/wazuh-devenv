#!/usr/bin/env python3

import os
import sys
import xml.etree.ElementTree as ET
from typing import Final

ENCODING: Final[str] = "utf-8"
TEST_CLASS_NAME: Final[str] = "TestGeneratedRules"
PLACEHOLDER_LOG: Final[str] = "TODO: provide a matching log here"


def collect_rules_from_file(rule_file: str) -> list[dict]:
    rules = []
    try:
        with open(rule_file, "r", encoding=ENCODING) as f:
            content = f.read()
        wrapped = f"<root>{content}</root>"
        tree = ET.fromstring(wrapped)

        for rule in tree.iter("rule"):
            rule_id = rule.attrib.get("id")
            level = rule.attrib.get("level")
            description = rule.findtext("description", "").strip()
            groups = []

            group_elem = rule.find("group")
            if group_elem is not None and group_elem.text:
                groups.extend(g.strip()
                              for g in group_elem.text.split(",") if g.strip())

            rule_entry = {
                "id": rule_id,
                "level": level,
                "description": description,
                "groups": groups
            }
            rules.append(rule_entry)
    except Exception as e:
        print(
            f"[ERROR] Could not parse rule file {rule_file}: {e}", file=sys.stderr)
    return rules


def generate_unit_test_code(rules: list[dict]) -> str:
    lines = [
        "import unittest",
        "from internal.logtest import LogtestStatus, send_log",
        "",
        "# TODO: Rename the class",
        f"class {TEST_CLASS_NAME}(unittest.TestCase):",
        ""
    ]

    for rule in rules:
        rule_id = rule["id"]
        level = rule["level"]
        description = rule["description"].replace('"', '\\"')
        groups = rule["groups"]

        lines.append(f"    def test_rule_{rule_id}(self):")
        lines.append(f"        log = r'''{PLACEHOLDER_LOG}'''")
        lines.append("        response = send_log(log)")
        lines.append("")
        lines.append(
            "        self.assertEqual(response.status, LogtestStatus.RuleMatch)")
        lines.append(
            f"        self.assertEqual(response.rule_id, '{rule_id}')")
        lines.append(f"        self.assertEqual(response.rule_level, {level})")
        lines.append(
            f"        self.assertEqual(response.rule_description, \"{description}\")")
        for group in groups:
            lines.append(
                f"        self.assertIn('{group}', response.rule_groups)")
        lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: generate_tests.py <path/to/rule_file.xml>", file=sys.stderr)
        sys.exit(1)

    rule_file_path = sys.argv[1]
    if not os.path.exists(rule_file_path):
        print(f"[ERROR] File not found: {rule_file_path}", file=sys.stderr)
        sys.exit(2)

    rules = collect_rules_from_file(rule_file_path)
    test_code = generate_unit_test_code(rules)
    print(test_code)
