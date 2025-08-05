#!/usr/bin/env python3

import ast
import os
import xml.etree.ElementTree as ET

ENCODING = "utf-8"
RULES_DIR = "./rules"
TESTS_ROOT = "./src/tests"


def collect_rule_ids_from_rules(rules_dir: str) -> set[str]:
    rule_ids = set()
    for root, _, files in os.walk(rules_dir):
        for file in files:
            if not file.endswith(".xml"):
                continue
            path = os.path.join(root, file)
            try:
                with open(path, "r", encoding=ENCODING) as f:
                    content = f.read()
                wrapped = f"<root>{content}</root>"
                tree = ET.fromstring(wrapped)
                for rule in tree.iter("rule"):
                    rule_id = rule.attrib.get("id")
                    if rule_id:
                        rule_ids.add(rule_id)
            except Exception as e:
                print(f"[WARN] Could not parse rule file {path}: {e}")
    return rule_ids


def collect_referenced_rule_ids_from_tests(test_root: str) -> set[str]:
    referenced_ids = set()

    for root, _, files in os.walk(test_root):
        for file in files:
            if not file.startswith("test_") or not file.endswith(".py"):
                continue

            path = os.path.join(root, file)
            try:
                with open(path, "r", encoding=ENCODING) as f:
                    tree = ast.parse(f.read(), filename=path)

                for node in ast.walk(tree):
                    if (
                        isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "assertEqual"
                        and len(node.args) == 2
                    ):
                        arg1, arg2 = node.args

                        def extract_literal_string(expr):
                            return str(expr.value).strip() if isinstance(expr, ast.Constant) and isinstance(expr.value, (str, int)) else None

                        def is_rule_id_access(expr):
                            return (
                                isinstance(expr, ast.Attribute)
                                and expr.attr == "rule_id"
                            )

                        # Case: assertEqual(<literal>, <X>.rule_id)
                        if is_rule_id_access(arg2):
                            val = extract_literal_string(arg1)
                        # Case: assertEqual(<X>.rule_id, <literal>)
                        elif is_rule_id_access(arg1):
                            val = extract_literal_string(arg2)
                        else:
                            val = None

                        if val:
                            referenced_ids.add(val)

            except Exception as e:
                print(f"[WARN] Could not parse test file {path}: {e}")

    return referenced_ids


def report_coverage(defined_ids: set[str], tested_ids: set[str]) -> None:
    uncovered = defined_ids - tested_ids
    coverage_percent = ((len(defined_ids) - len(uncovered)) / len(defined_ids)) * 100 if defined_ids else 0

    print("\n=== Wazuh Rule Coverage Report ===")
    print(f"Total rules defined: {len(defined_ids)}")
    print(f"Rules referenced in tests: {len(tested_ids)}")
    print(f"Coverage: {coverage_percent:.2f}%")

    if uncovered:
        print("\nUncovered Rule IDs:")
        for rule_id in sorted(uncovered):
            print(f"  - {rule_id}")


if __name__ == "__main__":
    print("[*] Scanning rules directory...")
    all_rule_ids = collect_rule_ids_from_rules(RULES_DIR)

    print("[*] Scanning test files...")
    referenced_ids = collect_referenced_rule_ids_from_tests(TESTS_ROOT)

    print("[*] Generating report...")
    report_coverage(all_rule_ids, referenced_ids)
