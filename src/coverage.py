#!/usr/bin/env python3

import ast
import os
import xml.etree.ElementTree as ET
from typing import Final

ENCODING: Final[str] = "utf-8"
BUILTIN_RULES_DIR: Final[str] = "/var/ossec/ruleset/rules"
CUSTOM_RULES_DIR: Final[str] = "./rules"
TESTS_ROOT: Final[str] = "./src/tests/regression_tests/custom"


def collect_rule_ids_from_rules(rules_dir: str) -> set[int]:
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
                        rule_ids.add(int(rule_id))
            except Exception as e:
                print(f"[WARN] Could not parse rule file {path}: {e}")
    return rule_ids


def collect_referenced_rule_ids_from_tests(test_root: str) -> tuple[set[int], int]:
    referenced_ids = set()
    test_func_count = 0

    for root, _, files in os.walk(test_root):
        for file in files:
            if not file.startswith("test_") or not file.endswith(".py"):
                continue

            path = os.path.join(root, file)
            try:
                with open(path, "r", encoding=ENCODING) as f:
                    tree = ast.parse(f.read(), filename=path)

                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                        test_func_count += 1
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
                            referenced_ids.add(int(val))

            except Exception as e:
                print(f"[WARN] Could not parse test file {path}: {e}")

    return referenced_ids, test_func_count


def report_coverage(defined_ids: set[int], tested_ids: set[int], test_func_count: int) -> None:
    uncovered = defined_ids - tested_ids
    coverage_percent = ((len(defined_ids) - len(uncovered)) / len(defined_ids)) * 100 if defined_ids else 0

    print("\n=== Wazuh Rule Coverage Report ===")
    print(f"Total rules defined: {len(defined_ids)}")
    print(f"Total test functions: {test_func_count}")
    print(f"Rules referenced in tests: {len(tested_ids)}")
    print(f"Coverage: {coverage_percent:.2f}%")

    if uncovered:
        print("\nUncovered Rule IDs:")
        for rule_id in sorted(uncovered):
            print(f"  - {rule_id}")


if __name__ == "__main__":

    # The BUILTIN_RULES_DIR is here for long term maintenance purposes.
    # User is not responsible for those tests.

    # if (not os.path.exists(BUILTIN_RULES_DIR)):
    #     raise FileNotFoundError(BUILTIN_RULES_DIR)
    if (not os.path.exists(CUSTOM_RULES_DIR)):
        raise FileNotFoundError(CUSTOM_RULES_DIR)
    if (not os.path.exists(TESTS_ROOT)):
        raise FileNotFoundError(TESTS_ROOT)

    # print("[*] Scanning built-in rules directory...")
    # builtin_rules = collect_rule_ids_from_rules(BUILTIN_RULES_DIR)
    # print(f"  [*] Found {len(builtin_rules)} rules...")

    print("[*] Scanning custom rules directory...")
    custom_rules = collect_rule_ids_from_rules(CUSTOM_RULES_DIR)
    print(f"  [*] Found {len(custom_rules)} rules...")

    # all_rule_ids = builtin_rules.union(custom_rules)
    all_rule_ids = custom_rules
    print("[*] Scanning test files...")
    referenced_ids, test_func_count = collect_referenced_rule_ids_from_tests(
        TESTS_ROOT)
    print(f"  [*] Found {len(referenced_ids)} rule IDs in tests...")

    print("[*] Generating report...")
    report_coverage(all_rule_ids, referenced_ids, test_func_count)
