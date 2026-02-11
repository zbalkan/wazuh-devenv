# wazuh-devenv

[![CodeQL Advanced](https://github.com/zbalkan/wazuh-devenv/actions/workflows/codeql.yml/badge.svg)](https://github.com/zbalkan/wazuh-devenv/actions/workflows/codeql.yml)
[![DevSkim](https://github.com/zbalkan/wazuh-devenv/actions/workflows/devskim.yml/badge.svg)](https://github.com/zbalkan/wazuh-devenv/actions/workflows/devskim.yml)
[![Wazuh unit testing](https://github.com/zbalkan/wazuh-devenv/actions/workflows/unit-testing.yml/badge.svg)](https://github.com/zbalkan/wazuh-devenv/actions/workflows/unit-testing.yml)

The project aims to create a development environment for detection engineers using Wazuh. While it is designed to utilize a `wazuh-manager` installed on WSL to allow testing custom rules locally before moving to production, it is possible to use a Linux VM for development as well. There is no WSL-specific configuration but no guarantees for the future.

## Installation

### For WSL

1. Ensure a WSL instance running in your environment. The distribution that matches the Production deployment is better.
2. Limit the WSL memory usage in `~/wsl.config` by adding `memory=16GB` or however you like. Wazuh is allocating as much memory as it can, so it is better to limit WSL as a whole.
3. Clone the repo to the preferred location for development. For me, using `~/wazuh-devenv` is easier.
4. Run the script `sudo ./install.sh` to start installation.
5. The script will ask you to copy your custom rules and decoders to the new locations. After you copied them, hit `y` and continue. Otherwise it will rollback the changes.
6. The script will ask you to provide the username you are going to use in WSL for development. Ensure you typed it correctly.
7. The installation and configuration will be completed successfully. If any error occurs, messages would be displayed for the user to fix the issues manually.
8. Initiate VS Code from the WSL for first engagement by navigating to the repository -such as `~/wazuh-devenv`, and typing `code .`. You don't have to keep the WSL terminal on afterwards.
9. Remove the origin from Github to prevent accidentally leaking your rules and decoders to public repositories by running `git remote rm origin`.
10. Add your organization's git repository for further use `git remote add origin <URL>`.
11. Initiate your preference of Python virtual environment.
12. You should be able to read and access rules from the repository. Add the rules and decoders to git.

### For Linux

1. Clone the repo to the preferred location for development. For me, using `~/wazuh-devenv` is easier.
2. Run the script `sudo ./install.sh` to start installation.
3. The script will ask you to copy rules and decoders to the new locations. After you copied them, hit `y` and continue. Otherwise it will rollback the changes.
4. The script will ask you to provide the username you are going to use for development. Ensure you typed it correctly.
5. The installation and configuration will be completed successfully. If any error occurs, messages would be displayed for the user to fix the issues manually.
6. Remove the origin from Github to prevent accidentally leaking your rules and decoders to public repositories by running `git remote rm origin`.
7. Add your organization's git repository for further use `git remote add origin <URL>`.
8. Initiate your preference of Python virtual environment.
9. You should be able to read and access rules from the repository. Add the rules and decoders to git.
10. Proceed with your choice of IDE.

You are ready to update and test your logs locally. You can combine the script into your CI/CD pipeline for deployment.

### CI/CD Usage

See the workflow file for an example.

## Sample rules

The sample rules are taken from the Wazuh blog [Creating decoders and rules from scratch](https://wazuh.com/blog/creating-decoders-and-rules-from-scratch/).

Mind the folder structure and semantics behind:

- `preflight_tests`: These are tests you should not touch. They check correct file permissions and Wazuh service availability.
- `regression_tests`: These tests are the ones you must focus on.
  - builtin: These are generated from the INI-formatted tests from Wazuh repository. I developed a [test generator](https://github.com/zbalkan/wazuh_test_generator) for this, then manually fixed remaining problems, and pasted the test code into this repository. Yo do not need to touch this folder.
  - custom: This is the place you must write the tests for your custom rules. It is under regression tests as they are testing **whether your rules are working or not after changes**.
- `behavioral_tests`: This directory is designed for Breach and Attack Simulations or advanced testing scenarios. You can read this old article on [testing Wazuh with Atomic Red Team](https://wazuh.com/blog/emulation-of-attck-techniques-and-detection-with-wazuh/). This is an advanced case and out of scope of this article.

## Usage

### Running tests

#### Using tester app

This is the basic way and it is designed to run tests in an order: preflight tests first, then the others.

```shell
usage: tester.py [-h] [--disable-builtin] [--disable-custom] [--disable-behavioral] [--verbosity {0,1,2}]

wazuh-devenv tester (0.2) is a Wazuh rule and decoder testing tool.

options:
  -h, --help            show this help message and exit
  --disable-builtin     Disable running built-in rule tests for regression. Enabled by default.
  --disable-custom      Disable running custom rule tests for regression. Enabled by default.
  --disable-behavioral  Disable running behavioral tests. Enabled by default.
  --verbosity {0,1,2}   Set verbosity level for test output (0, 1, or 2). Default is 1.
```

#### Using VS Code Test Explorer

Navigate to `View > Testing` and explore the tests in the repository.

### Writing tests

All custom tests should be placed in the `src/tests/regression_tests/custom/` directory. Test files must start with `test_` to be discovered by the test runner.
Here is a basic template for a new test file, for example `test_my_new_rule.py`:

```python
import unittest
from internal.logtest import send_log, send_multiple_logs, LogtestResponse, LogtestStatus


class TestMyNewRule(unittest.TestCase):

    def test_single_log_triggers_alert(self):
        """
        Tests if a specific log message triggers the expected rule.
        """
        # 1. Define the log message you want to test
        log = "sshd: Invalid user admin from 192.168.1.100"

        # 2. Send the log to the logtest engine
        response: LogtestResponse = send_log(log)

        # 3. Assert the results
        # Check that a rule matched
        self.assertEqual(response.status, LogtestStatus.RuleMatch)
        
        # Check that the correct rule ID was triggered
        self.assertEqual(response.rule_id, "5710") # Replace with your custom rule ID

        # (Optional) Check the alert level
        self.assertEqual(response.rule_level, 5)

    def test_multiple_logs_for_stateful_rule(self):
        """
        Tests a stateful rule that requires multiple events to trigger.
        """
        # 1. Define the sequence of log messages
        logs = [
            "sshd: Failed password for invalid user user1 from 1.2.3.4 port 1234 ssh2",
            "sshd: Failed password for invalid user user2 from 1.2.3.4 port 1234 ssh2",
            "sshd: Failed password for invalid user user3 from 1.2.3.4 port 1234 ssh2",
            "sshd: Failed password for invalid user user4 from 1.2.3.4 port 1234 ssh2"
        ]

        # 2. Send the sequence of logs in a single session
        responses = send_multiple_logs(logs)

        # 3. Assert the result of the FINAL event
        # The last response should contain the stateful alert
        last_response = responses[-1]
        self.assertEqual(last_response.status, LogtestStatus.RuleMatch)
        self.assertEqual(last_response.rule_id, "5712") # Replace with your composite rule ID
```

### Test coverage

```shell
usage: coverage.py.
```

The script does not accept any arguments. It scans the `rules` directory, collects the defined rule IDs, then compare against the tests. Coverage script expectes a line that has a variable of type `LogtestResponse`, and looking for a comparison of `rule_id` attribute with a non-empty string. The name of the variable does not matter.

```python
        response = send_log(log)
        self.assertEqual(response.rule_id, '410')
```

In the end, you will see a simple report like this:

```text
[*] Scanning custom rules directory...
  [*] Found 2 rules...
[*] Scanning test files...
  [*] Found 1 rule IDs in tests...
[*] Generating report...

=== Wazuh Rule Coverage Report ===
Total rules defined: 2
Total test functions: 1
Rules referenced in tests: 1
Coverage: 50.00%

Uncovered Rule IDs:
  - 222016
```

### Test generator

Test generator is moved to the original [wazuh-testgen](https://github.com/zbalkan/wazuh-testgen) project. You can clone that repository and use many ways to generate tests or test templates.

## VS Code configuration

If you are using VS Code, you can use the debug configuration `sample.launch.json` as a starter. Copy the file under `.vscode/` folder and rename the file `launch.json`.

## Logs

You can find the tester logs in `/tmp/tester.log`.

```plaintext
2025-02-08T19:27:50+0000:root:INFO:Starting tester v0.1
2025-02-08T19:27:50+0000:root:INFO:tester (0.1) is a Wazuh rule and decoder testing tool.
2025-02-08T19:27:50+0000:root:INFO:{"test_result": {"status": "FAILED", "ran": 8, "successful": 7, "failed": 1, "errored": 0, "failures": ["test_1_wazuh_service_exists (tests.preflight_tests.test_wazuh_service.TestWazuhService.test_1_wazuh_service_exists)"], "errors": []}}
2025-02-08T19:27:50+0000:root:ERROR:Preflight tests failed. Exiting.
2025-02-08T19:55:10+0000:root:INFO:Starting tester v0.1
2025-02-08T19:55:10+0000:root:INFO:tester (0.1) is a Wazuh rule and decoder testing tool.
2025-02-08T19:55:13+0000:root:INFO:{"test_result": {"status": "OK", "ran": 8, "successful": 8, "failed": 0, "errored": 0, "failures": [], "errors": []}}
2025-02-08T20:13:27+0000:root:INFO:{"test_result": {"status": "OK", "ran": 1635, "successful": 1635, "failed": 0, "errored": 0, "failures": [], "errors": []}}
2025-02-08T20:13:28+0000:root:INFO:{"test_result": {"status": "OK", "ran": 2, "successful": 2, "failed": 0, "errored": 0, "failures": [], "errors": []}}
2025-02-08T20:13:28+0000:root:INFO:{"test_result": {"status": "OK", "ran": 0, "successful": 0, "failed": 0, "errored": 0, "failures": [], "errors": []}}
2025-02-08T20:13:28+0000:root:INFO:Exiting.
```

## Permissions

When you add new files, you must ensure the file permissions are set as expected. The expected permissions are `660` and owners are `wazuh:wazuh`. Hence, your user is added to the members of `wazuh` group for easier coexistence.

There are unit tests for file permissions to help the user. If the tests fail, you can check for the root cause and then fix the ownership and permissions. You can use this snippet below whenever you need it for simplicity. You will need `sudo` as the parent folder ownership is set as `root:wazuh`.

```shell
decoders_dir=$(realpath ./decoders)
rules_dir=$(realpath ./rules)
chown wazuh:wazuh "$rules_dir"/*
chmod 660 "$rules_dir"/*
chown wazuh:wazuh "$decoders_dir"/*
chmod 660 "$decoders_dir"/*
```

These commands are already provided in the `fix_permissions.sh`. **Whenever you add a new file, use `sudo ./fix_permissions.sh` to ensure correct behavior**. Otherwise, you will see prefileght checks failing.

If your filesystem supports ACLs, `setfacl` is a good helper. Using the commands, you can ensure the future files will use the correct permissions. Since it is not universal, this change is optional.

```shell
# Set default ACLs to enforce wazuh:wazuh ownership and 660 permissions for future files
setfacl -d -m u:wazuh:rwx,g:wazuh:rwx "$decoders_dir"
setfacl -d -m o::--- "$decoders_dir"

# Set default ACLs to enforce wazuh:wazuh ownership and 660 permissions for future files
setfacl -d -m u:wazuh:rwx,g:wazuh:rwx "$rules_dir"
setfacl -d -m o::--- "$rules_dir"
```

## Notes

- Be aware that the *local_decoder.xml* and *local_rules.xml* are ignored by git as they will be the first files to be added when you copy the files. It is suggested to use a clear naming convention instead of these files.
- The builtin rules of Wazuh are included in the repository but it is recommended to disable them during development for faster testing of custom rules. It is suggested to enable testing builtin rules during CI/CD for more coverage.
- I find the INI tests in the Wazuh repo complicated as they can be separate tests or simulating multiple log sending. In this case I used `send_log` and `send_multiple_logs` as different test methods to simulate different behaviors. This is the case for some tests that are testing triggers of multiple alerts.
- The tests below are testing the syntax and behavior for decoders and rules, not the detections. They must be tested by the Wazuh devs, not users. So they are ignored.

| Tests | Rules and decoders |
|-------|--------------------|
| overwrite.ini<br>test_expr_negation_geoip.ini<br>test_expr_negation.ini<br>test_features.ini<br>test_osmatch_regex.ini<br>test_osregex_regex_geoip.ini<br>test_osregex_regex.ini<br>test_pcre2_regex_geoip.ini<br>test_pcre2_regex.ini<br>test_static_filters_geoip.ini<br>test_static_filters.ini | test_decoders.xml<br>test_expr_negation_decoders.xml<br>test_expr_negation_geoip_rules.xml<br>test_expr_negation_rules.xml<br>test_osmatch_regex_decoders.xml<br>test_osmatch_regex_rules.xml<br>test_osregex_regex_decoders.xml<br>test_osregex_regex_geoip_rules.xml<br>test_osregex_regex_rules.xml<br>test_overwrite_decoders.xml<br>test_overwrite_rules.xml<br>test_pcre2_regex_decoders.xml<br>test_pcre2_regex_geoip_rules.xml<br>test_pcre2_regex_rules.xml<br>test_rules.xml<br>test_static_filters_decoders.xml<br>test_static_filters_rules.xml |

## References

- [Detection-as-Code for Wazuh 4.x: A Practical Implementation Model](https://zaferbalkan.com/wazuh-devenv/) 
- [Detection-as-Code for Wazuh 4.x: Log replay for behavioral testing](https://zaferbalkan.com/log-replay/)
- [Detection-as-Code for Wazuh 4.x: Part 0](https://zaferbalkan.com/detection-engineering/)
