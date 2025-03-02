# wazuh-devenv

The project aims to create a development environment for detection engineers using Wazuh. While it is designed to utilize a `wazuh-manager` installed on WSL to allow testing custom rules locally before moving to production, it is possible to use a Linux VM for development as well. There is no WSL-specific configuration but no guarantees for the future.

## Setup for WSL

1. Ensure a WSL instance running in your environment. The distribution that matches the Production deployment is better.
2. Limit the WSL memory usage in `~/wsl.config` by adding `memory=16GB` or however you like. Wazuh is allocating as much memory as it can, so it is better to limit WSL as a whole. 
3. Clone the repo to the preferred location for development. For me, using `~/wazuh-devenv` is easier.
4. Run the script `sudo ./install.sh` to start installation.
5. The script will ask you to copy rules and decoders to the new locations. After you copied them, hit `y` and continue. Otherwise it will rollback the changes.
6. The script will ask you to provide the username you are going to use in WSL for development. Ensure you typed it correctly.
7. The installation and configuration will be completed successfully. If any error occurs, messages would be displayed for the user to fix the issues manually.
8. Initiate VS Code from the WSL for first engagement by navigating to the repository -such as `~/wazuh-devenv`, and typing `code .`. You don't have to keep the WSL terminal on afterwards.
9. Remove the origin from Github to prevent accidentally leaking your rules and decoders to public repositories by running `git remote rm origin`.
10. Add your organization's git repository for further use `git remote add origin <URL>`.
11. Initiate your preference of Python virtual environment.
12. You should be able to read and access rules from the repository. Add the rules and decoders to git.

You are ready to update and test your logs locally. You can combine the script into your CI/CD pipeline for deployment.

## Sample rules

The sample rules are taken from the Wazuh blog [Creating decoders and rules from scratch](https://wazuh.com/blog/creating-decoders-and-rules-from-scratch/).

## Usage

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

If you are using VS Code, you can use this debug configuration as a starter:

```json
{
    // Use IntelliSense to learn about possible attributes.
    // Hover to view descriptions of existing attributes.
    // For more information, visit: https://go.microsoft.com/fwlink/?linkid=830387
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Run all tests",
            "type": "debugpy",
            "request": "launch",
            "program": "src/tester.py",
            "console": "integratedTerminal",
        },
        {
            "name": "Disable built-in",
            "type": "debugpy",
            "request": "launch",
            "program": "src/tester.py",
            "console": "integratedTerminal",
            "args": [
                "--disable-builtin"
            ]
        },
        {
            "name": "Disable custom",
            "type": "debugpy",
            "request": "launch",
            "program": "src/tester.py",
            "console": "integratedTerminal",
            "args": [
                "--disable-builtin"
            ]
        },
        {
            "name": "Disable behavioral",
            "type": "debugpy",
            "request": "launch",
            "program": "src/tester.py",
            "console": "integratedTerminal",
            "args": [
                "--disable-behavioral"
            ]
        },
        {
            "name": "Preflight + behavioral",
            "type": "debugpy",
            "request": "launch",
            "program": "src/tester.py",
            "console": "integratedTerminal",
            "args": [
                "--disable-builtin",
                "--disable-custom"
            ]
        },
        {
            "name": "Preflight + custom",
            "type": "debugpy",
            "request": "launch",
            "program": "src/tester.py",
            "console": "integratedTerminal",
            "args": [
                "--disable-behavioral",
                "--disable-builtin"
            ]
        },
        {
            "name": "Only preflight",
            "type": "debugpy",
            "request": "launch",
            "program": "src/tester.py",
            "console": "integratedTerminal",
            "args": [
                "--disable-behavioral",
                "--disable-builtin",
                "--disable-custom"
            ]
        },
        {
            "name": "Help",
            "type": "debugpy",
            "request": "launch",
            "program": "src/tester.py",
            "console": "integratedTerminal",
            "args": [
                "-h"
            ]
        }
    ]
}
```
## Logs

You can find the tester logs in `/var/ossec/logs/tester.log`.

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

There are unit tests for file permissions to help the user. If the tests fail, you can check for the root cause and then fix the ownership and permissions.

You can use this snippet below whenever you need it for simplicity. You will need `sudo` as the parent folder ownership is set as `root:wazuh`.

```shell
decoders_dir=$(realpath ./decoders)
rules_dir=$(realpath ./rules)
chown wazuh:wazuh "$rules_dir"/*
chmod 660 "$rules_dir"/*
chown wazuh:wazuh "$decoders_dir"/*
chmod 660 "$decoders_dir"/*
```

These commands are already provided in the `fix_permissions.sh`.

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

* Be aware that the *local_decoder.xml* and *local_rules.xml* are ignored by git as they will be the first files to be added when you copied the files. It is suggested to use a clear naming convention instead of these files.
* The builtin rules of Wazuh are included in the repository but it is recommended to disable them during development for faster testing of custom rules. It is suggested to enable testing builtin rules during CI/CD for more coverage.
* The INI tests are complicated as they can be separate tests or simulating multiple log sending. In our case we used `send_log` and `send_multiple_logs` as different test methods to simulate different behaviors. This is the case for some tests that are testing triggers of multiple alerts.
* The tests below are testing the syntax and behavior for decoders and rules, not the detections. They must be tested by the Wazuh devs, not users. So they are ignored.

| Tests | Rules and decoders |
|-------|--------------------|
| overwrite.ini<br>test_expr_negation_geoip.ini<br>test_expr_negation.ini<br>test_features.ini<br>test_osmatch_regex.ini<br>test_osregex_regex_geoip.ini<br>test_osregex_regex.ini<br>test_pcre2_regex_geoip.ini<br>test_pcre2_regex.ini<br>test_static_filters_geoip.ini<br>test_static_filters.ini | test_decoders.xml<br>test_expr_negation_decoders.xml<br>test_expr_negation_geoip_rules.xml<br>test_expr_negation_rules.xml<br>test_osmatch_regex_decoders.xml<br>test_osmatch_regex_rules.xml<br>test_osregex_regex_decoders.xml<br>test_osregex_regex_geoip_rules.xml<br>test_osregex_regex_rules.xml<br>test_overwrite_decoders.xml<br>test_overwrite_rules.xml<br>test_pcre2_regex_decoders.xml<br>test_pcre2_regex_geoip_rules.xml<br>test_pcre2_regex_rules.xml<br>test_rules.xml<br>test_static_filters_decoders.xml<br>test_static_filters_rules.xml |
