# wazuh-devenv

The project utilizes of a wazuh-manager installed on WSL, allowing testing custom rules locally before moving to production.

# Setup

1. Ensure a WSL instance running in your environment. The distribution that matches the Production deployment is better.
2. Clone the repo to the preferred location for development.
3. Install Wazuh server aka wazuh-manager on WSL.
  1. Ignore the certificate creation and filebeat steps. We will not have an indexer.
  2. Continue installing Wazuh server following the [official documentation](https://documentation.wazuh.com/current/installation-guide/wazuh-server/step-by-step.html).
4. Update `/var/ossec/etc/ossec.conf/` with `<logall_json>yes</logall_json>` and `<log_format>plain,json</log_format>`. JSON is easier to work with.
5. Copy the custom rules to the `rules` directory in the repository and fix the permissions:
```shell
  chown root:wazuh ./rules
  chmod 770 ./rules
  chown wazuh:wazuh ./rules/*
  chmod 660 ./rules/*
```
6. Remove custom rules  under `/var/ossec/etc/rules`.
7. Copy the custom decoders to the `decoders` directory in the repository and fix the permissions
```shell
chown root:wazuh ./decoders
chmod 770 ./decoders
chown wazuh:wazuh ./decoders/*
chmod 660 ./decoders/*
```
8. Remove custom decoders  under `/var/ossec/etc/decoders`.
9. Create a mount point for decoders and rules by adding these lines below to `/etc/fstab`:
```bash
/path/to/wazuh-devenv/decoders /var/ossec/etc/decoders none bind 0 0
/path/to/wazuh-devenv/rules /var/ossec/etc/rules none bind 0 0
```
10. Add your user to the wazuh group `sudo usermod -a -G wazuh <username>`, and verify `groups <username>`.
11. Initiate VS Code from the WSL for first engagement.
12. You should be able to read and access rules from the repository. Add the rules and decoders folders to git.
13. You are ready to update and test your logs locally. You can combine into your CI/CD pipeline for deployment.
