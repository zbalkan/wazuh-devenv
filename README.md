# wazuh-devenv

The project utilizes of a wazuh-manager installed on WSL, allowing testing custom rules locally before moving to production.

## Setup

1. Ensure a WSL instance running in your environment. The distribution that matches the Production deployment is better.
2. Clone the repo to the preferred location for development.
3. Run the script `sudo ./install.sh` to start installation.
4. The script will ask you to copy rules and decoders to the new locations. When you copied them, hit `y` and continue. Otherwise it will rollback the changes.
5. The script will ask you to provide the username you will use in wsl for development. Ensure you typed it correctly.
6. The installation and configuration will be completed successfully. If there are any errors, there will be warnings for the user to fix manually.
7. Initiate VS Code from the WSL for first engagement.
8. You should be able to read and access rules from the repository. Add the rules and decoders folders to git.
9. Remove the origin from Github to prevent accidentally leaking your rules to public repositories by running `git remote rm origin`.
10. Add your organization's git repository for further use `git remote add origin <URL>`.

You are ready to update and test your logs locally. You can combine the script into your CI/CD pipeline for deployment.


## Permissions

When you add new files, you must ensure the file permissions are set as expected. The expected permissions are `660` and owners are `wazuh:wazuh`. You can use this snippet belof whenever you need it for simplicity.

```shell
decoders_dir=$(realpath ./decoders)
rules_dir=$(realpath ./rules)
chown wazuh:wazuh "$rules_dir"/*
chmod 660 "$rules_dir"/*
chown wazuh:wazuh "$decoders_dir"/*
chmod 660 "$decoders_dir"/*
```

If your filesystem supports ACLs, `setfacl` is a good helper. Using the commands, you can ensure the future files will use the correct permissions. Since it is not universal, this change is optional.

```shell
# Set default ACLs to enforce wazuh:wazuh ownership and 660 permissions for future files
setfacl -d -m u:wazuh:rwx,g:wazuh:rwx "$decoders_dir"
setfacl -d -m o::--- "$decoders_dir"

# Set default ACLs to enforce wazuh:wazuh ownership and 660 permissions for future files
setfacl -d -m u:wazuh:rwx,g:wazuh:rwx "$rules_dir"
setfacl -d -m o::--- "$rules_dir"
```


## Sample rules

The sample rules are taken from the Wazuh blog [Creating decoders and rules from scratch](https://wazuh.com/blog/creating-decoders-and-rules-from-scratch/).
