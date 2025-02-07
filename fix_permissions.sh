#!/usr/bin/env bash

# Ensure the script is executed as root
if [ "$(id -u)" -ne 0 ]; then
    error "This script can be executed only as root. Exiting..."
    exit 1
fi

set -o errexit
set -o nounset
set -o pipefail
if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

decoders_dir=$(realpath ./decoders)
rules_dir=$(realpath ./rules)
chown wazuh:wazuh "$rules_dir"/*
chmod 660 "$rules_dir"/*
chown wazuh:wazuh "$decoders_dir"/*
chmod 660 "$decoders_dir"/*