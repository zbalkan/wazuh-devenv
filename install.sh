#!/usr/bin/env bash

LOGFILE="/var/log/wazuh_setup.log"
exec > >(tee -a "$LOGFILE") 2>&1

# Lock to prevent multiple instances from running concurrently
LOCKFILE="/var/lock/wazuh-setup.lock"
exec 200>$LOCKFILE

# Release lock on exit or error
trap 'flock -u 200' EXIT

flock -n 200 || { echo "Another instance of the script is running. Exiting..."; exit 1; }


# Function to display informational messages
info() {
    local BLUE='\033[0;34m'
    local NC='\033[0m' # No Color
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Function to display warning messages
warn() {
    local YELLOW='\033[1;33m'
    local NC='\033[0m' # No Color
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Function to display error messages
error() {
    local RED='\033[0;31m'
    local NC='\033[0m' # No Color
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

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

if [[ "${1-}" =~ ^-*h(elp)?$ ]]; then
    info 'This script sets up the Wazuh Manager on WSL.'
    exit
fi

cd "$(dirname "$0")"

# Declare internal variables
decoders_dir=$(realpath ./decoders)
rules_dir=$(realpath ./rules)
ossec_conf="/var/ossec/etc/ossec.conf"
PKG_MANAGER=""

# Detect package manager
detect_package_manager() {
    info "Detecting available package manager..."

    if [ -x "$(command -v apt-get)" ]; then
        info "Detected APT package manager."
        PKG_MANAGER="APT"
    elif [ -x "$(command -v dnf)" ]; then
        # Since dnf is the modern replacement for yum, it is checked first.
        info "Detected DNF package manager."
        PKG_MANAGER="YUM"
    elif [ -x "$(command -v yum)" ]; then
        info "Detected YUM package manager."
        PKG_MANAGER="YUM"
    else
        error "No supported package manager found (APT or YUM/DNF). Exiting..."
        exit 1
    fi
}

# Install Wazuh Manager based on the detected package manager
install_wazuh_manager() {
    info "Installing Wazuh Manager..."
    if [[ "$PKG_MANAGER" == "APT" ]]; then
        setup_apt_repo_and_install
    elif [[ "$PKG_MANAGER" == "YUM" ]]; then
        setup_yum_repo_and_install
    else
        error "Unknown package manager: $PKG_MANAGER. Exiting..."
        exit 1
    fi
}

# Functions for Debian-based systems
setup_apt_repo_and_install() {
    info "Installing necessary APT dependencies..."
    apt-get install -y gnupg apt-transport-https

    info "Checking if Wazuh GPG key is already imported..."
    if gpg --list-keys --keyring /usr/share/keyrings/wazuh.gpg | grep -q "Wazuh"; then
        info "Wazuh GPG key is already imported."
    else
        info "Adding Wazuh GPG key for APT..."
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
    fi

    info "Checking if Wazuh APT repository is already configured..."
    if grep -q "https://packages.wazuh.com/4.x/apt/" /etc/apt/sources.list.d/wazuh.list 2>/dev/null; then
        info "Wazuh APT repository is already configured."
    else
        info "Adding Wazuh APT repository..."
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
    fi

    info "Updating APT packages information..."
    apt-get update

    info "Installing Wazuh Manager..."
    apt-get -y install wazuh-manager
    info "Wazuh Manager installed successfully."
}

# Functions for RHEL-based systems
setup_yum_repo_and_install() {
    info "Checking if Wazuh GPG key is already imported..."
    if rpm -qa gpg-pubkey | grep -q "$(curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --with-fingerprint 2>/dev/null | grep 'Key fingerprint' | awk '{print $4$5$6$7$8$9$10}')"; then
        info "Wazuh GPG key is already imported."
    else
        info "Importing Wazuh GPG key for YUM..."
        rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
    fi

    info "Checking if Wazuh repository is already configured..."
    if [[ -f /etc/yum.repos.d/wazuh.repo ]]; then
        info "Wazuh YUM repository is already configured."
    else
        info "Adding Wazuh YUM repository..."
        cat <<EOF | tee /etc/yum.repos.d/wazuh.repo
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
    fi

    info "Installing Wazuh Manager..."
    yum -y install wazuh-manager
    info "Wazuh Manager installed successfully."
}

update_configuration() {
    info "Updating Wazuh configuration..."

    # Update ossec.conf to enable JSON logging and disable unnecessary modules
    sed -i 's|<logall_json>.*</logall_json>|<logall_json>yes</logall_json>|' "$ossec_conf"
    sed -i 's|<logging>\n[[:space:]]*<log_format>.*</log_format>|<logging>\n    <log_format>plain,json</log_format>|' "$ossec_conf"

    # Disable syscollector, rootcheck, indexer, and syscheck (FIM) modules
    sed -z -i 's|<wodle name="syscollector">\n[[:space:]]*<disabled>no</disabled>|<wodle name="syscollector">\n    <disabled>yes</disabled>|' "$ossec_conf"
    sed -z -i 's|<rootcheck>\n[[:space:]]*<disabled>no</disabled>|<rootcheck>\n    <disabled>yes</disabled>|' "$ossec_conf"
    sed -z -i 's|<indexer>\n[[:space:]]*<enabled>yes</enabled>|<indexer>\n    <enabled>no</enabled>|' "$ossec_conf"
    sed -z -i 's|<syscheck>\n[[:space:]]*<disabled>no</disabled>|<syscheck>\n    <disabled>yes</disabled>|' "$ossec_conf"

    # Disable SCA (Security Configuration Assessment)
    sed -z -i 's|<sca>\n[[:space:]]*<enabled>yes</enabled>|<sca>\n    <enabled>no</enabled>|' "$ossec_conf"

    # Disable Vulnerability Detection
    sed -z -i 's|<vulnerability-detection>\n[[:space:]]*<enabled>yes</enabled>|<vulnerability-detection>\n    <enabled>no</enabled>|' "$ossec_conf"

    info "Wazuh configuration updated successfully."
}

enable_windows_eventlog_rule_testing(){
    # Wazuh checks event logs by the source
    # But to test it, we must ensure it accepts json logs
    sed -i '/<rule id="60000"/,/\/rule>/ { s|<decoded_as>.*</decoded_as>|<decoded_as>json</decoded_as>|/<category>/d}' /var/ossec/ruleset/rules/0575-win-base_rules.xml
}

optimize_for_rule_test(){
    # Optimize the configuration for rule testing
    # This is not necessary, but it can speed up the process
    sed -i '/<rule_test>/,/<\\/rule_test>/ {
    s|<threads>.*</threads>|<threads>auto</threads>|
    s|<max_sessions>.*</max_sessions>|<max_sessions>500</max_sessions>|
    s|<session_timeout>.*</session_timeout>|<session_timeout>1m</session_timeout>|
    }' "$ossec_conf"
}

create_empty_folders() {
    info "Creating directories for custom rules and decoders..."
    mkdir -p "$rules_dir"
    mkdir -p "$decoders_dir"
    info "Directories created successfully."
}

setup_bind_mounts() {
    info "Setting up bind mounts for Wazuh..."

    # Unmount existing mounts if they exist
    umount /var/ossec/etc/rules 2>/dev/null || true
    umount /var/ossec/etc/decoders 2>/dev/null || true

    # Move existing files from /var/ossec/etc/rules to $rules_dir if there are any
    if [ "$(ls -A /var/ossec/etc/rules)" ]; then
        info "Moving existing files from /var/ossec/etc/rules to $rules_dir..."
        mv /var/ossec/etc/rules/* "$rules_dir"/
        info "Files moved successfully."
    fi

    # Move existing files from /var/ossec/etc/decoders to $decoders_dir if there are any
    if [ "$(ls -A /var/ossec/etc/decoders)" ]; then
        info "Moving existing files from /var/ossec/etc/decoders to $decoders_dir..."
        mv /var/ossec/etc/decoders/* "$decoders_dir"/
        info "Files moved successfully."
    fi

    # Bind mount rules_dir to /var/ossec/etc/rules
    mount --bind "$rules_dir" /var/ossec/etc/rules
    if mountpoint -q /var/ossec/etc/rules; then
        info "Bind-mounted $rules_dir to /var/ossec/etc/rules successfully."
    else
        error "Failed to bind-mount $rules_dir to /var/ossec/etc/rules."
        exit 1
    fi

    # Bind mount decoders_dir to /var/ossec/etc/decoders
    mount --bind "$decoders_dir" /var/ossec/etc/decoders
    if mountpoint -q /var/ossec/etc/decoders; then
        info "Bind-mounted $decoders_dir to /var/ossec/etc/decoders successfully."
    else
        error "Failed to bind-mount $decoders_dir to /var/ossec/etc/decoders."
        exit 1
    fi

    # Ensure persistence across reboots by adding to /etc/fstab
    if ! grep -qs "$rules_dir /var/ossec/etc/rules" /etc/fstab; then
        echo "$rules_dir /var/ossec/etc/rules none bind 0 0" >> /etc/fstab
        info "Added $rules_dir bind mount to /etc/fstab for /var/ossec/etc/rules"
    fi

    if ! grep -qs "$decoders_dir /var/ossec/etc/decoders" /etc/fstab; then
        echo "$decoders_dir /var/ossec/etc/decoders none bind 0 0" >> /etc/fstab
        info "Added $decoders_dir bind mount to /etc/fstab for /var/ossec/etc/decoders"
    fi

    info "Bind mounts set up successfully."
}

ask_for_user_files() {
    info "You can now add your custom rules and decoders to the following directories:"
    info "Rules: $rules_dir"
    info "Decoders: $decoders_dir"
    info "Type 'y' if you have completed copying custom rules and decoders or 'n' to rollback changes."
    read -r -p "Do you want to continue? (y/N): " response
    if [[ "$response" != "y" ]]; then
        warn "Rolling back changes..."

        # Remove installed package based on package manager
        if [[ "$PKG_MANAGER" == "APT" ]]; then
            info "Removing Wazuh Manager and APT repository..."
            apt-get -y remove wazuh-manager

            # Remove Wazuh APT repo and key
            rm -f /etc/apt/sources.list.d/wazuh.list
            rm -f /usr/share/keyrings/wazuh.gpg

            info "APT repository and GPG key for Wazuh removed."
        elif [[ "$PKG_MANAGER" == "YUM" ]]; then
            info "Removing Wazuh Manager and YUM repository..."
            yum -y remove wazuh-manager

            # Remove Wazuh YUM repo and key
            rm -f /etc/yum.repos.d/wazuh.repo
            rpm -e "gpg-pubkey-$(rpm -q --qf "%{version}" gpg-pubkey | grep -i 'wazuh')"

            info "YUM repository and GPG key for Wazuh removed."
        fi

        # Remove custom rules and decoders directories
        rm -rf "$rules_dir"
        rm -rf "$decoders_dir"

        warn "Changes have been rolled back. Exiting..."
        exit 1
    fi
}

configure_permissions() {
    info "Configuring permissions for rules and decoders..."

    # Set permissions for the rules directory
    chown root:wazuh "$rules_dir"
    chmod 770 "$rules_dir"

    if [[ -n $(find "$rules_dir" -type f) ]]; then
        chown wazuh:wazuh "$rules_dir"/*
        chmod 660 "$rules_dir"/*
    else
        warn "No files found in $rules_dir, skipping file permissions."
    fi

    # Set permissions for the decoders directory
    chown root:wazuh "$decoders_dir"
    chmod 770 "$decoders_dir"

    if [[ -n $(find "$decoders_dir" -type f) ]]; then
        chown wazuh:wazuh "$decoders_dir"/*
        chmod 660 "$decoders_dir"/*
    else
        warn "No files found in $decoders_dir, skipping file permissions."
    fi

    info "Permissions configured successfully."
}

add_user_to_wazuh_group() {
    while true; do
        read -r -p "Enter the username to add to the wazuh group: " username

        # Check if the user exists on the system
        if id "$username" &>/dev/null; then
            # Add user to the wazuh group
            usermod -a -G wazuh "$username"

            # Verify if the user was added to the group
            if groups "$username" | grep -q "\bwazuh\b"; then
                info "User $username has been added to the wazuh group."
            else
                warn "Warning: User $username has not been added to the wazuh group. Please fix it manually."
            fi
            break
        else
            error "User $username does not exist. Please enter a valid username."
            read -r -p "Do you want to try again? (y/N): " try_again
            if [[ "$try_again" != "y" ]]; then
                warn "Exiting without adding any user to the wazuh group."
                break
            fi
        fi
    done
}

start_wazuh_service() {
    info "Starting Wazuh Manager service..."

    # Check if systemctl is available
    if command -v systemctl &>/dev/null && systemctl > /dev/null 2>&1; then
        # Use systemctl if available
        systemctl daemon-reload
        systemctl enable wazuh-manager
        systemctl start wazuh-manager

        if systemctl is-active --quiet wazuh-manager; then
            info "Wazuh Manager has been successfully installed and started using systemctl."
        else
            error "Wazuh installation or startup failed using systemctl. Please check the logs for more details."
        fi
    else
        # Fallback to service command if systemctl is not available (e.g., on WSL)
        info "Systemctl not available, falling back to service command..."
        service wazuh-manager start;
        exit_code=$?

        if [[ $exit_code -ne 0 ]]; then
            error "Service start command failed with exit code $exit_code"
            exit 1
        fi

        # Log that the service start completed successfully based on the exit code
        info "Wazuh Manager has been successfully started."
    fi
}

# main function
main() {
    info "Starting Wazuh Manager setup..."
    detect_package_manager
    install_wazuh_manager
    update_configuration
    enable_windows_eventlog_rule_testing
    optimize_for_rule_test
    create_empty_folders
    setup_bind_mounts
    ask_for_user_files
    configure_permissions
    add_user_to_wazuh_group
    start_wazuh_service
    info "Wazuh Manager setup completed successfully."
}

main "$@"
