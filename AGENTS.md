# AGENTS.md

This repository contains shell scripts for automated system deployment across multiple platforms. This document provides guidelines for agentic coding agents working with this codebase.

## Repository Overview

This project consists of 4 main deployment scripts:
- `DSM.sh` - Synology DSM deployment script
- `macOS.sh` - macOS deployment script  
- `ProxmoxVE.sh` - Proxmox VE deployment script
- `Ubuntu.sh` - Ubuntu deployment script

All scripts follow a similar structure with functions for:
1. System information gathering
2. Repository mirror configuration
3. Package installation and configuration
4. System configuration

## Code Style Guidelines

### General Principles
- Use `#!/bin/bash` shebang
- All scripts should be executable with `chmod +x`
- Use functions to organize code logically
- Follow consistent naming patterns across scripts

### Function Naming
- Use PascalCase for function names: `GetSystemInformation()`, `ConfigurePackages()`
- Group related functions under parent functions with descriptive names
- Use verb-noun pattern: `InstallCustomPackages()`, `GenerateHostname()`

### Variable Naming
- Use UPPERCASE_SNAKE_CASE for global variables: `NEW_HOSTNAME`, `GHPROXY_URL`
- Use lowercase_snake_case for local variables
- Export environment variables when needed: `export GHPROXY_URL`

### Code Organization
```bash
function ParentFunction() {
    function NestedFunction() {
        # Implementation
    }
    # Call nested functions
    NestedFunction
}
```

### Error Handling
- Check command existence before execution:
```bash
which "git" > "/dev/null" 2>&1
if [ "$?" -eq "0" ]; then
    # Command exists, proceed
fi
```
- Use proper exit codes for error conditions
- Handle architecture differences with conditional logic

### String Manipulation
- Use `sed` for text replacement with proper escaping
- Use `awk` for text processing
- Quote variables properly: `"$VARIABLE"` not `$VARIABLE`

### File Operations
- Create temporary files with `.autodeploy` suffix
- Always clean up temporary files: `rm -rf "/tmp/file.autodeploy"`
- Use proper permissions for sensitive files (600, 700, 400)
- Check file existence before operations

### Array Usage
```bash
array_name=(
    "item1"
    "item2"
    "item3"
)
for task in "${!array_name[@]}"; do
    echo "${array_name[$task]}"
done
```

## Testing and Validation

### Testing Single Scripts
Each script is standalone and can be tested with:
```bash
# Test with dry run (comment out actual modifications)
sudo bash DSM.sh
sudo bash macOS.sh  
sudo bash ProxmoxVE.sh
sudo bash Ubuntu.sh
```

### Validation Commands
```bash
# Check script syntax
bash -n SCRIPT_NAME.sh

# Check script execution trace (debug)
bash -x SCRIPT_NAME.sh

# Verify executable permissions
ls -la *.sh
```

### Testing Individual Functions
Add test calls at the end of scripts:
```bash
# Test individual function
GetSystemInformation
echo "Hostname: $NEW_HOSTNAME"
exit 0
```

## Platform-Specific Considerations

### DSM.sh
- Uses Synology-specific commands: `synogroup`, `chown root:docker`
- Paths: `/var/services/homes/` instead of `/home/`
- Package management via opkg

### macOS.sh
- Architecture detection (ARM vs x86_64)
- Homebrew paths: `/opt/homebrew/` (ARM) vs `/usr/local/` (Intel)
- LaunchDaemons for service management
- MAS (Mac App Store) integration

### ProxmoxVE.sh
- APT-based package management
- Kernel module loading and configuration
- Virtualization-specific optimizations
- Uses `proxmox-boot-tool` for bootloader config

### Ubuntu.sh
- APT package management with USTC mirrors
- Netplan for network configuration
- systemd for service management
- UFW firewall configuration

## Common Patterns

### Proxy Configuration
All scripts support GitHub proxy via `GHPROXY_URL` variable:
```bash
SetGHProxyDomain() {
    GHPROXY_URL="proxy.example.com"
    if [ "${GHPROXY_URL}" != "" ]; then
        export GHPROXY_URL="https://${GHPROXY_URL}/"
    fi
}
```

### Git Configuration
Standardized across all platforms:
```bash
function ConfigureGit() {
    gitconfig_key_list=(
        "commit.gpgsign"
        "gpg.program"
        "user.name"
        "user.email"
        # ... more configs
    )
    # Configure git settings
}
```

### SSH Key Generation
Consistent key generation across all scripts:
```bash
ssh-keygen -t ecdsa -b 384 -f "path/to/key" -C "comment" -N ""
ssh-keygen -t ed25519 -f "path/to/key" -C "comment" -N ""
ssh-keygen -t rsa -b 4096 -f "path/to/key" -C "comment" -N ""
```

## Security Considerations

### File Permissions
- SSH keys: 400 for private, 644 for public
- Config files: 600 or 644 depending on sensitivity
- Directories: 700 for SSH, 755 for general

### Secret Management
- Avoid hardcoding passwords in scripts
- Use variables for default passwords that should be changed
- GPG key import and trust configuration

### Service Security
- Firewall rules are restrictive by default
- SSH configuration hardening
- Fail2Ban integration where applicable

## Deployment Guidelines

### Before Running Scripts
1. Review script contents for site-specific customizations
2. Ensure proper backup of critical configuration
3. Test in non-production environment first

### Customization Points
- Proxy settings: `GHPROXY_URL`, proxy configurations
- DNS settings: Custom DNS servers in `CUSTOM_DNS` arrays
- Package lists: Modify `app_list` arrays as needed
- User accounts: Default usernames and passwords should be changed

### Script Execution
All scripts can be executed via:
```bash
# Direct execution
curl "https://source.zhijie.online/AutoDeploy/main/SCRIPT.sh" | sudo bash

# Or download first
wget -qO- "https://source.zhijie.online/AutoDeploy/main/SCRIPT.sh" | sudo bash
```

## Repository Structure Best Practices

### File Organization
- Keep scripts in root directory
- Use consistent naming: PlatformName.sh
- Maintain same function structure across scripts
- Document platform-specific differences

### Version Control
- Commit tested changes only
- Use descriptive commit messages
- Tag releases for stable versions
- Include license header in all scripts

### Documentation Updates
- Update AGENTS.md when adding new functions
- Document breaking changes
- Maintain platform-specific considerations
- Update usage examples

## Common Debugging Techniques

### Enable Debug Mode
Add to script beginning:
```bash
set -x  # Enable debug
set -e  # Exit on error
```

### Check Variables
```bash
# Debug variable values
echo "DEBUG: Variable = $VARIABLE" >&2
```

### Test Command Execution
```bash
# Dry run with echo
echo "Would run: command with options"

# Test with redirection
command > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Command succeeded"
fi
```