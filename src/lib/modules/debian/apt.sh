# ============================================================================
# modules/debian/apt.sh - APT configuration, batch installs and upgrades
# (Ubuntu / Proxmox VE, bash 4.4+)
# ConfigureAPT needs APT_PREFERENCES (array of "<release> <priority>").
# InstallDependencyPackages needs DEPENDENCY_PACKAGES + MICROCODE; set
# HYPERVISOR_AGENT (array, possibly empty) to also purge foreign guest agents.
# CleanupOutageKernels needs KERNEL_PATTERN (grep -E on installed kernels).
# ============================================================================

ConfigureAPT() {
    local apt_conf_list=(
        '# Disable HTTP Pipelining'
        'Acquire::http::Pipeline-Depth "0";'
        '# Disable Phased Updates'
        'APT::Get::Always-Include-Phased-Updates true;'
        'Update-Manager::Always-Include-Phased-Updates true;'
    )
    mkdir -p /etc/apt/apt.conf.d
    printf '%s\n' "${apt_conf_list[@]}" > /etc/apt/apt.conf.d/99autodeploy
    rm -rf /etc/apt/preferences.d
    mkdir -p /etc/apt/preferences.d
    local entry release priority
    : > /etc/apt/preferences
    for entry in "${APT_PREFERENCES[@]}"; do
        release="${entry%% *}"
        priority="${entry##* }"
        case "$priority" in
            *[!0-9]*) priority="500" ;;
        esac
        printf 'Package: *\nPin: release a=%s\nPin-Priority: %s\n\n' "$release" "$priority" >> /etc/apt/preferences
    done
    apt modernize-sources
    rm -f /etc/apt/sources.list.bak /etc/apt/sources.list.d/*.bak
}

ConfigureBusybox() {
    HaveCommand busybox || return 0
    busybox --install -s
}

# Weekly root maintenance crontab (apt upgrade + history wipe).
ConfigureCrontab() {
    CRONTAB_USER="root"
    CRONTAB_ENTRIES=(
        "0 0 * * 7 sudo apt update && sudo apt full-upgrade -qy && sudo apt autoremove -qy --purge"
        "# 0 4 * * 7 sudo reboot"
        "@reboot sudo rm -rf ~/.*_history ~/.ssh/known_hosts*"
    )
    InstallCrontab
}

InstallAptRepo() {
    local name="$1" key_url="$2" repo_line="$3"
    rm -f "/usr/share/keyrings/${name}-archive-keyring.gpg"
    curl -fsSL "$key_url" | gpg --dearmor -o "/usr/share/keyrings/${name}-archive-keyring.gpg"
    printf '%s\n' "$repo_line" > "/etc/apt/sources.list.d/${name}.list"
}

InstallAptPackages() {
    apt update
    # Filter available packages, then install them in a single apt invocation:
    # one dependency-resolution / dpkg-trigger pass instead of one per package.
    local pkg available=()
    for pkg in "$@"; do
        if apt-cache show "$pkg" > /dev/null 2>&1; then
            available+=("$pkg")
        else
            LogWarn "package not available, skipped: ${pkg}"
        fi
    done
    if [ "${#available[@]}" -gt 0 ]; then
        apt install -qy "${available[@]}"
    fi
}

InstallDependencyPackages() {
    local apt_list=("${DEPENDENCY_PACKAGES[@]}")
    apt_list+=(${HYPERVISOR_AGENT[@]+"${HYPERVISOR_AGENT[@]}"} ${MICROCODE[@]+"${MICROCODE[@]}"})
    # Purge guest agents that do not belong to the detected hypervisor. Only
    # runs when HYPERVISOR_AGENT is set (Ubuntu detects it; PVE skips entirely).
    if [ "${HYPERVISOR_AGENT+x}" = "x" ]; then
        local hypervisor_agent_list=("ksmtuned" "open-vm-tools" "qemu-guest-agent" "virtualbox-guest-dkms")
        local agent wanted keep
        for agent in "${hypervisor_agent_list[@]}"; do
            keep="false"
            for wanted in ${HYPERVISOR_AGENT[@]+"${HYPERVISOR_AGENT[@]}"}; do
                if [ "$agent" = "$wanted" ]; then
                    keep="true"
                fi
            done
            if [ "$keep" = "false" ] && dpkg -l "$agent" 2>/dev/null | grep -q '^ii'; then
                apt purge -qy "$agent"
                apt autoremove -qy --purge
            fi
        done
    fi
    InstallAptPackages "${apt_list[@]}"
}

UpgradePackages() {
    apt update
    apt full-upgrade -qy
    apt autoremove -qy --purge
}

# Extra paths to remove may be passed as arguments. Never wipe all of /tmp.
CleanupTempFiles() {
    apt clean
    rm -f /root/.*_history /tmp/*.autodeploy "$@"
}

# Keeps the newest kernel matching KERNEL_PATTERN, purges the rest.
CleanupOutageKernels() {
    local latest kernel
    latest=$(dpkg -l | grep -E "$KERNEL_PATTERN" | awk '{print $2}' | sort -V | tail -n 1 || true)
    if [ -z "$latest" ]; then
        return 0
    fi
    local kernel_list=()
    while IFS= read -r kernel; do
        if [ "$kernel" != "$latest" ]; then
            kernel_list+=("$kernel")
        fi
    done < <(dpkg -l | grep -E "$KERNEL_PATTERN" | awk '{print $2}' | sort -V || true)
    for kernel in ${kernel_list[@]+"${kernel_list[@]}"}; do
        apt purge -qy "$kernel"
    done
    apt autoremove -qy --purge
}
