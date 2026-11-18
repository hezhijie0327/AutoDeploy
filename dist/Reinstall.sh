#!/bin/bash
# Copyright 2026 Zhijie He
# Licensed under Apache-2.0 WITH Commons-Clause-1.0. See LICENSE.
#
# GENERATED FILE - edit src/ and run ./build.sh to regenerate.
# For a one-off tweak you may edit the Configuration block below.
#
## How to get and use?
# curl "https://source.zhijie.online/AutoDeploy/main/dist/Reinstall.sh" | sudo bash
# wget -qO- "https://source.zhijie.online/AutoDeploy/main/dist/Reinstall.sh" | sudo bash
# ============================================================================
# Configuration - shared across all platforms
# Common knobs shared by every generated script. Platform config files add
# platform-specific defaults on top of these. Every knob is env-overridable.
# ============================================================================

## Resume / progress
# State lives under the running user's home. AUTODEPLOY_FORCE=true re-runs all.
AUTODEPLOY_STATE_DIR="${AUTODEPLOY_STATE_DIR:-${HOME}/.autodeploy}"
AUTODEPLOY_FORCE="${AUTODEPLOY_FORCE:-false}"

## Credentials
OPENSSH_PASSWORD="${OPENSSH_PASSWORD:-}"
GPG_PUBKEY="${GPG_PUBKEY:-DD982DAAB9C71C78F9563E5207EB56787030D792}"

## Identity (Git)
GIT_USER_NAME="${GIT_USER_NAME:-}"
GIT_USER_EMAIL="${GIT_USER_EMAIL:-}"
GIT_USER_SIGNINGKEY="${GIT_USER_SIGNINGKEY:-}"
GIT_COMMIT_GPGSIGN="${GIT_COMMIT_GPGSIGN:-false}"
GIT_GPG_PROGRAM="${GIT_GPG_PROGRAM:-gpg}"
GIT_HTTP_PROXY="${GIT_HTTP_PROXY:-}"
GIT_HTTPS_PROXY="${GIT_HTTPS_PROXY:-}"

## Proxy / mirrors
GHPROXY_URL="${GHPROXY_URL:-}" # GitHub proxy: bare domain or full URL (scheme optional)
PROXY_URL="${PROXY_URL:-http://vpn.zhijie.online:7890}" # zsh proxy_on helper
PROXY_PROTOCOL="${PROXY_PROTOCOL:-socks5}" # proxychains upstream
PROXY_IP="${PROXY_IP:-127.0.0.1}"
PROXY_PORT="${PROXY_PORT:-7891}"
PROXY_USERNAME="${PROXY_USERNAME:-}"
PROXY_PASSWORD="${PROXY_PASSWORD:-}"

## Zsh
ZSH_THEME="${ZSH_THEME:-ys}"
# ============================================================================
# Configuration - Reinstall (Ubuntu only)
# Knobs for the network reinstall entry script. Runs as root via sudo.
# Override any knob via environment variable before running, e.g.:
#   REINSTALL_RELEASE='24.04' REINSTALL_PASSWORD='...' curl \
#     .../dist/Reinstall.sh | sudo bash
# ============================================================================

## Resume / progress
AUTODEPLOY_STEP_TOTAL=6 # must match the RunStep count (lint.sh checks)

## Target system
# Release pinning: defaults to the latest LTS (bump each cycle). Env override
# is allowed but must be one of the LTS releases mapped in GetUbuntuCodename.
REINSTALL_RELEASE="${REINSTALL_RELEASE:-26.04}"
REINSTALL_INSTALLER_PART_SIZE_MB="${REINSTALL_INSTALLER_PART_SIZE_MB:-2048}" # staging partition for the cloud image

## Installer bootstrap (Alpine netboot files run the install after reboot)
REINSTALL_ALPINE_VERSION="${REINSTALL_ALPINE_VERSION:-auto}" # auto = detect newest, or pin e.g. 3.22
REINSTALL_CONFHOME="${REINSTALL_CONFHOME:-https://source.zhijie.online/AutoDeploy/main/src/platforms/reinstall}" # trans.sh location
REINSTALL_CN_MIRROR="${REINSTALL_CN_MIRROR:-true}" # false -> official upstream mirrors

## Identity of the freshly installed system
REINSTALL_PASSWORD="${REINSTALL_PASSWORD:-}" # empty -> generate one (printed) or key-only
REINSTALL_SSH_KEYS="${REINSTALL_SSH_KEYS:-}" # authorized_keys content, or a file path; empty -> reuse this host's root keys
# ============================================================================
# core.sh - logging, error handling and the resume/progress state machine
# Shared across all platforms (DSM / macOS / Ubuntu / Proxmox VE / Reinstall).
# Part of the generated single-file scripts; not executable on its own.
# Compatible with bash 3.2 (macOS system bash) - avoid bash 4+ features here.
# ============================================================================

set -Eeuo pipefail

LogInfo() {
    printf '[AutoDeploy] %s\n' "$*"
}

LogWarn() {
    printf '[AutoDeploy] WARNING: %s\n' "$*" >&2
}

Die() {
    printf '[AutoDeploy] ERROR: %s\n' "$*" >&2
    exit 1
}

HaveCommand() {
    command -v "$1" > /dev/null 2>&1
}

RequireRoot() {
    if [ "$(id -u)" -ne 0 ]; then
        Die "this script must run as root (use sudo)"
    fi
}

# Move an existing file/directory aside instead of destroying it, so a re-run
# never wipes keys or configuration without a recovery path.
BackupPath() {
    local target="$1" backup
    if [ -e "$target" ]; then
        backup="${target}.bak.$(date '+%Y%m%d%H%M%S')"
        mv "$target" "$backup"
        LogInfo "backed up ${target} -> ${backup}"
    fi
}

WarnDefaultPassword() {
    local name="$1" value="$2" default_value="$3"
    if [ "$value" = "$default_value" ]; then
        LogWarn "${name} is using the built-in default. Change it after deployment, or override it with ${name}=<value> before running."
    fi
}

# Under `curl | sudo bash`, whoami is root; SUDO_USER is the real operator.
# Used by DSM/macOS; debian platforms use DEFAULT_USERNAME instead.
GetCurrentUsername() {
    # shellcheck disable=SC2034
    CURRENT_USERNAME="${SUDO_USER:-$(whoami)}"
}

SetGHProxyDomain() {
    GHPROXY_URL="${GHPROXY_URL:-}"
    if [ -n "$GHPROXY_URL" ]; then
        # Accept a bare domain (proxy.example.com) or a full URL
        # (https://proxy.example.com[/]); keep any given scheme.
        case "$GHPROXY_URL" in
            *://*) ;;
            *) GHPROXY_URL="https://${GHPROXY_URL}" ;;
        esac
        # Normalize to exactly one trailing slash.
        while [ "$GHPROXY_URL" != "${GHPROXY_URL%/}" ]; do
            GHPROXY_URL="${GHPROXY_URL%/}"
        done
        export GHPROXY_URL="${GHPROXY_URL}/"
    fi
}

## Resume + progress
# Each orchestration step runs through RunStep. A step is recorded in the state
# file only after it succeeds, so an interrupted run resumes at the first
# unfinished step. AUTODEPLOY_FORCE=true clears the state and re-runs everything.
# Platform must set: AUTODEPLOY_STATE_DIR, AUTODEPLOY_STEP_TOTAL.
StateFile() {
    printf '%s/state\n' "$AUTODEPLOY_STATE_DIR"
}

StepDone() {
    local state_file
    state_file=$(StateFile)
    [ -f "$state_file" ] && grep -qxF "$1" "$state_file"
}

MarkStep() {
    mkdir -p "$AUTODEPLOY_STATE_DIR"
    printf '%s\n' "$1" >> "$(StateFile)"
}

StepsCompleted() {
    local state_file
    state_file=$(StateFile)
    if [ -f "$state_file" ]; then
        wc -l < "$state_file" | tr -d ' '
    else
        printf '0\n'
    fi
}

RenderProgress() {
    local label="$1" total="${AUTODEPLOY_STEP_TOTAL:-0}" completed width=20 filled percent bar
    completed=$(StepsCompleted)
    if [ "$total" -le 0 ]; then
        LogInfo "$label"
        return 0
    fi
    percent=$((completed * 100 / total))
    filled=$((completed * width / total))
    bar="$(printf '%*s' "$filled" '' | tr ' ' '#')$(printf '%*s' "$((width - filled))" '' | tr ' ' '-')"
    LogInfo "[${bar}] ${completed}/${total} (${percent}%) ${label}"
}

RunStep() {
    local step_id="$1"
    shift
    if [ "${AUTODEPLOY_FORCE:-false}" != "true" ] && StepDone "$step_id"; then
        LogInfo "skip ${step_id} (completed in a previous run)"
        return 0
    fi
    RenderProgress "running ${step_id}"
    "$@"
    MarkStep "$step_id"
}

InitRun() {
    if [ "${AUTODEPLOY_FORCE:-false}" = "true" ]; then
        rm -f "$(StateFile)"
        LogInfo "AUTODEPLOY_FORCE=true: re-running all steps"
    else
        local completed
        completed=$(StepsCompleted)
        if [ "$completed" -gt 0 ]; then
            LogInfo "resuming: ${completed}/${AUTODEPLOY_STEP_TOTAL} steps already complete"
        fi
    fi
}

trap 'Die "failed at line ${LINENO}: ${BASH_COMMAND}"' ERR
# ============================================================================
# modules/debian/system.sh - system information gathering for Debian family
# (Ubuntu / Proxmox VE, bash 4.4+)
# Sets: NEW_DOMAIN, NEW_HOSTNAME, OLD_HOSTNAME, CURRENT_DNS, DHCP_DNS,
# CUSTOM_DNS, DNS_LINE, CPU_VENDOR_ID, ENABLE_IOMMU, MICROCODE,
# INTEL_GVT_MODULES, INTEL_HDMI_AUDIO_MODULE, NESTED_MODULES,
# OS_ARCHITECTURE, plus the Debian structural globals via SetDebianGlobals.
# ============================================================================

GenerateDomain() {
    RESET_DOMAIN="${RESET_DOMAIN:-false}"
    NEW_DOMAIN=()
    if [ -n "${CUSTOM_DOMAIN:-}" ]; then
        read -r -a NEW_DOMAIN <<< "$CUSTOM_DOMAIN"
        return 0
    fi
    local resolv_conf="${RESOLV_CONF:-/etc/resolv.conf}" search_line
    if [ -f "$resolv_conf" ]; then
        search_line=$(awk '/^search/ {for (i = 2; i <= NF; i++) printf "%s ", $i; exit}' "$resolv_conf")
        if [ -n "$search_line" ]; then
            read -r -a NEW_DOMAIN <<< "$search_line"
        fi
    fi
    if [ "${#NEW_DOMAIN[@]}" -eq 0 ] || [ "$RESET_DOMAIN" = "true" ]; then
        NEW_DOMAIN=("localdomain")
    fi
}

# Sets NEW_HOSTNAME (CUSTOM_HOSTNAME > hostname file > hostname command >
# HOSTNAME_PREFIX timestamp) and OLD_HOSTNAME (original hostname, used by the
# Proxmox VE node rename step).
GenerateHostname() {
    RESET_HOSTNAME="${RESET_HOSTNAME:-false}"
    OLD_HOSTNAME=""
    if [ -f "${HOSTNAME_FILE:-/etc/hostname}" ]; then
        OLD_HOSTNAME=$(awk '{print $1; exit}' "${HOSTNAME_FILE:-/etc/hostname}")
    fi
    if [ -z "$OLD_HOSTNAME" ] && HaveCommand hostname; then
        OLD_HOSTNAME=$(hostname)
    fi
    NEW_HOSTNAME=""
    if [ -n "${CUSTOM_HOSTNAME:-}" ]; then
        NEW_HOSTNAME="$CUSTOM_HOSTNAME"
        return 0
    fi
    NEW_HOSTNAME="$OLD_HOSTNAME"
    if [ -z "$NEW_HOSTNAME" ] || [ "$RESET_HOSTNAME" = "true" ]; then
        NEW_HOSTNAME="${HOSTNAME_PREFIX}-$(date '+%Y%m%d%H%M%S')"
    fi
}

# Sets CUSTOM_DNS / CURRENT_DNS / DHCP_DNS / DNS_LINE (first three, space joined)
CollectDNS() {
    USE_GLOBAL_DNS="${USE_GLOBAL_DNS:-false}"
    if [ "$USE_GLOBAL_DNS" = "true" ]; then
        CUSTOM_DNS=("${CUSTOM_DNS_GLOBAL[@]}")
    else
        CUSTOM_DNS=("${CUSTOM_DNS_CN[@]}")
    fi
    DHCP_DNS=()
    CURRENT_DNS=()
    local resolv_conf="${RESOLV_CONF:-/etc/resolv.conf}" ns
    if [ -f "$resolv_conf" ]; then
        while IFS= read -r ns; do
            case " ${CUSTOM_DNS[*]} ${DHCP_DNS[*]:-} 127.0.0.53 " in
                *" ${ns} "*) ;;
                *) CURRENT_DNS+=("$ns") ;;
            esac
        done < <(awk '/^nameserver/ {print $2}' "$resolv_conf")
    fi
    DNS_LINE=$(printf '%s\n' ${CURRENT_DNS[@]+"${CURRENT_DNS[@]}"} "${CUSTOM_DNS[@]}" | head -n 3 | tr '\n' ' ')
    DNS_LINE="${DNS_LINE% }"
}

GetCPUVendorID() {
    CPU_VENDOR_ID=$(awk -F: '/vendor_id/ {gsub(/^[ \t]+/, "", $2); print $2; exit}' /proc/cpuinfo)
    # pcie_acs_override is a patched-kernel parameter (common homelab kernels);
    # mainline kernels ignore it with a warning. Kept intentionally.
    case "$CPU_VENDOR_ID" in
        AuthenticAMD)
            CPU_VENDOR_ID="AMD"
            ENABLE_IOMMU=" amd_iommu=on iommu=pt pci=assign-busses pcie_acs_override=downstream,multifunction"
            INTEL_GVT_MODULES=()
            INTEL_HDMI_AUDIO_MODULE=()
            MICROCODE=("amd64-microcode")
            NESTED_MODULES=("kvm_amd")
            ;;
        GenuineIntel)
            CPU_VENDOR_ID="Intel"
            ENABLE_IOMMU=" intel_iommu=on iommu=pt pci=assign-busses pcie_acs_override=downstream,multifunction"
            INTEL_GVT_MODULES=("i915" "kvmgt")
            INTEL_HDMI_AUDIO_MODULE=("snd_hda_intel")
            MICROCODE=("intel-microcode")
            NESTED_MODULES=("kvm_intel")
            ;;
        *)
            CPU_VENDOR_ID="Unknown"
            ENABLE_IOMMU=""
            INTEL_GVT_MODULES=()
            INTEL_HDMI_AUDIO_MODULE=()
            MICROCODE=()
            NESTED_MODULES=()
            ;;
    esac
}

ComputeFullDomain() {
    NEW_FULL_DOMAIN=""
    local domain
    for domain in "${NEW_DOMAIN[@]}"; do
        NEW_FULL_DOMAIN="${NEW_FULL_DOMAIN} ${NEW_HOSTNAME}.${domain}"
    done
    NEW_FULL_DOMAIN="${NEW_FULL_DOMAIN# }"
}

# Write /etc/resolv.conf with up to three nameservers plus the search domain.
WriteResolvConf() {
    local resolv_conf_list=()
    resolv_conf_list+=(${CURRENT_DNS[@]+"${CURRENT_DNS[@]}"})
    resolv_conf_list+=("${CUSTOM_DNS[@]}")
    local count=0 entry
    chattr -i /etc/resolv.conf > /dev/null 2>&1 || true
    rm -f /etc/resolv.conf
    {
        for entry in "${resolv_conf_list[@]}"; do
            if [ "$count" -ge 3 ]; then
                break
            fi
            printf 'nameserver %s\n' "$entry"
            count=$((count + 1))
        done
        printf 'search %s\n' "${NEW_DOMAIN[*]}"
    } > /etc/resolv.conf
}

GetOSArchitecture() {
    if HaveCommand dpkg; then
        OS_ARCHITECTURE=$(dpkg --print-architecture)
    else
        case "$(uname -m)" in
            aarch64) OS_ARCHITECTURE="arm64" ;;
            x86_64) OS_ARCHITECTURE="amd64" ;;
        esac
    fi
    case "${OS_ARCHITECTURE:-}" in
        amd64|arm64) ;;
        *) Die "Unsupported architecture." ;;
    esac
}

# Structural globals shared by both Debian platforms; platform ConfigurePackages
# blocks may override any of them (e.g. Proxmox VE extends ZSH_PATH_LIST).
SetDebianGlobals() {
    PROXYCHAINS_CONF="/etc/proxychains4.conf"
    GPG_HOME="/home/${DEFAULT_USERNAME}/.gnupg"
    GPG_KEYSERVER="hkps://keyserver.ubuntu.com:443"
    GPG_PINENTRY="/usr/bin/pinentry-tty"
    GPG_HOME_OWNER="${DEFAULT_USERNAME}:${DEFAULT_USERNAME}"
    ZSH_HOME="/home/${DEFAULT_USERNAME}"
    ZSH_OWNER="${DEFAULT_USERNAME}:${DEFAULT_USERNAME}"
    ZSH_PATH_LIST=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/usr/local/bin" "/usr/local/sbin")
    ZSH_EXTRA_EXPORTS=("export DEBIAN_FRONTEND=\"noninteractive\"")
    ZSH_TRAPEXIT="false"
}
## Function
# Reinstall this Ubuntu machine to a fresh Ubuntu release after reboot.
# Phase 1 (this script): collect facts, stage an Alpine netboot installer in
# the initramfs, queue a one-time GRUB entry. The actual install runs in
# phase 2 (src/reinstall/trans.sh) after the reboot. Only the Ubuntu family
# is supported as the source system.

GetUbuntuCodename() {
    # LTS releases only.
    case "$1" in
        20.04) UBUNTU_CODENAME="focal" ;;
        22.04) UBUNTU_CODENAME="jammy" ;;
        24.04) UBUNTU_CODENAME="noble" ;;
        26.04) UBUNTU_CODENAME="resolute" ;;
        *) Die "unsupported Ubuntu release: $1 (supported LTS: 20.04 22.04 24.04 26.04)" ;;
    esac
}

# CheckReinstallEnvironment
# Only Debian/Ubuntu hosts with apt, grub and a supported architecture.
CheckReinstallEnvironment() {
    HaveCommand apt || Die "only Ubuntu/Debian hosts are supported (apt not found)"
    GetOSArchitecture
    HaveCommand grub-reboot || Die "grub-reboot not found; this tool expects a GRUB-booted Ubuntu host"
    [ -d /boot/grub ] || Die "/boot/grub not found; this tool expects a GRUB-booted Ubuntu host"
    HaveCommand openssl || apt-get install -qy openssl
    HaveCommand cpio || apt-get install -qy cpio
    if [ "$(free -m | awk '/^Mem:/ {print $2}')" -lt 1024 ]; then
        LogWarn "less than 1 GiB RAM; the installer may be slow or fail"
    fi
    free_mb=$(df -Pm / | awk 'NR==2 {print $4}')
    if [ "$free_mb" -lt 512 ]; then
        Die "less than 512 MiB free on / ; needed for the Alpine netboot files"
    fi
    LogInfo "architecture: ${OS_ARCHITECTURE}, firmware: $([ -d /sys/firmware/efi ] && echo efi || echo bios)"
}

# CollectReinstallFacts
# Network facts are replayed into the new system via netplan; the boot disk is
# located by partition-table UUID so the installer cannot pick the wrong disk.
CollectReinstallFacts() {
    MGMT_IFACE=$(ip -4 route show default | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i + 1); exit}}')
    [ -n "$MGMT_IFACE" ] || Die "no default IPv4 route found"
    MGMT_MAC=$(cat "/sys/class/net/${MGMT_IFACE}/address")
    MGMT_IPV4=$(ip -4 addr show "$MGMT_IFACE" scope global | awk '/inet / {print $2; exit}')
    MGMT_IPV4_GW=$(ip -4 route show default | awk '{print $3; exit}')
    MGMT_IPV6=$(ip -6 addr show "$MGMT_IFACE" scope global temporary 2>/dev/null | awk '/inet6/ && !/temporary/ {print $2; exit}')
    MGMT_IPV6_GW=$(ip -6 route show default 2>/dev/null | awk '/default/ {print $3; exit}')
    DNS_SERVERS=$(awk '/^nameserver/ {print $2}' /etc/resolv.conf | grep -v '^127\.' | head -n 3 | paste -sd, -)
    [ -n "$DNS_SERVERS" ] || DNS_SERVERS="223.5.5.5,8.8.8.8"

    root_source=$(findmnt -no SOURCE /)
    REINSTALL_DISK="/dev/$(lsblk -no PKNAME "$root_source" | head -n 1)"
    [ -b "$REINSTALL_DISK" ] || Die "could not resolve the boot disk from ${root_source}"
    MAIN_DISK_PTSIGN=$(lsblk -no PTUUID "$REINSTALL_DISK")
    [ -n "$MAIN_DISK_PTSIGN" ] || Die "disk ${REINSTALL_DISK} has no partition table signature"

    # modloop provides the kernel modules (nbd, filesystems) inside Alpine.
    if HaveCommand systemd-detect-virt && systemd-detect-virt -c -v > /dev/null 2>&1; then
        ALPINE_FLAVOUR="virt"
    elif HaveCommand virt-what && [ -n "$(virt-what)" ]; then
        ALPINE_FLAVOUR="virt"
    else
        ALPINE_FLAVOUR="lts"
    fi
    LogInfo "management NIC ${MGMT_IFACE} (${MGMT_IPV4:-dhcp}), disk ${REINSTALL_DISK}, alpine flavour ${ALPINE_FLAVOUR}"
}

# PrepareReinstallCredentials
# Password: env override, or generated (printed once). Keys: env override, or
# this host's existing root authorized_keys. Key-only installs lock the root
# password inside the new system.
PrepareReinstallCredentials() {
    REINSTALL_CREDENTIALS_MODE=""
    if [ -n "$REINSTALL_SSH_KEYS" ] && [ -f "$REINSTALL_SSH_KEYS" ]; then
        SSH_KEYS_CONTENT=$(cat "$REINSTALL_SSH_KEYS")
    elif [ -n "$REINSTALL_SSH_KEYS" ]; then
        SSH_KEYS_CONTENT="$REINSTALL_SSH_KEYS"
    elif [ -f /root/.ssh/authorized_keys ] && [ -s /root/.ssh/authorized_keys ]; then
        SSH_KEYS_CONTENT=$(cat /root/.ssh/authorized_keys)
        LogInfo "reusing the existing /root/.ssh/authorized_keys in the new system"
    else
        SSH_KEYS_CONTENT=""
    fi
    if [ -n "$REINSTALL_PASSWORD" ]; then
        REINSTALL_PASSWORD_HASH=$(openssl passwd -6 "$REINSTALL_PASSWORD")
        REINSTALL_CREDENTIALS_MODE="password"
    else
        REINSTALL_PASSWORD=$(head -c 16 /dev/urandom | base64 | tr -d '=+/' | head -c 16)
        REINSTALL_PASSWORD_HASH=$(openssl passwd -6 "$REINSTALL_PASSWORD")
        REINSTALL_CREDENTIALS_MODE="generated-password"
        LogWarn "no REINSTALL_PASSWORD given; generated: ${REINSTALL_PASSWORD} (store it now - it is shown only this once)"
    fi
}

# DownloadInstallerFiles
# Alpine netboot kernel/initrd/modloop plus the phase-2 installer script.
DownloadInstallerFiles() {
    GetUbuntuCodename "$REINSTALL_RELEASE"
    if [ "$REINSTALL_CN_MIRROR" = "true" ]; then
        ALPINE_MIRROR="http://mirrors.cernet.edu.cn/alpine"
        IMAGE_MIRROR="http://mirrors.cernet.edu.cn/ubuntu-cloud-images"
    else
        ALPINE_MIRROR="http://dl-cdn.alpinelinux.org/alpine"
        IMAGE_MIRROR="http://cloud-images.ubuntu.com"
    fi
    if [ "$REINSTALL_ALPINE_VERSION" = "auto" ]; then
        REINSTALL_ALPINE_VERSION=$(curl -fsSL "${ALPINE_MIRROR}/" | grep -oE 'v3\.[0-9]+' | sort -uV | tail -n 1 | tr -d v || true)
    fi
    case "$REINSTALL_ALPINE_VERSION" in
        3.[0-9][0-9]) ;;
        *) REINSTALL_ALPINE_VERSION="3.22" ;;
    esac
    case "$OS_ARCHITECTURE" in
        amd64) ALPINE_ARCH="x86_64" ;;
        arm64) ALPINE_ARCH="aarch64" ;;
    esac
    ALPINE_BASE="${ALPINE_MIRROR}/v${REINSTALL_ALPINE_VERSION}/releases/${ALPINE_ARCH}/netboot"
    REINSTALL_CLOUD_IMAGE="${IMAGE_MIRROR}/releases/${UBUNTU_CODENAME}/release/ubuntu-${REINSTALL_RELEASE}-server-cloudimg-${OS_ARCHITECTURE}.img"
    ALPINE_REPO="${ALPINE_MIRROR}/v${REINSTALL_ALPINE_VERSION}/main"

    curl -fsSL -o /reinstall-vmlinuz "${ALPINE_BASE}/vmlinuz-${ALPINE_FLAVOUR}"
    curl -fsSL -o /reinstall-initrd "${ALPINE_BASE}/initramfs-${ALPINE_FLAVOUR}"
    curl -fsSL -o /reinstall-modloop "${ALPINE_BASE}/modloop-${ALPINE_FLAVOUR}"
    curl -fsSL -o /reinstall-trans.sh "${REINSTALL_CONFHOME}/trans.sh"
    [ -s /reinstall-trans.sh ] || Die "failed to download the installer script from ${REINSTALL_CONFHOME}/trans.sh"
    for file in /reinstall-vmlinuz /reinstall-initrd /reinstall-modloop; do
        [ -s "$file" ] || Die "failed to download ${file}"
    done
    LogInfo "staged alpine v${REINSTALL_ALPINE_VERSION} (${ALPINE_FLAVOUR}) and Ubuntu ${REINSTALL_RELEASE} (${UBUNTU_CODENAME}) cloud image"
}

# BuildInstallerInitrd
# Unpack the Alpine initramfs, drop in trans.sh plus /configs, and patch the
# initramfs init to copy them into the RAM system before switch_root; the
# installer then runs via the OpenRC local service.
BuildInstallerInitrd() {
    workdir="/tmp/reinstall-initrd.autodeploy"
    rm -rf "$workdir"
    mkdir -p "$workdir"
    zcat /reinstall-initrd | cpio -idm -D "$workdir" > /dev/null 2>&1
    if [ ! -f "$workdir/init" ]; then
        Die "unexpected initramfs layout: no init script found"
    fi
    if ! grep -q '^exec switch_root' "$workdir/init"; then
        Die "could not find the switch_root call in the alpine init; aborting"
    fi
    mkdir -p "$workdir/configs"
    printf 'root:%s\n' "$REINSTALL_PASSWORD_HASH" > "$workdir/configs/password"
    if [ -n "$SSH_KEYS_CONTENT" ]; then
        printf '%s\n' "$SSH_KEYS_CONTENT" > "$workdir/configs/ssh_keys"
    fi
    cp /reinstall-trans.sh "$workdir/trans.sh"
    chmod +x "$workdir/trans.sh"
    awk '
        { print }
        /^exec switch_root/ && !injected {
            print "mkdir -p /sysroot/etc/local.d /sysroot/etc/runlevels/default"
            print "cp /trans.sh /sysroot/etc/local.d/trans.start"
            print "chmod +x /sysroot/etc/local.d/trans.start"
            print "cp -r /configs /sysroot/etc/configs"
            print "ln -sf /etc/init.d/local /sysroot/etc/runlevels/default/local"
            injected = 1
        }
    ' "$workdir/init" > "$workdir/init.autodeploy"
    mv "$workdir/init.autodeploy" "$workdir/init"
    chmod +x "$workdir/init"
    (cd "$workdir" && find . | cpio -o -H newc -R 0:0 | gzip -1) > /reinstall-initrd
    rm -rf "$workdir" /reinstall-trans.sh
    LogInfo "installer initramfs built with trans.sh and credentials baked in"
}

# InstallBootEntry
# Queue a one-time GRUB boot into the installer; the next reboot wipes the
# disk, so nothing of the host setup survives beyond this script.
InstallBootEntry() {
    GRUB_DEFAULT="saved"
    if grep -q '^GRUB_DEFAULT=' /etc/default/grub; then
        sed -i 's/^GRUB_DEFAULT=.*/GRUB_DEFAULT=saved/' /etc/default/grub
    else
        printf '%s\n' 'GRUB_DEFAULT=saved' >> /etc/default/grub
    fi
    grub-mkconfig -o /boot/grub/grub.cfg > /dev/null

    cmdline="quiet"
    cmdline="${cmdline} extra_img=${REINSTALL_CLOUD_IMAGE}"
    cmdline="${cmdline} extra_repo=${ALPINE_REPO}"
    cmdline="${cmdline} extra_mac=${MGMT_MAC}"
    cmdline="${cmdline} extra_iface=${MGMT_IFACE}"
    cmdline="${cmdline} extra_disk=${MAIN_DISK_PTSIGN}"
    cmdline="${cmdline} extra_arch=${OS_ARCHITECTURE}"
    cmdline="${cmdline} extra_codename=${UBUNTU_CODENAME}"
    cmdline="${cmdline} extra_partsize=${REINSTALL_INSTALLER_PART_SIZE_MB}"
    cmdline="${cmdline} extra_efi=$([ -d /sys/firmware/efi ] && echo 1 || echo 0)"
    if [ -n "$MGMT_IPV4" ]; then
        cmdline="${cmdline} extra_ipv4=${MGMT_IPV4} extra_ipv4_gw=${MGMT_IPV4_GW}"
    fi
    if [ -n "$MGMT_IPV6" ]; then
        cmdline="${cmdline} extra_ipv6=${MGMT_IPV6} extra_ipv6_gw=${MGMT_IPV6_GW}"
    fi
    cmdline="${cmdline} extra_dns=${DNS_SERVERS}"

    {
        printf '%s\n' 'menuentry "AutoDeploy Reinstall" --id autodeploy-reinstall {'
        printf '%s\n' '    search --no-floppy --file --set=root /reinstall-vmlinuz'
        printf '%s\n' "    linux /reinstall-vmlinuz ${cmdline}"
        printf '%s\n' '    initrd /reinstall-initrd'
        printf '%s\n' '}'
    } > /boot/grub/custom.cfg
    grub-reboot "AutoDeploy Reinstall"
    LogInfo "one-time boot entry installed; next reboot starts the reinstall"
}

RenderSummary() {
    LogInfo "============================================================"
    LogInfo "reinstall prepared: Ubuntu ${REINSTALL_RELEASE} (${UBUNTU_CODENAME}) on ${REINSTALL_DISK}"
    LogInfo "login: root"
    if [ "$REINSTALL_CREDENTIALS_MODE" = "generated-password" ]; then
        LogInfo "password (generated): ${REINSTALL_PASSWORD}"
    elif [ "$REINSTALL_CREDENTIALS_MODE" = "password" ]; then
        LogInfo "password: the value you passed in REINSTALL_PASSWORD"
    else
        LogInfo "password: locked (key-only login)"
    fi
    if [ -n "$SSH_KEYS_CONTENT" ]; then
        LogInfo "ssh keys: installed to /root/.ssh/authorized_keys"
    fi
    LogInfo "network: ${MGMT_IPV4:-dhcp4} on ${MGMT_IFACE} (mac ${MGMT_MAC})"
    LogInfo "reboot now with: reboot"
    LogInfo "============================================================"
}

## Process
RequireRoot
InitRun
RunStep "CheckReinstallEnvironment" CheckReinstallEnvironment
RunStep "CollectReinstallFacts" CollectReinstallFacts
RunStep "PrepareReinstallCredentials" PrepareReinstallCredentials
RunStep "DownloadInstallerFiles" DownloadInstallerFiles
RunStep "BuildInstallerInitrd" BuildInstallerInitrd
RunStep "InstallBootEntry" InstallBootEntry
RenderSummary
RenderProgress "complete"
rm -f /tmp/*.autodeploy > /dev/null 2>&1 || true
