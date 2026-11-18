#!/bin/bash
# Copyright 2026 Zhijie He
# Licensed under Apache-2.0 WITH Commons-Clause-1.0. See LICENSE.
#
# GENERATED FILE - edit src/ and run ./build.sh to regenerate.
# For a one-off tweak you may edit the Configuration block below.
#
## How to get and use?
# curl "https://source.zhijie.online/ZJDeploy/main/dist/Ubuntu.sh" | sudo bash
# wget -qO- "https://source.zhijie.online/ZJDeploy/main/dist/Ubuntu.sh" | sudo bash
# ============================================================================
# Configuration - shared across all platforms
# Common knobs shared by every generated script. Platform config files add
# platform-specific defaults on top of these. Every knob is env-overridable.
# ============================================================================

## Resume / progress
# State lives under the running user's home. ZJDEPLOY_FORCE=true re-runs all.
ZJDEPLOY_STATE_DIR="${ZJDEPLOY_STATE_DIR:-${HOME}/.zjdeploy}"
ZJDEPLOY_FORCE="${ZJDEPLOY_FORCE:-false}"

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
# Configuration - shared between Ubuntu and Proxmox VE (Debian family)
# Knobs shared by both Debian-family platforms. Platform config files
# (Ubuntu.sh / ProxmoxVE.sh) add the platform deltas on top of these.
# ============================================================================

## Credentials (defaults are intentional; change them after deployment)
ROOT_PASSWORD="${ROOT_PASSWORD:-}" # empty = generate a random one at run time (printed)
LOCK_ROOT="${LOCK_ROOT:-false}" # TRUE locks the root account after deployment
# The literal defaults are intentional: Synology DSM's UPS client only
# attempts the well-known monuser/secret pair, so NUT_MON_PASSWORD must
# stay fixed for DSM hosts to connect (override the admin one freely).
NUT_ADMIN_PASSWORD="${NUT_ADMIN_PASSWORD:-123456}"
NUT_MON_PASSWORD="${NUT_MON_PASSWORD:-secret}"
SNMP_AUTH_PASSWORD="${SNMP_AUTH_PASSWORD:-}" # empty -> root password (warns)
SNMP_PRIV_PASSWORD="${SNMP_PRIV_PASSWORD:-}" # empty -> hostname (warns)

## Behavior switches
PURGE_OTHER_USERS="${PURGE_OTHER_USERS:-true}" # remove other /home users (fresh-install assumption)
RESET_DOMAIN="${RESET_DOMAIN:-false}"
RESET_HOSTNAME="${RESET_HOSTNAME:-false}"
CUSTOM_HOSTNAME="${CUSTOM_HOSTNAME:-}" # explicit hostname; overrides auto-detection and RESET_HOSTNAME
CUSTOM_DOMAIN="${CUSTOM_DOMAIN:-}" # explicit search domain(s), space-separated; overrides RESET_DOMAIN
DISABLE_ICMP_ECHO="${DISABLE_ICMP_ECHO:-false}"
PREFER_IPV4="${PREFER_IPV4:-true}"
I915_GUC_OPTION="${I915_GUC_OPTION:-3}" # 0 | 1 GuC | 2 HuC | 3 GuC/HuC
NUT_MODE="${NUT_MODE:-none}" # netclient | netserver | none | standalone
NUT_HOST="${NUT_HOST:-localhost}" # NUT server host (netclient mode)
UPS_NAME="${UPS_NAME:-ups}" # UPS device name on the NUT server

## Network
CUSTOM_DNS="${CUSTOM_DNS:-223.5.5.5 223.6.6.6 2400:3200::1 2400:3200:baba::1}" # resolvers, space-separated (AliDNS)

## Proxy / mirrors
DOCKER_REGISTRY_MIRRORS=()

## Dependency packages (apt) - Debian family base
# Architecture-neutral packages present on both platforms. Platform configs
# extend via: DEPENDENCY_PACKAGES=("${DEPENDENCY_PACKAGES_BASE[@]}" <extras>)
DEPENDENCY_PACKAGES_BASE=(
    "apparmor"
    "apparmor-profiles"
    "apparmor-profiles-extra"
    "apparmor-utils"
    "apt-file"
    "apt-transport-https"
    "busybox"
    "ca-certificates"
    "chrony"
    "curl"
    "bind9-dnsutils"
    "ethtool"
    "fail2ban"
    "fastfetch"
    "fonts-noto-cjk"
    "fonts-noto-color-emoji"
    "fwupd"
    "git"
    "git-lfs"
    "gnupg"
    "iperf3"
    "jq"
    "knot-dnsutils"
    "libsnmp-dev"
    "lldpd"
    "lm-sensors"
    "lsb-release"
    "mailutils"
    "mtr-tiny"
    "nano"
    "net-tools"
    "nmap"
    "nut"
    "nut-i2c"
    "nut-ipmi"
    "nut-modbus"
    "nut-powerman-pdu"
    "nut-snmp"
    "nut-xml"
    "openssh-client"
    "openssh-server"
    "7zip"
    "pinentry-tty"
    "postfix"
    "proxychains4" # renamed from proxychains-ng in resolute/trixie
    "python3"
    "python3-pip"
    "qrencode"
    "rar"
    "rsyslog"
    "snmp"
    "snmp-mibs-downloader"
    "snmpd"
    "sudo-rs" # rust sudo is the 26.04 / trixie direction; classic sudo.ws stays out
    "systemd"
    "systemd-zram-generator"
    "tcpdump"
    "tshark"
    "tuned"
    "udisks2"
    "udisks2-bcache"
    "udisks2-btrfs"
    "udisks2-lvm2"
    "udisks2-zram"
    "unrar"
    "unzip"
    "uuid-runtime"
    "vim"
    "virt-what"
    "wget"
    "whois"
    "zip"
    "zsh"
)
# ============================================================================
# Configuration - Ubuntu
# Platform additions on top of config/common.sh + config/debian.sh. Override
# any knob via environment variable before running, e.g.:
#   ROOT_PASSWORD='...' PURGE_OTHER_USERS=false curl .../Ubuntu.sh | sudo bash
# ============================================================================

## Resume / progress
ZJDEPLOY_STEP_TOTAL=52 # must match the RunStep count (lint.sh checks)

## Credentials
DEFAULT_PASSWORD="${DEFAULT_PASSWORD:-}" # empty = generate a random one at run time (printed)
SNMP_USER="${SNMP_USER:-ubuntu}" # SNMPv3 read-only user

## Identity
DEFAULT_USERNAME="${DEFAULT_USERNAME:-default}"
DEFAULT_FIRSTNAME="${DEFAULT_FIRSTNAME:-User}"
DEFAULT_LASTNAME="${DEFAULT_LASTNAME:-Default}"

## Behavior switches
DISABLE_SWAP="${DISABLE_SWAP:-false}"
XANMOD_BRANCH="${XANMOD_BRANCH:-main}" # disable | main | edge | lts | rt; psABI v1 CPUs are forced to lts (edge has been identical to main since 7.3)
INSTALL_CLOUDFLARE_WARP="${INSTALL_CLOUDFLARE_WARP:-false}" # install cloudflare-warp from the Cloudflare repo
INSTALL_TOR="${INSTALL_TOR:-false}" # install tor from the torproject repo
SSH_PORT="${SSH_PORT:-9022}" # sshd listen port (fail2ban jail + ufw follow this)
COCKPIT_PORT="${COCKPIT_PORT:-9090}" # cockpit web UI port (cockpit.socket override)

## Release pinning (intentionally the latest release; bump each release)
LSB_CODENAME="${LSB_CODENAME:-resolute}"
LSB_VERSION="${LSB_VERSION:-26.04}"

## Network (STATIC_*_CONFIG format: address/prefix,gateway)
NIC_NAME="${NIC_NAME:-}" # e.g. enp6s18 / ens18; empty -> auto-detect
STATIC_IPV4_CONFIG="${STATIC_IPV4_CONFIG:-}" # e.g. 10.192.31.254/19,10.192.0.1
STATIC_IPV6_CONFIG="${STATIC_IPV6_CONFIG:-}" # e.g. 2409:8a20:8800::254/64,2409:8a20:8800::1

## Zsh
ZSH_BUILD_IN_PLUGINS="${ZSH_BUILD_IN_PLUGINS:-aliases colored-man-pages command-not-found common-aliases docker docker-compose extract git history ssh sudo systemd ubuntu ufw}"

## Dependency packages (apt) - Ubuntu additions
DEPENDENCY_PACKAGES=("${DEPENDENCY_PACKAGES_BASE[@]}"
    "cockpit"
    "cron"
    "iputils-ping"
    "landscape-common"
    "netplan.io"
    "nfs-common"
    "realmd"
    "socat"
    "ufw"
    "update-notifier-common"
    "wireguard"
)
# ============================================================================
# core.sh - logging, error handling and the resume/progress state machine
# Shared across all platforms (DSM / macOS / Ubuntu / Proxmox VE / Reinstall).
# Part of the generated single-file scripts; not executable on its own.
# Compatible with bash 3.2 (macOS system bash) - avoid bash 4+ features here.
# ============================================================================

set -Eeuo pipefail

LogInfo() {
    printf '[ZJDeploy] %s\n' "$*"
}

LogWarn() {
    printf '[ZJDeploy] WARNING: %s\n' "$*" >&2
}

Die() {
    printf '[ZJDeploy] ERROR: %s\n' "$*" >&2
    exit 1
}

# LogSeparator
# Full-width separator line for summary blocks; every block that frames a
# report prints these through here instead of inlining the dashes.
LogSeparator() {
    LogInfo "============================================================"
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

# MintRandomPassword
# 32 hex characters from /dev/urandom (od reads exactly 16 bytes, so no
# SIGPIPE games under pipefail). Linux-only; used when a password knob is
# left empty.
MintRandomPassword() {
    od -An -N16 -tx1 /dev/urandom | tr -d ' \n'
}

WarnDefaultPassword() {
    local name="$1" value="$2" default_value="$3"
    if [ "$value" = "$default_value" ]; then
        LogWarn "${name} is using the built-in default; change it after deployment or override it with ${name}=<value> before running"
    fi
}

# Under `curl | sudo bash`, whoami is root; SUDO_USER is the real operator.
# Used by DSM/macOS; debian platforms use DEFAULT_USERNAME instead.
GetCurrentUsername() {
    # shellcheck disable=SC2034
    CURRENT_USERNAME="${SUDO_USER:-$(whoami)}"
}

# Detect the package architecture (amd64 | arm64); anything else is fatal.
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
# unfinished step. ZJDEPLOY_FORCE=true clears the state and re-runs everything.
# Platform must set: ZJDEPLOY_STATE_DIR, ZJDEPLOY_STEP_TOTAL.
StateFile() {
    printf '%s/state\n' "$ZJDEPLOY_STATE_DIR"
}

StepDone() {
    local state_file
    state_file=$(StateFile)
    [ -f "$state_file" ] && grep -qxF "$1" "$state_file"
}

MarkStep() {
    mkdir -p "$ZJDEPLOY_STATE_DIR"
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
    local label="$1" total="${ZJDEPLOY_STEP_TOTAL:-0}" completed width=20 filled percent bar
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
    if [ "${ZJDEPLOY_FORCE:-false}" != "true" ] && StepDone "$step_id"; then
        LogInfo "skip ${step_id} (completed in a previous run)"
        return 0
    fi
    RenderProgress "running ${step_id}"
    "$@"
    MarkStep "$step_id"
}

InitRun() {
    if [ "${ZJDEPLOY_FORCE:-false}" = "true" ]; then
        rm -f "$(StateFile)"
        LogInfo "ZJDEPLOY_FORCE=true: re-running all steps"
    else
        local completed
        completed=$(StepsCompleted)
        if [ "$completed" -gt 0 ]; then
            LogInfo "resuming: ${completed}/${ZJDEPLOY_STEP_TOTAL} steps already complete"
        fi
    fi
}

trap 'Die "failed at line ${LINENO}: ${BASH_COMMAND}"' ERR
# ============================================================================
# modules/crontab.sh - crontab installation helper (all platforms, bash 3.2+)
# Caller must set: CRONTAB_USER, CRONTAB_ENTRIES (array)
# ============================================================================

InstallCrontab() {
    HaveCommand crontab || return 0
    local sudo_prefix=()
    if [ "$(id -u)" -ne 0 ]; then
        sudo_prefix=(sudo)
    fi
    printf '%s\n' "${CRONTAB_ENTRIES[@]}" | ${sudo_prefix[@]+"${sudo_prefix[@]}"} crontab -u "$CRONTAB_USER" -
    ${sudo_prefix[@]+"${sudo_prefix[@]}"} crontab -lu "$CRONTAB_USER"
}
# ============================================================================
# modules/git.sh - global git configuration (all platforms, bash 3.2+)
# Uses the GIT_* knobs from config/common.sh.
# ============================================================================

ApplyGitConfig() {
    local gitconfig_key_list=(
        "commit.gpgsign"
        "gpg.program"
        "http.proxy"
        "https.proxy"
        "user.name"
        "user.email"
        "user.signingkey"
        "url.${GHPROXY_URL}https://github.com/.insteadOf"
    )
    local gitconfig_value_list=(
        "${GIT_COMMIT_GPGSIGN:-false}"
        "${GIT_GPG_PROGRAM:-gpg}"
        "${GIT_HTTP_PROXY:-}"
        "${GIT_HTTPS_PROXY:-}"
        "${GIT_USER_NAME:-}"
        "${GIT_USER_EMAIL:-}"
        "${GIT_USER_SIGNINGKEY:-}"
        "https://github.com/"
    )
    local i
    for i in "${!gitconfig_key_list[@]}"; do
        git config --global --unset "${gitconfig_key_list[$i]}" || true
        if [ -n "${gitconfig_value_list[$i]}" ]; then
            git config --global "${gitconfig_key_list[$i]}" "${gitconfig_value_list[$i]}"
        fi
    done
}

ConfigureGit() {
    HaveCommand git || return 0
    ApplyGitConfig
    # On root-run platforms the default user gets a baseline config without
    # the operator's personal identity (configure that per user later).
    if [ "$(id -u)" -eq 0 ] && [ -n "${DEFAULT_USERNAME:-}" ]; then
        local user_gitconfig="/home/${DEFAULT_USERNAME}/.gitconfig"
        git config --file "$user_gitconfig" commit.gpgsign "${GIT_COMMIT_GPGSIGN:-false}"
        git config --file "$user_gitconfig" gpg.program "${GIT_GPG_PROGRAM:-gpg}"
        git config --file "$user_gitconfig" "url.${GHPROXY_URL}https://github.com/.insteadOf" "https://github.com/"
        chown "$DEFAULT_USERNAME:$DEFAULT_USERNAME" "$user_gitconfig"
    fi
}
# ============================================================================
# modules/gpg.sh - GPG key setup with SSH authentication support
# (all platforms, bash 3.2+)
# Platform must set: GPG_HOME, GPG_KEYSERVER, GPG_PINENTRY (may be empty),
# and optionally GPG_HOME_OWNER (user:group) when running as root.
# ============================================================================

ConfigureGPG() {
    HaveCommand gpg || return 0
    GPG_PUBKEY="${GPG_PUBKEY:-DD982DAAB9C71C78F9563E5207EB56787030D792}"
    BackupPath "$GPG_HOME"
    mkdir -p "$GPG_HOME"
    export GNUPGHOME="$GPG_HOME"
    gpg --keyserver "$GPG_KEYSERVER" --recv "$GPG_PUBKEY" || Die "failed to receive GPG key ${GPG_PUBKEY}"
    printf '%s:6:\n' "$GPG_PUBKEY" | gpg --import-ownertrust
    GPG_PUBKEY_ID_A=$(gpg --list-keys --keyid-format LONG | awk '/^(pub|sub)/ && /\[A\]/ {split($2, a, "/"); print a[2]}' | head -n 1)
    GPG_PUBKEY_ID_C=$(gpg --list-keys --keyid-format LONG | awk '/^(pub|sub)/ && /\[C\]/ {split($2, a, "/"); print a[2]}' | head -n 1)
    if [ -n "$GPG_PUBKEY_ID_A" ]; then
        {
            printf '%s\n' "enable-ssh-support"
            if [ -n "$GPG_PINENTRY" ]; then
                printf '%s\n' "pinentry-program ${GPG_PINENTRY}"
            fi
        } > "${GPG_HOME}/gpg-agent.conf"
        printf '%s\n' "$GPG_PUBKEY_ID_A" > "${GPG_HOME}/sshcontrol"
    fi
    if [ -n "$GPG_PUBKEY_ID_C" ]; then
        gpg --export-ssh-key "$GPG_PUBKEY_ID_C" > "${GPG_HOME}/authorized_keys"
    fi
    gpgconf --kill gpg-agent > /dev/null 2>&1 || true
    unset GNUPGHOME
    if [ -n "${GPG_HOME_OWNER:-}" ]; then
        chown -R "$GPG_HOME_OWNER" "$GPG_HOME"
    fi
    find "$GPG_HOME" -type d -exec chmod 700 {} +
    find "$GPG_HOME" -type f -exec chmod 600 {} +
}
# ============================================================================
# modules/hosts.sh - standard /etc/hosts entries (all platforms, bash 3.2+)
# Pure data table. Debian platforms append platform extras via WriteHostfile
# (modules/debian/system.sh); macOS writes the table with sudo tee directly.
# ============================================================================

# shellcheck disable=SC2034 # consumed by WriteHostfile (debian system.sh) and macOS
HOSTS_BASE_ENTRIES=(
    "127.0.0.1 localhost"
    "255.255.255.255 broadcasthost"
    "::1 ip6-localhost ip6-loopback localhost"
    "fe00::0 ip6-localnet"
    "ff00::0 ip6-mcastprefix"
    "ff02::1 ip6-allnodes"
    "ff02::2 ip6-allrouters"
    "ff02::3 ip6-allhosts"
)
# ============================================================================
# modules/proxychains.sh - proxychains-ng client configuration
# (all platforms, bash 3.2+)
# Platform must set: PROXYCHAINS_CONF
# ============================================================================

ConfigureProxyChains() {
    local proxy_line="${PROXY_PROTOCOL:-socks5} ${PROXY_IP:-127.0.0.1} ${PROXY_PORT:-7891}"
    # proxychains reads user/pass as a pair; append only when both are set,
    # so an empty password can never leave a trailing space behind.
    if [ -n "${PROXY_USERNAME:-}" ] && [ -n "${PROXY_PASSWORD:-}" ]; then
        proxy_line="${proxy_line} ${PROXY_USERNAME} ${PROXY_PASSWORD}"
    fi
    local proxychains_list=(
        'localnet 127.0.0.0/255.0.0.0'
        'localnet 10.0.0.0/255.0.0.0'
        'localnet 172.16.0.0/255.240.0.0'
        'localnet 192.168.0.0/255.255.0.0'
        'localnet ::1/128'
        'proxy_dns'
        'remote_dns_subnet 224'
        'strict_chain'
        'tcp_connect_time_out 8000'
        'tcp_read_time_out 15000'
        '[ProxyList]'
        "${proxy_line}"
    )
    printf '%s\n' "${proxychains_list[@]}" > "$PROXYCHAINS_CONF"
}
# ============================================================================
# modules/pypi.sh - pip mirror configuration (all platforms, bash 3.2+)
# On root-run platforms the resulting config is copied to DEFAULT_USERNAME.
# ============================================================================

ConfigurePythonPyPI() {
    local which_pip=""
    if HaveCommand pip3; then
        which_pip="pip3"
    elif HaveCommand pip; then
        which_pip="pip"
    else
        return 0
    fi
    "$which_pip" config set global.index-url "https://mirrors.cernet.edu.cn/pypi/web/simple"
    if [ "$(id -u)" -eq 0 ] && [ -n "${DEFAULT_USERNAME:-}" ] && [ -f "/root/.config/pip/pip.conf" ]; then
        install -D -m 644 -o "$DEFAULT_USERNAME" -g "$DEFAULT_USERNAME" \
            "/root/.config/pip/pip.conf" "/home/${DEFAULT_USERNAME}/.config/pip/pip.conf"
    fi
}
# ============================================================================
# modules/ssh.sh - SSH key pair generation and per-user .ssh initialization
# (all platforms, bash 3.2+)
# ============================================================================

# Generate the user key pairs (ecdsa/ed25519/rsa) inside an existing .ssh dir.
# DSA is intentionally gone: OpenSSH >= 9.8 disables it, 10.x removed it.
GenerateSSHKeys() {
    local ssh_dir="$1" comment="$2"
    ssh-keygen -t ecdsa -b 384 -f "${ssh_dir}/id_ecdsa" -C "$comment" -N "${OPENSSH_PASSWORD:-}"
    ssh-keygen -t ed25519 -f "${ssh_dir}/id_ed25519" -C "$comment" -N "${OPENSSH_PASSWORD:-}"
    ssh-keygen -t rsa -b 4096 -f "${ssh_dir}/id_rsa" -C "$comment" -N "${OPENSSH_PASSWORD:-}"
    chmod 400 "${ssh_dir}"/id_*
    chmod 644 "${ssh_dir}"/id_*.pub
}

GenerateHostSSHKeys() {
    local ssh_dir="$1" comment="$2"
    rm -f "${ssh_dir}"/ssh_host_*
    ssh-keygen -t ecdsa -b 384 -f "${ssh_dir}/ssh_host_ecdsa_key" -C "$comment" -N "${OPENSSH_PASSWORD:-}"
    ssh-keygen -t ed25519 -f "${ssh_dir}/ssh_host_ed25519_key" -C "$comment" -N "${OPENSSH_PASSWORD:-}"
    ssh-keygen -t rsa -b 4096 -f "${ssh_dir}/ssh_host_rsa_key" -C "$comment" -N "${OPENSSH_PASSWORD:-}"
    chmod 400 "${ssh_dir}"/ssh_host_*
    chmod 644 "${ssh_dir}"/ssh_host_*.pub
}

# Initialize a user .ssh dir: back up any existing one, create the skeleton,
# generate the key pairs, fix permissions. Callers that import authorized_keys
# from GPG_HOME do so afterwards (the mv replaces the placeholder file).
# Pass owner (user:group) when running as root; empty owner = skip chown.
InitUserSSHDir() {
    local ssh_dir="$1" comment="$2" owner="${3:-}"
    BackupPath "$ssh_dir"
    mkdir -p "$ssh_dir"
    touch "${ssh_dir}/authorized_keys" "${ssh_dir}/known_hosts"
    GenerateSSHKeys "$ssh_dir" "$comment"
    chmod 600 "${ssh_dir}/authorized_keys"
    chmod 644 "${ssh_dir}/known_hosts"
    chmod 700 "$ssh_dir"
    if [ -n "$owner" ]; then
        chown -R "$owner" "$ssh_dir"
    fi
}
# ============================================================================
# modules/wireguard.sh - wg0 client configuration writer
# (all platforms, bash 3.2+)
# Writes /etc/wireguard/wg0.conf. The private key never touches a temp file.
# Platform handles directory ownership and bringing the interface up.
# ============================================================================

GenerateWireGuardConfig() {
    local tunnel_address="10.172.$((RANDOM % 256)).$((RANDOM % 256))/32"
    local private_key public_key preshared_key
    private_key=$(wg genkey)
    public_key=$(printf '%s' "$private_key" | wg pubkey)
    preshared_key=$(wg genpsk)
    local wireguard_list=(
        "[Interface]"
        "Address = ${tunnel_address}"
        "# DNS = 127.0.0.1, ::1"
        "ListenPort = 51820"
        "MTU = 1420"
        "PrivateKey = ${private_key}"
        "# [Peer]"
        "# AllowedIPs = ${tunnel_address}"
        "# Endpoint = 127.0.0.1:51820"
        "# PersistentKeepalive = 5"
        "# PresharedKey = ${preshared_key}"
        "# PublicKey = ${public_key}"
    )
    printf '%s\n' "${wireguard_list[@]}" > "/etc/wireguard/wg0.conf"
    chmod 600 "/etc/wireguard/wg0.conf"
}
# ============================================================================
# modules/zsh.sh - oh-my-zsh installation and .zshrc generation
# (all platforms, bash 3.2+)
# Platform must set: ZSH_PATHS (array). ConfigureZsh additionally needs
# ZSH_HOME, ZSH_BUILD_IN_PLUGINS, ZSH_EXTRA_EXPORTS (array, may be empty),
# ZSH_TRAPEXIT (true/false), ZSH_OWNER (may be empty); InstallOhMyZsh needs
# OMZ_HOME, OMZ_OWNER (may be empty).
# ============================================================================

GenerateCommandPath() {
    DEFAULT_PATH=""
    local path_entry
    for path_entry in "${ZSH_PATHS[@]}"; do
        DEFAULT_PATH="${path_entry}:${DEFAULT_PATH}"
    done
    DEFAULT_PATH="${DEFAULT_PATH%:}"
}

GenerateOMZProfile() {
    local proxy_url="${PROXY_URL:-http://vpn.zhijie.online:7890}"
    local no_proxy='localhost,127.0.0.1,::1'
    local external_plugins="zsh-autosuggestions zsh-completions zsh-history-substring-search zsh-syntax-highlighting"
    local omz_list=(
        "export EDITOR=\"nano\""
        "export GPG_TTY=\$(tty)"
        ${ZSH_EXTRA_EXPORTS[@]+"${ZSH_EXTRA_EXPORTS[@]}"}
        "export PATH=\"${DEFAULT_PATH}:\$PATH\""
        "export SSH_AUTH_SOCK=\"\$(gpgconf --list-dirs agent-ssh-socket)\" && gpgconf --launch gpg-agent && gpg-connect-agent updatestartuptty /bye > \"/dev/null\" 2>&1"
        "export ZSH=\"\$HOME/.oh-my-zsh\""
        "function proxy_off(){ unset all_proxy; unset ftp_proxy; unset http_proxy; unset https_proxy; unset rsync_proxy; unset no_proxy }"
        "function proxy_on(){ export all_proxy=\"${proxy_url}\"; export ftp_proxy=\"${proxy_url}\"; export http_proxy=\"${proxy_url}\"; export https_proxy=\"${proxy_url}\"; export rsync_proxy=\"${proxy_url}\"; export no_proxy=\"${no_proxy}\" }"
        "plugins=(${ZSH_BUILD_IN_PLUGINS} ${external_plugins})"
        "ZSH_CACHE_DIR=\"\$ZSH/cache\""
        "ZSH_CUSTOM=\"\$ZSH/custom\""
        "ZSH_THEME=\"${ZSH_THEME:-ys}\""
        "DISABLE_AUTO_UPDATE=\"true\""
        "DISABLE_UPDATE_PROMPT=\"true\""
        "UPDATE_ZSH_DAYS=\"7\""
        "ZSH_COMPDUMP=\"\$ZSH_CACHE_DIR/.zcompdump\""
        "ZSH_DISABLE_COMPFIX=\"false\""
        "CASE_SENSITIVE=\"true\""
        "COMPLETION_WAITING_DOTS=\"true\""
        "DISABLE_AUTO_TITLE=\"false\""
        "DISABLE_LS_COLORS=\"false\""
        "DISABLE_MAGIC_FUNCTIONS=\"true\""
        "DISABLE_UNTRACKED_FILES_DIRTY=\"false\""
        "ENABLE_CORRECTION=\"true\""
        "HIST_STAMPS=\"yyyy-mm-dd\""
        "HYPHEN_INSENSITIVE=\"false\""
        "ZSH_THEME_RANDOM_QUIET=\"true\""
        "ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE=\"bg=250,fg=238,bold,underline\""
        "ZSH_AUTOSUGGEST_STRATEGY=(match_prev_cmd history completion)"
        "ZSH_AUTOSUGGEST_USE_ASYNC=\"true\""
        "source \"\$ZSH/oh-my-zsh.sh\""
    )
    if [ "${ZSH_TRAPEXIT:-false}" = "true" ]; then
        omz_list+=('TRAPEXIT() { rm -rf ~/.zsh_history(N) ~/.ssh/known_hosts*(N) }')
    fi
    printf '%s\n' "${omz_list[@]}" > "${ZSH_HOME}/.zshrc"
    if [ -n "${ZSH_OWNER:-}" ]; then
        chown "$ZSH_OWNER" "${ZSH_HOME}/.zshrc"
    fi
}

ConfigureZsh() {
    HaveCommand zsh || return 0
    [ -d "${ZSH_HOME}/.oh-my-zsh" ] || return 0
    GenerateCommandPath
    GenerateOMZProfile
}

InstallOhMyZsh() {
    HaveCommand git || Die "git is required to install oh-my-zsh"
    local plugin_list=(
        "zsh-autosuggestions"
        "zsh-completions"
        "zsh-history-substring-search"
        "zsh-syntax-highlighting"
    )
    local omz_dir="${OMZ_HOME}/.oh-my-zsh"
    BackupPath "$omz_dir"
    git clone --depth=1 "${GHPROXY_URL:-}https://github.com/ohmyzsh/ohmyzsh.git" "$omz_dir"
    local plugin
    for plugin in "${plugin_list[@]}"; do
        git clone --depth=1 "${GHPROXY_URL:-}https://github.com/zsh-users/${plugin}.git" "${omz_dir}/custom/plugins/${plugin}"
    done
    # Single quotes are intentional: this script is generated, not expanded here.
    # shellcheck disable=SC2016
    local plugin_upgrade_list=(
        '#!/bin/bash'
        'plugin_list=($(ls "$HOME/.oh-my-zsh/custom/plugins" | grep -v "^example$"))'
        'for plugin_list_task in "${!plugin_list[@]}"; do'
        "    rm -rf \"\$HOME/.oh-my-zsh/custom/plugins/\${plugin_list[\$plugin_list_task]}\" && git clone --depth=1 \"${GHPROXY_URL:-}https://github.com/zsh-users/\${plugin_list[\$plugin_list_task]}.git\" \"\$HOME/.oh-my-zsh/custom/plugins/\${plugin_list[\$plugin_list_task]}\""
        'done'
    )
    printf '%s\n' "${plugin_upgrade_list[@]}" > "${omz_dir}/oh-my-zsh-plugin.sh"
    if [ -n "${OMZ_OWNER:-}" ]; then
        chown -R "$OMZ_OWNER" "$omz_dir"
    fi
}
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
    printf '%s\n' "${apt_conf_list[@]}" > /etc/apt/apt.conf.d/99zjdeploy
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
# shellcheck disable=SC2034 # CRONTAB_* feed InstallCrontab (modules/crontab.sh)
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
    curl -fsSL "$key_url" | gpg --batch --yes --dearmor -o "/usr/share/keyrings/${name}-archive-keyring.gpg"
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
    rm -f /root/.*_history /tmp/*.zjdeploy "$@"
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
    if [ "${#kernel_list[@]}" -gt 0 ]; then
        # One apt pass for all outdated kernels, matching the batching in
        # InstallAptPackages.
        apt purge -qy "${kernel_list[@]}"
        apt autoremove -qy --purge
    fi
}
# ============================================================================
# modules/debian/daemons.sh - shared Debian-family service configuration
# (Ubuntu / Proxmox VE, bash 4.4+)
# ConfigureDockerEngine optionally reads DOCKER_REGISTRY_MIRRORS (array).
# InstallDockerEngine needs DOCKER_APT_DISTRO (ubuntu | debian).
# InstallFRRouting needs FRR_APT_LINE and optionally FRR_EXTRA_PACKAGES.
# ConfigureNut reads the NUT_* knobs; ConfigureSNMP-related parts live in
# modules/debian/security.sh.
# ============================================================================

ConfigureChrony() {
    HaveCommand chronyc || return 0
    local chrony_list=(
        "allow"
        "clientloglimit 65536"
        "driftfile /var/lib/chrony/chrony.drift"
        "dumpdir /run/chrony"
        "keyfile /etc/chrony/chrony.keys"
        "leapsectz right/UTC"
        "logdir /var/log/chrony"
        "makestep 1 3"
        "ratelimit burst 8 interval 3 leak 2"
        "rtcsync"
    )
    local chrony_ntp_list=(
        "ntp.ntsc.ac.cn"
        "ntp1.nim.ac.cn"
        "ntp2.nim.ac.cn"
        "ntp.aliyun.com"
        "ntp.tencent.com"
        "time.apple.com"
        "time.windows.com"
        "time.cloudflare.com"
        "time.nist.gov"
        "pool.ntp.org"
    )
    local prefer_list=("ntp.ntsc.ac.cn" "ntp1.nim.ac.cn" "ntp2.nim.ac.cn")
    local server suffix
    {
        printf '%s\n' "${chrony_list[@]}"
        for server in "${chrony_ntp_list[@]}"; do
            suffix=" iburst"
            case " ${prefer_list[*]} " in
                *" ${server} "*) suffix=" iburst prefer" ;;
            esac
            printf 'server %s%s\n' "$server" "$suffix"
        done
    } > /etc/chrony/chrony.conf
    systemctl restart chrony
    sleep 5
    chronyc activity
    chronyc tracking
    chronyc clients
    hwclock -w || true
}

ConfigureDockerEngine() {
    HaveCommand docker || return 0
    local docker_list=(
        "{"
        "  \"allow-direct-routing\": true,"
        "  \"experimental\": true,"
        "  \"firewall-backend\": \"nftables\","
        "  \"ip-forward\": true,"
        "  \"live-restore\": true,"
        "  \"log-driver\": \"json-file\","
        "  \"log-opts\": {"
        "    \"max-file\": \"3\","
        "    \"max-size\": \"10m\""
        "  }"
        "}"
    )
    if [ "${#DOCKER_REGISTRY_MIRRORS[@]}" -gt 0 ]; then
        docker_list=(
            "{"
            "  \"allow-direct-routing\": true,"
            "  \"experimental\": true,"
            "  \"firewall-backend\": \"nftables\","
            "  \"ip-forward\": true,"
            "  \"live-restore\": true,"
            "  \"log-driver\": \"json-file\","
            "  \"log-opts\": {"
            "    \"max-file\": \"3\","
            "    \"max-size\": \"10m\""
            "  },"
            "  \"registry-mirrors\": ["
            "$(printf '    "%s",\n' "${DOCKER_REGISTRY_MIRRORS[@]}" | sed '$s/,$//')"
            "  ]"
            "}"
        )
    fi
    mkdir -p "/docker"
    chown -R "${DEFAULT_USERNAME}:docker" "/docker"
    chmod -R 775 "/docker"
    mkdir -p /etc/docker
    # daemon.json is the single source of truth; the legacy /etc/default/docker
    # DOCKER_OPTS file is ignored by the systemd unit and contradicted the
    # docker-managed iptables, so it is deliberately not written.
    printf '%s\n' "${docker_list[@]}" > /etc/docker/daemon.json
    systemctl enable docker
    systemctl restart docker
}

InstallDockerEngine() {
    InstallAptRepo "docker" "https://mirrors.cernet.edu.cn/docker-ce/linux/${DOCKER_APT_DISTRO}/gpg" \
        "deb [arch=${OS_ARCHITECTURE:-amd64} signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://mirrors.cernet.edu.cn/docker-ce/linux/${DOCKER_APT_DISTRO} ${LSB_CODENAME} stable"
    apt update
    apt purge -qy containerd docker-compose docker-doc docker.io podman-docker runc || true
    InstallAptPackages "containerd.io" "docker-buildx-plugin" "docker-ce" "docker-ce-cli" "docker-compose-plugin"
}

ConfigureFRRouting() {
    HaveCommand vtysh || return 0
    local frrouting_list=(
        "frr defaults datacenter"
        "log syslog errors"
    )
    printf '%s\n' "${frrouting_list[@]}" > /etc/frr/frr.conf
    systemctl restart frr
    sleep 5
    vtysh -c "show running-config"
    vtysh -c "show ip route"
    vtysh -c "show ipv6 route"
}

InstallFRRouting() {
    InstallAptRepo "frrouting" "https://deb.frrouting.org/frr/keys.gpg" "$FRR_APT_LINE"
    InstallAptPackages "frr" "frr-pythontools" ${FRR_EXTRA_PACKAGES[@]+"${FRR_EXTRA_PACKAGES[@]}"} "frr-snmp"
}

ConfigureLLDPD() {
    HaveCommand lldpcli || return 0
    printf '%s\n' 'DAEMON_ARGS="-c -e -f -s -x"' > /etc/default/lldpd
    systemctl restart lldpd
    lldpcli show neighbors detail
}

ConfigureNut() {
    HaveCommand upsmon || return 0

    # upsd account entries: "name,password,role,actions" (actions space-separated).
    # The helpers write one file each and take their input as arguments; the
    # parsed user list stays a local of this function (dynamic scoping).
    BuildUpsdUserList() {
        NUT_ADMIN_PASSWORD="${NUT_ADMIN_PASSWORD:-123456}"
        NUT_MON_PASSWORD="${NUT_MON_PASSWORD:-secret}"
        WarnDefaultPassword "NUT_ADMIN_PASSWORD" "$NUT_ADMIN_PASSWORD" "123456"
        WarnDefaultPassword "NUT_MON_PASSWORD" "$NUT_MON_PASSWORD" "secret"
        upsd_user_list=(
            "admin,${NUT_ADMIN_PASSWORD},master,FSD SET"
            "monuser,${NUT_MON_PASSWORD},slave,"
        )
    }
    WriteNutConf() { # args: mode
        printf 'MODE=%s\n' "$1" > /etc/nut/nut.conf
    }
    WriteUpsConf() {
        local ups_driver_list=(
            "ups,usbhid-ups,auto"
        )
        local ups_conf_list=(
            "maxretry = 3"
            "retrydelay = 5"
        )
        local entry ups_name ups_driver ups_port
        {
            printf '%s\n' "${ups_conf_list[@]}"
            for entry in "${ups_driver_list[@]}"; do
                ups_name="${entry%%,*}"
                ups_driver=$(printf '%s' "$entry" | cut -d ',' -f 2)
                ups_port="${entry##*,}"
                printf '[%s]\n    driver = %s\n    port = %s\n' "$ups_name" "$ups_driver" "$ups_port"
            done
        } > /etc/nut/ups.conf
    }
    WriteUpsdConf() { # args: mode (standalone listens on loopback only)
        local upsd_config_list=(
            "MAXAGE 15"
            "MAXCONN 1024"
            "STATEPATH /var/run/nut"
        )
        {
            if [ "$1" = "standalone" ]; then
                printf '%s\n' "LISTEN 127.0.0.1 3493" "LISTEN ::1 3493"
            else
                printf '%s\n' "LISTEN 0.0.0.0 3493"
            fi
            printf '%s\n' "${upsd_config_list[@]}"
        } > /etc/nut/upsd.conf
    }
    WriteUpsdUsers() { # args: upsd user entries
        local entry username password role actions
        {
            for entry in "$@"; do
                username="${entry%%,*}"
                entry="${entry#*,}"
                password="${entry%%,*}"
                entry="${entry#*,}"
                role="${entry%%,*}"
                actions="${entry#*,}"
                printf '[%s]\n' "$username"
                if [ -n "$actions" ]; then
                    printf '    actions = %s\n    instcmds = ALL\n' "$actions"
                fi
                printf '    password = %s\n    upsmon %s\n' "$password" "$role"
            done
        } > /etc/nut/upsd.users
    }
    WriteUpsmonConf() { # args: monitor_system, upsd user entry
        local monitor_system="$1" user_entry="$2" username password role
        username="${user_entry%%,*}"
        user_entry="${user_entry#*,}"
        password="${user_entry%%,*}"
        role="${user_entry#*,}"
        local upsmon_list=(
            "DEADTIME 15"
            "FINALDELAY 5"
            "HOSTSYNC 15"
            "MINSUPPLIES 1"
            "NOCOMMWARNTIME 300"
            "POLLFREQ 5"
            "POLLFREQALERT 5"
            "POWERDOWNFLAG /etc/killpower"
            "RBWARNTIME 43200"
            'SHUTDOWNCMD "/sbin/shutdown -h +0"'
            "MONITOR ${monitor_system} 1 ${username} ${password} ${role}"
        )
        printf '%s\n' "${upsmon_list[@]}" > /etc/nut/upsmon.conf
    }

    local mode="$NUT_MODE" upsd_user_list=() service_list=()
    rm -f /etc/nut/*
    case "$mode" in
        netclient)
            BuildUpsdUserList
            service_list=(
                "nut-client,enable"
                "nut-driver,disable"
                "nut-monitor,enable"
                "nut-server,disable"
            )
            WriteNutConf "$mode"
            WriteUpsmonConf "${UPS_NAME}@${NUT_HOST}" "${upsd_user_list[1]}"
            ;;
        netserver|standalone)
            BuildUpsdUserList
            service_list=(
                "nut-client,enable"
                "nut-driver,enable"
                "nut-monitor,enable"
                "nut-server,enable"
            )
            WriteNutConf "$mode"
            WriteUpsConf
            WriteUpsdConf "$mode"
            WriteUpsdUsers "${upsd_user_list[@]}"
            WriteUpsmonConf "${UPS_NAME}@localhost" "${upsd_user_list[0]}"
            ;;
        none)
            service_list=(
                "nut-client,disable"
                "nut-driver,disable"
                "nut-monitor,disable"
                "nut-server,disable"
            )
            WriteNutConf "$mode"
            ;;
        *)
            Die "unsupported NUT_MODE: ${mode} (supported: netclient | netserver | none | standalone)"
            ;;
    esac
    chown -R root:nut /etc/nut
    chmod 640 /etc/nut/*
    local entry service_name service_action
    for entry in "${service_list[@]}"; do
        service_name="${entry%%,*}"
        service_action="${entry##*,}"
        systemctl "$service_action" "$service_name" > /dev/null 2>&1 || LogWarn "systemctl ${service_action} ${service_name} failed"
    done
}

ConfigurePostfix() {
    [ -f /etc/postfix/main.cf ] || return 0
    local current_hostname
    current_hostname=$(awk -F '=' '/^myhostname/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}' /etc/postfix/main.cf)
    if [ -n "$current_hostname" ]; then
        sed -i "s/${current_hostname}/${NEW_HOSTNAME}/g" /etc/postfix/main.cf
    fi
}
# ============================================================================
# modules/debian/kernel.sh - kernel modules, sysctl tuning and scheduler
# (Ubuntu / Proxmox VE, bash 4.4+)
# ConfigureModules needs CPU_VENDOR_ID, ENABLE_IOMMU, INTEL_GVT_MODULES,
# INTEL_HDMI_AUDIO_MODULE, NESTED_MODULES and MODULE_LIST_EXTRA (may be empty).
# ConfigureSysctl needs SYSCTL_INTERFACE_MODE (include|exclude) and
# SYSCTL_INTERFACE_PATTERN, plus the DISABLE_ICMP_ECHO switch.
# ============================================================================

ConfigureModules() {
    if [ -d /etc/modprobe.d ]; then
        rm -rf /etc/modprobe.d
        mkdir -p /etc/modprobe.d
    fi
    rm -f /etc/modules
    local iommu_modules=()
    if [ -n "$ENABLE_IOMMU" ]; then
        iommu_modules=("vfio" "vfio_iommu_type1" "vfio_pci" "vfio_virqfd")
        printf '%s\n' "options vfio_iommu_type1 allow_unsafe_interrupts=1" > /etc/modprobe.d/vfio_iommu_type1.conf
    fi
    local module_list=(
        "kvm"
        "tls"
        ${INTEL_GVT_MODULES[@]+"${INTEL_GVT_MODULES[@]}"}
        ${INTEL_HDMI_AUDIO_MODULE[@]+"${INTEL_HDMI_AUDIO_MODULE[@]}"}
        ${iommu_modules[@]+"${iommu_modules[@]}"}
        ${NESTED_MODULES[@]+"${NESTED_MODULES[@]}"}
        ${MODULE_LIST_EXTRA[@]+"${MODULE_LIST_EXTRA[@]}"}
    )
    printf '%s\n' "${module_list[@]}" | sort -u > /etc/modules
    printf '%s\n' "options kvm ignore_msrs=1 report_ignored_msrs=0" >> /etc/modprobe.d/kvm.conf
    if [ "$CPU_VENDOR_ID" = "AMD" ]; then
        printf '%s\n' "options kvm-amd nested=1" > /etc/modprobe.d/kvm-amd.conf
    elif [ "$CPU_VENDOR_ID" = "Intel" ]; then
        # 0 | 1 - GuC | 2 - HuC | 3 - GuC / HuC
        printf '%s\n' "options i915 enable_guc=${I915_GUC_OPTION:-3} enable_gvt=1" > /etc/modprobe.d/i915.conf
        printf '%s\n' "options kvm-intel nested=Y" > /etc/modprobe.d/kvm-intel.conf
        printf '%s\n' "options snd-hda-intel enable_msi=1" > /etc/modprobe.d/snd-hda-intel.conf
    fi
}

# mode: include|exclude; pattern: extended regex matched against interface names
CollectInterfaces() {
    local mode="$1" pattern="$2" iface
    while IFS= read -r iface; do
        if [ "$mode" = "include" ]; then
            if [[ "$iface" =~ $pattern ]]; then
                printf '%s\n' "$iface"
            fi
        else
            if [[ ! "$iface" =~ $pattern ]]; then
                printf '%s\n' "$iface"
            fi
        fi
    done < <(awk -F: 'NR>2 {gsub(/^[ \t]+/, "", $1); print $1}' /proc/net/dev)
}

ConfigureSysctl() {
    HaveCommand sysctl || return 0
    local icmp_echo=()
    if [ "${DISABLE_ICMP_ECHO:-false}" = "true" ]; then
        icmp_echo=(
            "net.ipv4.icmp_echo_ignore_all = 1"
            "net.ipv6.icmp.echo_ignore_all = 1"
        )
    fi
    local interface_list=("all" "default") iface
    while IFS= read -r iface; do
        interface_list+=("$iface")
    done < <(CollectInterfaces "$SYSCTL_INTERFACE_MODE" "$SYSCTL_INTERFACE_PATTERN")
    local sysctl_list=(
        "fs.protected_fifos = 2"
        "fs.protected_hardlinks = 1"
        "fs.protected_regular = 2"
        "fs.protected_symlinks = 1"
        "fs.suid_dumpable = 0"
        "kernel.dmesg_restrict = 1"
        "kernel.kptr_restrict = 2"
        "kernel.randomize_va_space = 2"
        "kernel.unprivileged_bpf_disabled = 1"
        "net.core.bpf_jit_harden = 2"
        "net.core.default_qdisc = fq_pie"
        "net.core.rmem_max = 7500000"
        "net.core.wmem_max = 7500000"
        "net.ipv4.conf.all.accept_source_route = 0"
        "net.ipv4.conf.default.accept_source_route = 0"
        "net.ipv4.ip_forward = 1"
        "net.ipv4.tcp_congestion_control = bbr"
        "net.ipv4.tcp_fastopen = 3"
        "vm.dirty_background_ratio = 5"
        "vm.dirty_ratio = 15"
        "vm.overcommit_memory = 1"
        "vm.page-cluster = 0"
        "vm.swappiness = 10"
        ${icmp_echo[@]+"${icmp_echo[@]}"}
    )
    mkdir -p /etc/sysctl.d
    if [ ! -f /etc/sysctl.d/99-sysctl.conf ]; then
        ln -s /etc/sysctl.conf /etc/sysctl.d/99-sysctl.conf
    fi
    {
        printf '%s\n' "${sysctl_list[@]}"
        for iface in "${interface_list[@]}"; do
            printf 'net.ipv6.conf.%s.accept_ra = 2\n' "$iface"
            printf 'net.ipv6.conf.%s.addr_gen_mode = 0\n' "$iface"
            printf 'net.ipv6.conf.%s.autoconf = 1\n' "$iface"
            printf 'net.ipv6.conf.%s.forwarding = 1\n' "$iface"
            printf 'net.ipv6.conf.%s.use_tempaddr = 0\n' "$iface"
        done
    } | sort -u > /etc/sysctl.d/99-zjdeploy.conf
    sysctl --system
}

ConfigureTuned() {
    HaveCommand tuned-adm || return 0
    tuned-adm profile "$(tuned-adm recommend)"
    tuned-adm active
}

ConfigureGAI() {
    local prefer_ipv4_option
    if [ "${PREFER_IPV4:-true}" = "true" ]; then
        prefer_ipv4_option="precedence ::ffff:0:0/96 100"
    else
        prefer_ipv4_option="precedence ::ffff:0:0/96 10"
    fi
    local gai_conf_list=(
        "label ::/0 1"
        "label ::1/128 0"
        "label 2001:0::/32 7"
        "label 2002::/16 2"
        "label ::/96 3"
        "label fc00::/7 6"
        "label fec0::/10 5"
        "label ::ffff:0:0/96 4"
        "precedence ::/0 40"
        "precedence ::1/128 50"
        "precedence 2002::/16 30"
        "precedence ::/96 20"
        "$prefer_ipv4_option"
        "scopev4 ::ffff:0.0.0.0/96 14"
        "scopev4 ::ffff:127.0.0.0/104 2"
        "scopev4 ::ffff:169.254.0.0/112 2"
    )
    printf '%s\n' "${gai_conf_list[@]}" | sort -u > /etc/gai.conf
}
# ============================================================================
# modules/debian/security.sh - Fail2Ban, CrowdSec and SNMPv3
# (Ubuntu / Proxmox VE, bash 4.4+)
# ConfigureFail2Ban must be given FAIL2BAN_JAILS (array) and
# FAIL2BAN_BANACTION (ufw | nftables-multiport | default = keep the distro
# jail.conf values), plus optional FAIL2BAN_FILTER_NAME + FAIL2BAN_FILTER
# (array). ConfigureSNMPBase needs SNMP_USER (platform config: ubuntu / proxmox).
# (sshd lives in debian/ssh.sh alongside the OpenSSH key setup.)
# ============================================================================

ConfigureFail2Ban() {
    HaveCommand fail2ban-client || return 0
    if [ -d /etc/fail2ban/jail.d ]; then
        rm -f /etc/fail2ban/jail.d/*
    else
        mkdir -p /etc/fail2ban/jail.d
    fi
    if [ -f /etc/fail2ban/fail2ban.conf ]; then
        cp /etc/fail2ban/fail2ban.conf /etc/fail2ban/fail2ban.local
    fi
    if [ -f /etc/fail2ban/jail.conf ]; then
        if [ "${FAIL2BAN_BANACTION}" = "ufw" ]; then
            sed -E \
                -e 's/action = iptables-allports/action = ufw/g' \
                -e 's/banaction = iptables-multiport(-log)?/banaction = ufw/g' \
                -e 's/banaction = ufw-log/banaction = ufw/g' \
                -e 's/banaction_allports = iptables-allports/banaction_allports = ufw/g' \
                /etc/fail2ban/jail.conf > /etc/fail2ban/jail.local
        elif [ "${FAIL2BAN_BANACTION:-default}" != "default" ]; then
            # Rewriting the iptables defaults keeps the %(banaction_allports)s
            # references intact; the allports twin is derived from the suffix
            # (e.g. nftables-multiport -> nftables-allports).
            local allports_action="${FAIL2BAN_BANACTION%-multiport}-allports"
            sed -E \
                -e "s/^banaction = iptables-multiport(-log)?\$/banaction = ${FAIL2BAN_BANACTION}/" \
                -e "s/^banaction_allports = iptables-allports\$/banaction_allports = ${allports_action}/" \
                /etc/fail2ban/jail.conf > /etc/fail2ban/jail.local
        else
            cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
        fi
    fi
    if [ -n "${FAIL2BAN_FILTER_NAME:-}" ]; then
        printf '%s\n' "${FAIL2BAN_FILTER[@]}" > "/etc/fail2ban/filter.d/${FAIL2BAN_FILTER_NAME}.conf"
    fi
    printf '%s\n' "${FAIL2BAN_JAILS[@]}" > /etc/fail2ban/jail.d/fail2ban_default.conf
    systemctl enable fail2ban
    fail2ban-client reload
    sleep 5
    fail2ban-client status
}

ConfigureCrowdSec() {
    HaveCommand cscli || return 0
    local collection
    for collection in "crowdsecurity/iptables" "crowdsecurity/linux-lpe" "crowdsecurity/linux" "crowdsecurity/sshd"; do
        cscli collections install "$collection"
    done
    systemctl restart crowdsec
    cscli hub list
}

InstallCrowdSec() {
    InstallAptRepo "crowdsec" "https://packagecloud.io/crowdsec/crowdsec/gpgkey" \
        "deb [arch=${OS_ARCHITECTURE:-amd64} signed-by=/usr/share/keyrings/crowdsec-archive-keyring.gpg] https://packagecloud.io/crowdsec/crowdsec/any any main
deb-src [arch=${OS_ARCHITECTURE:-amd64} signed-by=/usr/share/keyrings/crowdsec-archive-keyring.gpg] https://packagecloud.io/crowdsec/crowdsec/any any main"
    if HaveCommand cscli; then
        local bouncer
        while IFS= read -r bouncer; do
            cscli bouncers delete "$bouncer"
        done < <(cscli bouncers list | grep 'FirewallBouncer' | awk '{print $1}' || true)
    fi
    InstallAptPackages "crowdsec" "crowdsec-firewall-bouncer-nftables"
}

# SNMP_USER comes from the platform config block (ubuntu / proxmox).
ConfigureSNMPBase() {
    HaveCommand snmpwalk || return 0
    if [ -z "${SNMP_AUTH_PASSWORD:-}" ]; then
        SNMP_AUTH_PASSWORD="${ROOT_PASSWORD}"
        LogWarn "SNMP_AUTH_PASSWORD defaults to the root password; override it via SNMP_AUTH_PASSWORD"
    fi
    if [ -z "${SNMP_PRIV_PASSWORD:-}" ]; then
        SNMP_PRIV_PASSWORD="${NEW_HOSTNAME}"
        LogWarn "SNMP_PRIV_PASSWORD defaults to the hostname; override it via SNMP_PRIV_PASSWORD"
    fi
    SNMP_SYS_CONTACT="${DEFAULT_FULLNAME}"
    SNMP_SYS_LOCATION="${NEW_HOSTNAME}"
    SNMP_SYS_NAME="${NEW_FULL_DOMAIN}"
    local snmp_list=(
        "agentaddress udp:161,udp6:161"
        "master agentx"
        "rouser ${SNMP_USER}"
        "sysContact ${SNMP_SYS_CONTACT}"
        "sysLocation ${SNMP_SYS_LOCATION}"
        "sysName ${SNMP_SYS_NAME}"
        "sysServices 76"
    )
    systemctl stop snmpd
    pkill -x snmpd > /dev/null 2>&1 || true
    sed -i 's/^mibs :/# mibs :/g' /etc/snmp/snmp.conf
    printf 'createUser %s SHA "%s" AES "%s"\n' "$SNMP_USER" "$SNMP_AUTH_PASSWORD" "$SNMP_PRIV_PASSWORD" > /var/lib/snmp/snmpd.conf
    printf '%s\n' "${snmp_list[@]}" | sort > /etc/snmp/snmpd.conf
    systemctl start snmpd
    # Verification only; head closes the pipe early, so ignore SIGPIPE.
    snmpwalk -v3 -a SHA -A "$SNMP_AUTH_PASSWORD" -x AES -X "$SNMP_PRIV_PASSWORD" -l authPriv -u "$SNMP_USER" 127.0.0.1 | head || true
}
# ============================================================================
# modules/debian/ssh.sh - OpenSSH host keys, user key setup and sshd
# (Ubuntu / Proxmox VE, bash 4.4+)
# ConfigureOpenSSH needs NEW_HOSTNAME + DEFAULT_USERNAME (+DEFAULT_PASSWORD
# for the key ownership) and the ssh.sh key helpers; ConfigureSshd needs
# SSH_PORT (defaults to 22, e.g. Proxmox VE keeps 22 for cluster-internal
# SSH).
# ============================================================================

ConfigureOpenSSH() {
    HaveCommand ssh-keygen || return 0
    if [ -d /etc/ssh ]; then
        GenerateHostSSHKeys /etc/ssh "root@${NEW_HOSTNAME}"
    fi
    InitUserSSHDir /root/.ssh "root@${NEW_HOSTNAME}"
    local user_ssh="/home/${DEFAULT_USERNAME}/.ssh"
    InitUserSSHDir "$user_ssh" "${DEFAULT_USERNAME}@${NEW_HOSTNAME}" "$DEFAULT_USERNAME:$DEFAULT_USERNAME"
    if [ -f "/home/${DEFAULT_USERNAME}/.gnupg/authorized_keys" ]; then
        mv "/home/${DEFAULT_USERNAME}/.gnupg/authorized_keys" "${user_ssh}/authorized_keys"
        chmod 600 "${user_ssh}/authorized_keys"
    fi
}

# Root password login is intentional: the root account gets locked afterwards
# via LOCK_ROOT=true (see ConfigureRootUser). Needs SSH_PORT (defaults to 22,
# e.g. Proxmox VE keeps 22 for cluster-internal SSH).
ConfigureSshd() {
    [ -f /usr/share/openssh/sshd_config ] || return 0
    local port="${SSH_PORT:-22}"
    # Replace the commented Port directive in place (keeps the vendor
    # layout); fall back to an appended line when the file has none.
    sed -E \
        -e "s/^#?[[:space:]]*Port[[:space:]].*/Port ${port}/" \
        -e 's/^#?PasswordAuthentication .*/PasswordAuthentication yes/' \
        -e 's/^#?PermitRootLogin .*/PermitRootLogin yes/' \
        -e 's/^#?PubkeyAuthentication .*/PubkeyAuthentication yes/' \
        /usr/share/openssh/sshd_config > /etc/ssh/sshd_config
    grep -qE '^Port[[:space:]]' /etc/ssh/sshd_config || printf 'Port %s\n' "$port" >> /etc/ssh/sshd_config
    rm -f /etc/ssh/sshd_config.d/*
    # Ubuntu 25.10+/PVE 9: sshd runs behind ssh.socket, and after changing
    # Port the socket configuration must be regenerated and the socket
    # restarted (the notice in the vendor sshd_config documents exactly
    # this); restarting the service alone does not move the port.
    if systemctl is-enabled ssh.socket > /dev/null 2>&1 || systemctl is-active ssh.socket > /dev/null 2>&1; then
        systemctl daemon-reload
        systemctl restart ssh.socket
    fi
}
# ============================================================================
# modules/debian/storage.sh - swap helpers for Debian family
# (Ubuntu / Proxmox VE, bash 4.4+)
# Platform ConfigureSWAP orchestrators combine these with their own
# CreateSWAP / RemoveSWAP / UpdateFSTAB variants (swapfile vs LVM).
# ============================================================================

# Swap size in MiB from RAM in MiB (pure, tested in tests/)
ComputeSwapSize() {
    local ram_mb="$1" ram_size frac_first
    ram_size=$(awk -v ram="$ram_mb" 'BEGIN{print log(ram)/log(2)}')
    if [[ "$ram_size" == *.* ]]; then
        frac_first=$(printf '%s' "$ram_size" | cut -d '.' -f 2 | cut -c 1)
        ram_size=${ram_size%%.*}
        if [ "$frac_first" -gt 5 ]; then
            ram_size=$((ram_size + 1))
        fi
    fi
    if [ "$ram_size" -le 11 ]; then
        printf '%s\n' $((2 ** ram_size * 2))
    elif [ "$ram_size" -le 13 ]; then
        printf '%s\n' $((2 ** ram_size))
    elif [ "$ram_size" -le 16 ]; then
        printf '%s\n' $((2 ** 12))
    else
        printf '%s\n' $((2 ** 13))
    fi
}

ClearSWAP() {
    HaveCommand sysctl || return 0
    sync
    sysctl -w vm.drop_caches=3 vm.overcommit_memory=0 vm.swappiness=0
}

# zram-generator config shared by both platforms (always-on compressed swap).
CreateZRamSWAP() {
    local zram_conf_list=(
        "[zram0]"
        "compression-algorithm = zstd"
        "zram-size = min(ram / 2, 8192)"
    )
    rm -rf "/etc/systemd/zram-generator.conf.d"
    mkdir -p "/etc/systemd/zram-generator.conf.d"
    printf '%s\n' "${zram_conf_list[@]}" > "/etc/systemd/zram-generator.conf.d/zram.conf"
}
# ============================================================================
# modules/debian/system.sh - system information gathering for Debian family
# (Ubuntu / Proxmox VE, bash 4.4+)
# Sets: NEW_DOMAIN, NEW_HOSTNAME, OLD_HOSTNAME, CURRENT_DNS, DNS_SERVERS,
# DNS_LINE, CPU_VENDOR_ID, ENABLE_IOMMU, MICROCODE,
# INTEL_GVT_MODULES, INTEL_HDMI_AUDIO_MODULE, NESTED_MODULES,
# OS_ARCHITECTURE, plus the Debian structural globals via SetDebianGlobals.
# WriteHostfile needs NEW_HOSTNAME, HOSTS_BASE_ENTRIES (modules/hosts.sh)
# and takes extra host entries as arguments.
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

# Git-commit-hash style random hostname (12 lowercase hex chars, RFC-1123-safe)
# for hosts where nothing is detectable or on an explicit RESET_HOSTNAME.
MintRandomHostname() {
    printf '%04x%04x%04x' "$RANDOM" "$RANDOM" "$RANDOM"
}

# Sets NEW_HOSTNAME (CUSTOM_HOSTNAME > hostname file > hostname command >
# random hash, either because nothing is detectable or on an explicit
# RESET_HOSTNAME) and OLD_HOSTNAME (original hostname, used by the Proxmox VE
# node rename step).
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
        NEW_HOSTNAME=$(MintRandomHostname)
    fi
}

# Parses CUSTOM_DNS and collects the nameservers still in use. Sets
# DNS_SERVERS / CURRENT_DNS / DNS_LINE (first three, space joined).
CollectDNS() {
    read -r -a DNS_SERVERS <<< "$CUSTOM_DNS"
    CURRENT_DNS=()
    local resolv_conf="${RESOLV_CONF:-/etc/resolv.conf}" ns
    if [ -f "$resolv_conf" ]; then
        while IFS= read -r ns; do
            case " ${DNS_SERVERS[*]} 127.0.0.53 " in
                *" ${ns} "*) ;;
                *) CURRENT_DNS+=("$ns") ;;
            esac
        done < <(awk '/^nameserver/ {print $2}' "$resolv_conf")
    fi
    DNS_LINE=$(printf '%s\n' ${CURRENT_DNS[@]+"${CURRENT_DNS[@]}"} "${DNS_SERVERS[@]}" | head -n 3 | tr '\n' ' ')
    DNS_LINE="${DNS_LINE% }"
}

# shellcheck disable=SC2034 # the case branches feed ConfigureModules, the
# platform Grub steps and InstallDependencyPackages
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
    resolv_conf_list+=("${DNS_SERVERS[@]}")
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

# Write /etc/hosts plus /etc/hostname and apply it via hostnamectl.
# Extra entries (e.g. the Ubuntu loopback alias or the PVE management IP)
# come first as arguments, above HOSTS_BASE_ENTRIES.
WriteHostfile() {
    local host_list=("$@")
    host_list+=("${HOSTS_BASE_ENTRIES[@]}")
    printf '%s\n' "${host_list[@]}" > "/etc/hosts"
    printf '%s\n' "$NEW_HOSTNAME" > "/etc/hostname"
    hostnamectl set-hostname "$NEW_HOSTNAME"
}

# Structural globals shared by both Debian platforms; platform ConfigurePackages
# blocks may override any of them (e.g. Proxmox VE extends ZSH_PATHS).
# shellcheck disable=SC2034 # consumed by the gpg/proxychains/zsh modules
SetDebianGlobals() {
    PROXYCHAINS_CONF="/etc/proxychains4.conf"
    GPG_HOME="/home/${DEFAULT_USERNAME}/.gnupg"
    GPG_KEYSERVER="hkps://keyserver.ubuntu.com:443"
    GPG_PINENTRY="/usr/bin/pinentry-tty"
    GPG_HOME_OWNER="${DEFAULT_USERNAME}:${DEFAULT_USERNAME}"
    ZSH_HOME="/home/${DEFAULT_USERNAME}"
    ZSH_OWNER="${DEFAULT_USERNAME}:${DEFAULT_USERNAME}"
    ZSH_PATHS=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/usr/local/bin" "/usr/local/sbin")
    ZSH_EXTRA_EXPORTS=("export DEBIAN_FRONTEND=\"noninteractive\"")
    ZSH_TRAPEXIT="false"
}
# ============================================================================
# modules/debian/users.sh - default user and root account management
# (Ubuntu / Proxmox VE, bash 4.4+)
# ConfigureDefaultUser needs DEFAULT_USERNAME/FULLNAME/PASSWORD (plus
# DEFAULT_PASSWORD_SENTINEL for the warning) and the PURGE_OTHER_USERS switch;
# the pveum blocks are no-ops on non-PVE hosts (HaveCommand pveum).
# ============================================================================

ConfigureDefaultUser() {
    if [ -z "$DEFAULT_PASSWORD" ]; then
        DEFAULT_PASSWORD=$(MintRandomPassword)
        LogWarn "DEFAULT_PASSWORD was empty: generated a random one - note it down (override via env on re-runs)"
        LogInfo "default user password: ${DEFAULT_PASSWORD}"
    fi
    PURGE_OTHER_USERS="${PURGE_OTHER_USERS:-true}"
    if [ "$PURGE_OTHER_USERS" = "true" ]; then
        LogWarn "PURGE_OTHER_USERS=true: removing every other user under /home (set PURGE_OTHER_USERS=false to keep them)"
        local home_dir user
        for home_dir in /home/*; do
            if [ -d "$home_dir" ]; then
                user="${home_dir##*/}"
                if [ "$user" != "$DEFAULT_USERNAME" ]; then
                    userdel -rf "$user" > /dev/null 2>&1 || true
                    if HaveCommand pveum; then
                        pveum userdel "${user}@pam" > /dev/null 2>&1 || true
                    fi
                fi
            fi
        done
    fi
    if id "$DEFAULT_USERNAME" > /dev/null 2>&1; then
        userdel -rf "$DEFAULT_USERNAME" > /dev/null 2>&1 || true
    fi
    useradd -c "$DEFAULT_FULLNAME" -d "/home/${DEFAULT_USERNAME}" -s "/bin/zsh" -m "$DEFAULT_USERNAME"
    printf '%s:%s\n' "$DEFAULT_USERNAME" "$DEFAULT_PASSWORD" | chpasswd
    adduser "$DEFAULT_USERNAME" "docker"
    adduser "$DEFAULT_USERNAME" "sudo"
    # shellcheck disable=SC2034 # consumed by InstallCrontab (modules/crontab.sh)
    CRONTAB_USER="$DEFAULT_USERNAME"
    # shellcheck disable=SC2034 # consumed by InstallCrontab (modules/crontab.sh)
    CRONTAB_ENTRIES=(
        "@reboot rm -rf ~/.*_history ~/.ssh/known_hosts*"
    )
    InstallCrontab
    if HaveCommand pveum; then
        if pveum group list | grep -q 'LADM'; then
            pveum group modify "LADM" -comment "Local Administrators"
        else
            pveum groupadd "LADM" -comment "Local Administrators"
        fi
        pveum aclmod "/" -group "LADM" -role "Administrator"
        if pveum user list | grep -q "${DEFAULT_USERNAME}@pam"; then
            pveum usermod "${DEFAULT_USERNAME}@pam" -comment "$DEFAULT_FULLNAME" -firstname "$DEFAULT_FIRSTNAME" -group "LADM" -lastname "$DEFAULT_LASTNAME"
        else
            pveum useradd "${DEFAULT_USERNAME}@pam" -comment "$DEFAULT_FULLNAME" -firstname "$DEFAULT_FIRSTNAME" -group "LADM" -lastname "$DEFAULT_LASTNAME"
        fi
        pveum usermod "root@pam" -comment "Proxmox Root" -firstname "Root" -group "LADM" -lastname "Proxmox"
    fi
}

# Only the deployment user switches to zsh; system accounts keep their shells.
ConfigureDefaultShell() {
    if HaveCommand zsh && [ -n "${DEFAULT_USERNAME:-}" ]; then
        usermod -s /bin/zsh "$DEFAULT_USERNAME"
    fi
    usermod -s /bin/bash root
}

ConfigureRootUser() {
    LOCK_ROOT="${LOCK_ROOT:-false}"
    if [ -z "$ROOT_PASSWORD" ]; then
        ROOT_PASSWORD=$(MintRandomPassword)
        LogWarn "ROOT_PASSWORD was empty: generated a random one - note it down (override via env on re-runs)"
        LogInfo "root password: ${ROOT_PASSWORD}"
    fi
    printf 'root:%s\n' "$ROOT_PASSWORD" | chpasswd
    if [ "$LOCK_ROOT" = "true" ]; then
        passwd -l root
    else
        passwd -u root
    fi
}
## Function
# Get System Information
GetSystemInformation() {
    # Identity, credentials and release pinning live in the Configuration block.
    DEFAULT_FULLNAME="${DEFAULT_LASTNAME} ${DEFAULT_FIRSTNAME}"

    CheckMachineEnvironment() {
        CheckHypervisorEnvironment() {
            if ! HaveCommand virt-what; then
                local apt_sources_file="/etc/apt/sources.list"
                if [ ! -f "$apt_sources_file" ]; then
                    apt_sources_file="/etc/apt/sources.list.d/ubuntu.sources"
                fi
                sed -i -E \
                    -e 's/[a-z.]*archive\.ubuntu\.com/mirrors.cernet.edu.cn/g' \
                    -e 's/[a-z.]*ports\.ubuntu\.com/mirrors.cernet.edu.cn/g' \
                    -e 's/[a-z.]*security\.ubuntu\.com/mirrors.cernet.edu.cn/g' \
                    "$apt_sources_file"
                apt update
                apt install virt-what -qy
                HaveCommand virt-what || Die "virt-what has not been installed!"
            fi
            local hypervisor_environment
            hypervisor_environment=$(virt-what)
            HYPERVISOR_AGENT=()
            case "$hypervisor_environment" in
                kvm) HYPERVISOR_AGENT=("ksmtuned" "qemu-guest-agent") ;;
                vmware) HYPERVISOR_AGENT=("open-vm-tools") ;;
                virtualbox) HYPERVISOR_AGENT=("virtualbox-guest-dkms") ;;
            esac
        }
        CheckHypervisorEnvironment
    }
    GetPsabiLevel() {
        # https://dl.xanmod.org/check_x86-64_psabi.sh
        PSABI_LEVEL=$(awk 'BEGIN{while(!/flags/)if(getline<"/proc/cpuinfo"!=1)exit 0;if(/lm/&&/cmov/&&/cx8/&&/fpu/&&/fxsr/&&/mmx/&&/syscall/&&/sse2/)l=1;if(l==1&&/cx16/&&/lahf/&&/popcnt/&&/sse4_1/&&/sse4_2/&&/ssse3/)l=2;if(l==2&&/avx/&&/avx2/&&/bmi1/&&/bmi2/&&/f16c/&&/fma/&&/abm/&&/movbe/&&/xsave/)l=3;if(l==3&&/avx512f/&&/avx512bw/&&/avx512cd/&&/avx512dq/&&/avx512vl/)l=4;print l}')
    }
    GetUbuntuMirror() {
        GetOSArchitecture
        case "${OS_ARCHITECTURE:-}" in
            arm64) APT_MIRROR_REPO="ubuntu-ports" ;;
            amd64) APT_MIRROR_REPO="ubuntu" ;;
        esac
    }
    CollectDNS
    GenerateDomain
    CheckMachineEnvironment
    GenerateHostname
    GetPsabiLevel
    GetCPUVendorID
    GetUbuntuMirror
    SetGHProxyDomain
}

# Set Repository Mirror
SetRepositoryMirror() {
    local mirror_list=(
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${APT_MIRROR_REPO} ${LSB_CODENAME} main multiverse restricted universe"
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${APT_MIRROR_REPO} ${LSB_CODENAME}-backports main multiverse restricted universe"
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${APT_MIRROR_REPO} ${LSB_CODENAME}-proposed main multiverse restricted universe"
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${APT_MIRROR_REPO} ${LSB_CODENAME}-security main multiverse restricted universe"
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${APT_MIRROR_REPO} ${LSB_CODENAME}-updates main multiverse restricted universe"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${APT_MIRROR_REPO} ${LSB_CODENAME} main multiverse restricted universe"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${APT_MIRROR_REPO} ${LSB_CODENAME}-backports main multiverse restricted universe"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${APT_MIRROR_REPO} ${LSB_CODENAME}-proposed main multiverse restricted universe"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${APT_MIRROR_REPO} ${LSB_CODENAME}-security main multiverse restricted universe"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${APT_MIRROR_REPO} ${LSB_CODENAME}-updates main multiverse restricted universe"
    )
    mkdir -p "/etc/apt/sources.list.d"
    rm -f /etc/apt/sources.list.d/*.*
    printf '%s\n' "${mirror_list[@]}" > "/etc/apt/sources.list"
}

# Configure Packages
ConfigurePackages() {
    ConfigureCockpit() {
        HaveCommand cockpit-bridge || return 0
        mkdir -p /etc/cockpit
        local cockpit_conf_list=(
            "[Session]"
            "IdleTimeout = 60"
            "[WebService]"
            "MaxStartups = 3:75:5"
        )
        printf '%s\n' "${cockpit_conf_list[@]}" > /etc/cockpit/cockpit.conf
        if [ "$COCKPIT_PORT" != "9090" ]; then
            # cockpit.socket hardcodes 9090; a drop-in moves the listen port.
            mkdir -p /etc/systemd/system/cockpit.socket.d
            local socket_override_list=(
                "[Socket]"
                "ListenStream="
                "ListenStream=${COCKPIT_PORT}"
            )
            printf '%s\n' "${socket_override_list[@]}" > /etc/systemd/system/cockpit.socket.d/zjdeploy.conf
            systemctl daemon-reload
        fi
        systemctl enable --now cockpit.socket
    }
    ConfigureCloudflareWARP() {
        # Get token from `https://<YOUR_TEAM_NAME>.cloudflareaccess.com/warp`
        # Login via `warp-cli registration token 'com.cloudflare.warp://<your-team-name>.cloudflareaccess.com/auth?token=<your-token>'`
        HaveCommand warp-cli || return 0
        ufw allow in on CloudflareWARP
    }
    ConfigureGrub() {
        HaveCommand update-grub || return 0
        rm -f "/etc/default/grub.d/50-cloudimg-settings.cfg"
        [ -f "/usr/share/grub/default/grub" ] || return 0
        sed -E \
            -e "s/GRUB_CMDLINE_LINUX_DEFAULT=\"quiet splash\"/GRUB_CMDLINE_LINUX_DEFAULT=\"quiet security=apparmor mitigations=auto,nosmt${ENABLE_IOMMU}\"/g" \
            -e 's/#GRUB_DISABLE_OS_PROBER=false/GRUB_DISABLE_OS_PROBER=true/g' \
            -e 's/GRUB_TIMEOUT=.*/GRUB_TIMEOUT=5/g' \
            -e '/GRUB_TIMEOUT_STYLE=/d' \
            "/usr/share/grub/default/grub" > "/etc/default/grub"
        update-grub
    }
    ConfigureLandscape() {
        [ -f "/usr/lib/python3/dist-packages/landscape/lib/network.py" ] || return 0
        sed -i 's/tostring/tobytes/g' "/usr/lib/python3/dist-packages/landscape/lib/network.py"
    }
    ConfigureNetplan() {
        HaveCommand netplan || return 0
        local static_ipv4_addr static_ipv4_gateway static_ipv6_addr static_ipv6_gateway
        static_ipv4_addr=$(printf '%s' "$STATIC_IPV4_CONFIG" | cut -d ',' -f 1)
        static_ipv4_gateway=$(printf '%s' "$STATIC_IPV4_CONFIG" | cut -d ',' -f 2)
        static_ipv6_addr=$(printf '%s' "$STATIC_IPV6_CONFIG" | cut -d ',' -f 1)
        static_ipv6_gateway=$(printf '%s' "$STATIC_IPV6_CONFIG" | cut -d ',' -f 2)
        if [ -z "$NIC_NAME" ]; then
            local iface_path
            for iface_path in /sys/class/net/*; do
                case "${iface_path##*/}" in
                    docker0|lo|wg0) ;;
                    *) NIC_NAME="${iface_path##*/}"; break ;;
                esac
            done
        fi
        local netplan_list=(
            "network:"
            "  version: 2"
            "  renderer: NetworkManager"
            "  ethernets:"
            "    ${NIC_NAME}:"
        )
        if [ -n "$static_ipv4_addr" ]; then
            netplan_list+=("      dhcp4: false")
        else
            netplan_list+=("      dhcp4: true")
        fi
        if [ -n "$static_ipv6_addr" ]; then
            netplan_list+=("      dhcp6: false")
        else
            netplan_list+=("      dhcp6: true")
        fi
        if [ -n "$static_ipv4_addr" ] || [ -n "$static_ipv6_addr" ]; then
            netplan_list+=("      addresses:")
            if [ -n "$static_ipv4_addr" ]; then
                netplan_list+=("        - ${static_ipv4_addr}")
            fi
            if [ -n "$static_ipv6_addr" ]; then
                netplan_list+=("        - ${static_ipv6_addr}")
            fi
        fi
        if [ -n "$static_ipv4_gateway" ] || [ -n "$static_ipv6_gateway" ]; then
            netplan_list+=("      routes:")
            if [ -n "$static_ipv4_gateway" ]; then
                netplan_list+=("        - to: 0.0.0.0/0")
                netplan_list+=("          via: ${static_ipv4_gateway}")
            fi
            if [ -n "$static_ipv6_gateway" ]; then
                netplan_list+=("        - to: ::/0")
                netplan_list+=("          via: ${static_ipv6_gateway}")
            fi
        fi
        mkdir -p /etc/netplan
        rm -f /etc/netplan/*.yaml
        printf '%s\n' "${netplan_list[@]}" > "/etc/netplan/netplan.yaml"
        chmod 600 "/etc/netplan/netplan.yaml"
        netplan apply
    }
    ConfigureResolved() {
        if HaveCommand resolvectl; then
            local resolved_list=(
                "[Resolve]"
                "DNS=${DNS_LINE}"
                "DNSOverTLS=opportunistic"
                "DNSSEC=allow-downgrade"
                "DNSStubListener=false"
                "Domains=${NEW_DOMAIN[*]}"
            )
            mkdir -p "/etc/systemd/resolved.conf.d"
            rm -f /etc/systemd/resolved.conf.d/*.conf
            printf '%s\n' "${resolved_list[@]}" > "/etc/systemd/resolved.conf.d/resolved.conf"
            systemctl restart systemd-resolved
            chattr -i /etc/resolv.conf > /dev/null 2>&1 || true
            rm -f /etc/resolv.conf
            ln -s "/run/systemd/resolve/resolv.conf" "/etc/resolv.conf"
        else
            WriteResolvConf
            chattr +i /etc/resolv.conf
        fi
    }
    ConfigureSystemd() {
        systemctl disable systemd-networkd-wait-online > /dev/null 2>&1 || true
    }
    ConfigureUfw() {
        HaveCommand ufw || return 0
        [ -f "/etc/default/ufw" ] || return 0
        sed -i -E \
            -e 's/DEFAULT_APPLICATION_POLICY="(ACCEPT|DROP|SKIP)"/DEFAULT_APPLICATION_POLICY="REJECT"/g' \
            -e 's/DEFAULT_FORWARD_POLICY="(DROP|REJECT)"/DEFAULT_FORWARD_POLICY="ACCEPT"/g' \
            -e 's/DEFAULT_INPUT_POLICY="(ACCEPT|DROP)"/DEFAULT_INPUT_POLICY="REJECT"/g' \
            -e 's/DEFAULT_OUTPUT_POLICY="(DROP|REJECT)"/DEFAULT_OUTPUT_POLICY="ACCEPT"/g' \
            -e 's/MANAGE_BUILTINS=yes/MANAGE_BUILTINS=no/g' \
            -e 's/IPV6=no/IPV6=yes/g' \
            "/etc/default/ufw"
        ufw --force reset
        ufw allow 123/udp
        ufw allow 161/udp
        ufw limit ${SSH_PORT}/tcp
        ufw allow ${COCKPIT_PORT}/tcp # cockpit web UI
        ufw allow 323/udp
        ufw allow 3493/tcp
        ufw allow 51820/udp
        ufw allow in on wg0
        ufw --force enable
        ufw status verbose
    }
    ConfigureWireGuard() {
        HaveCommand wg || return 0
        mkdir -p "/etc/wireguard"
        rm -f /etc/wireguard/*
        GenerateWireGuardConfig
        chown -R "${DEFAULT_USERNAME}:sudo" "/etc/wireguard"
        chmod -R 775 "/etc/wireguard"
        chown "${DEFAULT_USERNAME}:${DEFAULT_USERNAME}" "/etc/wireguard/wg0.conf"
        chmod 600 "/etc/wireguard/wg0.conf"
        systemctl enable wg-quick@wg0
        if [ -f "/lib/systemd/system/wg-quick@.service" ]; then
            if [ ! -f "/lib/systemd/system/wg-quick@.service.bak" ]; then
                cp "/lib/systemd/system/wg-quick@.service" "/lib/systemd/system/wg-quick@.service.bak"
            fi
            sed -E \
                -e 's/RemainAfterExit=yes/RemainAfterExit=yes\nRestartSec=5\nRestart=always/g' \
                -e 's/^Type=oneshot/#Type=oneshot/g' \
                "/lib/systemd/system/wg-quick@.service.bak" > "/lib/systemd/system/wg-quick@.service"
            systemctl daemon-reload
        fi
        systemctl start wg-quick@wg0
        wg
    }

    APT_PREFERENCES=(
        "${LSB_CODENAME}-backports 990"
        "${LSB_CODENAME}-security 500"
        "${LSB_CODENAME}-updates 500"
        "${LSB_CODENAME} 500"
        "${LSB_CODENAME}-proposed 100"
    )
    FAIL2BAN_BANACTION="ufw"
    FAIL2BAN_FILTER_NAME="cockpit"
    FAIL2BAN_FILTER=(
        "[Definition]"
        "failregex = ^\s*(?:\S+\s+)?(?:cockpit\[\d+\]: )?pam_unix\(cockpit:auth\): authentication failure;.*rhost=<HOST>"
        "journalmatch = _SYSTEMD_UNIT=cockpit.service"
    )
    FAIL2BAN_JAILS=(
        "[sshd]"
        "bantime = 604800"
        "enabled = true"
        "filter = sshd"
        "findtime = 60"
        "logpath = /var/log/auth.log"
        "maxretry = 5"
        "port = ${SSH_PORT}"
        "[cockpit]"
        "backend = systemd"
        "bantime = 604800"
        "enabled = true"
        "filter = cockpit"
        "findtime = 60"
        "maxretry = 5"
        "port = ${COCKPIT_PORT}"
    )
    MODULE_LIST_EXTRA=()
    SYSCTL_INTERFACE_MODE="exclude"
    SYSCTL_INTERFACE_PATTERN='^(docker0|lo|wg0)$'

    RunStep "ConfigureAPT" ConfigureAPT
    RunStep "ConfigureBusybox" ConfigureBusybox
    RunStep "ConfigureChrony" ConfigureChrony
    RunStep "ConfigureCloudflareWARP" ConfigureCloudflareWARP
    RunStep "ConfigureCockpit" ConfigureCockpit
    RunStep "ConfigureCrontab" ConfigureCrontab
    RunStep "ConfigureCrowdSec" ConfigureCrowdSec
    RunStep "ConfigureDockerEngine" ConfigureDockerEngine
    RunStep "ConfigureFail2Ban" ConfigureFail2Ban
    RunStep "ConfigureFRRouting" ConfigureFRRouting
    RunStep "ConfigureGPG" ConfigureGPG
    RunStep "ConfigureGit" ConfigureGit
    RunStep "ConfigureGrub" ConfigureGrub
    RunStep "ConfigureLandscape" ConfigureLandscape
    RunStep "ConfigureLLDPD" ConfigureLLDPD
    RunStep "ConfigureModules" ConfigureModules
    RunStep "ConfigureNetplan" ConfigureNetplan
    RunStep "ConfigureNut" ConfigureNut
    RunStep "ConfigureOpenSSH" ConfigureOpenSSH
    RunStep "ConfigurePostfix" ConfigurePostfix
    RunStep "ConfigureProxyChains" ConfigureProxyChains
    RunStep "ConfigurePythonPyPI" ConfigurePythonPyPI
    RunStep "ConfigureResolved" ConfigureResolved
    RunStep "ConfigureSNMP" ConfigureSNMPBase
    RunStep "ConfigureSshd" ConfigureSshd
    RunStep "ConfigureSysctl" ConfigureSysctl
    RunStep "ConfigureSystemd" ConfigureSystemd
    RunStep "ConfigureTuned" ConfigureTuned
    RunStep "ConfigureUfw" ConfigureUfw
    RunStep "ConfigureWireGuard" ConfigureWireGuard
    RunStep "ConfigureZsh" ConfigureZsh
}

# Configure System
ConfigureSystem() {
    # Install-time structural globals: this container's Install* steps run
    # BEFORE ConfigurePackages, so the variables their modules need are
    # declared here rather than there.
    DOCKER_APT_DISTRO="ubuntu"
    FRR_APT_LINE="deb [arch=${OS_ARCHITECTURE} signed-by=/usr/share/keyrings/frrouting-archive-keyring.gpg] https://deb.frrouting.org/frr stable frr-stable"
    FRR_EXTRA_PACKAGES=("frr-rpki-rtrlib")
    SetDebianGlobals
    ConfigureHostfile() {
        WriteHostfile "127.0.1.1 ${NEW_HOSTNAME}"
    }
    ConfigureLocales() {
        apt purge -qy locales
        apt update
        apt install -qy locales
        locale-gen "en_US.UTF-8"
        update-locale "en_US.UTF-8"
    }
    ConfigureSWAP() {
        CreateSWAP() {
            local ram_mb
            ram_mb=$(free -m | awk '/^Mem:/ {print $2}')
            SWAP_SIZE=$(ComputeSwapSize "$ram_mb")
            truncate -s 0 "/swapfile"
            if [ "$(stat -f -c %T "/swapfile" 2>/dev/null)" = "btrfs" ]; then
                chattr +C "/swapfile"
            fi
            fallocate -l "${SWAP_SIZE}M" "/swapfile"
            chmod 600 "/swapfile"
            mkswap "/swapfile"
            swapon "/swapfile"
        }
        RemoveSWAP() {
            local swapfile
            while IFS= read -r swapfile; do
                swapoff "$swapfile" > /dev/null 2>&1 || true
                rm -f "$swapfile"
            done < <(awk 'NR>1 {print $1}' /proc/swaps)
        }
        UpdateFSTAB() {
            sed -i '/swap/d' /etc/fstab
            if [ -f "/swapfile" ] && [ "$DISABLE_SWAP" = "false" ]; then
                printf '%s\n' "/swapfile none swap sw 0 0" >> "/etc/fstab"
            fi
        }
        ClearSWAP
        RemoveSWAP
        if [ "$DISABLE_SWAP" = "false" ]; then
            CreateSWAP
        fi
        CreateZRamSWAP
        UpdateFSTAB
    }
    ConfigureTimeZone() {
        rm -f "/etc/localtime"
        ln -s "/usr/share/zoneinfo/Asia/Shanghai" "/etc/localtime"
    }
    RunStep "ConfigureDefaultShell" ConfigureDefaultShell
    RunStep "ConfigureDefaultUser" ConfigureDefaultUser
    RunStep "ConfigureGAI" ConfigureGAI
    RunStep "ConfigureHostfile" ConfigureHostfile
    RunStep "ConfigureLocales" ConfigureLocales
    RunStep "ConfigureRootUser" ConfigureRootUser
    RunStep "ConfigureSWAP" ConfigureSWAP
    RunStep "ConfigureTimeZone" ConfigureTimeZone
}

# Install Custom Packages
InstallCustomPackages() {
    InstallCloudflareWARP() {
        [ "$INSTALL_CLOUDFLARE_WARP" = "true" ] || { LogInfo "INSTALL_CLOUDFLARE_WARP=false - skipped"; return 0; }
        InstallAptRepo "cloudflare-warp" "https://pkg.cloudflareclient.com/pubkey.gpg" \
            "deb [arch=${OS_ARCHITECTURE} signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com ${LSB_CODENAME} main"
        InstallAptPackages "cloudflare-warp"
    }
    InstallTor() {
        [ "$INSTALL_TOR" = "true" ] || { LogInfo "INSTALL_TOR=false - skipped"; return 0; }
        InstallAptRepo "tor" "https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc" \
            "deb [arch=${OS_ARCHITECTURE} signed-by=/usr/share/keyrings/tor-archive-keyring.gpg] https://deb.torproject.org/torproject.org stable main"
        InstallAptPackages "tor"
    }
    InstallXanModKernel() {
        # Note: NVIDIA, OpenZFS, VirtualBox, VMware and some other dkms modules
        # may not officially support EDGE and RT branch kernels.
        local branch="$XANMOD_BRANCH"
        # psABI v1 (legacy) CPUs are covered only by the LTS branch - main,
        # edge and rt publish x64v2/v3 packages only.
        if [ "$PSABI_LEVEL" = "1" ] && [ "$branch" != "lts" ]; then
            branch="lts"
        fi
        # no kernel benefit beyond v3
        local level="$PSABI_LEVEL"
        if [ "$level" = "4" ]; then
            level="3"
        fi
        # XanMod publishes amd64 packages only - the repo is added just when
        # a xanmod kernel will actually be installed; everything else stays
        # on the stock Ubuntu kernel (arm64 uses linux-generic: the HWE
        # kernels are amd64-only).
        if [ "$OS_ARCHITECTURE" = "amd64" ] && [ "$level" != "0" ] && [ "$branch" != "disable" ]; then
            local suffix=""
            if [ "$branch" != "main" ]; then
                suffix="${branch}-"
            fi
            InstallAptRepo "xanmod" "https://dl.xanmod.org/archive.key" \
                "deb [arch=amd64 signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] https://deb.xanmod.org ${LSB_CODENAME} main non-free"
            InstallAptPackages "linux-xanmod-${suffix}x64v${level}"
        elif [ "$OS_ARCHITECTURE" = "amd64" ]; then
            InstallAptPackages "linux-generic-hwe-${LSB_VERSION}"
        else
            InstallAptPackages "linux-generic"
        fi
    }
    OMZ_HOME="/home/${DEFAULT_USERNAME}"
    OMZ_OWNER="${DEFAULT_USERNAME}:${DEFAULT_USERNAME}"
    RunStep "InstallCloudflareWARP" InstallCloudflareWARP
    RunStep "InstallCrowdSec" InstallCrowdSec
    RunStep "InstallDockerEngine" InstallDockerEngine
    RunStep "InstallFRRouting" InstallFRRouting
    RunStep "InstallOhMyZsh" InstallOhMyZsh
    RunStep "InstallTor" InstallTor
    RunStep "InstallXanModKernel" InstallXanModKernel
}

## Process
# Set DEBIAN_FRONTEND to "noninteractive"
export DEBIAN_FRONTEND="noninteractive"
RequireRoot
# Call GetSystemInformation (always runs: later steps need its globals)
GetSystemInformation
InitRun
# Set TRANSPORT_PROTOCOL="http"; Call SetRepositoryMirror
TRANSPORT_PROTOCOL="http"
RunStep "SetRepositoryMirror.http" SetRepositoryMirror
# Call InstallDependencyPackages
RunStep "InstallDependencyPackages" InstallDependencyPackages
# Set TRANSPORT_PROTOCOL="https"; Call SetRepositoryMirror
TRANSPORT_PROTOCOL="https"
RunStep "SetRepositoryMirror.https" SetRepositoryMirror
# Call UpgradePackages
RunStep "UpgradePackages" UpgradePackages
# Call InstallCustomPackages
InstallCustomPackages
# Call ConfigureSystem
ConfigureSystem
# Call ConfigurePackages
ConfigurePackages
# Call CleanupTempFiles
RunStep "CleanupTempFiles" CleanupTempFiles /etc/ufw/*."$(date '+%Y%m%d')"*
# Call CleanupOutageKernels
KERNEL_PATTERN='(linux-image)-[0-9].*'
RunStep "CleanupOutageKernels" CleanupOutageKernels
RenderProgress "complete"
