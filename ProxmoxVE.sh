#!/bin/bash
# Copyright 2026 Zhijie He
# Licensed under Apache-2.0 WITH Commons-Clause-1.0. See LICENSE.
#
# GENERATED FILE - edit src/ and run ./build.sh to regenerate.
# For a one-off tweak you may edit the Configuration block below.
#
## How to get and use?
# curl "https://source.zhijie.online/AutoDeploy/main/ProxmoxVE.sh" | sudo bash
# wget -qO- "https://source.zhijie.online/AutoDeploy/main/ProxmoxVE.sh" | sudo bash
# ============================================================================
# Configuration - Proxmox VE
# The single place to tune a deployment. Edit defaults here, or override any
# knob via environment variable before running, e.g.:
#   ROOT_PASSWORD='...' RESET_CLUSTER=false curl .../ProxmoxVE.sh | sudo bash
# ============================================================================

## Resume / progress
# State lives under the running user's home. AUTODEPLOY_FORCE=true re-runs all.
AUTODEPLOY_STATE_DIR="${AUTODEPLOY_STATE_DIR:-${HOME}/.autodeploy}"
AUTODEPLOY_FORCE="${AUTODEPLOY_FORCE:-false}"
AUTODEPLOY_STEP_TOTAL=50 # must match the RunStep count (lint.sh checks)

## Credentials (defaults are intentional; change them after deployment)
ROOT_PASSWORD="${ROOT_PASSWORD:-R00t@123!}"
DEFAULT_PASSWORD="${DEFAULT_PASSWORD:-*Proxmox123*}"
LOCK_ROOT="${LOCK_ROOT:-FALSE}" # TRUE locks the root account after deployment
NUT_ADMIN_PASSWORD="${NUT_ADMIN_PASSWORD:-123456}"
NUT_MON_PASSWORD="${NUT_MON_PASSWORD:-secret}"
SNMP_AUTH_PASS="${SNMP_AUTH_PASS:-}" # empty -> root password (warns)
SNMP_PRIV_PASS="${SNMP_PRIV_PASS:-}" # empty -> hostname (warns)
SNMP_USER="${SNMP_USER:-proxmox}"
OPENSSH_PASSWORD="${OPENSSH_PASSWORD:-}"
GPG_PUBKEY="${GPG_PUBKEY:-DD982DAAB9C71C78F9563E5207EB56787030D792}"

## Identity
DEFAULT_USERNAME="${DEFAULT_USERNAME:-proxmox}"
DEFAULT_FIRSTNAME="${DEFAULT_FIRSTNAME:-User}"
DEFAULT_LASTNAME="${DEFAULT_LASTNAME:-Proxmox}"
HOSTNAME_PREFIX="${HOSTNAME_PREFIX:-ProxmoxVE}"
GIT_USER_NAME="${GIT_USER_NAME:-}"
GIT_USER_EMAIL="${GIT_USER_EMAIL:-}"
GIT_USER_SIGNINGKEY="${GIT_USER_SIGNINGKEY:-}"
GIT_COMMIT_GPGSIGN="${GIT_COMMIT_GPGSIGN:-false}"
GIT_GPG_PROGRAM="${GIT_GPG_PROGRAM:-gpg}"
GIT_HTTP_PROXY="${GIT_HTTP_PROXY:-}"
GIT_HTTPS_PROXY="${GIT_HTTPS_PROXY:-}"

## Behavior switches
PURGE_OTHER_USERS="${PURGE_OTHER_USERS:-true}" # remove other /home users (fresh-install assumption)
RESET_CLUSTER="${RESET_CLUSTER:-true}" # FALSE on clustered nodes! resets corosync state
USE_GLOBAL_DNS="${USE_GLOBAL_DNS:-false}" # true -> Google DNS, false -> AliDNS
RESET_DOMAIN="${RESET_DOMAIN:-false}"
RESET_HOSTNAME="${RESET_HOSTNAME:-false}"
DISABLE_ICMP_ECHO="${DISABLE_ICMP_ECHO:-false}"
PREFER_IPV4="${PREFER_IPV4:-true}"
DISABLE_DISPLAY="${DISABLE_DISPLAY:-false}" # disable efifb/vesafb (GPU passthrough)
PATCH_INTEL_82599_SFP="${PATCH_INTEL_82599_SFP:-false}" # allow unsupported SFP on ixgbe
ZFS_ARC_MAX="${ZFS_ARC_MAX:-1}" # ZFS ARC max, GiB
I915_GUC_OPTION="${I915_GUC_OPTION:-3}" # 0 | 1 GuC | 2 HuC | 3 GuC/HuC
NUT_MODE="${NUT_MODE:-}" # netclient | netserver | none | standalone
NUT_HOST="${NUT_HOST:-}"

## Release pinning (intentionally the latest PVE release; bump each release)
LSB_CODENAME="${LSB_CODENAME:-trixie}"
CEPH_CODENAME="${CEPH_CODENAME:-tentacle}"

## Network
CUSTOM_DNS_CN=(
    "223.5.5.5"
    "223.6.6.6"
    "2400:3200::1"
    "2400:3200:baba::1"
)
CUSTOM_DNS_GLOBAL=(
    "8.8.4.4"
    "8.8.8.8"
    "2001:4860:4860::8844"
    "2001:4860:4860::8888"
)

## Proxy / mirrors
GHPROXY_URL="${GHPROXY_URL:-}" # GitHub proxy domain, no scheme
PROXY_URL="${PROXY_URL:-http://vpn.zhijie.online:7890}" # zsh proxy_on helper
PROXY_PROTOCOL="${PROXY_PROTOCOL:-socks5}" # proxychains upstream
PROXY_IP="${PROXY_IP:-127.0.0.1}"
PROXY_PORT="${PROXY_PORT:-7891}"
PROXY_USERNAME="${PROXY_USERNAME:-}"
PROXY_PASSWORD="${PROXY_PASSWORD:-}"
DOCKER_REGISTRY_MIRRORS=()

## Zsh
ZSH_THEME="${ZSH_THEME:-ys}"
ZSH_BUILD_IN_PLUGINS="${ZSH_BUILD_IN_PLUGINS:-aliases colored-man-pages command-not-found common-aliases debian docker docker-compose extract git history ssh sudo systemd}"

## Dependency packages (apt)
DEPENDENCY_PACKAGES=(
    "apparmor"
    "apparmor-profiles"
    "apparmor-profiles-extra"
    "apparmor-utils"
    "apt-file"
    "apt-transport-https"
    "busybox"
    "ca-certificates"
    "ceph"
    "chrony"
    "curl"
    "dnsutils"
    "efibootmgr"
    "efitools"
    "efivar"
    "ethtool"
    "fail2ban"
    "fastfetch"
    "fonts-noto-cjk"
    "fonts-noto-color-emoji"
    "fwupd"
    "git"
    "git-lfs"
    "gnupg"
    "grub-efi-amd64-signed"
    "iperf3"
    "jq"
    "knot-dnsutils"
    "libsnmp-dev"
    "lldpd"
    "lm-sensors"
    "lsb-release"
    "mailutils"
    "mokutil"
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
    "openvswitch-switch"
    "p7zip-full"
    "pinentry-tty"
    "postfix"
    "proxmox-secure-boot-support"
    "proxychains-ng"
    "python3"
    "python3-pip"
    "qrencode"
    "rar"
    "rsyslog"
    "sbsigntool"
    "shim-signed"
    "snmp"
    "snmp-mibs-downloader"
    "snmpd"
    "sudo"
    "sudo-rs"
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
# common.sh - shared across all platforms (DSM / macOS / Ubuntu / Proxmox VE)
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

## Function
# Get System Information (shared parts)
GetCurrentUsername() {
    # Under `curl | sudo bash`, whoami is root; SUDO_USER is the real operator.
    # Used by DSM/macOS; debian platforms use DEFAULT_USERNAME instead.
    # shellcheck disable=SC2034
    CURRENT_USERNAME="${SUDO_USER:-$(whoami)}"
}

SetGHProxyDomain() {
    GHPROXY_URL="${GHPROXY_URL:-}"
    if [ -n "$GHPROXY_URL" ]; then
        export GHPROXY_URL="https://${GHPROXY_URL}/"
    fi
}

# Configure Packages (shared)
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

# Platform must set: GPG_HOME, GPG_KEYSERVER, GPG_PINENTRY (may be empty),
# and optionally GPG_HOME_OWNER (user:group) when running as root.
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

# Platform must set: PROXYCHAINS_CONF
ConfigureProxyChains() {
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
        "${PROXY_PROTOCOL:-socks5} ${PROXY_IP:-127.0.0.1} ${PROXY_PORT:-7891}${PROXY_USERNAME:+ ${PROXY_USERNAME} ${PROXY_PASSWORD:-}}"
    )
    printf '%s\n' "${proxychains_list[@]}" > "$PROXYCHAINS_CONF"
}

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

# Platform must set: ZSH_PATH_LIST (array)
GenerateCommandPath() {
    DEFAULT_PATH=""
    local path_entry
    for path_entry in "${ZSH_PATH_LIST[@]}"; do
        DEFAULT_PATH="${path_entry}:${DEFAULT_PATH}"
    done
    DEFAULT_PATH="${DEFAULT_PATH%:}"
}

# Platform must set: ZSH_HOME, ZSH_BUILD_IN_PLUGINS, ZSH_EXTRA_EXPORTS (array,
# may be empty), ZSH_TRAPEXIT (true/false), ZSH_OWNER (may be empty).
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

# Platform must set: OMZ_HOME, OMZ_OWNER (may be empty)
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

# Write /etc/wireguard/wg0.conf. The private key never touches a temp file.
# Platform handles directory ownership and bringing the interface up.
GenerateWireGuardConfig() {
    TUNNEL_CLIENT_IPADDR="10.172.$((RANDOM % 256)).$((RANDOM % 256))/32"
    local private_key public_key preshared_key
    private_key=$(wg genkey)
    public_key=$(printf '%s' "$private_key" | wg pubkey)
    preshared_key=$(wg genpsk)
    local wireguard_list=(
        "[Interface]"
        "Address = ${TUNNEL_CLIENT_IPADDR}"
        "# DNS = 127.0.0.1, ::1"
        "ListenPort = 51820"
        "MTU = 1420"
        "PrivateKey = ${private_key}"
        "# [Peer]"
        "# AllowedIPs = ${TUNNEL_CLIENT_IPADDR}"
        "# Endpoint = 127.0.0.1:51820"
        "# PersistentKeepalive = 5"
        "# PresharedKey = ${preshared_key}"
        "# PublicKey = ${public_key}"
    )
    printf '%s\n' "${wireguard_list[@]}" > "/etc/wireguard/wg0.conf"
    chmod 600 "/etc/wireguard/wg0.conf"
}

# Platform must set: CRONTAB_USER, CRONTAB_ENTRIES (array)
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
# debian.sh - shared between Ubuntu and Proxmox VE (Debian-family, bash 4.4+)
# Part of the generated single-file scripts; not executable on its own.
# ============================================================================

## Function
# Get System Information (shared parts)
GenerateDomain() {
    RESET_DOMAIN="${RESET_DOMAIN:-false}"
    NEW_DOMAIN=()
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

GenerateHostname() {
    RESET_HOSTNAME="${RESET_HOSTNAME:-false}"
    NEW_HOSTNAME=""
    local hostname_file="${HOSTNAME_FILE:-/etc/hostname}"
    if [ -f "$hostname_file" ]; then
        NEW_HOSTNAME=$(awk '{print $1; exit}' "$hostname_file")
    fi
    if [ -z "$NEW_HOSTNAME" ] && HaveCommand hostname; then
        NEW_HOSTNAME=$(hostname)
    fi
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

# Configure Packages (shared)
# Platform must set: APT_PREFERENCES (array of "<release> <priority>")
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
    DHCP_NTP=()
    local chrony_ntp_list=(
        ${DHCP_NTP[@]+"${DHCP_NTP[@]}"}
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
            case " ${prefer_list[*]} ${DHCP_NTP[*]:-} " in
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

ConfigureCrowdSec() {
    HaveCommand cscli || return 0
    local collection
    for collection in "crowdsecurity/iptables" "crowdsecurity/linux-lpe" "crowdsecurity/linux" "crowdsecurity/sshd"; do
        cscli collections install "$collection"
    done
    systemctl restart crowdsec
    cscli hub list
}

ConfigureDockerEngine() {
    HaveCommand docker || return 0
    DOCKER_REGISTRY_MIRRORS=()
    local docker_list=(
        "{"
        "  \"allow-direct-routing\": true,"
        "  \"experimental\": true,"
        "  \"firewall-backend\": \"nftables\","
        "  \"ip-forward\": true"
        "}"
    )
    if [ "${#DOCKER_REGISTRY_MIRRORS[@]}" -gt 0 ]; then
        docker_list=(
            "{"
            "  \"allow-direct-routing\": true,"
            "  \"experimental\": true,"
            "  \"firewall-backend\": \"nftables\","
            "  \"ip-forward\": true,"
            "  \"registry-mirrors\": ["
            "$(printf '    "%s",\n' "${DOCKER_REGISTRY_MIRRORS[@]}" | sed '$s/,$//')"
            "  ]"
            "}"
        )
    fi
    if [ ! -d "/docker" ]; then
        mkdir "/docker"
    fi
    chown -R "${DEFAULT_USERNAME}:docker" "/docker"
    chmod -R 775 "/docker"
    mkdir -p /etc/docker
    printf '%s\n' 'DOCKER_OPTS="--iptables=false"' > /etc/default/docker
    printf '%s\n' "${docker_list[@]}" > /etc/docker/daemon.json
    systemctl enable docker
    systemctl restart docker
}

# Platform must set: FAIL2BAN_JAILS (array), FAIL2BAN_BANACTION (ufw or default),
# and optionally FAIL2BAN_FILTER_NAME + FAIL2BAN_FILTER (array).
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

ConfigureLLDPD() {
    HaveCommand lldpcli || return 0
    printf '%s\n' 'DAEMON_ARGS="-c -e -f -s -x"' > /etc/default/lldpd
    systemctl restart lldpd
    lldpcli show neighbors detail
}

# Platform must set: MODULE_LIST_EXTRA (array, may be empty)
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

ConfigureNut() {
    HaveCommand upsmon || return 0
    function Create_upsd_users() {
        NUT_ADMIN_PASSWORD="${NUT_ADMIN_PASSWORD:-123456}"
        NUT_MON_PASSWORD="${NUT_MON_PASSWORD:-secret}"
        WarnDefaultPassword "NUT_ADMIN_PASSWORD" "$NUT_ADMIN_PASSWORD" "123456"
        WarnDefaultPassword "NUT_MON_PASSWORD" "$NUT_MON_PASSWORD" "secret"
        upsd_user_list=(
            "admin,${NUT_ADMIN_PASSWORD},master,FSD,SET"
            "monuser,${NUT_MON_PASSWORD},slave,,"
        )
    }
    function Generate_nut_conf() {
        printf 'MODE=%s\n' "${NUT_MODE:-none}" > /etc/nut/nut.conf
    }
    function Generate_ups_conf() {
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
    function Generate_upsd_conf() {
        local upsd_config_list=(
            "MAXAGE 15"
            "MAXCONN 1024"
            "STATEPATH /var/run/nut"
        )
        {
            if [ "${NUT_MODE}" = "standalone" ]; then
                printf '%s\n' "LISTEN 127.0.0.1 3493" "LISTEN ::1 3493"
            else
                printf '%s\n' "LISTEN 0.0.0.0 3493"
            fi
            printf '%s\n' "${upsd_config_list[@]}"
        } > /etc/nut/upsd.conf
    }
    function Generate_upsd_users() {
        local entry upsd_username upsd_password upsd_role upsd_actions
        {
            for entry in "${upsd_user_list[@]}"; do
                upsd_username=$(printf '%s' "$entry" | cut -d ',' -f 1)
                upsd_password=$(printf '%s' "$entry" | cut -d ',' -f 2)
                upsd_role=$(printf '%s' "$entry" | cut -d ',' -f 3)
                upsd_actions=$(printf '%s' "$entry" | cut -d ',' -f 4-5 | tr ',' ' ' | sed 's/^ //g;s/ $//g')
                printf '[%s]\n' "$upsd_username"
                if [ -n "$upsd_actions" ]; then
                    printf '    actions = %s\n    instcmds = ALL\n' "$upsd_actions"
                fi
                printf '    password = %s\n    upsmon %s\n' "$upsd_password" "$upsd_role"
            done
        } > /etc/nut/upsd.users
    }
    function Generate_upsmon_conf() {
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
            "MONITOR ${UPSMON_SYSTEM} 1 ${UPSMON_USERNAME} ${UPSMON_PASSWORD} ${UPSMON_ROLE}"
        )
        printf '%s\n' "${upsmon_list[@]}" > /etc/nut/upsmon.conf
    }
    NUT_MODE="${NUT_MODE:-}" # netclient | netserver | none | standalone
    NUT_HOST="${NUT_HOST:-}" # localhost
    rm -f /etc/nut/*.*
    local nut_service_list=()
    case "${NUT_MODE:-none}" in
        netclient)
            Create_upsd_users
            UPSMON_USERNAME=$(printf '%s' "${upsd_user_list[1]}" | cut -d ',' -f 1)
            UPSMON_PASSWORD=$(printf '%s' "${upsd_user_list[1]}" | cut -d ',' -f 2)
            UPSMON_ROLE=$(printf '%s' "${upsd_user_list[1]}" | cut -d ',' -f 3)
            UPSMON_SYSTEM="${UPS_NAME:-ups}@${NUT_HOST:-localhost}"
            nut_service_list=(
                "nut-client,enable"
                "nut-driver,disable"
                "nut-monitor,enable"
                "nut-server,disable"
            )
            Generate_nut_conf
            Generate_upsmon_conf
            ;;
        netserver|standalone)
            Create_upsd_users
            UPSMON_USERNAME=$(printf '%s' "${upsd_user_list[0]}" | cut -d ',' -f 1)
            UPSMON_PASSWORD=$(printf '%s' "${upsd_user_list[0]}" | cut -d ',' -f 2)
            UPSMON_ROLE=$(printf '%s' "${upsd_user_list[0]}" | cut -d ',' -f 3)
            UPSMON_SYSTEM="${UPS_NAME:-ups}@localhost"
            nut_service_list=(
                "nut-client,enable"
                "nut-driver,enable"
                "nut-monitor,enable"
                "nut-server,enable"
            )
            Generate_nut_conf
            Generate_ups_conf
            Generate_upsd_conf
            Generate_upsd_users
            Generate_upsmon_conf
            ;;
        none)
            nut_service_list=(
                "nut-client,disable"
                "nut-driver,disable"
                "nut-monitor,disable"
                "nut-server,disable"
            )
            Generate_nut_conf
            ;;
    esac
    chown -R root:nut /etc/nut
    chmod 640 /etc/nut/*.*
    local entry service_name service_status
    for entry in "${nut_service_list[@]}"; do
        service_name="${entry%%,*}"
        service_status="${entry##*,}"
        systemctl "$service_status" "$service_name" > /dev/null 2>&1 || true
    done
}

ConfigureOpenSSH() {
    HaveCommand ssh-keygen || return 0
    if [ -d /etc/ssh ]; then
        GenerateHostSSHKeys /etc/ssh "root@${NEW_HOSTNAME}"
    fi
    BackupPath /root/.ssh
    mkdir -p /root/.ssh
    touch /root/.ssh/authorized_keys /root/.ssh/known_hosts
    GenerateSSHKeys /root/.ssh "root@${NEW_HOSTNAME}"
    chmod 600 /root/.ssh/authorized_keys
    chmod 644 /root/.ssh/known_hosts
    chmod 700 /root/.ssh
    local user_ssh="/home/${DEFAULT_USERNAME}/.ssh"
    BackupPath "$user_ssh"
    mkdir -p "$user_ssh"
    if [ -f "/home/${DEFAULT_USERNAME}/.gnupg/authorized_keys" ]; then
        mv "/home/${DEFAULT_USERNAME}/.gnupg/authorized_keys" "${user_ssh}/authorized_keys"
    else
        touch "${user_ssh}/authorized_keys"
    fi
    touch "${user_ssh}/known_hosts"
    GenerateSSHKeys "$user_ssh" "${DEFAULT_USERNAME}@${NEW_HOSTNAME}"
    chown -R "$DEFAULT_USERNAME:$DEFAULT_USERNAME" "$user_ssh"
    chmod 600 "${user_ssh}/authorized_keys"
    chmod 644 "${user_ssh}/known_hosts"
    chmod 700 "$user_ssh"
}

ConfigurePostfix() {
    [ -f /etc/postfix/main.cf ] || return 0
    local current_hostname
    current_hostname=$(awk -F '=' '/^myhostname/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}' /etc/postfix/main.cf)
    if [ -n "$current_hostname" ]; then
        sed -i "s/${current_hostname}/${NEW_HOSTNAME}/g" /etc/postfix/main.cf
    fi
}

# Platform wrapper sets SNMP_USER, then calls this.
ConfigureSNMPBase() {
    HaveCommand snmpwalk || return 0
    if [ -z "${SNMP_AUTH_PASS:-}" ]; then
        SNMP_AUTH_PASS="${ROOT_PASSWORD}"
        LogWarn "SNMP_AUTH_PASS defaults to the root password; override it via SNMP_AUTH_PASS."
    fi
    if [ -z "${SNMP_PRIV_PASS:-}" ]; then
        SNMP_PRIV_PASS="${NEW_HOSTNAME}"
        LogWarn "SNMP_PRIV_PASS defaults to the hostname; override it via SNMP_PRIV_PASS."
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
    printf 'createUser %s SHA "%s" AES "%s"\n' "$SNMP_USER" "$SNMP_AUTH_PASS" "$SNMP_PRIV_PASS" > /var/lib/snmp/snmpd.conf
    printf '%s\n' "${snmp_list[@]}" | sort > /etc/snmp/snmpd.conf
    systemctl start snmpd
    # Verification only; head closes the pipe early, so ignore SIGPIPE.
    snmpwalk -v3 -a SHA -A "$SNMP_AUTH_PASS" -x AES -X "$SNMP_PRIV_PASS" -l authPriv -u "$SNMP_USER" 127.0.0.1 | head || true
}

# Root password login is intentional: the root account gets locked afterwards
# via LOCK_ROOT=TRUE (see ConfigureRootUser).
ConfigureSshd() {
    [ -f /usr/share/openssh/sshd_config ] || return 0
    sed -E \
        -e 's/^#?PasswordAuthentication .*/PasswordAuthentication yes/' \
        -e 's/^#?PermitRootLogin .*/PermitRootLogin yes/' \
        -e 's/^#?PubkeyAuthentication .*/PubkeyAuthentication yes/' \
        /usr/share/openssh/sshd_config > /etc/ssh/sshd_config
    rm -f /etc/ssh/sshd_config.d/*
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

# Platform must set: SYSCTL_INTERFACE_MODE, SYSCTL_INTERFACE_PATTERN
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
        "net.core.default_qdisc = fq_pie"
        "net.core.rmem_max = 7500000"
        "net.core.wmem_max = 7500000"
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
    } | sort -u > /etc/sysctl.d/99-autodeploy.conf
    sysctl -p
}

ConfigureTuned() {
    HaveCommand tuned-adm || return 0
    tuned-adm profile "$(tuned-adm recommend)"
    tuned-adm active
}

# Configure System (shared)
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

# Only the deployment user switches to zsh; system accounts keep their shells.
ConfigureDefaultShell() {
    if HaveCommand zsh && [ -n "${DEFAULT_USERNAME:-}" ]; then
        usermod -s /bin/zsh "$DEFAULT_USERNAME"
    fi
    usermod -s /bin/bash root
}

ConfigureRootUser() {
    LOCK_ROOT="${LOCK_ROOT:-FALSE}"
    ROOT_PASSWORD="${ROOT_PASSWORD:-R00t@123!}"
    WarnDefaultPassword "ROOT_PASSWORD" "$ROOT_PASSWORD" 'R00t@123!'
    printf 'root:%s\n' "$ROOT_PASSWORD" | chpasswd
    if [ "$LOCK_ROOT" = "TRUE" ]; then
        passwd -l root
    else
        passwd -u root
    fi
}

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

# Install / Upgrade / Cleanup (shared helpers)
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

# Platform must set: KERNEL_PATTERN (grep -E matching installed kernel packages)
# Keeps the newest kernel, purges the rest.
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
## Function
# Get System Information
function GetSystemInformation() {
    # Identity, credentials and release pinning live in the Configuration block.
    DEFAULT_FULLNAME="${DEFAULT_LASTNAME} ${DEFAULT_FIRSTNAME}"

    function GenerateResolv() {
        CollectDNS
        WriteResolvConf
    }
    function GetHostname() {
        OLD_HOSTNAME=""
        if [ -f "/etc/hostname" ]; then
            OLD_HOSTNAME=$(awk '{print $1; exit}' "/etc/hostname")
        fi
        if [ -z "$OLD_HOSTNAME" ] && HaveCommand hostname; then
            OLD_HOSTNAME=$(hostname)
        fi
    }
    function GetManagementIPAddress() {
        CURRENT_MANAGEMENT_IP=""
        if ip link show vmbr0 > /dev/null 2>&1; then
            CURRENT_MANAGEMENT_IP=$(ip address show vmbr0 | awk '/inet / {print $2}' | sort | head -n 1 | sed 's/\/.*//')
        fi
        if [ -z "$CURRENT_MANAGEMENT_IP" ]; then
            LogWarn "vmbr0 has no IPv4 address; /etc/hosts gets no management IP entry"
        fi
    }
    GenerateDomain
    GenerateHostname
    GenerateResolv
    GetCPUVendorID
    GetHostname
    GetManagementIPAddress
    SetGHProxyDomain
}

# Set Repository Mirror
function SetRepositoryMirror() {
    local mirror_list=(
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/debian-security ${LSB_CODENAME}-security contrib main non-free non-free-firmware"
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/debian ${LSB_CODENAME} contrib main non-free non-free-firmware"
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/debian ${LSB_CODENAME}-backports contrib main non-free non-free-firmware"
        "# deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/debian ${LSB_CODENAME}-backports-sloppy contrib main non-free non-free-firmware"
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/debian ${LSB_CODENAME}-proposed-updates contrib main non-free non-free-firmware"
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/debian ${LSB_CODENAME}-updates contrib main non-free non-free-firmware"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/debian-security ${LSB_CODENAME}-security contrib main non-free non-free-firmware"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/debian ${LSB_CODENAME} contrib main non-free non-free-firmware"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/debian ${LSB_CODENAME}-backports contrib main non-free non-free-firmware"
        "# deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/debian ${LSB_CODENAME}-backports-sloppy contrib main non-free non-free-firmware"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/debian ${LSB_CODENAME}-proposed-updates contrib main non-free non-free-firmware"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/debian ${LSB_CODENAME}-updates contrib main non-free non-free-firmware"
    )
    local proxmox_mirror_list=(
        "# deb ${TRANSPORT_PROTOCOL}://enterprise.proxmox.com/debian/ceph-${CEPH_CODENAME} ${LSB_CODENAME} enterprise"
        "# deb ${TRANSPORT_PROTOCOL}://enterprise.proxmox.com/debian/pve ${LSB_CODENAME} pve-enterprise"
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/proxmox/debian ${LSB_CODENAME} pve-no-subscription pve-test"
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/proxmox/debian/ceph-${CEPH_CODENAME} ${LSB_CODENAME} no-subscription test"
    )
    if [ ! -d "/etc/apt/sources.list.d" ]; then
        mkdir "/etc/apt/sources.list.d"
    else
        rm -f /etc/apt/sources.list.d/*.*
    fi
    printf '%s\n' "${mirror_list[@]}" > "/etc/apt/sources.list"
    printf '%s\n' "${proxmox_mirror_list[@]}" > "/etc/apt/sources.list.d/proxmox.list"
}

# Configure Packages
function ConfigurePackages() {
    function ConfigureAPTPVEExtras() {
        local pve_repo_preference_list=(
            "pve-enterprise 1000"
            "pve-no-subscription 990"
            "pve-test 100"
            "enterprise 1000"
            "no-subscription 990"
            "test 100"
        )
        local entry component priority
        : > "/etc/apt/preferences.d/proxmox.pref"
        for entry in "${pve_repo_preference_list[@]}"; do
            component="${entry%% *}"
            priority="${entry##* }"
            case "$priority" in
                *[!0-9]*) priority="500" ;;
            esac
            printf 'Package: *\nPin: release c=%s,o=Proxmox\nPin-Priority: %s\n\n' "$component" "$priority" >> "/etc/apt/preferences.d/proxmox.pref"
        done
        if [ -f "/etc/apt/sources.list.d/debian-backports.sources" ]; then
            sed -i 's|Signed-By:.*|Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg|g' "/etc/apt/sources.list.d/debian-backports.sources"
        fi
    }
    function ConfigureCrontab() {
        CRONTAB_USER="root"
        CRONTAB_ENTRIES=(
            "0 0 * * 7 sudo apt update && sudo apt full-upgrade -qy && sudo apt autoremove -qy --purge"
            "# 0 4 * * 7 sudo reboot"
            "@reboot sudo rm -rf ~/.*_history ~/.ssh/known_hosts*"
        )
        InstallCrontab
    }
    function ConfigureGrub() {
        local display_option="" sfp_option="" btrfs_option=""
        if [ "${DISABLE_DISPLAY:-false}" = "true" ]; then
            display_option=" video=efifb:off,vesafb:off"
        fi
        if [ "${PATCH_INTEL_82599_SFP:-false}" = "true" ]; then
            sfp_option=" ixgbe.allow_unsupported_sfp=1"
        fi
        if [ "$(findmnt -no FSTYPE / 2>/dev/null || true)" = "btrfs" ]; then
            btrfs_option=" rootflags=degraded"
        fi
        if HaveCommand update-grub && [ -f "/usr/share/grub/default/grub" ]; then
            sed -E \
                -e "s/GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"/GRUB_CMDLINE_LINUX_DEFAULT=\"quiet security=apparmor mitigations=auto,nosmt${btrfs_option}${sfp_option}${display_option}${ENABLE_IOMMU}\"/g" \
                -e 's/#GRUB_DISABLE_OS_PROBER=false/GRUB_DISABLE_OS_PROBER=true/g' \
                -e 's/GRUB_TIMEOUT=.*/GRUB_TIMEOUT=5/g' \
                -e '/GRUB_TIMEOUT_STYLE=/d' \
                "/usr/share/grub/default/grub" > "/etc/default/grub"
            update-grub
        fi
        if HaveCommand proxmox-boot-tool && [ -f "/etc/kernel/cmdline" ]; then
            if [ ! -f "/etc/kernel/cmdline.bak" ]; then
                cp "/etc/kernel/cmdline" "/etc/kernel/cmdline.bak"
            fi
            sed -E "s/boot=zfs/boot=zfs quiet security=apparmor mitigations=auto,nosmt${sfp_option}${display_option}${ENABLE_IOMMU}/g" \
                "/etc/kernel/cmdline.bak" > "/etc/kernel/cmdline"
            proxmox-boot-tool refresh
        fi
    }
    function ConfigureZfsModules() {
        if HaveCommand arcstat; then
            ZFS_ARC_MAX="${ZFS_ARC_MAX:-1}" # GiB
            printf 'options zfs zfs_arc_max=%s\n' "$((ZFS_ARC_MAX * 1024 * 1024 * 1024))" > "/etc/modprobe.d/zfs.conf"
            update-initramfs -u -k all
        fi
        if modinfo ixgbe > /dev/null 2>&1; then
            printf '%s\n' "options ixgbe allow_unsupported_sfp=1" > "/etc/modprobe.d/ixgbe.conf"
        fi
    }
    function ConfigurePVEPrivKeys() {
        [ -d "/etc/pve/priv" ] || return 0
        rm -f "/etc/pve/priv/authorized_keys" "/etc/pve/priv/known_hosts"
        touch "/etc/pve/priv/authorized_keys" "/etc/pve/priv/known_hosts"
        chmod 600 "/etc/pve/priv/authorized_keys" "/etc/pve/priv/known_hosts"
    }
    function ConfigurePVECeph() {
        if [ -d "/etc/systemd/system/ceph-mon.target.wants" ]; then
            local mon_path mon
            for mon_path in "/etc/systemd/system/ceph-mon.target.wants"/ceph-mon@*; do
                if [ -e "$mon_path" ]; then
                    mon="${mon_path##*/}"
                    systemctl stop "$mon"
                    systemctl disable "$mon"
                fi
            done
            rm -rf "/etc/ceph" "/etc/pve/ceph.conf" "/var/lib/ceph"
            mkdir -p "/etc/ceph" "/var/lib/ceph/mgr" "/var/lib/ceph/mon"
        fi
    }
    function ConfigurePVECluster() {
        RESET_CLUSTER="${RESET_CLUSTER:-true}"
        if [ "$RESET_CLUSTER" != "true" ]; then
            LogInfo "RESET_CLUSTER=false: leaving cluster configuration untouched"
            return 0
        fi
        LogWarn "RESET_CLUSTER=true: resetting corosync/pve-cluster state (standalone node assumed; set RESET_CLUSTER=false on clustered nodes)"
        systemctl stop pve-cluster || true
        systemctl stop corosync || true
        pmxcfs -l
        rm -f "/etc/pve/corosync.conf"
        rm -rf /etc/corosync/* /var/log/corosync/* /var/lib/corosync/*
        killall pmxcfs || true
        systemctl start pve-cluster
    }
    function ConfigurePVEContainer() {
        sed -Ezi.bak 's|http://download.proxmox.com|https://mirrors.cernet.edu.cn/proxmox|g' "/usr/share/perl5/PVE/APLInfo.pm"
        systemctl restart pvedaemon
    }
    function ConfigurePVEDashboard() {
        # Removes the "No valid subscription" nag; re-run after proxmox-widget-toolkit updates.
        sed -Ezi.bak "s/(Ext.Msg.show\(\{\s+title: gettext\('No valid sub)/void\(\{ \/\/\1/g" "/usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js"
        systemctl restart pveproxy
    }
    function ConfigurePVEFirewall() {
        local cluster_fw_list=(
            "[OPTIONS]"
            "ebtables: 1"
            "enable: 1"
            "log_ratelimit: burst=5,enable=1,rate=1/second"
            "policy_in: REJECT"
            "policy_out: ACCEPT"
            "[RULES]"
            "IN ACCEPT -p icmp -log nolog"
            "IN ACCEPT -p ipv6-icmp -log nolog"
            "IN ACCEPT -p tcp -dport 135 -log nolog"
            "IN ACCEPT -p udp -dport 135 -log nolog"
            "IN ACCEPT -p udp -dport 137:139 -log nolog"
            "IN ACCEPT -p tcp -dport 139 -log nolog"
            "IN ACCEPT -p udp -dport 1900 -log nolog"
            "IN ACCEPT -p tcp -dport 22 -log nolog"
            "IN ACCEPT -p tcp -dport 3128 -log nolog"
            "IN ACCEPT -p tcp -dport 43 -log nolog"
            "IN ACCEPT -p tcp -dport 445 -log nolog"
            "IN ACCEPT -p udp -dport 445 -log nolog"
            "IN ACCEPT -p udp -dport 5405:5412 -log nolog"
            "IN ACCEPT -p tcp -dport 5900:5999 -log nolog"
            "IN ACCEPT -p tcp -dport 8006 -log nolog"
        )
        local host_fw_list=(
            "[OPTIONS]"
            "enable: 1"
            "log_level_in: nolog"
            "log_level_out: nolog"
            "log_nf_conntrack: 0"
            "ndp: 1"
            "nf_conntrack_allow_invalid: 1"
            "nf_conntrack_max: 262144"
            "nf_conntrack_tcp_timeout_established: 432000"
            "nf_conntrack_tcp_timeout_syn_recv: 60"
            "nftables: 1"
            "nosmurfs: 0"
            "protection_synflood: 0"
            "protection_synflood_burst: 1000"
            "protection_synflood_rate: 200"
            "smurf_log_level: nolog"
            "tcp_flags_log_level: nolog"
            "tcpflags: 0"
            "[RULES]"
            "IN ACCEPT -p icmp -log nolog"
            "IN ACCEPT -p ipv6-icmp -log nolog"
            "IN ACCEPT -p udp -dport 111 -log nolog"
            "IN ACCEPT -p udp -dport 123 -log nolog"
            "IN ACCEPT -p udp -dport 161 -log nolog"
            "IN ACCEPT -p tcp -dport 22 -log nolog"
            "IN ACCEPT -p tcp -dport 3128 -log nolog"
            "IN ACCEPT -p tcp -dport 3493 -log nolog"
            "IN ACCEPT -p udp -dport 323 -log nolog"
            "IN ACCEPT -p udp -dport 5404:5405 -log nolog"
            "IN ACCEPT -p tcp -dport 5900:5999 -log nolog"
            "IN ACCEPT -p tcp -dport 60000:60050 -log nolog"
            "IN ACCEPT -p tcp -dport 8006 -log nolog"
        )
        local vm_container_fw_list=(
            "[OPTIONS]"
            "dhcp: 1"
            "enable: 0"
            "ipfilter: 0"
            "log_level_in: nolog"
            "log_level_out: nolog"
            "macfilter: 0"
            "ndp: 1"
            "policy_in: REJECT"
            "policy_out: ACCEPT"
            "radv: 1"
            "[RULES]"
            "IN ACCEPT -p icmp -log nolog"
            "IN ACCEPT -p ipv6-icmp -log nolog"
        )
        local vm_container_list=("template") conf_path vmid dir
        for dir in "/etc/pve/lxc" "/etc/pve/qemu-server"; do
            if [ -d "$dir" ]; then
                for conf_path in "$dir"/*.conf; do
                    if [ -e "$conf_path" ]; then
                        vmid="${conf_path##*/}"
                        vm_container_list+=("${vmid%.conf}")
                    fi
                done
            fi
        done
        if [ ! -d "/etc/pve/firewall" ]; then
            mkdir "/etc/pve/firewall"
            chown -R root:www-data "/etc/pve/firewall"
        fi
        if [ ! -d "/etc/pve/nodes" ]; then
            mkdir "/etc/pve/nodes"
            chown -R root:www-data "/etc/pve/nodes"
        fi
        printf '%s\n' "${cluster_fw_list[@]}" > "/etc/pve/firewall/cluster.fw"
        printf '%s\n' "${host_fw_list[@]}" > "/etc/pve/nodes/${NEW_HOSTNAME}/host.fw"
        local vm
        for vm in "${vm_container_list[@]}"; do
            printf '%s\n' "${vm_container_fw_list[@]}" > "/etc/pve/firewall/${vm}.fw"
        done
    }
    function ConfigureZfs() {
        HaveCommand zpool || return 0
        local pool
        while IFS= read -r pool; do
            zfs set compression=zstd "$pool"
            zpool set autotrim=on "$pool"
            systemctl enable --now "zfs-trim-weekly@${pool}.timer"
        done < <(zpool list -H -o name)
    }

    APT_PREFERENCES=(
        "${LSB_CODENAME}-backports-sloppy 990"
        "${LSB_CODENAME}-backports 990"
        "${LSB_CODENAME}-security 500"
        "${LSB_CODENAME}-updates 500"
        "${LSB_CODENAME} 500"
        "${LSB_CODENAME}-proposed-updates 100"
    )
    FAIL2BAN_BANACTION="default"
    FAIL2BAN_FILTER_NAME="proxmox"
    FAIL2BAN_FILTER=(
        "[Definition]"
        "failregex = pvedaemon\[.*authentication failure; rhost=<HOST> user=.* msg=.*"
        "journalmatch = _SYSTEMD_UNIT=pvedaemon.service"
    )
    FAIL2BAN_JAILS=(
        "[proxmox]"
        "backend = systemd"
        "bantime = 604800"
        "enabled = true"
        "filter = proxmox"
        "findtime = 60"
        "maxretry = 5"
        "port = 8006"
        "[sshd]"
        "bantime = 604800"
        "enabled = true"
        "filter = sshd"
        "findtime = 60"
        "logpath = /var/log/auth.log"
        "maxretry = 5"
        "port = 22"
    )
    MODULE_LIST_EXTRA=("ip_conntrack_ftp" "nfnetlink_queue")
    SYSCTL_INTERFACE_MODE="include"
    SYSCTL_INTERFACE_PATTERN='^vmbr'
    PROXYCHAINS_CONF="/etc/proxychains4.conf"
    GPG_HOME="/home/${DEFAULT_USERNAME}/.gnupg"
    GPG_KEYSERVER="hkps://keyserver.ubuntu.com:443"
    GPG_PINENTRY="/usr/bin/pinentry-tty"
    GPG_HOME_OWNER="${DEFAULT_USERNAME}:${DEFAULT_USERNAME}"
    ZSH_HOME="/home/${DEFAULT_USERNAME}"
    ZSH_OWNER="${DEFAULT_USERNAME}:${DEFAULT_USERNAME}"
    ZSH_PATH_LIST=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/usr/local/bin" "/usr/local/sbin" "/usr/lib/cargo/bin")
    ZSH_EXTRA_EXPORTS=("export DEBIAN_FRONTEND=\"noninteractive\"")
    ZSH_TRAPEXIT="false"

    RunStep "ConfigureAPT" ConfigureAPT
    RunStep "ConfigureAPTPVEExtras" ConfigureAPTPVEExtras
    RunStep "ConfigureBusybox" ConfigureBusybox
    RunStep "ConfigureChrony" ConfigureChrony
    RunStep "ConfigureCrontab" ConfigureCrontab
    RunStep "ConfigureCrowdSec" ConfigureCrowdSec
    RunStep "ConfigureDockerEngine" ConfigureDockerEngine
    RunStep "ConfigureFail2Ban" ConfigureFail2Ban
    RunStep "ConfigureFRRouting" ConfigureFRRouting
    RunStep "ConfigureGPG" ConfigureGPG
    RunStep "ConfigureGit" ConfigureGit
    RunStep "ConfigureGrub" ConfigureGrub
    RunStep "ConfigureLLDPD" ConfigureLLDPD
    RunStep "ConfigureModules" ConfigureModules
    RunStep "ConfigureZfsModules" ConfigureZfsModules
    RunStep "ConfigureNut" ConfigureNut
    RunStep "ConfigureOpenSSH" ConfigureOpenSSH
    RunStep "ConfigurePVEPrivKeys" ConfigurePVEPrivKeys
    RunStep "ConfigurePostfix" ConfigurePostfix
    RunStep "ConfigureProxyChains" ConfigureProxyChains
    RunStep "ConfigurePVECeph" ConfigurePVECeph
    RunStep "ConfigurePVECluster" ConfigurePVECluster
    RunStep "ConfigurePVEContainer" ConfigurePVEContainer
    RunStep "ConfigurePVEDashboard" ConfigurePVEDashboard
    RunStep "ConfigurePVEFirewall" ConfigurePVEFirewall
    RunStep "ConfigurePythonPyPI" ConfigurePythonPyPI
    RunStep "ConfigureSNMP" ConfigureSNMPBase
    RunStep "ConfigureSshd" ConfigureSshd
    RunStep "ConfigureSysctl" ConfigureSysctl
    RunStep "ConfigureTuned" ConfigureTuned
    RunStep "ConfigureZfs" ConfigureZfs
    RunStep "ConfigureZsh" ConfigureZsh
}

# Configure System
function ConfigureSystem() {
    function ConfigureDefaultUser() {
        WarnDefaultPassword "DEFAULT_PASSWORD" "$DEFAULT_PASSWORD" '*Proxmox123*'
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
        CRONTAB_USER="$DEFAULT_USERNAME"
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
    function ConfigureHostfile() {
        ComputeFullDomain
        local host_list=()
        if [ -n "$CURRENT_MANAGEMENT_IP" ]; then
            host_list+=("${CURRENT_MANAGEMENT_IP} ${NEW_FULL_DOMAIN} ${NEW_HOSTNAME}")
        fi
        host_list+=(
            "127.0.0.1 localhost"
            "255.255.255.255 broadcasthost"
            "::1 ip6-localhost ip6-loopback localhost"
            "fe00::0 ip6-localnet"
            "ff00::0 ip6-mcastprefix"
            "ff02::1 ip6-allnodes"
            "ff02::2 ip6-allrouters"
            "ff02::3 ip6-allhosts"
        )
        printf '%s\n' "${host_list[@]}" > "/etc/hosts"
        printf '%s\n' "$NEW_HOSTNAME" > "/etc/hostname"
        hostnamectl set-hostname "$NEW_HOSTNAME"
    }
    function ConfigureProxmoxVENode() {
        if [ "$OLD_HOSTNAME" != "$NEW_HOSTNAME" ]; then
            if [ -d "/etc/pve/nodes/${OLD_HOSTNAME}" ]; then
                tar -czvf "/etc/pve/nodes/${OLD_HOSTNAME}.tar.gz" "/etc/pve/nodes/${OLD_HOSTNAME}"
                if [ -f "/etc/pve/nodes/${OLD_HOSTNAME}.tar.gz" ]; then
                    rm -rf "/etc/pve/nodes/${OLD_HOSTNAME}"
                fi
            fi
            if [ -f "/var/lib/rrdcached/db/pve2-node/${OLD_HOSTNAME}" ]; then
                cp -rf "/var/lib/rrdcached/db/pve2-node/${OLD_HOSTNAME}" "/var/lib/rrdcached/db/pve2-node/${NEW_HOSTNAME}"
                if [ -f "/var/lib/rrdcached/db/pve2-node/${NEW_HOSTNAME}" ]; then
                    rm -rf "/var/lib/rrdcached/db/pve2-node/${OLD_HOSTNAME}"
                fi
            fi
            if [ -d "/var/lib/rrdcached/db/pve2-storage/${OLD_HOSTNAME}" ]; then
                cp -rf "/var/lib/rrdcached/db/pve2-storage/${OLD_HOSTNAME}" "/var/lib/rrdcached/db/pve2-storage/${NEW_HOSTNAME}"
                if [ -d "/var/lib/rrdcached/db/pve2-storage/${NEW_HOSTNAME}" ]; then
                    rm -rf "/var/lib/rrdcached/db/pve2-storage/${OLD_HOSTNAME}"
                fi
            fi
        fi
    }
    function ConfigureSecureBoot() {
        if [ "$(findmnt -n -o FSTYPE / 2>/dev/null || true)" = "zfs" ]; then
            local esp
            while IFS= read -r esp; do
                proxmox-boot-tool init "$esp" grub
            done < <(lsblk -nr -o NAME,FSTYPE,SIZE | grep -v '^zd' | awk '$2=="vfat" {print "/dev/"$1}' || true)
        fi
    }
    function ConfigureSWAP() {
        function ClearSWAP() {
            HaveCommand sysctl || return 0
            sync
            sysctl -w vm.drop_caches=3 vm.overcommit_memory=0 vm.swappiness=0
        }
        function CreateSWAP() {
            local zram_conf_list=(
                "[zram0]"
                "compression-algorithm = zstd"
                "zram-size = min(ram / 2, 8192)"
            )
            rm -rf "/etc/systemd/zram-generator.conf.d"
            mkdir -p "/etc/systemd/zram-generator.conf.d"
            printf '%s\n' "${zram_conf_list[@]}" > "/etc/systemd/zram-generator.conf.d/zram.conf"
        }
        function RemoveSWAP() {
            local swapfile
            while IFS= read -r swapfile; do
                swapoff "$swapfile" > /dev/null 2>&1 || true
                if [[ "$swapfile" =~ ^/dev/dm- ]]; then
                    lvremove -f "/dev/mapper/pve-swap" > /dev/null 2>&1 || true
                    lvextend -l +100%FREE "/dev/mapper/pve-root"
                else
                    rm -f "$swapfile"
                fi
            done < <(awk 'NR>1 {print $1}' /proc/swaps)
        }
        function UpdateFSTAB() {
            grep -v "swap" /etc/fstab > "/tmp/fstab.autodeploy" || true
            cat "/tmp/fstab.autodeploy" > "/etc/fstab"
            rm -f "/tmp/fstab.autodeploy"
        }
        ClearSWAP
        RemoveSWAP
        CreateSWAP
        UpdateFSTAB
    }
    RunStep "ConfigureDefaultShell" ConfigureDefaultShell
    RunStep "ConfigureDefaultUser" ConfigureDefaultUser
    RunStep "ConfigureGAI" ConfigureGAI
    RunStep "ConfigureHostfile" ConfigureHostfile
    RunStep "ConfigureProxmoxVENode" ConfigureProxmoxVENode
    RunStep "ConfigureRootUser" ConfigureRootUser
    RunStep "ConfigureSecureBoot" ConfigureSecureBoot
    RunStep "ConfigureSWAP" ConfigureSWAP
}

# Install Custom Packages
function InstallCustomPackages() {
    function InstallCrowdSec() {
        InstallAptRepo "crowdsec" "https://packagecloud.io/crowdsec/crowdsec/gpgkey" \
            "deb [arch=amd64 signed-by=/usr/share/keyrings/crowdsec-archive-keyring.gpg] https://packagecloud.io/crowdsec/crowdsec/any any main
deb-src [arch=amd64 signed-by=/usr/share/keyrings/crowdsec-archive-keyring.gpg] https://packagecloud.io/crowdsec/crowdsec/any any main"
        if HaveCommand cscli; then
            local bouncer
            while IFS= read -r bouncer; do
                cscli bouncers delete "$bouncer"
            done < <(cscli bouncers list | grep 'FirewallBouncer' | awk '{print $1}' || true)
        fi
        InstallAptPackages "crowdsec" "crowdsec-firewall-bouncer-nftables"
    }
    function InstallDockerEngine() {
        InstallAptRepo "docker" "https://mirrors.cernet.edu.cn/docker-ce/linux/debian/gpg" \
            "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://mirrors.cernet.edu.cn/docker-ce/linux/debian ${LSB_CODENAME} stable"
        apt update
        apt purge -qy containerd docker-compose docker-doc docker.io podman-docker runc || true
        InstallAptPackages "containerd.io" "docker-buildx-plugin" "docker-ce" "docker-ce-cli" "docker-compose-plugin"
    }
    function InstallFRRouting() {
        InstallAptRepo "frrouting" "https://deb.frrouting.org/frr/keys.gpg" \
            "deb [arch=amd64 signed-by=/usr/share/keyrings/frrouting-archive-keyring.gpg] https://deb.frrouting.org/frr ${LSB_CODENAME} frr-stable"
        InstallAptPackages "frr" "frr-pythontools" "frr-snmp"
    }
    OMZ_HOME="/home/${DEFAULT_USERNAME}"
    OMZ_OWNER="${DEFAULT_USERNAME}:${DEFAULT_USERNAME}"
    RunStep "InstallCrowdSec" InstallCrowdSec
    RunStep "InstallDockerEngine" InstallDockerEngine
    RunStep "InstallFRRouting" InstallFRRouting
    RunStep "InstallOhMyZsh" InstallOhMyZsh
}

# Install Dependency Packages
function InstallDependencyPackages() {
    local apt_list=("${DEPENDENCY_PACKAGES[@]}")
    apt_list+=(${MICROCODE[@]+"${MICROCODE[@]}"})
    InstallAptPackages "${apt_list[@]}"
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
RunStep "CleanupTempFiles" CleanupTempFiles /etc/apt/sources.list.d/pve-enterprise.list*
# Call CleanupOutageKernels
KERNEL_PATTERN='(pve-kernel|proxmox-kernel)-[0-9].*-pve'
RunStep "CleanupOutageKernels" CleanupOutageKernels
RenderProgress "complete"
