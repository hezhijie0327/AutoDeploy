#!/bin/bash
# Copyright 2026 Zhijie He
# Licensed under Apache-2.0 WITH Commons-Clause-1.0. See LICENSE.
#
# GENERATED FILE - do not edit directly. Edit src/ and run ./build.sh.
#
## How to get and use?
# curl "https://source.zhijie.online/AutoDeploy/main/DSM.sh" | sudo bash
# wget -qO- "https://source.zhijie.online/AutoDeploy/main/DSM.sh" | sudo bash
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
        "ZSH_THEME=\"ys\""
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
## Function
# Get System Information
function GetSystemInformation() {
    GetCurrentUsername
    HOME_BASE="/var/services/homes/${CURRENT_USERNAME}"
    GHPROXY_URL="${GHPROXY_URL:-proxy.zhijie.online}"
    SetGHProxyDomain
}

# Configure Packages
function ConfigurePackages() {
    function ConfigureDocker() {
        HaveCommand synogroup || return 0
        synogroup --add docker || true
        if [ -S "/var/run/docker.sock" ]; then
            chown root:docker "/var/run/docker.sock"
        fi
        synogroup --member docker "$CURRENT_USERNAME"
    }
    function ConfigureOpenSSH() {
        HaveCommand ssh-keygen || return 0
        local user_ssh="${HOME_BASE}/.ssh"
        BackupPath "$user_ssh"
        mkdir -p "$user_ssh"
        if [ -f "${GPG_HOME}/authorized_keys" ]; then
            mv "${GPG_HOME}/authorized_keys" "${user_ssh}/authorized_keys"
        else
            touch "${user_ssh}/authorized_keys"
        fi
        touch "${user_ssh}/known_hosts"
        GenerateSSHKeys "$user_ssh" "${CURRENT_USERNAME}@$(hostname)"
        chown -R "${CURRENT_USERNAME}:users" "$user_ssh"
        chmod 600 "${user_ssh}/authorized_keys"
        chmod 644 "${user_ssh}/known_hosts"
        chmod 700 "$user_ssh"
    }
    function ConfigurePing() {
        HaveCommand setcap || return 0
        HaveCommand ping || return 0
        setcap 'cap_net_raw+ep' "$(command -v ping)"
    }

    GPG_HOME="${HOME_BASE}/.gnupg"
    GPG_KEYSERVER="hkp://keyserver.ubuntu.com"
    GPG_PINENTRY=""
    GPG_HOME_OWNER="${CURRENT_USERNAME}:users"
    ZSH_HOME="$HOME_BASE"
    ZSH_OWNER="${CURRENT_USERNAME}:users"
    ZSH_PATH_LIST=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/usr/local/bin" "/usr/local/sbin" "/usr/syno/bin" "/usr/syno/sbin")
    ZSH_BUILD_IN_PLUGINS="aliases colored-man-pages command-not-found common-aliases docker docker-compose extract git history ssh sudo"
    ZSH_EXTRA_EXPORTS=("export DEBIAN_FRONTEND=\"noninteractive\"")
    ZSH_TRAPEXIT="true"

    ConfigureDocker
    ConfigureGit
    ConfigureGPG
    ConfigureOpenSSH
    ConfigurePing
    ConfigureZsh
}

# Configure System
function ConfigureSystem() {
    function ConfigureDefaultShell() {
        HaveCommand zsh || return 0
        local zsh_path
        zsh_path=$(command -v zsh)
        local profile_list=(
            "if [[ -x ${zsh_path} ]]; then"
            "    export SHELL=${zsh_path}"
            "    exec ${zsh_path}"
            "fi"
        )
        printf '%s\n' "${profile_list[@]}" > "${HOME_BASE}/.profile"
    }
    ConfigureDefaultShell
}

# Install Custom Packages
function InstallCustomPackages() {
    OMZ_HOME="$HOME_BASE"
    OMZ_OWNER="${CURRENT_USERNAME}:users"
    InstallOhMyZsh
}

## Process
RequireRoot
# Call GetSystemInformation
GetSystemInformation
# Call InstallCustomPackages
InstallCustomPackages
# Call ConfigureSystem
ConfigureSystem
# Call ConfigurePackages
ConfigurePackages
