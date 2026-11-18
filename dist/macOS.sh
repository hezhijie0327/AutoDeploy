#!/bin/bash
# Copyright 2026 Zhijie He
# Licensed under Apache-2.0 WITH Commons-Clause-1.0. See LICENSE.
#
# GENERATED FILE - edit src/ and run ./build.sh to regenerate.
# For a one-off tweak you may edit the Configuration block below.
#
## How to get and use?
# /bin/bash -c "$(curl -fsSL 'https://source.zhijie.online/AutoDeploy/main/dist/macOS.sh')"
# /bin/bash -c "$(wget -qO- 'https://source.zhijie.online/AutoDeploy/main/dist/macOS.sh')"
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
# Configuration - macOS
# Platform additions on top of config/common.sh. Runs as the operator (no
# root). Override any knob via environment variable before running.
# ============================================================================

## Resume / progress
AUTODEPLOY_STEP_TOTAL=16 # must match the RunStep count (lint.sh checks)

## Behavior switches
REINSTALL_BREW="${REINSTALL_BREW:-false}" # true wipes and reinstalls Homebrew
INSTALL_APP_FROM_CASK="${INSTALL_APP_FROM_CASK:-false}" # install CASK_APPS via brew (disabled by default)
INSTALL_APP_FROM_MAS="${INSTALL_APP_FROM_MAS:-false}" # install MAS_APPS via mas (needs an App Store sign-in)

## Zsh
ZSH_BUILD_IN_PLUGINS="${ZSH_BUILD_IN_PLUGINS:-aliases brew colored-man-pages command-not-found common-aliases docker docker-compose extract git history macos ssh sudo}"

## Homebrew formulae
BREW_PACKAGES=(
    "bash"
    "cloudflared"
    "coreutils"
    "curl"
    "fastfetch"
    "fd"
    "ffmpeg"
    "findutils"
    "gawk"
    "git"
    "git-lfs"
    "gnupg"
    "gnutls"
    "grep"
    "iperf3"
    "iproute2mac"
    "jq"
    "knot"
    "mailutils"
    "mas"
    "mtr"
    "nano"
    "nmap"
    "openssh"
    "p7zip"
    "pinentry"
    "proxychains-ng"
    "python3"
    "qrencode"
    "rar"
    "ripgrep"
    "tcpdump"
    "the_silver_searcher"
    "unzip"
    "vim"
    "wget"
    "whois"
    "wireguard-tools"
    "wireshark"
    "ykman"
    "youtube-dl"
    "zip"
    "zsh"
)

## Homebrew casks (installed only if InstallAppFromCask is enabled)
CASK_APPS=(
    "blackhole-16ch" # BlackHole 16ch
    "blackhole-2ch" # BlackHole 2ch
    "blackhole-64ch" # BlackHole 64ch
    "docker" # Docker
    "drawio" # Draw.io
    "iina" # IINA
    "jordanbaird-ice" # Ice
    "keka" # Keka
    "kekaexternalhelper" # Keka External Helper
    "lm-studio" # LM Studio
    "microsoft-edge" # Microsoft Edge
    "obs" # OBS
    "onyx" # OnyX
    "rectangle" # Rectangle
    "stats" # Stats
    "visual-studio-code" # Visual Studio Code
)

## Mac App Store ids (installed only if InstallAppFromMAS is enabled)
MAS_APPS=(
    "1136220934" # Infuse
    "1289583905" # Pixelmator Pro
    "1352778147" # Bitwarden
    "409222199" # Cyberduck
    "424389933" # Final Cut Pro
    "424390742" # Compressor
    "434290957" # Motion
    "451108668" # QQ
    "462054704" # Microsoft Word
    "462058435" # Microsoft Excel
    "462062816" # Microsoft PowerPoint
    "497799835" # Xcode
    "595615424" # QQ音乐
    "634148309" # Logic Pro
    "634159523" # MainStage
    "823766827" # OneDrive
    "836500024" # Wechat
    "985367838" # Microsoft Outlook
)
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
# Platform must set: ZSH_PATH_LIST (array). ConfigureZsh additionally needs
# ZSH_HOME, ZSH_BUILD_IN_PLUGINS, ZSH_EXTRA_EXPORTS (array, may be empty),
# ZSH_TRAPEXIT (true/false), ZSH_OWNER (may be empty); InstallOhMyZsh needs
# OMZ_HOME, OMZ_OWNER (may be empty).
# ============================================================================

GenerateCommandPath() {
    DEFAULT_PATH=""
    local path_entry
    for path_entry in "${ZSH_PATH_LIST[@]}"; do
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
## Function
# Get System Information
GetSystemInformation() {
    SetBrewPrefix() {
        case "$(uname -m)" in
            arm64) BREW_PREFIX="/opt/homebrew" ;;
            *) BREW_PREFIX="/usr/local" ;;
        esac
    }
    GetCurrentUsername
    SetBrewPrefix
    SetGHProxyDomain
    # Fallback in case ConfigureZsh returns early (no zsh / no oh-my-zsh).
    DEFAULT_PATH=""
}

# Configure Packages
ConfigurePackages() {
    ConfigureCrontab() {
        CRONTAB_USER="$CURRENT_USERNAME"
        CRONTAB_ENTRIES=(
            "PATH=\"${DEFAULT_PATH}:\$PATH\""
            "0 0 * * 7 brew update && brew upgrade --greedy && brew cleanup"
            "@reboot rm -rf ~/.*_history ~/.ssh/known_hosts*"
        )
        InstallCrontab
    }
    ConfigureOpenSSH() {
        HaveCommand ssh-keygen || return 0
        if [ -d "${BREW_PREFIX}/etc/ssh" ]; then
            if [ -d "/etc/ssh" ] && [ ! -L "/etc/ssh" ]; then
                sudo rm -rf /etc/ssh
            fi
            if [ ! -e "/etc/ssh" ]; then
                sudo ln -s "${BREW_PREFIX}/etc/ssh" /etc/ssh
            fi
            GenerateHostSSHKeys "${BREW_PREFIX}/etc/ssh" "${CURRENT_USERNAME}@$(hostname)"
            chown "${CURRENT_USERNAME}:admin" "${BREW_PREFIX}/etc/ssh"/ssh_host_*
        fi
        local user_ssh="/Users/${CURRENT_USERNAME}/.ssh"
        InitUserSSHDir "$user_ssh" "${CURRENT_USERNAME}@$(hostname)"
        if [ -f "${GPG_HOME}/authorized_keys" ]; then
            mv "${GPG_HOME}/authorized_keys" "${user_ssh}/authorized_keys"
            chmod 600 "${user_ssh}/authorized_keys"
        fi
    }
    ConfigureSshd() {
        # Root password login is intentional; the account is locked down later.
        local sshd_config="${BREW_PREFIX}/etc/ssh/sshd_config"
        [ -f "$sshd_config" ] || return 0
        if [ ! -f "${sshd_config}.bak" ]; then
            cp "$sshd_config" "${sshd_config}.bak"
            chown "${CURRENT_USERNAME}:admin" "${sshd_config}.bak"
            chmod 644 "${sshd_config}.bak"
        fi
        sed -E \
            -e 's/^#?PasswordAuthentication .*/PasswordAuthentication yes/' \
            -e 's/^#?PermitRootLogin .*/PermitRootLogin yes/' \
            -e 's/^#?PubkeyAuthentication .*/PubkeyAuthentication yes/' \
            -e 's/^#?UsePAM .*/UsePAM yes/' \
            "${sshd_config}.bak" > "$sshd_config"
        chown "${CURRENT_USERNAME}:admin" "$sshd_config"
        chmod 644 "$sshd_config"
    }
    ConfigureWireGuard() {
        HaveCommand wg || return 0
        if [ ! -d "/etc/wireguard" ]; then
            sudo mkdir "/etc/wireguard"
        else
            sudo rm -f /etc/wireguard/*
        fi
        sudo chown "${CURRENT_USERNAME}:staff" "/etc/wireguard"
        GenerateWireGuardConfig
        sudo wg-quick up wg0
        sudo wg
    }

    PROXYCHAINS_CONF="${BREW_PREFIX}/etc/proxychains.conf"
    GPG_HOME="/Users/${CURRENT_USERNAME}/.gnupg"
    GPG_KEYSERVER="hkps://keyserver.ubuntu.com:443"
    GPG_PINENTRY="${BREW_PREFIX}/bin/pinentry-tty"
    ZSH_HOME="/Users/${CURRENT_USERNAME}"
    ZSH_OWNER=""
    ZSH_PATH_LIST=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/usr/local/bin" "/usr/local/sbin" "${BREW_PREFIX}/bin" "${BREW_PREFIX}/sbin")
    ZSH_EXTRA_EXPORTS=(
        "export HOMEBREW_API_DOMAIN=\"https://mirrors.cernet.edu.cn/homebrew-bottles/api\""
        "export HOMEBREW_BOTTLE_DOMAIN=\"https://mirrors.cernet.edu.cn/homebrew-bottles/bottles\""
        "export HOMEBREW_BREW_GIT_REMOTE=\"https://mirrors.cernet.edu.cn/brew.git\""
        "export HOMEBREW_NO_AUTO_UPDATE=\"1\""
    )
    ZSH_TRAPEXIT="false"

    RunStep "ConfigureGit" ConfigureGit
    RunStep "ConfigureGPG" ConfigureGPG
    RunStep "ConfigureOpenSSH" ConfigureOpenSSH
    RunStep "ConfigureProxyChains" ConfigureProxyChains
    RunStep "ConfigurePythonPyPI" ConfigurePythonPyPI
    RunStep "ConfigureSshd" ConfigureSshd
    RunStep "ConfigureWireGuard" ConfigureWireGuard
    # Always runs: ConfigureCrontab needs the DEFAULT_PATH it computes.
    ConfigureZsh
    RunStep "ConfigureCrontab" ConfigureCrontab
}

# Configure System
ConfigureSystem() {
    ConfigureHostfile() {
        # tee runs under sudo; a plain `sudo cat > /etc/hosts` would redirect
        # in the unprivileged shell and fail.
        printf '%s\n' "${HOSTS_BASE_ENTRIES[@]}" | sudo tee /etc/hosts > /dev/null
    }
    ConfigureSystemDefault() {
        defaults write com.apple.desktopservices DSDontWriteNetworkStores -bool true
        defaults write com.apple.desktopservices DSDontWriteUSBStores -bool true
    }
    RunStep "ConfigureHostfile" ConfigureHostfile
    RunStep "ConfigureSystemDefault" ConfigureSystemDefault
}

# Install Custom Packages
InstallCustomPackages() {
    InstallAppFromCask() {
        [ "$INSTALL_APP_FROM_CASK" = "true" ] || { LogInfo "INSTALL_APP_FROM_CASK=false - skipped"; return 0; }
        local app_list=("${CASK_APPS[@]}")
        HaveCommand brew || return 0
        local app available=()
        for app in "${app_list[@]}"; do
            if brew info --cask "$app" > /dev/null 2>&1; then
                available+=("$app")
            else
                LogWarn "cask not found, skipped: ${app}"
            fi
        done
        if [ "${#available[@]}" -gt 0 ]; then
            brew install --cask "${available[@]}"
        fi
    }
    InstallAppFromMAS() {
        [ "$INSTALL_APP_FROM_MAS" = "true" ] || { LogInfo "INSTALL_APP_FROM_MAS=false - skipped"; return 0; }
        local app_list=("${MAS_APPS[@]}")
        HaveCommand mas || return 0
        local app
        for app in "${app_list[@]}"; do
            if mas info "$app" > /dev/null 2>&1; then
                if ! mas install "$app"; then
                    mas purchase "$app" || LogWarn "mas purchase failed for ${app}"
                fi
            fi
        done
    }
    OMZ_HOME="/Users/${CURRENT_USERNAME}"
    OMZ_OWNER=""
    RunStep "InstallAppFromCask" InstallAppFromCask
    RunStep "InstallAppFromMAS" InstallAppFromMAS
    RunStep "InstallOhMyZsh" InstallOhMyZsh
}

# Install Dependency Packages
InstallDependencyPackages() {
    export HOMEBREW_API_DOMAIN="https://mirrors.cernet.edu.cn/homebrew-bottles/api"
    export HOMEBREW_BOTTLE_DOMAIN="https://mirrors.cernet.edu.cn/homebrew-bottles/bottles"
    export HOMEBREW_BREW_GIT_REMOTE="https://mirrors.cernet.edu.cn/brew.git"
    export PATH="${BREW_PREFIX}/sbin:${BREW_PREFIX}/bin:${PATH}"
    if [ "$REINSTALL_BREW" = "true" ]; then
        sudo rm -rf "$BREW_PREFIX" "/usr/local/Homebrew"
    fi
    if ! HaveCommand brew; then
        /bin/bash -c "$(curl -fsSL "${GHPROXY_URL:-}https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh")"
    fi
    local app_list=("${BREW_PACKAGES[@]}")
    brew developer on
    brew update
    # Classify first, then batch-install: brew pays a Ruby startup + dependency
    # pass per invocation, so one call per kind beats one call per package.
    local app formulae=() casks=()
    for app in "${app_list[@]}"; do
        if brew info --formula "$app" > /dev/null 2>&1; then
            formulae+=("$app")
        elif brew info --cask "$app" > /dev/null 2>&1; then
            casks+=("$app")
        else
            LogWarn "formula/cask not found, skipped: ${app}"
        fi
    done
    if [ "${#formulae[@]}" -gt 0 ]; then
        brew install --formula "${formulae[@]}"
    fi
    if [ "${#casks[@]}" -gt 0 ]; then
        brew install --cask "${casks[@]}"
    fi
}

# Upgrade Packages
UpgradePackages() {
    brew update
    brew upgrade --greedy
    mas upgrade || LogWarn "mas upgrade failed (sign in to the App Store first)"
    sudo softwareupdate --install --all
}

# Cleanup Temp Files
CleanupTempFiles() {
    brew cleanup
    rm -f "/Users/${CURRENT_USERNAME}/".*_history /tmp/*.autodeploy
}

## Process
# Call GetSystemInformation (always runs: later steps need its globals)
GetSystemInformation
InitRun
# Call InstallDependencyPackages
RunStep "InstallDependencyPackages" InstallDependencyPackages
# Call UpgradePackages
RunStep "UpgradePackages" UpgradePackages
# Call InstallCustomPackages
InstallCustomPackages
# Call ConfigureSystem
ConfigureSystem
# Call ConfigurePackages
ConfigurePackages
# Call CleanupTempFiles
RunStep "CleanupTempFiles" CleanupTempFiles
RenderProgress "complete"
