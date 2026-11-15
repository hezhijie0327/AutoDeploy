#!/bin/bash
# Copyright 2026 Zhijie He
# Licensed under Apache-2.0 WITH Commons-Clause-1.0. See LICENSE.
#
# GENERATED FILE - do not edit directly. Edit src/ and run ./build.sh.
#
## How to get and use?
# curl "https://source.zhijie.online/AutoDeploy/main/Ubuntu.sh" | sudo bash
# wget -qO- "https://source.zhijie.online/AutoDeploy/main/Ubuntu.sh" | sudo bash
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
        CUSTOM_DNS=(
            "8.8.4.4"
            "8.8.8.8"
            "2001:4860:4860::8844"
            "2001:4860:4860::8888"
        )
    else
        CUSTOM_DNS=(
            "223.5.5.5"
            "223.6.6.6"
            "2400:3200::1"
            "2400:3200:baba::1"
        )
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
    local pkg
    for pkg in "$@"; do
        if apt-cache show "$pkg" > /dev/null 2>&1; then
            apt install -qy "$pkg"
        else
            LogWarn "package not available, skipped: ${pkg}"
        fi
    done
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
    # Defined early: InstallCustomPackages runs before ConfigureSystem and
    # already needs the default username.
    DEFAULT_FIRSTNAME="User"
    DEFAULT_LASTNAME="Ubuntu"
    DEFAULT_FULLNAME="${DEFAULT_LASTNAME} ${DEFAULT_FIRSTNAME}"
    DEFAULT_USERNAME="${DEFAULT_USERNAME:-ubuntu}"
    DEFAULT_PASSWORD="${DEFAULT_PASSWORD:-*Ubuntu123*}"
    HOSTNAME_PREFIX="Ubuntu"

    function CheckMachineEnvironment() {
        function CheckHypervisorEnvironment() {
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
    function GetCPUpsABILevel() {
        # https://dl.xanmod.org/check_x86-64_psabi.sh
        PSABI_LEVEL=$(awk 'BEGIN{while(!/flags/)if(getline<"/proc/cpuinfo"!=1)exit 0;if(/lm/&&/cmov/&&/cx8/&&/fpu/&&/fxsr/&&/mmx/&&/syscall/&&/sse2/)l=1;if(l==1&&/cx16/&&/lahf/&&/popcnt/&&/sse4_1/&&/sse4_2/&&/ssse3/)l=2;if(l==2&&/avx/&&/avx2/&&/bmi1/&&/bmi2/&&/f16c/&&/fma/&&/abm/&&/movbe/&&/xsave/)l=3;if(l==3&&/avx512f/&&/avx512bw/&&/avx512cd/&&/avx512dq/&&/avx512vl/)l=4;print l}')
    }
    function GetOSArchitecture() {
        if HaveCommand dpkg; then
            OS_ARCHITECTURE=$(dpkg --print-architecture)
        else
            case "$(uname -m)" in
                aarch64) OS_ARCHITECTURE="arm64" ;;
                x86_64) OS_ARCHITECTURE="amd64" ;;
            esac
        fi
        case "${OS_ARCHITECTURE:-}" in
            arm64) MIRROR_URL="ubuntu-ports" ;;
            amd64) MIRROR_URL="ubuntu" ;;
            *) Die "Unsupported architecture." ;;
        esac
    }
    function SetLSBCodename() {
        # Intentionally pinned to the latest release; bump these every release.
        LSB_CODENAME="resolute"
        LSB_VERSION="26.04"
    }
    CollectDNS
    GenerateDomain
    CheckMachineEnvironment
    GenerateHostname
    GetCPUpsABILevel
    GetCPUVendorID
    GetOSArchitecture
    SetLSBCodename
    SetGHProxyDomain
}

# Set Repository Mirror
function SetRepositoryMirror() {
    local mirror_list=(
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${MIRROR_URL} ${LSB_CODENAME} main multiverse restricted universe"
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${MIRROR_URL} ${LSB_CODENAME}-backports main multiverse restricted universe"
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${MIRROR_URL} ${LSB_CODENAME}-proposed main multiverse restricted universe"
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${MIRROR_URL} ${LSB_CODENAME}-security main multiverse restricted universe"
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${MIRROR_URL} ${LSB_CODENAME}-updates main multiverse restricted universe"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${MIRROR_URL} ${LSB_CODENAME} main multiverse restricted universe"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${MIRROR_URL} ${LSB_CODENAME}-backports main multiverse restricted universe"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${MIRROR_URL} ${LSB_CODENAME}-proposed main multiverse restricted universe"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${MIRROR_URL} ${LSB_CODENAME}-security main multiverse restricted universe"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${MIRROR_URL} ${LSB_CODENAME}-updates main multiverse restricted universe"
    )
    if [ ! -d "/etc/apt/sources.list.d" ]; then
        mkdir "/etc/apt/sources.list.d"
    else
        rm -f /etc/apt/sources.list.d/*.*
    fi
    printf '%s\n' "${mirror_list[@]}" > "/etc/apt/sources.list"
}

# Configure Packages
function ConfigurePackages() {
    function ConfigureCloudflareWARP() {
        # Get token from `https://<YOUR_TEAM_NAME>.cloudflareaccess.com/warp`
        # Login via `warp-cli registration token 'com.cloudflare.warp://<your-team-name>.cloudflareaccess.com/auth?token=<your-token>'`
        HaveCommand warp-cli || return 0
        ufw allow in on CloudflareWARP
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
    function ConfigureLandscape() {
        [ -f "/usr/lib/python3/dist-packages/landscape/lib/network.py" ] || return 0
        sed -i 's/tostring/tobytes/g' "/usr/lib/python3/dist-packages/landscape/lib/network.py"
    }
    function ConfigureNetplan() {
        HaveCommand netplan || return 0
        NIC_NAME="${NIC_NAME:-}" # enp6s18 / ens18
        STATIC_IPV4_CONFIG="${STATIC_IPV4_CONFIG:-}" # 10.192.31.254/19,10.192.0.1
        STATIC_IPV6_CONFIG="${STATIC_IPV6_CONFIG:-}" # 2409:8a20:8800::254/64,2409:8a20:8800::1
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
    function ConfigureResolved() {
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
    function ConfigureSystemd() {
        systemctl disable systemd-networkd-wait-online > /dev/null 2>&1 || true
    }
    function ConfigureUfw() {
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
        ufw reload
        ufw --force reset
        ufw allow 123/udp
        ufw allow 161/udp
        ufw limit 22/tcp
        ufw allow 323/udp
        ufw allow 3493/tcp
        ufw allow 51820/udp
        ufw allow in on wg0
        ufw --force enable
        ufw status verbose
    }
    function ConfigureWireGuard() {
        HaveCommand wg || return 0
        if [ ! -d "/etc/wireguard" ]; then
            mkdir "/etc/wireguard"
        else
            rm -f /etc/wireguard/*
        fi
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
    FAIL2BAN_JAILS=(
        "[sshd]"
        "bantime = 604800"
        "enabled = true"
        "filter = sshd"
        "findtime = 60"
        "logpath = /var/log/auth.log"
        "maxretry = 5"
        "port = 22"
    )
    MODULE_LIST_EXTRA=()
    SYSCTL_INTERFACE_MODE="exclude"
    SYSCTL_INTERFACE_PATTERN='^(docker0|lo|wg0)$'
    PROXYCHAINS_CONF="/etc/proxychains4.conf"
    GPG_HOME="/home/${DEFAULT_USERNAME}/.gnupg"
    GPG_KEYSERVER="hkps://keyserver.ubuntu.com:443"
    GPG_PINENTRY="/usr/bin/pinentry-tty"
    GPG_HOME_OWNER="${DEFAULT_USERNAME}:${DEFAULT_USERNAME}"
    ZSH_HOME="/home/${DEFAULT_USERNAME}"
    ZSH_OWNER="${DEFAULT_USERNAME}:${DEFAULT_USERNAME}"
    ZSH_PATH_LIST=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/usr/local/bin" "/usr/local/sbin")
    ZSH_BUILD_IN_PLUGINS="aliases colored-man-pages command-not-found common-aliases docker docker-compose extract git history ssh sudo systemd ubuntu ufw"
    ZSH_EXTRA_EXPORTS=("export DEBIAN_FRONTEND=\"noninteractive\"")
    ZSH_TRAPEXIT="false"

    ConfigureAPT
    ConfigureBusybox
    ConfigureChrony
    ConfigureCloudflareWARP
    ConfigureCrontab
    ConfigureCrowdSec
    ConfigureDockerEngine
    ConfigureFail2Ban
    ConfigureFRRouting
    ConfigureGPG && ConfigureGit
    ConfigureGrub
    ConfigureLandscape
    ConfigureLLDPD
    ConfigureModules
    ConfigureNetplan
    ConfigureNut
    ConfigureOpenSSH
    ConfigurePostfix
    ConfigureProxyChains
    ConfigurePythonPyPI
    ConfigureResolved
    ConfigureSshd
    ConfigureSysctl
    ConfigureSystemd
    ConfigureTuned
    ConfigureUfw
    ConfigureWireGuard
    ConfigureZsh
}

# Configure System
function ConfigureSystem() {
    function ConfigureDefaultUser() {
        WarnDefaultPassword "DEFAULT_PASSWORD" "$DEFAULT_PASSWORD" '*Ubuntu123*'
        PURGE_OTHER_USERS="${PURGE_OTHER_USERS:-true}"
        if [ "$PURGE_OTHER_USERS" = "true" ]; then
            LogWarn "PURGE_OTHER_USERS=true: removing every other user under /home (set PURGE_OTHER_USERS=false to keep them)"
            local home_dir user
            for home_dir in /home/*; do
                if [ -d "$home_dir" ]; then
                    user="${home_dir##*/}"
                    if [ "$user" != "$DEFAULT_USERNAME" ]; then
                        userdel -rf "$user" > /dev/null 2>&1 || true
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
    }
    function ConfigureHostfile() {
        ComputeFullDomain
        local host_list=(
            "127.0.0.1 localhost"
            "127.0.1.1 ${NEW_HOSTNAME}"
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
    function ConfigureLocales() {
        apt purge -qy locales
        apt update
        apt install -qy locales
        locale-gen "en_US.UTF-8"
        update-locale "en_US.UTF-8"
    }
    function ConfigureSWAP() {
        function ClearSWAP() {
            HaveCommand sysctl || return 0
            sync
            sysctl -w vm.drop_caches=3 vm.overcommit_memory=0 vm.swappiness=0
        }
        function CreateSWAP() {
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
        function CreateZRamSWAP() {
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
                rm -f "$swapfile"
            done < <(awk 'NR>1 {print $1}' /proc/swaps)
        }
        function UpdateFSTAB() {
            grep -v "swap" /etc/fstab > "/tmp/fstab.autodeploy" || true
            if [ -f "/swapfile" ] && [ "$DISABLE_SWAP" = "false" ]; then
                printf '%s\n' "/swapfile none swap sw 0 0" >> "/tmp/fstab.autodeploy"
            fi
            cat "/tmp/fstab.autodeploy" > "/etc/fstab"
            rm -f "/tmp/fstab.autodeploy"
        }
        DISABLE_SWAP="${DISABLE_SWAP:-false}"
        ClearSWAP
        RemoveSWAP
        if [ "$DISABLE_SWAP" = "false" ]; then
            CreateSWAP
        fi
        CreateZRamSWAP
        UpdateFSTAB
    }
    function ConfigureTimeZone() {
        rm -f "/etc/localtime"
        ln -s "/usr/share/zoneinfo/Asia/Shanghai" "/etc/localtime"
    }
    ConfigureDefaultShell
    ConfigureDefaultUser
    ConfigureGAI
    ConfigureHostfile
    ConfigureLocales
    ConfigureRootUser
    ConfigureSWAP
    ConfigureTimeZone
}

# Install Custom Packages
function InstallCustomPackages() {
    function InstallCloudflareWARP() {
        InstallAptRepo "cloudflare-warp" "https://pkg.cloudflareclient.com/pubkey.gpg" \
            "deb [arch=${OS_ARCHITECTURE} signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com ${LSB_CODENAME} main"
        InstallAptPackages "cloudflare-warp"
    }
    function InstallCrowdSec() {
        InstallAptRepo "crowdsec" "https://packagecloud.io/crowdsec/crowdsec/gpgkey" \
            "deb [arch=${OS_ARCHITECTURE} signed-by=/usr/share/keyrings/crowdsec-archive-keyring.gpg] https://packagecloud.io/crowdsec/crowdsec/any any main
deb-src [arch=${OS_ARCHITECTURE} signed-by=/usr/share/keyrings/crowdsec-archive-keyring.gpg] https://packagecloud.io/crowdsec/crowdsec/any any main"
        if HaveCommand cscli; then
            local bouncer
            while IFS= read -r bouncer; do
                cscli bouncers delete "$bouncer"
            done < <(cscli bouncers list | grep 'FirewallBouncer' | awk '{print $1}' || true)
        fi
        InstallAptPackages "crowdsec" "crowdsec-firewall-bouncer-nftables"
    }
    function InstallDockerEngine() {
        InstallAptRepo "docker" "https://mirrors.cernet.edu.cn/docker-ce/linux/ubuntu/gpg" \
            "deb [arch=${OS_ARCHITECTURE} signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://mirrors.cernet.edu.cn/docker-ce/linux/ubuntu ${LSB_CODENAME} stable"
        apt update
        apt purge -qy containerd docker-compose docker-doc docker.io podman-docker runc || true
        InstallAptPackages "containerd.io" "docker-buildx-plugin" "docker-ce" "docker-ce-cli" "docker-compose-plugin"
    }
    function InstallFRRouting() {
        InstallAptRepo "frrouting" "https://deb.frrouting.org/frr/keys.gpg" \
            "deb [arch=${OS_ARCHITECTURE} signed-by=/usr/share/keyrings/frrouting-archive-keyring.gpg] https://deb.frrouting.org/frr stable frr-stable"
        InstallAptPackages "frr" "frr-pythontools" "frr-rpki-rtrlib" "frr-snmp"
    }
    function InstallTor() {
        InstallAptRepo "tor" "https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc" \
            "deb [arch=${OS_ARCHITECTURE} signed-by=/usr/share/keyrings/tor-archive-keyring.gpg] https://deb.torproject.org/torproject.org stable main"
        InstallAptPackages "tor"
    }
    function InstallXanModKernel() {
        # Note: NVIDIA, OpenZFS, VirtualBox, VMware and some other dkms modules
        # may not officially support EDGE and RT branch kernels.
        XANMOD_BRANCH="${XANMOD_BRANCH:-edge}" # disable | main | edge | lts | rt
        local branch="$XANMOD_BRANCH"
        # psABI v1 CPUs cannot run edge/rt builds (compare before suffixing!)
        if [ "$PSABI_LEVEL" = "1" ] && { [ "$branch" = "edge" ] || [ "$branch" = "rt" ]; }; then
            branch="main"
        fi
        # no kernel benefit beyond v3
        local level="$PSABI_LEVEL"
        if [ "$level" = "4" ]; then
            level="3"
        fi
        local apt_list=()
        if [ "$OS_ARCHITECTURE" = "amd64" ] && [ "$level" != "0" ] && [ "$branch" != "disable" ]; then
            local suffix=""
            if [ "$branch" != "main" ]; then
                suffix="${branch}-"
            fi
            apt_list=("linux-xanmod-${suffix}x64v${level}")
        else
            apt_list=("linux-generic-hwe-${LSB_VERSION}")
        fi
        InstallAptRepo "xanmod" "https://dl.xanmod.org/archive.key" \
            "deb [arch=${OS_ARCHITECTURE} signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] https://deb.xanmod.org ${LSB_CODENAME} main non-free"
        InstallAptPackages "${apt_list[@]}"
    }
    OMZ_HOME="/home/${DEFAULT_USERNAME}"
    OMZ_OWNER="${DEFAULT_USERNAME}:${DEFAULT_USERNAME}"
    #InstallCloudflareWARP
    InstallCrowdSec
    InstallDockerEngine
    InstallFRRouting
    InstallOhMyZsh
    #InstallTor
    InstallXanModKernel
}

# Install Dependency Packages
function InstallDependencyPackages() {
    local apt_list=(
        "apparmor"
        "apparmor-profiles"
        "apparmor-profiles-extra"
        "apparmor-utils"
        "apt-file"
        "apt-transport-https"
        "busybox"
        "ca-certificates"
        "chrony"
        "cron"
        "curl"
        "dnsutils"
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
        "iputils-ping"
        "jq"
        "knot-dnsutils"
        "landscape-common"
        "libsnmp-dev"
        "lldpd"
        "lm-sensors"
        "lsb-release"
        "mailutils"
        "mtr-tiny"
        "nano"
        "netplan.io"
        "net-tools"
        "nfs-common"
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
        "p7zip-full"
        "pinentry-tty"
        "postfix"
        "proxychains-ng"
        "python3"
        "python3-pip"
        "qrencode"
        "rar"
        "realmd"
        "resolvconf"
        "rsyslog"
        "snmp"
        "snmpd"
        "snmp-mibs-downloader"
        "socat"
        "sudo"
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
        "ufw"
        "unrar"
        "unzip"
        "update-notifier-common"
        "uuid-runtime"
        "vim"
        "virt-what"
        "wget"
        "whois"
        "wireguard"
        "zip"
        "zsh"
    )
    apt_list+=(${HYPERVISOR_AGENT[@]+"${HYPERVISOR_AGENT[@]}"} ${MICROCODE[@]+"${MICROCODE[@]}"})
    # Purge guest agents that do not belong to the detected hypervisor.
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
    InstallAptPackages "${apt_list[@]}"
}

## Process
# Set DEBIAN_FRONTEND to "noninteractive"
export DEBIAN_FRONTEND="noninteractive"
RequireRoot
# Call GetSystemInformation
GetSystemInformation
# Set TRANSPORT_PROTOCOL="http"; Call SetRepositoryMirror
TRANSPORT_PROTOCOL="http" && SetRepositoryMirror
# Call InstallDependencyPackages
InstallDependencyPackages
# Set TRANSPORT_PROTOCOL="https"; Call SetRepositoryMirror
TRANSPORT_PROTOCOL="https" && SetRepositoryMirror
# Call UpgradePackages
UpgradePackages
# Call InstallCustomPackages
InstallCustomPackages
# Call ConfigureSystem
ConfigureSystem
# Call ConfigurePackages
ConfigurePackages
# Call CleanupTempFiles
CleanupTempFiles /etc/ufw/*."$(date '+%Y%m%d')"*
# Call CleanupOutageKernels
KERNEL_PATTERN='(linux-image)-[0-9].*'
CleanupOutageKernels
