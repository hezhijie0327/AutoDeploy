## Function
# Get System Information
function GetSystemInformation() {
    function SetBrewPrefix() {
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
function ConfigurePackages() {
    function ConfigureCrontab() {
        CRONTAB_USER="$CURRENT_USERNAME"
        CRONTAB_ENTRIES=(
            "PATH=\"${DEFAULT_PATH}:\$PATH\""
            "0 0 * * 7 brew update && brew upgrade --greedy && brew cleanup"
            "@reboot rm -rf ~/.*_history ~/.ssh/known_hosts*"
        )
        InstallCrontab
    }
    function ConfigureOpenSSH() {
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
        BackupPath "$user_ssh"
        mkdir -p "$user_ssh"
        if [ -f "${GPG_HOME}/authorized_keys" ]; then
            mv "${GPG_HOME}/authorized_keys" "${user_ssh}/authorized_keys"
        else
            touch "${user_ssh}/authorized_keys"
        fi
        touch "${user_ssh}/known_hosts"
        GenerateSSHKeys "$user_ssh" "${CURRENT_USERNAME}@$(hostname)"
        chmod 600 "${user_ssh}/authorized_keys"
        chmod 644 "${user_ssh}/known_hosts"
        chmod 700 "$user_ssh"
    }
    function ConfigureSshd() {
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
    function ConfigureWireGuard() {
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
function ConfigureSystem() {
    function ConfigureHostfile() {
        local host_list=(
            "127.0.0.1 localhost"
            "255.255.255.255 broadcasthost"
            "::1 ip6-localhost ip6-loopback localhost"
            "fe00::0 ip6-localnet"
            "ff00::0 ip6-mcastprefix"
            "ff02::1 ip6-allnodes"
            "ff02::2 ip6-allrouters"
            "ff02::3 ip6-allhosts"
        )
        # tee runs under sudo; a plain `sudo cat > /etc/hosts` would redirect
        # in the unprivileged shell and fail.
        printf '%s\n' "${host_list[@]}" | sudo tee /etc/hosts > /dev/null
    }
    function ConfigureSystemDefault() {
        defaults write com.apple.desktopservices DSDontWriteNetworkStores -bool true
        defaults write com.apple.desktopservices DSDontWriteUSBStores -bool true
    }
    RunStep "ConfigureHostfile" ConfigureHostfile
    RunStep "ConfigureSystemDefault" ConfigureSystemDefault
}

# Install Custom Packages
function InstallCustomPackages() {
    function InstallAppFromCask() {
        local app_list=("${CASK_APPS[@]}")
        HaveCommand brew || return 0
        local app
        for app in "${app_list[@]}"; do
            if brew info --cask "$app" > /dev/null 2>&1; then
                brew install --cask "$app"
            else
                LogWarn "cask not found, skipped: ${app}"
            fi
        done
    }
    function InstallAppFromMAS() {
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
    #RunStep "InstallAppFromCask" InstallAppFromCask
    #RunStep "InstallAppFromMAS" InstallAppFromMAS
    RunStep "InstallOhMyZsh" InstallOhMyZsh
}

# Install Dependency Packages
function InstallDependencyPackages() {
    REINSTALL_BREW="${REINSTALL_BREW:-false}"
    export HOMEBREW_API_DOMAIN="https://mirrors.cernet.edu.cn/homebrew-bottles/api"
    export HOMEBREW_BOTTLE_DOMAIN="https://mirrors.cernet.edu.cn/homebrew-bottles/bottles"
    export HOMEBREW_BREW_GIT_REMOTE="https://mirrors.cernet.edu.cn/brew.git"
    export PATH="${BREW_PREFIX}/sbin:${BREW_PREFIX}/bin:${PATH}"
    if [ "$REINSTALL_BREW" = "true" ]; then
        sudo rm -rf "$BREW_PREFIX" "/usr/local/Homebrew"
    fi
    if ! HaveCommand brew; then
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    local app_list=("${BREW_PACKAGES[@]}")
    brew developer on
    brew update
    local app
    for app in "${app_list[@]}"; do
        if brew info --formula "$app" > /dev/null 2>&1; then
            brew install --formula "$app"
        elif brew info --cask "$app" > /dev/null 2>&1; then
            brew install --cask "$app"
        else
            LogWarn "formula/cask not found, skipped: ${app}"
        fi
    done
}

# Upgrade Packages
function UpgradePackages() {
    brew update
    brew upgrade --greedy
    mas upgrade || LogWarn "mas upgrade failed (sign in to the App Store first)"
    sudo softwareupdate --install --all
}

# Cleanup Temp Files
function CleanupTempFiles() {
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
