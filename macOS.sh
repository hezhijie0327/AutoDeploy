#!/bin/bash

# Current Version: 1.9.8

## How to get and use?
# /bin/bash -c "$(curl -fsSL 'https://source.zhijie.online/AutoDeploy/main/macOS.sh')"
# /bin/bash -c "$(wget -qO- 'https://source.zhijie.online/AutoDeploy/main/macOS.sh')"

## Function
# Get System Information
function GetSystemInformation() {
    function GetCurrentUsername() {
        CurrentUsername=$(whoami)
    }
    function IsArmArchitecture() {
        if [ "$(uname -m)" == "arm64" ]; then
            ARM_ARCHITECTURE="TRUE"
            softwareupdate --install-rosetta
        else
            if [ "$(uname -m)" != "x86_64" ]; then
                echo "Unsupported architecture."
                exit 1
            else
                ARM_ARCHITECTURE="FALSE"
            fi
        fi
    }
    GetCurrentUsername
    IsArmArchitecture
}
# Configure Packages
function ConfigurePackages() {
    function ConfigureCrontab() {
        crontab_list=(
            "@reboot rm -rf /Users/${CurrentUsername}/.*_history /Users/${CurrentUsername}/.ssh/known_hosts*"
        )
        which "crontab" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/tmp/crontab.autodeploy" && for crontab_list_task in "${!crontab_list[@]}"; do
                echo "${crontab_list[$crontab_list_task]}" >> "/tmp/crontab.autodeploy"
            done && sudo crontab -u "${CurrentUsername}" "/tmp/crontab.autodeploy" && sudo crontab -lu "${CurrentUsername}" && rm -rf "/tmp/crontab.autodeploy"
        fi
    }
    function ConfigureGit() {
        gitconfig_key_list=(
            "http.proxy"
            "https.proxy"
            "user.name"
            "user.email"
            "url.https://github.com.cnpmjs.org/.insteadOf"
        )
        gitconfig_value_list=(
            ""
            ""
            ""
            ""
            "https://github.com/"
        )
        which "git" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            for gitconfig_list_task in "${!gitconfig_key_list[@]}"; do
                git config --global --unset ${gitconfig_key_list[$gitconfig_list_task]}
                if [ "${gitconfig_value_list[$gitconfig_list_task]}" != "" ]; then
                    git config --global ${gitconfig_key_list[$gitconfig_list_task]} "${gitconfig_value_list[$gitconfig_list_task]}"
                fi
            done
        fi
    }
    function ConfigureOpenSSH () {
        OPENSSH_PASSWORD=""
        which "ssh-keygen" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            if [ -d "/etc/ssh" ]; then
                sudo rm -rf /etc/ssh/ssh_host_* && sudo ssh-keygen -t dsa -b 1024 -f "/etc/ssh/ssh_host_dsa_key" -C "root@$(hostname)" -N "${OPENSSH_PASSWORD}" && sudo ssh-keygen -t ecdsa -b 384 -f "/etc/ssh/ssh_host_ecdsa_key" -C "root@$(hostname)" -N "${OPENSSH_PASSWORD}" && sudo ssh-keygen -t ed25519 -f "/etc/ssh/ssh_host_ed25519_key" -C "root@$(hostname)" -N "${OPENSSH_PASSWORD}" && sudo ssh-keygen -t rsa -b 4096 -f "/etc/ssh/ssh_host_rsa_key" -C "root@$(hostname)" -N "${OPENSSH_PASSWORD}" && sudo chmod 400 /etc/ssh/ssh_host_* && sudo chmod 644 /etc/ssh/ssh_host_*.pub
                rm -rf /opt/homebrew/etc/ssh/ssh_host_* && ssh-keygen -t dsa -b 1024 -f "/opt/homebrew/etc/ssh/ssh_host_dsa_key" -C "${CurrentUsername}@$(hostname)" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ecdsa -b 384 -f "/opt/homebrew/etc/ssh/ssh_host_ecdsa_key" -C "${CurrentUsername}@$(hostname)" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ed25519 -f "/opt/homebrew/etc/ssh/ssh_host_ed25519_key" -C "${CurrentUsername}@$(hostname)" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t rsa -b 4096 -f "/opt/homebrew/etc/ssh/ssh_host_rsa_key" -C "${CurrentUsername}@$(hostname)" -N "${OPENSSH_PASSWORD}" && chown ${CurrentUsername}:admin /opt/homebrew/etc/ssh/ssh_host_* && chmod 400 /opt/homebrew/etc/ssh/ssh_host_* && chmod 644 /opt/homebrew/etc/ssh/ssh_host_*.pub
            fi
            rm -rf "/Users/${CurrentUsername}/.ssh" && mkdir "/Users/${CurrentUsername}/.ssh" && touch "/Users/${CurrentUsername}/.ssh/authorized_keys" && touch "/Users/${CurrentUsername}/.ssh/known_hosts" && ssh-keygen -t dsa -b 1024 -f "/Users/${CurrentUsername}/.ssh/id_dsa" -C "${CurrentUsername}@$(hostname)" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ecdsa -b 384 -f "/Users/${CurrentUsername}/.ssh/id_ecdsa" -C "${CurrentUsername}@$(hostname)" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ed25519 -f "/Users/${CurrentUsername}/.ssh/id_ed25519" -C "${CurrentUsername}@$(hostname)" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t rsa -b 4096 -f "/Users/${CurrentUsername}/.ssh/id_rsa" -C "${CurrentUsername}@$(hostname)" -N "${OPENSSH_PASSWORD}" && sudo chown ${CurrentUsername}:staff "/Users/${CurrentUsername}/.ssh" && sudo chown ${CurrentUsername}:staff /Users/${CurrentUsername}/.ssh/* && chmod 400 /Users/${CurrentUsername}/.ssh/id_* && chmod 600 /Users/${CurrentUsername}/.ssh/authorized_keys && chmod 600 /Users/${CurrentUsername}/.ssh/known_hosts && chmod 644 /Users/${CurrentUsername}/.ssh/id_*.pub && chmod 700 /Users/${CurrentUsername}/.ssh
        fi
    }
    function ConfigurePythonPyPI() {
        which "pip3" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            WHICH_PIP="pip3"
        else
            which "pip" > "/dev/null" 2>&1
            if [ "$?" -eq "0" ]; then
                WHICH_PIP="pip"
            else
                WHICH_PIP="null"
            fi
        fi
        if [ "${WHICH_PIP}" != "null" ]; then
            ${WHICH_PIP} config set global.index-url "https://mirrors.ustc.edu.cn/pypi/web/simple"
        fi
    }
    function ConfigureSshd() {
        if [ ! -f "/opt/homebrew/etc/ssh/sshd_config.bak" ]; then
            cp -rf "/opt/homebrew/etc/ssh/sshd_config" "/opt/homebrew/etc/ssh/sshd_config.bak" && chown ${CurrentUsername}:admin "/opt/homebrew/etc/ssh/sshd_config.bak" && chmod 644 "/opt/homebrew/etc/ssh/sshd_config.bak"
        fi
        if [ -f "/opt/homebrew/etc/ssh/sshd_config.bak" ]; then
            cat "/opt/homebrew/etc/ssh/sshd_config.bak" | sed "s/\#PasswordAuthentication\ yes/PasswordAuthentication\ yes/g;s/\#PermitRootLogin\ prohibit\-password/PermitRootLogin\ yes/g;s/\#PubkeyAuthentication\ yes/PubkeyAuthentication\ yes/g" > "/tmp/sshd_config.autodeploy" && cat "/tmp/sshd_config.autodeploy" > "/opt/homebrew/etc/ssh/sshd_config" && chown ${CurrentUsername}:admin "/opt/homebrew/etc/ssh/sshd_config" && chmod 644 "/opt/homebrew/etc/ssh/sshd_config" && rm -rf "/tmp/sshd_config.autodeploy"
            sudo rm -rf "/etc/ssh/sshd_config" && cat "/opt/homebrew/etc/ssh/sshd_config.bak" | sed "s/\#PasswordAuthentication\ yes/PasswordAuthentication\ yes/g;s/\#PermitRootLogin\ prohibit\-password/PermitRootLogin\ yes/g;s/\#PubkeyAuthentication\ yes/PubkeyAuthentication\ yes/g" > "/tmp/sshd_config.autodeploy" && sudo mv "/tmp/sshd_config.autodeploy" "/etc/ssh/sshd_config" && sudo chown root:wheel "/etc/ssh/sshd_config" && sudo chmod 644 "/etc/ssh/sshd_config" && sudo rm -rf "/tmp/sshd_config.autodeploy"
        fi
    }
    function ConfigureWireGuard() {
        TUNNEL_CLIENT_V4="192.168.$(shuf -i '224-255' -n 1).$(shuf -i '1-254' -n 1)/32"
        which "bc" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            which "sha1sum" > "/dev/null" 2>&1
            if [ "$?" -eq "0" ]; then
                which "uuidgen" > "/dev/null" 2>&1
                if [ "$?" -eq "0" ]; then
                    UNIQUE_CLIENT=$(echo "obase=16;$(shuf -i '1-65535' -n 1)" | bc | tr "A-Z" "a-z")
                    UNIQUE_PREFIX=$(echo $(date "+%s%N")$(uuidgen | tr -d "-" | tr "A-Z" "a-z") | sha1sum | cut -c 31-)
                    TUNNEL_PREFIX="fd$(echo ${UNIQUE_PREFIX} | cut -c 1-2):$(echo ${UNIQUE_PREFIX} | cut -c 3-6):$(echo ${UNIQUE_PREFIX} | cut -c 7-10)"
                    TUNNEL_CLIENT_V6="${TUNNEL_PREFIX}::${UNIQUE_CLIENT}/128"
                else
                    TUNNEL_CLIENT_V6=""
                fi
            fi
        fi
        if [ ! -d "/etc/wireguard" ]; then
            sudo mkdir "/etc/wireguard"
        else
            sudo rm -rf /etc/wireguard/*
        fi && sudo chown ${CurrentUsername}:staff "/etc/wireguard"
        which "wg" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            wireguard_list=(
                "[Interface]"
                "Address = ${TUNNEL_CLIENT_V4}, ${TUNNEL_CLIENT_V6}"
                "ListenPort = 51820"
                "PrivateKey = $(wg genkey | tee '/tmp/wireguard.autodeploy')"
                "#[Peer]"
                "#AllowedIPs = ${TUNNEL_CLIENT_V4}, ${TUNNEL_CLIENT_V6}"
                "#Endpoint = 127.0.0.1:51820"
                "#PersistentKeepalive = 5"
                "#PublicKey = $(cat '/tmp/wireguard.autodeploy' | wg pubkey)"
            )
            rm -rf "/tmp/wireguard.autodeploy" && for wireguard_list_task in "${!wireguard_list[@]}"; do
                echo "${wireguard_list[$wireguard_list_task]}" | sed "s/, $//g" >> "/tmp/wireguard.autodeploy"
            done && cat "/tmp/wireguard.autodeploy" > "/etc/wireguard/wg0.conf" && chmod 600 "/etc/wireguard/wg0.conf" && rm -rf "/tmp/wireguard.autodeploy" && sudo wg-quick up wg0 && sudo wg
        fi
    }
    function ConfigureZsh() {
        function GenerateCommandPath() {
            if [ "${ARM_ARCHITECTURE}" == "TRUE" ]; then
                ARM_HOMEBREW_BIN="/opt/homebrew/bin"
                ARM_HOMEBREW_SBIN="/opt/homebrew/sbin"
            fi
            default_path_list=(
                "/bin"
                "/sbin"
                "/usr/bin"
                "/usr/sbin"
                "/usr/local/bin"
                "/usr/local/sbin"
                "${ARM_HOMEBREW_BIN}"
                "${ARM_HOMEBREW_SBIN}"
            )
            DEFAULT_PATH="" && for default_path_list_task in "${!default_path_list[@]}"; do
                if [ "${default_path_list[$default_path_list_task]}" != "" ]; then
                    DEFAULT_PATH="${default_path_list[$default_path_list_task]}:${DEFAULT_PATH}"
                    DEFAULT_PATH=$(echo "${DEFAULT_PATH}" | sed "s/\:$//g")
                fi
            done
            export PATH="${DEFAULT_PATH}" && BREW_PATH="$(brew --prefix)/opt" && custom_path_list=($(ls "${BREW_PATH}" | grep -v "@" | sort | awk "{ print $2 }")) && CUSTOM_PATH="" && for custom_path_list_task in "${!custom_path_list[@]}"; do
                if [ -d "${BREW_PATH}/${custom_path_list[$custom_path_list_task]}/bin" ]; then
                    CUSTOM_PATH="${BREW_PATH}/${custom_path_list[$custom_path_list_task]}/bin:${CUSTOM_PATH}"
                    CUSTOM_PATH=$(echo "${CUSTOM_PATH}" | sed "s/\:$//g")
                fi
                if [ -d "${BREW_PATH}/${custom_path_list[$custom_path_list_task]}/share/man" ]; then
                    CUSTOM_MANPATH="${BREW_PATH}/${custom_path_list[$custom_path_list_task]}/share/man:${CUSTOM_MANPATH}"
                    CUSTOM_MANPATH=$(echo "${CUSTOM_MANPATH}" | sed "s/\:$//g")
                fi
            done
        }
        function GenerateOMZProfile() {
            omz_list=(
                "export EDITOR=\"nano\""
                "export GPG_TTY=\$\(tty\)"
                "export HOMEBREW_BOTTLE_DOMAIN=\"https://mirrors.ustc.edu.cn/homebrew-bottles/bottles\""
                "export HOMEBREW_GITHUB_API_TOKEN=\"your_token_here\""
                "export MANPATH=\"${CUSTOM_MANPATH}:\$MANPATH\""
                "export PATH=\"${CUSTOM_PATH}:${DEFAULT_PATH}:\$PATH\""
                "export ZSH=\"\$HOME/.oh-my-zsh\""
                "plugins=(zsh-autosuggestions zsh-completions zsh-history-substring-search zsh-syntax-highlighting)"
                "ZSH_CACHE_DIR=\"\$ZSH/cache\""
                "ZSH_CUSTOM=\"\$ZSH/custom\""
                "ZSH_THEME=\"ys\""
                "DISABLE_AUTO_UPDATE=\"false\""
                "DISABLE_UPDATE_PROMPT=\"false\""
                "UPDATE_ZSH_DAYS=\"7\""
                "ZSH_COMPDUMP=\"\$ZSH_CACHE_DIR/.zcompdump\""
                "ZSH_DISABLE_COMPFIX=\"false\""
                "CASE_SENSITIVE=\"true\""
                "COMPLETION_WAITING_DOTS=\"true\""
                "DISABLE_AUTO_TITLE=\"false\""
                "DISABLE_LS_COLORS=\"false\""
                "DISABLE_MAGIC_FUNCTIONS=\"false\""
                "DISABLE_UNTRACKED_FILES_DIRTY=\"false\""
                "ENABLE_CORRECTION=\"true\""
                "HIST_STAMPS=\"yyyy-mm-dd\""
                "HYPHEN_INSENSITIVE=\"false\""
                "ZSH_THEME_RANDOM_QUIET=\"true\""
                "ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE=\"bg=250,fg=238,bold,underline\""
                "ZSH_AUTOSUGGEST_STRATEGY=(match_prev_cmd history completion)"
                "ZSH_AUTOSUGGEST_USE_ASYNC=\"true\""
                "source \"\$(brew --repository)/Library/Taps/homebrew/homebrew-command-not-found/handler.sh\""
                "source \"\$ZSH/oh-my-zsh.sh\""
            )
            which "zsh" > "/dev/null" 2>&1
            if [ "$?" -eq "0" ] && [ -d "/Users/${CurrentUsername}/.oh-my-zsh" ]; then
                rm -rf "/tmp/omz.autodeploy" && for omz_list_task in "${!omz_list[@]}"; do
                    echo "${omz_list[$omz_list_task]}" >> "/tmp/omz.autodeploy"
                done && cat "/tmp/omz.autodeploy" > "/Users/${CurrentUsername}/.zshrc" && rm -rf "/tmp/omz.autodeploy"
            fi
        }
        GenerateCommandPath
        GenerateOMZProfile
    }
    ConfigureCrontab
    ConfigureGit
    ConfigureOpenSSH
    ConfigurePythonPyPI
    ConfigureSshd
    ConfigureWireGuard
    ConfigureZsh
}
# Configure System
function ConfigureSystem() {
    function ConfigureHostfile() {
        host_list=(
            "127.0.0.1 localhost"
            "255.255.255.255 broadcasthost"
            "::1 ip6-localhost ip6-loopback localhost"
            "fe00::0 ip6-localnet"
            "ff00::0 ip6-mcastprefix"
            "ff02::1 ip6-allnodes"
            "ff02::2 ip6-allrouters"
            "ff02::3 ip6-allhosts"
        )
        rm -rf "/tmp/hosts.autodeploy" && for host_list_task in "${!host_list[@]}"; do
            echo "${host_list[$host_list_task]}" >> "/tmp/hosts.autodeploy"
        done && sudo chmod -R 666 "/etc/hosts" && sudo cat "/tmp/hosts.autodeploy" > "/etc/hosts" && sudo chmod -R 644 "/etc/hosts" && rm -rf "/tmp/hosts.autodeploy"
    }
    ConfigureHostfile
}
# Install Custom Packages
function InstallCustomPackages() {
    function InstallAppFromCask() {
        app_list=(
            "betterzip" # BetterZip
            "cleanmymac" # CleanMyMac X
            "cleanshot" # CleanShot X
            "docker" # Docker
            "downie" # Downie 4
            "firefox" # Firefox
            "iina" # IINA
            "parallels" # Parallels Desktop
            "permute" # Permute 3
            "pixelsnap" # PixelSnap 2
            "steermouse" # SteerMouse
            "visual-studio-code" # Visual Studio Code
        )
        which "brew" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            for app_list_task in "${!app_list[@]}"; do
                brew info --cask ${app_list[$app_list_task]} && if [ "$?" -eq "0" ]; then
                    brew install --cask ${app_list[$app_list_task]}
                fi
            done
        fi
    }
    function InstallAppFromMAS() {
        app_list=(
            "1136220934" # Infuse
            "1189898970" # WeCom
            "1365531024" # 1Blocker
            "409222199" # Cyberduck
            "419330170" # Moom
            "424389933" # Final Cut Pro
            "424390742" # Compressor
            "430798174" # HazeOver
            "434290957" # Motion
            "451108668" # QQ
            "462054704" # Microsoft Word
            "462058435" # Microsoft Excel
            "462062816" # Microsoft PowerPoint
            "497799835" # Xcode
            "595615424" # QQ Music
            "634148309" # Logic Pro
            "634159523" # MainStage
            "823766827" # OneDrive
            "824183456" # Affinity Photo
            "836500024" # Wechat
            "899247664" # TestFlight
            "993841014" # CopyLess 2
        )
        which "mas" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            for app_list_task in "${!app_list[@]}"; do
                mas info ${app_list[$app_list_task]} && if [ "$?" -eq "0" ]; then
                    mas install ${app_list[$app_list_task]} && if [ "$?" -eq "1" ]; then
                        mas purchase ${app_list[$app_list_task]}
                    fi
                fi
            done
        fi
    }
    function InstallOhMyZsh() {
        plugin_list=(
            "zsh-autosuggestions"
            "zsh-completions"
            "zsh-history-substring-search"
            "zsh-syntax-highlighting"
        )
        rm -rf "/Users/${CurrentUsername}/.oh-my-zsh" && git clone --depth=1 "https://github.com.cnpmjs.org/ohmyzsh/ohmyzsh.git" "/Users/${CurrentUsername}/.oh-my-zsh" && if [ -d "/Users/${CurrentUsername}/.oh-my-zsh/custom/plugins" ]; then
            for plugin_list_task in "${!plugin_list[@]}"; do
                rm -rf "/Users/${CurrentUsername}/.oh-my-zsh/custom/plugins/${plugin_list[$plugin_list_task]}" && git clone --depth=1 "https://github.com.cnpmjs.org/zsh-users/${plugin_list[$plugin_list_task]}.git" "/Users/${CurrentUsername}/.oh-my-zsh/custom/plugins/${plugin_list[$plugin_list_task]}"
            done
        fi
    }
    InstallAppFromCask
    InstallAppFromMAS
    InstallOhMyZsh
}
# Install Dependency Packages
function InstallDependencyPackages() {
    tap_list=(
        "homebrew-aliases"
        "homebrew-autoupdate"
        "homebrew-bundle"
        "homebrew-cask"
        "homebrew-cask-drivers"
        "homebrew-cask-fonts"
        "homebrew-cask-versions"
        "homebrew-command-not-found"
        "homebrew-core"
        "homebrew-formula-analytics"
        "homebrew-portable-ruby"
        "homebrew-services"
        "homebrew-test-bot"
    )
    export PATH="/opt/homebrew/sbin:/opt/homebrew/bin:${PATH}"
    which "brew" > "/dev/null" 2>&1
    if [ "$?" -eq "1" ]; then
        /bin/bash -c "$(curl -fsSL 'https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh' | sed 's/https\:\/\/github\.com/https\:\/\/github\.com\.cnpmjs\.org/g')"
    fi && export HOMEBREW_BOTTLE_DOMAIN="https://mirrors.ustc.edu.cn/homebrew-bottles/bottles"
    if [ -d "$(brew --repo)/Library/Taps/homebrew" ]; then
        app_list=(
            "bash"
            "coreutils"
            "curl"
            "ffmpeg"
            "findutils"
            "gawk"
            "git"
            "git-flow"
            "git-lfs"
            "gnu-apl"
            "gnu-barcode"
            "gnu-chess"
            "gnu-cobol"
            "gnu-complexity"
            "gnu-getopt"
            "gnu-go"
            "gnu-indent"
            "gnu-prolog"
            "gnu-scientific-library"
            "gnu-sed"
            "gnu-shogi"
            "gnu-tar"
            "gnu-time"
            "gnu-typist"
            "gnu-units"
            "gnu-which"
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
            "neofetch"
            "nmap"
            "openssh"
            "p7zip"
            "python3"
            "qrencode"
            "rar"
            "tcpdump"
            "unzip"
            "vim"
            "wget"
            "whois"
            "wireguard-tools"
            "wireshark"
            "youtube-dl"
            "zip"
            "zsh"
        )
        for tap_list_task in "${!tap_list[@]}"; do
            rm -rf "$(brew --repo)/Library/Taps/homebrew/${tap_list[$tap_list_task]}" && git clone "https://github.com.cnpmjs.org/Homebrew/${tap_list[$tap_list_task]}.git" "$(brew --repo)/Library/Taps/homebrew/${tap_list[$tap_list_task]}"
        done && brew update && for app_list_task in "${!app_list[@]}"; do
            brew info --formula ${app_list[$app_list_task]} && if [ "$?" -eq "0" ]; then
                brew install --formula ${app_list[$app_list_task]}
            else
                brew info --cask ${app_list[$app_list_task]} && if [ "$?" -eq "0" ]; then
                    brew install --cask ${app_list[$app_list_task]}
                fi
            fi
        done
    fi
}
# Upgrade Packages
function UpgradePackages() {
    brew update && brew upgrade --cask --greedy && brew upgrade --formula && mas upgrade && softwareupdate -ai
}
# Cleanup Temp Files
function CleanupTempFiles() {
    brew cleanup && rm -rf /Users/${CurrentUsername}/.*_history /tmp/*.autodeploy
}

## Process
# Call GetSystemInformation
GetSystemInformation
# Call InstallDependencyPackages
InstallDependencyPackages
# Call UpgradePackages
UpgradePackages
# Call InstallCustomPackages
InstallCustomPackages
# Call ConfigurePackages
ConfigurePackages
# Call ConfigureSystem
ConfigureSystem
# Call CleanupTempFiles
CleanupTempFiles
