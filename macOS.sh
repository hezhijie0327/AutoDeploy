#!/bin/bash

# Current Version: 2.7.1

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
    function SetGHProxyDomain() {
        GHPROXY_URL=""
        if [ "${GHPROXY_URL}" != "" ]; then
            export GHPROXY_URL="https://${GHPROXY_URL}/"
        fi
    }
    GetCurrentUsername
    IsArmArchitecture
    SetGHProxyDomain
}
# Configure Packages
function ConfigurePackages() {
    function ConfigureCrontab() {
        which "ollama" > "/dev/null" 2>&1
        if [ "$?" -eq "1" ]; then
            OLLAMA_ENV_SETUP="@reboot launchctl setenv OLLAMA_HOST '0.0.0.0' && launchctl setenv OLLAMA_ORIGINS '*'"
        fi

        crontab_list=(
            "@reboot rm -rf /Users/${CurrentUsername}/.*_history /Users/${CurrentUsername}/.ssh/known_hosts*"
            "$OLLAMA_ENV_SETUP"
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
            "commit.gpgsign"
            "gpg.program"
            "http.proxy"
            "https.proxy"
            "user.name"
            "user.email"
            "user.signingkey"
            "url.${GHPROXY_URL}https://github.com/.insteadOf"
        )
        gitconfig_value_list=(
            "false"
            "gpg"
            ""
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
    function ConfigureGPG() {
        GPG_PUBKEY=""
        if [ "${GPG_PUBKEY}" == "" ]; then
            GPG_PUBKEY="DD982DAAB9C71C78F9563E5207EB56787030D792"
        fi
        which "gpg" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/Users/${CurrentUsername}/.gnupg" && gpg --keyserver hkps://keyserver.ubuntu.com:443 --recv ${GPG_PUBKEY} && echo "${GPG_PUBKEY}" | awk 'BEGIN { FS = "\n" }; { print $1":6:" }' | gpg --import-ownertrust && GPG_PUBKEY_ID_A=$(gpg --list-keys --keyid-format LONG | grep "pub\|sub" | awk '{print $2, $4}' | grep "\[A\]" | awk '{print $1}' | awk -F '/' '{print $2}') && GPG_PUBKEY_ID_C=$(gpg --list-keys --keyid-format LONG | grep "pub\|sub" | awk '{print $2, $4}' | grep "\[C\]" | awk '{print $1}' | awk -F '/' '{print $2}')
            if [ "${GPG_PUBKEY_ID_A}" != "" ]; then
                if [ "${ARM_ARCHITECTURE}" == "TRUE" ]; then
                    PINENTRY_PROGRAM_PATH="/opt/homebrew/bin"
                else
                    PINENTRY_PROGRAM_PATH="/usr/local/bin"
                fi
                gpg_agent_list=(
                    "enable-ssh-support"
                    "pinentry-program ${PINENTRY_PROGRAM_PATH}/pinentry"
                )
                rm -rf "/Users/${CurrentUsername}/.gnupg/gpg-agent.conf" && for gpg_agent_list_task in "${!gpg_agent_list[@]}"; do
                    echo "${gpg_agent_list[$gpg_agent_list_task]}" >> "/Users/${CurrentUsername}/.gnupg/gpg-agent.conf"
                done && echo "${GPG_PUBKEY_ID_A}" > "/Users/${CurrentUsername}/.gnupg/sshcontrol"
            fi
        fi
    }
    function ConfigureOpenSSH() {
        OPENSSH_PASSWORD=""
        which "ssh-keygen" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            if [ -d "/opt/homebrew/etc/ssh" ]; then
                if [ -d "/etc/ssh" ]; then
                    sudo rm -rf /etc/ssh
                fi && sudo ln -s /opt/homebrew/etc/ssh /etc/ssh

                rm -rf /opt/homebrew/etc/ssh/ssh_host_* && ssh-keygen -t ecdsa -b 384 -f "/opt/homebrew/etc/ssh/ssh_host_ecdsa_key" -C "${CurrentUsername}@$(hostname)" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ed25519 -f "/opt/homebrew/etc/ssh/ssh_host_ed25519_key" -C "${CurrentUsername}@$(hostname)" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t rsa -b 4096 -f "/opt/homebrew/etc/ssh/ssh_host_rsa_key" -C "${CurrentUsername}@$(hostname)" -N "${OPENSSH_PASSWORD}" && chown ${CurrentUsername}:admin /opt/homebrew/etc/ssh/ssh_host_* && chmod 400 /opt/homebrew/etc/ssh/ssh_host_* && chmod 644 /opt/homebrew/etc/ssh/ssh_host_*.pub
            fi
            rm -rf "/Users/${CurrentUsername}/.ssh" && mkdir "/Users/${CurrentUsername}/.ssh" && if [ "${GPG_PUBKEY_ID_C}" != "" ]; then
                which "gpg" > "/dev/null" 2>&1
                if [ "$?" -eq "0" ]; then
                    gpg --export-ssh-key ${GPG_PUBKEY_ID_C} > "/Users/${CurrentUsername}/.ssh/authorized_keys"
                else
                    touch "/Users/${CurrentUsername}/.ssh/authorized_keys"
                fi
            else
                touch "/Users/${CurrentUsername}/.ssh/authorized_keys"
            fi && touch "/Users/${CurrentUsername}/.ssh/known_hosts" && ssh-keygen -t dsa -b 1024 -f "/Users/${CurrentUsername}/.ssh/id_dsa" -C "${CurrentUsername}@$(hostname)" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ecdsa -b 384 -f "/Users/${CurrentUsername}/.ssh/id_ecdsa" -C "${CurrentUsername}@$(hostname)" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ed25519 -f "/Users/${CurrentUsername}/.ssh/id_ed25519" -C "${CurrentUsername}@$(hostname)" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t rsa -b 4096 -f "/Users/${CurrentUsername}/.ssh/id_rsa" -C "${CurrentUsername}@$(hostname)" -N "${OPENSSH_PASSWORD}" && sudo chown -R ${CurrentUsername}:staff "/Users/${CurrentUsername}/.ssh" && sudo chown -R ${CurrentUsername}:staff /Users/${CurrentUsername}/.ssh/* && chmod 400 /Users/${CurrentUsername}/.ssh/id_* && chmod 600 "/Users/${CurrentUsername}/.ssh/authorized_keys" && chmod 644 "/Users/${CurrentUsername}/.ssh/known_hosts" && chmod 644 /Users/${CurrentUsername}/.ssh/id_*.pub && chmod 700 "/Users/${CurrentUsername}/.ssh"
        fi
    }
    function ConfigureProxyChains() {
        PROXY_PROTOCOL=""
        PROXY_IP=""
        PROXY_PORT=""
        PROXY_USERNAME=""
        PROXY_PASSWORD=""

        proxychains_list=(
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
            "${PROXY_PROTOCOL:-socks5} ${PROXY_IP:-127.0.0.1} ${PROXY_PORT:-7890} ${PROXY_USERNAME} ${PROXY_PASSWORD}"
        )
    
        if [ -f "/opt/homebrew/etc/proxychains.conf" ]; then
            rm -rf "/opt/homebrew/etc/proxychains.conf"
        fi && for proxychains_list_task in "${!proxychains_list[@]}"; do
            echo "${proxychains_list[$proxychains_list_task]}" >> "/opt/homebrew/etc/proxychains.conf"
        done
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
            cat "/opt/homebrew/etc/ssh/sshd_config.bak" | sed "s/\#PasswordAuthentication\ yes/PasswordAuthentication\ yes/g;s/\#PermitRootLogin\ prohibit\-password/PermitRootLogin\ yes/g;s/\#PubkeyAuthentication\ yes/PubkeyAuthentication\ yes/g;s/\#UsePAM no/UsePAM yes/g" > "/tmp/sshd_config.autodeploy" && cat "/tmp/sshd_config.autodeploy" > "/opt/homebrew/etc/ssh/sshd_config" && chown ${CurrentUsername}:admin "/opt/homebrew/etc/ssh/sshd_config" && chmod 644 "/opt/homebrew/etc/ssh/sshd_config" && rm -rf "/tmp/sshd_config.autodeploy"
        fi
    }
    function ConfigureWireGuard() {
        ENABLE_IPV6_ADDRESS="false"

        TUNNEL_CLIENT_V4="10.172.$(shuf -i '0-255' -n 1).$(shuf -i '0-255' -n 1)/32"

        if [ "${ENABLE_IPV6_ADDRESS:-false}" == "true" ]; then
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

            TUNNEL_CLIENT_V6=", ${TUNNEL_CLIENT_V6}"
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
                "Address = ${TUNNEL_CLIENT_V4}${TUNNEL_CLIENT_V6}"
                "# DNS = 127.0.0.1, ::1"
                "ListenPort = 51820"
                "MTU = 1280"
                "PrivateKey = $(wg genkey | tee '/tmp/wireguard.autodeploy')"
                "# [Peer]"
                "# AllowedIPs = ${TUNNEL_CLIENT_V4}${TUNNEL_CLIENT_V6}"
                "# Endpoint = 127.0.0.1:51820"
                "# PersistentKeepalive = 5"
                "# PresharedKey = $(wg genpsk)"
                "# PublicKey = $(cat '/tmp/wireguard.autodeploy' | wg pubkey)"
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
            if [ -d "/Users/${CurrentUsername}/.docker/bin" ]; then
                DOCKER_HOMEBREW_BIN="/Users/${CurrentUsername}/.docker/bin"
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
                "${DOCKER_HOMEBREW_BIN}"
            )
            DEFAULT_PATH="" && for default_path_list_task in "${!default_path_list[@]}"; do
                if [ "${default_path_list[$default_path_list_task]}" != "" ]; then
                    DEFAULT_PATH="${default_path_list[$default_path_list_task]}:${DEFAULT_PATH}"
                    DEFAULT_PATH=$(echo "${DEFAULT_PATH}" | sed "s/\:$//g")
                fi
            done
            export PATH="${DEFAULT_PATH}" && BREW_PATH="$(brew --prefix)/opt" && custom_path_list=($(ls "${BREW_PATH}" | grep -v "@" | sort | awk "{ print $2 }")) && CUSTOM_PATH="" && for custom_path_list_task in "${!custom_path_list[@]}"; do
                if [ -d "${BREW_PATH}/${custom_path_list[$custom_path_list_task]}/libexec/gnubin" ]; then
                    CUSTOM_PATH="${BREW_PATH}/${custom_path_list[$custom_path_list_task]}/libexec/gnubin:${CUSTOM_PATH}"
                elif [ -d "${BREW_PATH}/${custom_path_list[$custom_path_list_task]}/bin" ]; then
                    CUSTOM_PATH="${BREW_PATH}/${custom_path_list[$custom_path_list_task]}/bin:${CUSTOM_PATH}"
                fi && CUSTOM_PATH=$(echo "${CUSTOM_PATH}" | sed "s/\:$//g")
                if [ -d "${BREW_PATH}/${custom_path_list[$custom_path_list_task]}/libexec/gnuman" ]; then
                    CUSTOM_MANPATH="${BREW_PATH}/${custom_path_list[$custom_path_list_task]}/libexec/gnuman:${CUSTOM_MANPATH}"
                elif [ -d "${BREW_PATH}/${custom_path_list[$custom_path_list_task]}/share/man" ]; then
                    CUSTOM_MANPATH="${BREW_PATH}/${custom_path_list[$custom_path_list_task]}/share/man:${CUSTOM_MANPATH}"
                fi && CUSTOM_MANPATH=$(echo "${CUSTOM_MANPATH}" | sed "s/\:$//g")
            done
        }
        function GenerateOMZProfile() {
            HOMEBREW_GITHUB_API_TOKEN=""
            omz_list=(
                "export EDITOR=\"nano\""
                "export GPG_TTY=\$(tty)"
                "export HOMEBREW_API_DOMAIN=\"https://mirrors.ustc.edu.cn/homebrew-bottles/api\""
                "export HOMEBREW_BOTTLE_DOMAIN=\"https://mirrors.ustc.edu.cn/homebrew-bottles/bottles\""
                "export HOMEBREW_BREW_GIT_REMOTE=\"${GHPROXY_URL}https://github.com/homebrew/brew.git\""
                "export HOMEBREW_GITHUB_API_TOKEN=\"${HOMEBREW_GITHUB_API_TOKEN}\""
                "export HOMEBREW_NO_AUTO_UPDATE=\"1\""
                "export MANPATH=\"${CUSTOM_MANPATH}:\$MANPATH\""
                "export PATH=\"${CUSTOM_PATH}:${DEFAULT_PATH}:\$PATH\""
                "# export SSH_AUTH_SOCK=\"\$(gpgconf --list-dirs agent-ssh-socket)\" && gpgconf --launch gpg-agent && gpg-connect-agent updatestartuptty /bye > \"/dev/null\" 2>&1"
                "export ZSH=\"\$HOME/.oh-my-zsh\""
                "function proxy_off(){ unset all_proxy; unset ftp_proxy; unset http_proxy; unset https_proxy; unset rsync_proxy }"
                "function proxy_on(){ export all_proxy=\"socks5://vpn.zhijie.online:7890\"; export ftp_proxy=\"http://vpn.zhijie.online:7890\"; export http_proxy=\"http://vpn.zhijie.online:7890\"; export https_proxy=\"http://vpn.zhijie.online:7890\"; export rsync_proxy=\"http://vpn.zhijie.online:7890\" }"
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
    ConfigureGPG
    ConfigureOpenSSH
    ConfigureProxyChains
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
    function ConfigureSystemDefault() {
        defaults write com.apple.desktopservices DSDontWriteNetworkStores -bool true
        defaults write com.apple.desktopservices DSDontWriteUSBStores -bool true
    }
    ConfigureHostfile
    ConfigureSystemDefault
}
# Install Custom Packages
function InstallCustomPackages() {
    function InstallAppFromCask() {
        app_list=(
            "blackhole-16ch" # BlackHole 16ch
            "blackhole-2ch" # BlackHole 2ch
            "blackhole-64ch" # BlackHole 64ch
            "docker" # Docker
            "drawio" # Draw.io
            "iina" # IINA
            "jordanbaird-ice" # Ice
            "keka" # Keka
            "kekaexternalhelper" # Keka External Helper
            "maccy" # Maccy
            "microsoft-edge" # Microsoft Edge
            "obs" # OBS
            "onyx" # OnyX
            "parallels" # Parallels Desktop
            "rectangle" # Rectangle
            "stats" # Stats
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
        plugin_upgrade_list=(
            '#!/bin/bash'
            'plugin_list=($(ls "$HOME/.oh-my-zsh/custom/plugins" | grep -v "^example$" | awk "{print $1}"))'
            'for plugin_list_task in "${!plugin_list[@]}"; do'
            "    rm -rf \"\$HOME/.oh-my-zsh/custom/plugins/\${plugin_list[\$plugin_list_task]}\" && git clone --depth=1 \"${GHPROXY_URL}https://github.com/zsh-users/\${plugin_list[\$plugin_list_task]}.git\" \"\$HOME/.oh-my-zsh/custom/plugins/\${plugin_list[\$plugin_list_task]}\""
            'done'
        )
        rm -rf "/Users/${CurrentUsername}/.oh-my-zsh" && git clone --depth=1 "${GHPROXY_URL}https://github.com/ohmyzsh/ohmyzsh.git" "/Users/${CurrentUsername}/.oh-my-zsh" && if [ -d "/Users/${CurrentUsername}/.oh-my-zsh/custom/plugins" ]; then
            for plugin_list_task in "${!plugin_list[@]}"; do
                rm -rf "/Users/${CurrentUsername}/.oh-my-zsh/custom/plugins/${plugin_list[$plugin_list_task]}" && git clone --depth=1 "${GHPROXY_URL}https://github.com/zsh-users/${plugin_list[$plugin_list_task]}.git" "/Users/${CurrentUsername}/.oh-my-zsh/custom/plugins/${plugin_list[$plugin_list_task]}"
            done
        fi && rm -rf "/Users/${CurrentUsername}/.oh-my-zsh/oh-my-zsh-plugin.sh" && for plugin_upgrade_list_task in "${!plugin_upgrade_list[@]}"; do
            echo "${plugin_upgrade_list[$plugin_upgrade_list_task]}" >> "/Users/${CurrentUsername}/.oh-my-zsh/oh-my-zsh-plugin.sh"
        done
    }
    InstallAppFromCask
    InstallAppFromMAS
    InstallOhMyZsh
}
# Install Dependency Packages
function InstallDependencyPackages() {
    REINSTALL_BREW="false"

    export HOMEBREW_API_DOMAIN="https://mirrors.ustc.edu.cn/homebrew-bottles/api"
    export HOMEBREW_BOTTLE_DOMAIN="https://mirrors.ustc.edu.cn/homebrew-bottles/bottles"
    export HOMEBREW_BREW_GIT_REMOTE="${GHPROXY_URL}https://github.com/homebrew/brew.git"
    export PATH="/opt/homebrew/sbin:/opt/homebrew/bin:${PATH}"
    
    if [ "${REINSTALL_BREW}" == "true" ]; then
        sudo rm -rf "/opt/homebrew" "/usr/local/Homebrew"
    fi

    which "brew" > "/dev/null" 2>&1
    if [ "$?" -eq "1" ]; then
        curl -fsSL "${GHPROXY_URL}https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh" | sed "s|https://github.com|https://${GHPROXY_URL}/https://github.com|g" | sed 's|#!/bin/bash|#!/bin/bash\nexport HOMEBREW_BOTTLE_DOMAIN="https://mirrors.ustc.edu.cn/homebrew-bottles/bottles"|g' > "/tmp/brew.autodeploy" && bash "/tmp/brew.autodeploy"
    fi

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
        "pinentry"
        "proxychains-ng"
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
        "ykman"
        "youtube-dl"
        "zip"
        "zsh"
    )
    brew update && for app_list_task in "${!app_list[@]}"; do
        brew info --formula ${app_list[$app_list_task]} && if [ "$?" -eq "0" ]; then
            brew install --formula ${app_list[$app_list_task]}
        else
            brew info --cask ${app_list[$app_list_task]} && if [ "$?" -eq "0" ]; then
                brew install --cask ${app_list[$app_list_task]}
            fi
        fi
    done
}
# Upgrade Packages
function UpgradePackages() {
    brew update && brew upgrade --greedy && mas upgrade && softwareupdate -ai
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
# Call ConfigureSystem
ConfigureSystem
# Call ConfigurePackages
ConfigurePackages
# Call CleanupTempFiles
CleanupTempFiles
