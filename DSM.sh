#!/bin/bash

## How to get and use?
# curl "https://source.zhijie.online/AutoDeploy/main/DSM.sh" | sudo bash
# wget -qO- "https://source.zhijie.online/AutoDeploy/main/DSM.sh" | sudo bash

## Function
# Get System Information
function GetSystemInformation() {
    function GetCurrentUsername() {
        CurrentUsername=$(whoami)
    }
    function SetGHProxyDomain() {
        GHPROXY_URL="proxy.zhijie.online"
        if [ "${GHPROXY_URL}" != "" ]; then
            export GHPROXY_URL="https://${GHPROXY_URL}/"
        fi
    }
    GetCurrentUsername
    SetGHProxyDomain
}

# Configure Packages
function ConfigurePackages() {
    function ConfigureDocker() {
        sudo synogroup --add docker
        sudo chown root:docker /var/run/docker.sock
        sudo synogroup --member docker ${CurrentUsername}
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
            rm -rf "/var/services/homes/${CurrentUsername}/.gnupg" && gpg --keyserver hkp://keyserver.ubuntu.com --recv ${GPG_PUBKEY} && echo "${GPG_PUBKEY}" | awk 'BEGIN { FS = "\n" }; { print $1":6:" }' | gpg --import-ownertrust && GPG_PUBKEY_ID_A=$(gpg --list-keys --keyid-format LONG | grep "pub\|sub" | awk '{print $2, $4}' | grep "\[A\]" | awk '{print $1}' | awk -F '/' '{print $2}') && GPG_PUBKEY_ID_C=$(gpg --list-keys --keyid-format LONG | grep "pub\|sub" | awk '{print $2, $4}' | grep "\[C\]" | awk '{print $1}' | awk -F '/' '{print $2}')
            if [ "${GPG_PUBKEY_ID_A}" != "" ]; then
                gpg_agent_list=(
                    "enable-ssh-support"
                )
                rm -rf "/var/services/homes/${CurrentUsername}/.gnupg/gpg-agent.conf" && for gpg_agent_list_task in "${!gpg_agent_list[@]}"; do
                    echo "${gpg_agent_list[$gpg_agent_list_task]}" >> "/var/services/homes/${CurrentUsername}/.gnupg/gpg-agent.conf"
                done && echo "${GPG_PUBKEY_ID_A}" > "/var/services/homes/${CurrentUsername}/.gnupg/sshcontrol"
            fi

            chmod 700 /var/services/homes/hezhijie/.gnupg && chmod 600 /var/services/homes/hezhijie/.gnupg/*
        fi
    }
    function ConfigureOpenSSH() {
        OPENSSH_PASSWORD=""
        which "ssh-keygen" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/var/services/homes/${CurrentUsername}/.ssh" && mkdir "/var/services/homes/${CurrentUsername}/.ssh" && if [ "${GPG_PUBKEY_ID_C}" != "" ]; then
                which "gpg" > "/dev/null" 2>&1
                if [ "$?" -eq "0" ]; then
                    gpg --export-ssh-key ${GPG_PUBKEY_ID_C} > "/var/services/homes/${CurrentUsername}/.ssh/authorized_keys"
                else
                    touch "/var/services/homes/${CurrentUsername}/.ssh/authorized_keys"
                fi
            else
                touch "/var/services/homes/${CurrentUsername}/.ssh/authorized_keys"
            fi && touch "/var/services/homes/${CurrentUsername}/.ssh/known_hosts" && ssh-keygen -t dsa -b 1024 -f "/var/services/homes/${CurrentUsername}/.ssh/id_dsa" -C "${CurrentUsername}@$(hostname)" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ecdsa -b 384 -f "/var/services/homes/${CurrentUsername}/.ssh/id_ecdsa" -C "${CurrentUsername}@$(hostname)" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ed25519 -f "/var/services/homes/${CurrentUsername}/.ssh/id_ed25519" -C "${CurrentUsername}@$(hostname)" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t rsa -b 4096 -f "/var/services/homes/${CurrentUsername}/.ssh/id_rsa" -C "${CurrentUsername}@$(hostname)" -N "${OPENSSH_PASSWORD}" && sudo chown -R ${CurrentUsername}:users "/var/services/homes/${CurrentUsername}/.ssh" && sudo chown -R ${CurrentUsername}:users /var/services/homes/${CurrentUsername}/.ssh/* && chmod 400 /var/services/homes/${CurrentUsername}/.ssh/id_* && chmod 600 "/var/services/homes/${CurrentUsername}/.ssh/authorized_keys" && chmod 644 "/var/services/homes/${CurrentUsername}/.ssh/known_hosts" && chmod 644 /var/services/homes/${CurrentUsername}/.ssh/id_*.pub && chmod 700 "/var/services/homes/${CurrentUsername}/.ssh"
        fi
    }
    function ConfigurePing() {
        sudo setcap 'cap_net_raw+ep' "$(which ping)"
    }
    function ConfigureZsh() {
        function GenerateCommandPath() {
            default_path_list=(
                "/bin"
                "/sbin"
                "/usr/bin"
                "/usr/sbin"
                "/usr/local/bin"
                "/usr/local/sbin"
                "/usr/syno/bin"
                "/usr/syno/sbin"
            )
            DEFAULT_PATH="" && for default_path_list_task in "${!default_path_list[@]}"; do
                if [ "${default_path_list[$default_path_list_task]}" != "" ]; then
                    DEFAULT_PATH="${default_path_list[$default_path_list_task]}:${DEFAULT_PATH}"
                    DEFAULT_PATH=$(echo "${DEFAULT_PATH}" | sed "s/\:$//g")
                fi
            done
        }
        function GenerateOMZProfile() {
            PROXY_URL='http://vpn.zhijie.online:7890' # http://username:password@ip:port
            NO_PROXY='localhost,127.0.0.1,::1'

            omz_list=(
                "export DEBIAN_FRONTEND=\"noninteractive\""
                "export EDITOR=\"nano\""
                "export GPG_TTY=\$(tty)"
                "export PATH=\"${DEFAULT_PATH}:\$PATH\""
                "# export SSH_AUTH_SOCK=\"\$(gpgconf --list-dirs agent-ssh-socket)\" && gpgconf --launch gpg-agent && gpg-connect-agent updatestartuptty /bye > \"/dev/null\" 2>&1"
                "export ZSH=\"\$HOME/.oh-my-zsh\""
                "function proxy_off(){ unset all_proxy; unset ftp_proxy; unset http_proxy; unset https_proxy; unset rsync_proxy; unset no_proxy }"
                "function proxy_on(){ export all_proxy=\"${PROXY_URL}\"; export ftp_proxy=\"${PROXY_URL}\"; export http_proxy=\"${PROXY_URL}\"; export https_proxy=\"${PROXY_URL}\"; export rsync_proxy=\"${PROXY_URL}\"; export no_proxy=\"${NO_PROXY}\" }"
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
                'TRAPEXIT() { rm -rf ~/.zsh_history(N) ~/.ssh/known_hosts*(N) }'
            )
            which "zsh" > "/dev/null" 2>&1
            if [ "$?" -eq "0" ] && [ -d "/var/services/homes/${CurrentUsername}/.oh-my-zsh" ]; then
                rm -rf "/tmp/omz.autodeploy" && for omz_list_task in "${!omz_list[@]}"; do
                    echo "${omz_list[$omz_list_task]}" >> "/tmp/omz.autodeploy"
                done && cat "/tmp/omz.autodeploy" > "/var/services/homes/${CurrentUsername}/.zshrc" && rm -rf "/tmp/omz.autodeploy"
            fi
        }
        GenerateCommandPath
        GenerateOMZProfile
    }
    ConfigureDocker
    ConfigureGit
    ConfigureGPG
    ConfigureOpenSSH
    ConfigurePing
    ConfigureZsh
}

function ConfigureSystem() {
    function ConfigureDefaultShell() {
        which "zsh" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            profile_list=(
                'if [[ -x /usr/local/bin/zsh ]]; then'
                "    export SHELL=$(which zsh)"
                "    exec $(which zsh)"
                'fi'
            )

            rm -rf "/var/services/homes/${CurrentUsername}/.profile" && for profile_list_task in "${!profile_list[@]}"; do
                echo "${profile_list[$profile_list_task]}" >> "/var/services/homes/${CurrentUsername}/.profile"
            done
        fi
    }
    ConfigureDefaultShell
}

# Install Custom Packages
function InstallCustomPackages() {
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
        rm -rf "/var/services/homes/${CurrentUsername}/.oh-my-zsh" && git clone --depth=1 "${GHPROXY_URL}https://github.com/ohmyzsh/ohmyzsh.git" "/var/services/homes/${CurrentUsername}/.oh-my-zsh" && if [ -d "/var/services/homes/${CurrentUsername}/.oh-my-zsh/custom/plugins" ]; then
            for plugin_list_task in "${!plugin_list[@]}"; do
                rm -rf "/var/services/homes/${CurrentUsername}/.oh-my-zsh/custom/plugins/${plugin_list[$plugin_list_task]}" && git clone --depth=1 "${GHPROXY_URL}https://github.com/zsh-users/${plugin_list[$plugin_list_task]}.git" "/var/services/homes/${CurrentUsername}/.oh-my-zsh/custom/plugins/${plugin_list[$plugin_list_task]}"
            done
        fi && rm -rf "/var/services/homes/${CurrentUsername}/.oh-my-zsh/oh-my-zsh-plugin.sh" && for plugin_upgrade_list_task in "${!plugin_upgrade_list[@]}"; do
            echo "${plugin_upgrade_list[$plugin_upgrade_list_task]}" >> "/var/services/homes/${CurrentUsername}/.oh-my-zsh/oh-my-zsh-plugin.sh"
        done
    }
    InstallOhMyZsh
}

## Process
# Call GetSystemInformation
GetSystemInformation
# Call InstallCustomPackages
InstallCustomPackages
# Call ConfigureSystem
ConfigureSystem
# Call ConfigurePackages
ConfigurePackages
