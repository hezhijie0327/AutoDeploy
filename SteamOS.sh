#!/bin/bash

# Current Version: 1.2.1

## How to get and use?
# curl "https://source.zhijie.online/AutoDeploy/main/SteamOS.sh" | sudo bash
# wget -qO- "https://source.zhijie.online/AutoDeploy/main/SteamOS.sh" | sudo bash

## Function
function GetSystemInformation() {
    function CheckSteamDeckUser() {
        if [[ $(passwd -S "deck" | awk -F " " '{print $2}') != "P" ]]; then
            echo "deck's password has not been set. Please run <passwd> first!"
            exit 1
        fi
    }
    function GetCurrentHostname() {
        export CURRENT_HOSTNAME=$(cat "/etc/hostname")
    }
    function SetFlathubMirror() {
        flatpak remote-modify flathub --url="https://mirror.sjtu.edu.cn/flathub"
        wget -P "/tmp" "https://mirror.sjtu.edu.cn/flathub/flathub.gpg" && flatpak remote-modify --gpg-import="/tmp/flathub.gpg" flathub && rm -rf "/tmp/flathub.gpg"
    }
    function SetGHProxyDomain() {
        export GHPROXY_URL="ghproxy.com"
    }
    CheckSteamDeckUser
    GetCurrentHostname
    SetFlathubMirror
    SetGHProxyDomain
}
function ConfigureSystem() {
    function ConfigureDefaultShell() {
        if [ -f "/etc/passwd" ]; then
            echo "$(cat '/etc/passwd' | sed 's/\/bin\/bash/\/bin\/zsh/g;s/\/bin\/sh/\/bin\/zsh/g')" > "/tmp/shell.autodeploy"
            cat "/tmp/shell.autodeploy" > "/etc/passwd" && rm -rf "/tmp/shell.autodeploy"
        fi
    }
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
        done && cat "/tmp/hosts.autodeploy" > "/etc/hosts" && rm -rf "/tmp/hosts.autodeploy"
    }
    function ConfigureRootUser() {
        LOCK_ROOT="TRUE"
        ROOT_PASSWORD='R00t@123!'
        echo root:$ROOT_PASSWORD | chpasswd && if [ "${LOCK_ROOT}" == "TRUE" ]; then
            passwd -l "root"
        else
            passwd -u "root"
        fi
    }
    function ConfigureSWAP() {
        swapoff -a && dd if=/dev/zero of="/home/swapfile" bs=1G count=$(( $(dmesg | grep "memory" | grep "VRAM" | cut -d ':' -f 2 | cut -d ' ' -f 2 | tr -d 'a-zA-Z') * 2 / 1024 )) && chmod 0600 "/home/swapfile" && mkswap "/home/swapfile" && swapon "/home/swapfile"
    }
    ConfigureDefaultShell
    ConfigureHostfile
    ConfigureRootUser
    ConfigureSWAP
}
function ConfigurePackages() {
    function ConfigureGit() {
        gitconfig_key_list=(
            "commit.gpgsign"
            "gpg.program"
            "http.proxy"
            "https.proxy"
            "user.name"
            "user.email"
            "user.signingkey"
            "url.https://${GHPROXY_URL}/https://github.com/.insteadOf"
        )
        gitconfig_value_list=(
            "${GIT_COMMIT_GPGSIGN:-false}"
            "${GIT_GPG_PROGRAM:-gpg}"
            "${GIT_HTTP_PROXY}"
            "${GIT_HTTPS_PROXY}"
            "${GIT_USER_NAME}"
            "${GIT_USER_EMAIL}"
            "${GIT_USER_SIGNINGKEY}"
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
        if [ -f "/root/.gitconfig" ] && [ "${GIT_USER_CONFIG}" != "TRUE" ]; then
            mv "/root/.gitconfig" "/root/.gitconfig.bak" && GIT_COMMIT_GPGSIGN="" && GIT_GPG_PROGRAM="" && GIT_HTTP_PROXY="" && GIT_HTTPS_PROXY="" && GIT_USER_NAME="" && GIT_USER_EMAIL="" && GIT_USER_SIGNINGKEY="" && GIT_USER_CONFIG="TRUE" && ConfigureGit && mv "/root/.gitconfig" "/home/deck/.gitconfig" && chown -R deck:deck "/home/deck/.gitconfig" && mv "/root/.gitconfig.bak" "/root/.gitconfig"
        fi
    }
    function ConfigureGPG() {
        GPG_PUBKEY=""
        if [ "${GPG_PUBKEY}" == "" ]; then
            GPG_PUBKEY="DD982DAAB9C71C78F9563E5207EB56787030D792"
        fi
        which "gpg" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/home/deck/.gnupg" "/root/.gnupg" && gpg --keyserver hkps://keyserver.ubuntu.com:443 --recv ${GPG_PUBKEY} && echo "${GPG_PUBKEY}" | awk 'BEGIN { FS = "\n" }; { print $1":6:" }' | gpg --import-ownertrust && GPG_PUBKEY_ID_A=$(gpg --list-keys --keyid-format LONG | grep "pub\|sub" | awk '{print $2, $4}' | grep "\[A\]" | awk '{print $1}' | awk -F '/' '{print $2}') && GPG_PUBKEY_ID_C=$(gpg --list-keys --keyid-format LONG | grep "pub\|sub" | awk '{print $2, $4}' | grep "\[C\]" | awk '{print $1}' | awk -F '/' '{print $2}')
            if [ "${GPG_PUBKEY_ID_A}" != "" ]; then
                rm -rf "/root/.gnupg/gpg-agent.conf" && echo -e "enable-ssh-support\npinentry-program /usr/bin/pinentry-curses" > "/root/.gnupg/gpg-agent.conf" && echo "${GPG_PUBKEY_ID_A}" > "/root/.gnupg/sshcontrol" && gpg --export-ssh-key ${GPG_PUBKEY_ID_C} > "/root/.gnupg/authorized_keys" && if [ -d "/root/.gnupg" ]; then
                    mv "/root/.gnupg" "/home/deck/.gnupg" && chown -R deck:deck "/home/deck/.gnupg"
                fi
            fi
        fi
    }
    function ConfigureIOMMU() {
        ENABLE_IOMMU="true"
        if [ "${ENABLE_IOMMU}" == "true" ]; then
            sed -i 's/amd_iommu=off/amd_iommu=on iommu=pt/' '/etc/default/grub'
        else
            sed -i 's/amd_iommu=on iommu=pt/amd_iommu=off/' '/etc/default/grub'
        fi && update-grub
    }
    function ConfigureOpenSSH() {
        OPENSSH_PASSWORD=""
        which "ssh-keygen" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            if [ -d "/etc/ssh" ]; then
                rm -rf /etc/ssh/ssh_host_* && ssh-keygen -t dsa -b 1024 -f "/etc/ssh/ssh_host_dsa_key" -C "root@${CURRENT_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ecdsa -b 384 -f "/etc/ssh/ssh_host_ecdsa_key" -C "root@${CURRENT_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ed25519 -f "/etc/ssh/ssh_host_ed25519_key" -C "root@${CURRENT_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t rsa -b 4096 -f "/etc/ssh/ssh_host_rsa_key" -C "root@${CURRENT_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && chmod 400 /etc/ssh/ssh_host_* && chmod 644 /etc/ssh/ssh_host_*.pub
            fi
            rm -rf "/root/.ssh" && mkdir "/root/.ssh" && touch "/root/.ssh/authorized_keys" && touch "/root/.ssh/known_hosts" && ssh-keygen -t dsa -b 1024 -f "/root/.ssh/id_dsa" -C "root@${CURRENT_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ecdsa -b 384 -f "/root/.ssh/id_ecdsa" -C "root@${CURRENT_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ed25519 -f "/root/.ssh/id_ed25519" -C "root@${CURRENT_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t rsa -b 4096 -f "/root/.ssh/id_rsa" -C "root@${CURRENT_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && chmod 400 /root/.ssh/id_* && chmod 600 "/root/.ssh/authorized_keys" && chmod 644 "/root/.ssh/known_hosts" && chmod 644 /root/.ssh/id_*.pub && chmod 700 "/root/.ssh"
            rm -rf "/home/deck/.ssh" && mkdir "/home/deck/.ssh" && if [ -f "/home/deck/.gnupg/authorized_keys" ]; then
                mv "/home/deck/.gnupg/authorized_keys" "/home/deck/.ssh/authorized_keys"
            else
                touch "/home/deck/.ssh/authorized_keys"
            fi && touch "/home/deck/.ssh/known_hosts" && ssh-keygen -t dsa -b 1024 -f "/home/deck/.ssh/id_dsa" -C "deck@${CURRENT_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ecdsa -b 384 -f "/home/deck/.ssh/id_ecdsa" -C "deck@${CURRENT_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ed25519 -f "/home/deck/.ssh/id_ed25519" -C "deck@${CURRENT_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t rsa -b 4096 -f "/home/deck/.ssh/id_rsa" -C "deck@${CURRENT_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && chown -R deck:deck "/home/deck/.ssh" && chown -R deck:deck /home/deck/.ssh/* && chmod 400 /home/deck/.ssh/id_* && chmod 600 "/home/deck/.ssh/authorized_keys" && chmod 644 "/home/deck/.ssh/known_hosts" && chmod 644 /home/deck/.ssh/id_*.pub && chmod 700 "/home/deck/.ssh" && systemctl enable sshd
        fi
    }
    function ConfigureSshd() {
        cat "/etc/ssh/sshd_config" | sed "s/\#PasswordAuthentication\ yes/PasswordAuthentication\ yes/g;s/\#PermitRootLogin\ prohibit\-password/PermitRootLogin\ yes/g;s/\#PubkeyAuthentication\ yes/PubkeyAuthentication\ yes/g" > "/tmp/sshd_config.autodeploy" && cat "/tmp/sshd_config.autodeploy" > "/etc/ssh/sshd_config" && rm -rf "/tmp/sshd_config.autodeploy"
    }
    function ConfigureSysctl() {
        which "sysctl" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            if [ ! -d "/etc/sysctl.d" ]; then
                mkdir "/etc/sysctl.d"
            fi
            echo -e "net.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr" > "/etc/sysctl.d/bbr.conf"
            echo -e "net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1" > "/etc/sysctl.d/ip_forward.conf"
            echo -e "net.ipv4.tcp_fastopen = 3" > "/etc/sysctl.d/tcp_fastopen.conf"
            echo -e "vm.swappiness = 10" > "/etc/sysctl.d/swappiness.conf"
        fi
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
                "/usr/bin/site_perl:/usr/bin/vendor_perl:/usr/bin/core_perl"
            )
            DEFAULT_PATH="" && for default_path_list_task in "${!default_path_list[@]}"; do
                if [ "${default_path_list[$default_path_list_task]}" != "" ]; then
                    DEFAULT_PATH="${default_path_list[$default_path_list_task]}:${DEFAULT_PATH}"
                    DEFAULT_PATH=$(echo "${DEFAULT_PATH}" | sed "s/\:$//g")
                fi
            done
        }
        function GenerateOMZProfile() {
            omz_list=(
                "export DEBIAN_FRONTEND=\"noninteractive\""
                "export EDITOR=\"nano\""
                "export GPG_TTY=\$(tty)"
                "export PATH=\"${DEFAULT_PATH}:\$PATH\""
                "# export SSH_AUTH_SOCK=\"\$(gpgconf --list-dirs agent-ssh-socket)\" && gpgconf --launch gpg-agent && gpg-connect-agent updatestartuptty /bye > \"/dev/null\" 2>&1"
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
                "source \"\$ZSH/oh-my-zsh.sh\""
            )
            which "zsh" > "/dev/null" 2>&1
            if [ "$?" -eq "0" ] && [ -d "/etc/zsh/oh-my-zsh" ]; then
                rm -rf "/tmp/omz.autodeploy" && for omz_list_task in "${!omz_list[@]}"; do
                    echo "${omz_list[$omz_list_task]}" >> "/tmp/omz.autodeploy"
                done && cat "/tmp/omz.autodeploy" > "/etc/zsh/oh-my-zsh.zshrc" && rm -rf "/tmp/omz.autodeploy" && rm -rf "/root/.oh-my-zsh" "/root/.zshrc" && ln -s "/etc/zsh/oh-my-zsh" "/root/.oh-my-zsh" && ln -s "/etc/zsh/oh-my-zsh.zshrc" "/root/.zshrc"
            fi
            if [ -d "/etc/zsh/oh-my-zsh" ]; then
                cp -rf "/etc/zsh/oh-my-zsh" "/home/deck/.oh-my-zsh" && chown -R deck:deck "/home/deck/.oh-my-zsh"
                if [ -f "/etc/zsh/oh-my-zsh.zshrc" ]; then
                    cp -rf "/etc/zsh/oh-my-zsh.zshrc" "/home/deck/.zshrc" && chown -R deck:deck "/home/deck/.zshrc"
                fi
            fi
        }
        GenerateCommandPath
        GenerateOMZProfile
    }
    ConfigureGPG && ConfigureGit
    ConfigureIOMMU
    ConfigureOpenSSH
    ConfigureSshd
    ConfigureSysctl
    ConfigureZsh
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
            "    rm -rf \"\$HOME/.oh-my-zsh/custom/plugins/\${plugin_list[\$plugin_list_task]}\" && git clone --depth=1 \"https://${GHPROXY_URL}/https://github.com/zsh-users/\${plugin_list[\$plugin_list_task]}.git\" \"\$HOME/.oh-my-zsh/custom/plugins/\${plugin_list[\$plugin_list_task]}\""
            'done'
        )
        rm -rf "/etc/zsh/oh-my-zsh" && git clone --depth=1 "https://${GHPROXY_URL}/https://github.com/ohmyzsh/ohmyzsh.git" "/etc/zsh/oh-my-zsh" && if [ -d "/etc/zsh/oh-my-zsh/custom/plugins" ]; then
            for plugin_list_task in "${!plugin_list[@]}"; do
                rm -rf "/etc/zsh/oh-my-zsh/custom/plugins/${plugin_list[$plugin_list_task]}" && git clone --depth=1 "https://${GHPROXY_URL}/https://github.com/zsh-users/${plugin_list[$plugin_list_task]}.git" "/etc/zsh/oh-my-zsh/custom/plugins/${plugin_list[$plugin_list_task]}"
            done
        fi && rm -rf "/etc/zsh/oh-my-zsh/oh-my-zsh-plugin.sh" && for plugin_upgrade_list_task in "${!plugin_upgrade_list[@]}"; do
            echo "${plugin_upgrade_list[$plugin_upgrade_list_task]}" >> "/tmp/oh-my-zsh-plugin.autodeploy"
        done && cat "/tmp/oh-my-zsh-plugin.autodeploy" > "/etc/zsh/oh-my-zsh/oh-my-zsh-plugin.sh" && rm -rf "/tmp/oh-my-zsh-plugin.autodeploy"
    }
    function InstallProtonGE() {
        flatpak install -y com.valvesoftware.Steam.CompatibilityTool.Proton-GE
        if [ ! -d "/home/deck/.steam/root/compatibilitytools.d" ]; then
            mkdir "/home/deck/.steam/root/compatibilitytools.d"
        fi
        if [ -d "/home/deck/.steam/root/compatibilitytools.d/Proton-GE" ]; then
            rm -rf "/home/deck/.steam/root/compatibilitytools.d/Proton-GE"
        fi
        if [ -d "/var/lib/flatpak/runtime/com.valvesoftware.Steam.CompatibilityTool.Proton-GE/x86_64/stable/active/files" ]; then
            cp -rf "/var/lib/flatpak/runtime/com.valvesoftware.Steam.CompatibilityTool.Proton-GE/x86_64/stable/active/files" "/home/deck/.steam/root/compatibilitytools.d/Proton-GE"
        fi
        echo '#!/bin/bash\nif [ -d "/var/lib/flatpak/runtime/com.valvesoftware.Steam.CompatibilityTool.Proton-GE/x86_64/stable/active/files" ]; then sudo flatpak install -y com.valvesoftware.Steam.CompatibilityTool.Proton-GE && sudo cp -rf "/var/lib/flatpak/runtime/com.valvesoftware.Steam.CompatibilityTool.Proton-GE/x86_64/stable/active/files" "/home/deck/.steam/root/compatibilitytools.d/Proton-GE" && sudo chown -R deck:deck "/home/deck/.steam/root/compatibilitytools.d" && sudo flatpak uninstall -y com.valvesoftware.Steam.CompatibilityTool.Proton-GE; fi' > "/home/deck/.steam/root/compatibilitytools.d/Proton-GE.sh" && chown -R deck:deck "/home/deck/.steam/root/compatibilitytools.d"
        flatpak uninstall -y com.valvesoftware.Steam.CompatibilityTool.Proton-GE
    }
    InstallOhMyZsh
    InstallProtonGE
}

## Process
# Call GetSystemInformation
GetSystemInformation
# Disable Steam OS Protection
steamos-readonly disable
# Call InstallCustomPackages
InstallCustomPackages
# Call ConfigureSystem
ConfigureSystem
# Call ConfigurePackages
ConfigurePackages
# Enable Steam OS Protection
steamos-readonly enable
