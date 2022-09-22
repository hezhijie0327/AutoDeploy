#!/bin/bash

# Current Version: 1.0.7

## How to get and use?
# curl "https://source.zhijie.online/AutoDeploy/main/OpenWrt.sh" | sudo bash
# wget -qO- "https://source.zhijie.online/AutoDeploy/main/OpenWrt.sh" | sudo bash

## How to install OpenWrt on Ubuntu?
# dd if=openwrt-*-x86-64-combined-ext4.img of=/dev/sda bs=4M; sync;
# parted /dev/sda print
# parted /dev/sda resizepart 2 <MAX SIZE>G
# resize2fs /dev/sda2

## Function
# Get System Information
function GetSystemInformation() {
    function DetectBASH() {
        if which "bash" > "/dev/null" 2>&1; then
            echo "BASH has been installed!"
        else
            SetRepositoryMirror && opkg update && opkg install bash
            if which "bash" > "/dev/null" 2>&1; then
                echo "BASH is installed. Please run script with BASH."
                bash
                exit 1
            else
                echo "BASH is not installed."
                exit 1
            fi
        fi
    }
    function GenerateHostname() {
        NEW_HOSTNAME="OpenWrt-$(date '+%Y%m%d%H%M%S')"
    }
    function GetCPUVendorID() {
        CPU_VENDOR_ID=$(cat '/proc/cpuinfo' | grep 'vendor_id' | uniq | awk -F ':' '{print $2}' | awk -F ' ' '{print $1}')
        if [ "${CPU_VENDOR_ID}" == "AuthenticAMD" ]; then
            MICROCODE=("amd64-microcode")
        elif [ "${CPU_VENDOR_ID}" == "GenuineIntel" ]; then
            MICROCODE=("intel-microcode")
        else
            MICROCODE=()
        fi
    }
    function SetGHProxyDomain() {
        export GHPROXY_URL="ghproxy.com"
    }
    DetectBASH
    GenerateHostname
    GetCPUVendorID
    SetGHProxyDomain
}
# Configure Packages
function ConfigurePackages() {
    function ConfigureChrony() {
        chrony_list=(
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
        chrony_ntp_list=(
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
            "${DHCP_NTP[@]}"
        )
        which "chronyc" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/tmp/chrony.autodeploy" && for chrony_list_task in "${!chrony_list[@]}"; do
                echo "${chrony_list[$chrony_list_task]}" >> "/tmp/chrony.autodeploy"
            done && for chrony_ntp_list_task in "${!chrony_ntp_list[@]}"; do
                if [ "${chrony_ntp_list[$chrony_ntp_list_task]}" == "ntp.ntsc.ac.cn" ] || [ "${chrony_ntp_list[$chrony_ntp_list_task]}" == "ntp1.nim.ac.cn" ] || [ "${chrony_ntp_list[$chrony_ntp_list_task]}" == "ntp2.nim.ac.cn" ] || [ "$(echo ${DHCP_NTP[@]} | grep ${chrony_ntp_list[$chrony_ntp_list_task]})" != "" ]; then
                    echo "server ${chrony_ntp_list[$chrony_ntp_list_task]} iburst prefer" >> "/tmp/chrony.autodeploy"
                else
                    echo "server ${chrony_ntp_list[$chrony_ntp_list_task]} iburst" >> "/tmp/chrony.autodeploy"
                fi
            done && cat "/tmp/chrony.autodeploy" > "/etc/chrony/chrony.conf" && rm -rf "/tmp/chrony.autodeploy" && "/etc/init.d/chronyd" restart && sleep 5s && chronyc activity && chronyc tracking && chronyc clients && hwclock -w
        fi
    }
    function ConfigureCrontab() {
        crontab_list=(
            "0 0 * * 7 opkg update && opkg list-upgradable | cut -f 1 -d ' ' | xargs opkg upgrade > "/dev/null" 2>&1"
            "@reboot sudo rm -rf /root/.*_history /root/.ssh/known_hosts*"
        )
        which "crontab" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/tmp/crontab.autodeploy" && for crontab_list_task in "${!crontab_list[@]}"; do
                echo "${crontab_list[$crontab_list_task]}" >> "/tmp/crontab.autodeploy"
            done && crontab -u "root" "/tmp/crontab.autodeploy" && crontab -lu "root" && rm -rf "/tmp/crontab.autodeploy"
        fi
    }
    function ConfigureCrowdSec() {
        crowdsec_hub_list=(
            "crowdsecurity/iptables"
            "crowdsecurity/linux-lpe"
            "crowdsecurity/linux"
        )
        which "cscli" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            for crowdsec_hub_list_task in "${!crowdsec_hub_list[@]}"; do
                cscli collections install ${crowdsec_hub_list[$crowdsec_hub_list_task]}
            done
        fi && "/etc/init.d/crowdsec" restart && cscli hub list
    }
    function ConfigureFail2Ban() {
        fail2ban_list=(
            "[sshd]"
            "bantime = 604800"
            "enabled = true"
            "filter = sshd"
            "findtime = 60"
            "logpath = /var/log/auth.log"
            "maxretry = 5"
            "port = 22"
        )
        which "fail2ban-client" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            if [ -d "/etc/fail2ban/jail.d" ]; then
                rm -rf /etc/fail2ban/jail.d/*
            else
                mkdir "/etc/fail2ban/jail.d"
            fi
            if [ -f "/etc/fail2ban/fail2ban.conf" ]; then
                cat "/etc/fail2ban/fail2ban.conf" > "/etc/fail2ban/fail2ban.local"
            fi
            if [ -f "/etc/fail2ban/jail.conf" ]; then
                cat "/etc/fail2ban/jail.conf" > "/etc/fail2ban/jail.local"
            fi
            rm -rf "/tmp/fail2ban.autodeploy" && for fail2ban_list_task in "${!fail2ban_list[@]}"; do
                echo "${fail2ban_list[$fail2ban_list_task]}" >> "/tmp/fail2ban.autodeploy"
            done && cat "/tmp/fail2ban.autodeploy" > "/etc/fail2ban/jail.d/fail2ban_default.conf" && rm -rf "/tmp/fail2ban.autodeploy" && fail2ban-client reload && sleep 5s && fail2ban-client status
        fi
    }
    function ConfigureGit() {
        gitconfig_key_list=(
            "http.proxy"
            "https.proxy"
            "user.name"
            "user.email"
            "user.signingkey"
            "url.https://${GHPROXY_URL}/https://github.com/.insteadOf"
        )
        gitconfig_value_list=(
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
    }
    function ConfigureOpenSSH() {
        OPENSSH_PASSWORD=""
        which "ssh-keygen" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            if [ -d "/etc/ssh" ]; then
                rm -rf /etc/ssh/ssh_host_* && ssh-keygen -t dsa -b 1024 -f "/etc/ssh/ssh_host_dsa_key" -C "root@${NEW_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ecdsa -b 384 -f "/etc/ssh/ssh_host_ecdsa_key" -C "root@${NEW_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ed25519 -f "/etc/ssh/ssh_host_ed25519_key" -C "root@${NEW_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t rsa -b 4096 -f "/etc/ssh/ssh_host_rsa_key" -C "root@${NEW_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && chmod 400 /etc/ssh/ssh_host_* && chmod 644 /etc/ssh/ssh_host_*.pub
            fi
            rm -rf "/root/.ssh" && mkdir "/root/.ssh" && touch "/root/.ssh/authorized_keys" && touch "/root/.ssh/known_hosts" && ssh-keygen -t dsa -b 1024 -f "/root/.ssh/id_dsa" -C "root@${NEW_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ecdsa -b 384 -f "/root/.ssh/id_ecdsa" -C "root@${NEW_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ed25519 -f "/root/.ssh/id_ed25519" -C "root@${NEW_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t rsa -b 4096 -f "/root/.ssh/id_rsa" -C "root@${NEW_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && chmod 400 /root/.ssh/id_* && chmod 600 "/root/.ssh/authorized_keys" && chmod 644 "/root/.ssh/known_hosts" && chmod 644 /root/.ssh/id_*.pub && chmod 700 "/root/.ssh"
        fi
    }
    function ConfigureSshd() {
        if [ -f "/etc/ssh/sshd_config" ]; then
            if [ ! -f "/etc/ssh/sshd_config.bak" ]; then
                cp -rf "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
            fi
            cat "/etc/ssh/sshd_config.bak" | sed "s/\#PasswordAuthentication\ yes/PasswordAuthentication\ yes/g;s/\#PermitRootLogin\ prohibit\-password/PermitRootLogin\ yes/g;s/\#PubkeyAuthentication\ yes/PubkeyAuthentication\ yes/g" > "/tmp/sshd_config.autodeploy" && cat "/tmp/sshd_config.autodeploy" > "/etc/ssh/sshd_config" && rm -rf "/tmp/sshd_config.autodeploy"
        fi
    }
    function ConfigureSysctl() {
        sysctl_list=(
            "net.core.default_qdisc = fq"
            "net.ipv4.ip_forward = 1"
            "net.ipv4.tcp_congestion_control = bbr"
            "net.ipv4.tcp_fastopen = 3"
            "net.ipv6.conf.all.forwarding = 1"
        )
        which "sysctl" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/tmp/sysctl.autodeploy" && for sysctl_list_task in "${!sysctl_list[@]}"; do
                sysctl -w "$(echo ${sysctl_list[$sysctl_list_task]} | sed 's/\ //g')" > "/dev/null" 2>&1
                if [ "$?" -eq "0" ]; then
                    echo "${sysctl_list[$sysctl_list_task]}" >> "/tmp/sysctl.autodeploy"
                fi
            done && cat "/tmp/sysctl.autodeploy" > "/etc/sysctl.conf" && sysctl -p && rm -rf "/tmp/sysctl.autodeploy"
        fi
    }
    function ConfigureZsh() {
        function GenerateCommandPath() {
            default_path_list=(
                "/bin"
                "/sbin"
                "/usr/bin"
                "/usr/sbin"
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
                "export PATH=\"${DEFAULT_PATH}:\$PATH\""
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
            if [ "$?" -eq "0" ] && [ -d "/etc/zsh/oh-my-zsh" ]; then
                rm -rf "/tmp/omz.autodeploy" && for omz_list_task in "${!omz_list[@]}"; do
                    echo "${omz_list[$omz_list_task]}" >> "/tmp/omz.autodeploy"
                done && cat "/tmp/omz.autodeploy" > "/etc/zsh/oh-my-zsh.zshrc" && rm -rf "/tmp/omz.autodeploy" && rm -rf "/root/.oh-my-zsh" "/root/.zshrc" && ln -s "/etc/zsh/oh-my-zsh" "/root/.oh-my-zsh" && ln -s "/etc/zsh/oh-my-zsh.zshrc" "/root/.zshrc"
            fi
        }
        GenerateCommandPath
        GenerateOMZProfile
    }
    ConfigureChrony
    ConfigureCrontab
    ConfigureCrowdSec
    ConfigureFail2Ban
    ConfigureGit
    ConfigureOpenSSH
    ConfigureSshd
    ConfigureSysctl
    ConfigureZsh
}
# Configure System
function ConfigureSystem() {
    function ConfigureDefaultShell() {
        if [ -f "/etc/passwd" ]; then
            echo "$(cat '/etc/passwd' | sed 's/\/bin\/ash/\/usr\/bin\/zsh/g')" > "/tmp/shell.autodeploy"
            cat "/tmp/shell.autodeploy" > "/etc/passwd" && rm -rf "/tmp/shell.autodeploy"
        fi
    }
    function ConfigureHostfile() {
        host_list=(
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
        rm -rf "/tmp/hosts.autodeploy" && for host_list_task in "${!host_list[@]}"; do
            echo "${host_list[$host_list_task]}" >> "/tmp/hosts.autodeploy"
        done && cat "/tmp/hosts.autodeploy" > "/etc/hosts" && rm -rf "/tmp/hosts.autodeploy" && echo "${NEW_HOSTNAME}" > "/tmp/hostname.autodeploy" && cat "/tmp/hostname.autodeploy" > "/etc/hostname" && rm -rf "/tmp/hostname.autodeploy"
    }
    function ConfigureRootUser() {
        ROOT_PASSWORD='R00t@123!'
        echo root:$ROOT_PASSWORD | chpasswd
    }
    ConfigureDefaultShell
    ConfigureHostfile
    ConfigureRootUser
}
# Set Repository Mirror
function SetRepositoryMirror() {
    sed -i 's/downloads.openwrt.org/mirrors.ustc.edu.cn\/openwrt/g' "/etc/opkg/distfeeds.conf"
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
            echo "${plugin_upgrade_list[$plugin_upgrade_list_task]}" >> "/etc/zsh/oh-my-zsh/oh-my-zsh-plugin.sh"
        done
    }
    InstallOhMyZsh
}
# Install Dependency Packages
function InstallDependencyPackages() {
    app_regular_list=(
        "bind-dig"
        "ca-certificates"
        "chrony"
        "coreutils"
        "coreutils-b2sum"
        "coreutils-base32"
        "coreutils-base64"
        "coreutils-basename"
        "coreutils-basenc"
        "coreutils-cat"
        "coreutils-chcon"
        "coreutils-chgrp"
        "coreutils-chmod"
        "coreutils-chown"
        "coreutils-chroot"
        "coreutils-cksum"
        "coreutils-comm"
        "coreutils-cp"
        "coreutils-csplit"
        "coreutils-cut"
        "coreutils-date"
        "coreutils-dd"
        "coreutils-df"
        "coreutils-dir"
        "coreutils-dircolors"
        "coreutils-dirname"
        "coreutils-du"
        "coreutils-echo"
        "coreutils-env"
        "coreutils-expand"
        "coreutils-expr"
        "coreutils-factor"
        "coreutils-false"
        "coreutils-fmt"
        "coreutils-fold"
        "coreutils-groups"
        "coreutils-head"
        "coreutils-hostid"
        "coreutils-id"
        "coreutils-install"
        "coreutils-join"
        "coreutils-kill"
        "coreutils-link"
        "coreutils-ln"
        "coreutils-logname"
        "coreutils-ls"
        "coreutils-md5sum"
        "coreutils-mkdir"
        "coreutils-mkfifo"
        "coreutils-mknod"
        "coreutils-mktemp"
        "coreutils-mv"
        "coreutils-nice"
        "coreutils-nl"
        "coreutils-nohup"
        "coreutils-nproc"
        "coreutils-numfmt"
        "coreutils-od"
        "coreutils-paste"
        "coreutils-pathchk"
        "coreutils-pinky"
        "coreutils-pr"
        "coreutils-printenv"
        "coreutils-printf"
        "coreutils-ptx"
        "coreutils-pwd"
        "coreutils-readlink"
        "coreutils-realpath"
        "coreutils-rm"
        "coreutils-rmdir"
        "coreutils-runcon"
        "coreutils-seq"
        "coreutils-sha1sum"
        "coreutils-sha224sum"
        "coreutils-sha256sum"
        "coreutils-sha384sum"
        "coreutils-sha512sum"
        "coreutils-shred"
        "coreutils-shuf"
        "coreutils-sleep"
        "coreutils-sort"
        "coreutils-split"
        "coreutils-stat"
        "coreutils-stdbuf"
        "coreutils-stty"
        "coreutils-sum"
        "coreutils-sync"
        "coreutils-tac"
        "coreutils-tail"
        "coreutils-tee"
        "coreutils-test"
        "coreutils-timeout"
        "coreutils-touch"
        "coreutils-tr"
        "coreutils-true"
        "coreutils-truncate"
        "coreutils-tsort"
        "coreutils-tty"
        "coreutils-uname"
        "coreutils-unexpand"
        "coreutils-uniq"
        "coreutils-unlink"
        "coreutils-uptime"
        "coreutils-users"
        "coreutils-vdir"
        "coreutils-wc"
        "coreutils-who"
        "coreutils-whoami"
        "coreutils-yes"
        "crowdsec"
        "curl"
        "ddns-scripts"
        "ddns-scripts-cloudflare"
        "dnsmasq-full"
        "docker"
        "docker-compose"
        "dockerd"
        "etherwake"
        "ethtool"
        "fail2ban"
        "fail2ban-src"
        "fdisk"
        "git"
        "git-http"
        "git-lfs"
        "gawk"
        "grep"
        "iperf3"
        "jq"
        "kmod-tcp-bbr"
        "knot-dig"
        "lua-cs-bouncer"
        "luci"
        "luci-ssl-openssl"
        "mtr-json"
        "nano"
        "nmap"
        "ntfs-3g"
        "openssh-client"
        "openssh-server"
        "parted"
        "python3"
        "python3-pip"
        "qrencode"
        "resize2fs"
        "tcpdump"
        "vim"
        "wget"
        "whois"
        "wireguard-tools"
        "zsh"
    )
    app_luci_list=(
        "luci-app-ddns"
        "luci-app-dockerman"
        "luci-app-firewall"
        "luci-app-nft-qos"
        "luci-app-upnp"
        "luci-app-wireguard"
        "luci-app-wol"
    )
    app_luci_lang_list=(
        "luci-i18n-base-zh-cn"
        "luci-i18n-ddns-zh-cn"
        "luci-i18n-dockerman-zh-cn"
        "luci-i18n-firewall-zh-cn"
        "luci-i18n-nft-qos-zh-cn"
        "luci-i18n-upnp-zh-cn"
        "luci-i18n-wireguard-zh-cn"
        "luci-i18n-wol-zh-cn"
    )
    app_list=(${app_regular_list[@]} ${app_luci_list[*]} ${app_luci_lang_list[*]} ${MICROCODE[*]})
    opkg update && for app_list_task in "${!app_list[@]}"; do
        opkg install --force-overwrite ${app_list[$app_list_task]}
    done
}
# Upgrade Packages
function UpgradePackages() {
    opkg update && opkg list-upgradable | cut -f 1 -d ' ' | xargs opkg upgrade > "/dev/null" 2>&1
}
# Cleanup Temp Files
function CleanupTempFiles() {
    cleanup_list=(
        "dnsmasq"
        "dropbear"
    )
    opkg_config=($(find "/etc/config" -name "*-opkg" -print | awk "{print $2}"))
    for cleanup_list_task in "${!cleanup_list[@]}"; do
        opkg remove --force-remove "${cleanup_list[$cleanup_list_task]}" > "/dev/null" 2>&1
        FILE_LIST=($(find "/" \( -path "/dev" -o -path "/home" -o -path "/mnt" -o -path "/proc" -o -path "/root" -o -path "/sys" \) -prune -o -name "${cleanup_list[$cleanup_list_task]}" -print | awk "{print $2}"))
        for FILE_LIST_TASK in "${!FILE_LIST[@]}"; do
            rm -rf "${FILE_LIST[$FILE_LIST_TASK]}"
        done
    done
    for opkg_config_task in "${!opkg_config[@]}"; do
        mv ${opkg_config[$opkg_config_task]} ${opkg_config[$opkg_config_task]%-opkg}
    done
    rm -rf /root/.*_history /tmp/*.autodeploy
}

## Process
# Call GetSystemInformation
GetSystemInformation
# Call SetRepositoryMirror
SetRepositoryMirror
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
