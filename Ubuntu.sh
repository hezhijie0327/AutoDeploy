#!/bin/bash

# Current Version: 1.8.9

## How to get and use?
# curl "https://source.zhijie.online/AutoDeploy/main/Ubuntu.sh" | sudo bash
# wget -qO- "https://source.zhijie.online/AutoDeploy/main/Ubuntu.sh" | sudo bash

## Function
# Call Service Controller
function CallServiceController(){
    if [ "${OPRATIONS}" == "" ]; then
        echo "An error occurred during processing. Missing (OPRATIONS) value, please check it and try again."
        exit 1
    fi
    if [ "${SERVICE_NAME}" == "" ]; then
        echo "An error occurred during processing. Missing (SERVICE_NAME) value, please check it and try again."
        exit 1
    fi
    if [ "${wsl_kernel}" == "TRUE" ]; then
        serivce ${SERVICE_NAME} ${OPRATIONS}
    elif [ "${wsl_kernel}" == "FALSE" ]; then
        systemctl ${OPRATIONS} ${SERVICE_NAME}
    else
        echo "Unsupported service controller."
        exit 1
    fi
}
# Get System Information
function GetSystemInformation() {
    function GenerateHostname() {
        NEW_HOSTNAME="Ubuntu-$(date '+%Y%m%d%H%M%S')"
    }
    function GetLSBCodename() {
        LSBCodename_LTS="focal"
        LSBCodename_NON_LTS="hirsute"
        Version_LTS="20.04"
        Version_NON_LTS="21.04"
        which "lsb_release" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            if [ "$(lsb_release -ds | grep 'LTS')" == "" ]; then
                LSBCodename="${LSBCodename_NON_LTS}"
            else
                LSBCodename="${LSBCodename_LTS}"
            fi
        else
            if [ -f '/etc/issue' ]; then
                if [ "$(cat '/etc/issue' | grep 'LTS')" == "" ]; then
                    LSBCodename="${LSBCodename_NON_LTS}"
                else
                    LSBCodename="${LSBCodename_LTS}"
                fi
            else
                LSBCodename="${LSBCodename_LTS}"
            fi
        fi
    }
    function IsArmArchitecture() {
        if [ "$(uname -m)" == "aarch64" ]; then
            mirror_arch="arm64"
            mirror_path="ubuntu-ports"
        elif [ "$(uname -m)" == "x86_64" ]; then
            mirror_arch="amd64"
            mirror_path="ubuntu"
        else
            echo "Unsupported architecture."
            exit 1
        fi
    }
    function IsWSLKernelRelease() {
        if [ "$(uname -r | grep 'WSL')" == "" ]; then
            wsl_kernel="FALSE"
        else
            wsl_kernel="TRUE"
            function Create_Startup_Script() {
                startup_list=(
                    '#!/bin/bash'
                    "service cron start > \"/dev/null\" 2>&1"
                    "service ssh start > \"/dev/null\" 2>&1"
                )
                rm -rf "/tmp/startup.autodeploy" && for startup_list_task in "${!startup_list[@]}"; do
                    echo "${startup_list[$startup_list_task]}" >> "/tmp/startup.autodeploy"
                done && cat "/tmp/startup.autodeploy" > "/opt/startup.sh" && rm -rf "/tmp/startup.autodeploy"
            }
            function Fix_Resolv_Conf_Issue() {
                resolv_conf_list=(
                    "223.5.5.5"
                    "223.6.6.6"
                    "2400:3200::1"
                    "2400:3200:baba::1"
                )
                wsl_conf_list=(
                    "[network]"
                    "generateResolvConf = false"
                )
                rm -rf "/tmp/resolv.autodeploy" && for resolv_conf_list_task in "${!resolv_conf_list[@]}"; do
                    echo "nameserver ${resolv_conf_list[$resolv_conf_list_task]}" >> "/tmp/resolv.autodeploy"
                done && rm -rf "/etc/resolv.conf" && cat "/tmp/resolv.autodeploy" > "/etc/resolv.conf" && rm -rf "/tmp/resolv.autodeploy"
                rm -rf "/tmp/wsl.autodeploy" && for wsl_conf_list_task in "${!wsl_conf_list[@]}"; do
                    echo "${wsl_conf_list[$wsl_conf_list_task]}" >> "/tmp/wsl.autodeploy"
                done && cat "/tmp/wsl.autodeploy" > "/etc/wsl.conf" && rm -rf "/tmp/wsl.autodeploy"
            }
            function Fix_Sshd_Server_Issue() {
                CURRENT_PATH=$(pwd)
                cd "/etc/ssh" && ssh-keygen -A && cd "${CURRENT_PATH}"
            }
            function Fix_Ubuntu_Advantage_Tools_Upgrade_Error() {
                if [ ! -d "/run/cloud-init" ]; then
                    mkdir "/run/cloud-init"
                fi
                if [ ! -f "/run/cloud-init/instance-data.json" ]; then
                    echo "{}" > "/run/cloud-init/instance-data.json"
                fi
            }
            function Fix_Unsupport_Udev_Issue() {
                policy_rc_d_list=(
                    "#!/bin/sh"
                    "exit 101"
                )
                rm -rf "/tmp/policy-rc.d.autodeploy" && for policy_rc_d_list_task in "${!policy_rc_d_list[@]}"; do
                    echo "${policy_rc_d_list[$policy_rc_d_list_task]}" >> "/tmp/policy-rc.d.autodeploy"
                done && cat "/tmp/policy-rc.d.autodeploy" > "/usr/sbin/policy-rc.d" && chmod +x "/usr/sbin/policy-rc.d" && dpkg-divert --local --rename --add "/sbin/initctl" && rm -rf "/sbin/initctl" && ln -s "/bin/true" "/sbin/initctl" && rm -rf "/tmp/policy-rc.d.autodeploy"
            }
            Create_Startup_Script
            Fix_Resolv_Conf_Issue
            Fix_Sshd_Server_Issue
            Fix_Ubuntu_Advantage_Tools_Upgrade_Error
            Fix_Unsupport_Udev_Issue
        fi
    }
    GenerateHostname
    GetLSBCodename
    IsArmArchitecture
    IsWSLKernelRelease
}
# Set Repository Mirror
function SetRepositoryMirror() {
    mirror_list=(
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/${mirror_path} ${LSBCodename} main restricted universe multiverse"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/${mirror_path} ${LSBCodename}-backports main restricted universe multiverse"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/${mirror_path} ${LSBCodename}-proposed main restricted universe multiverse"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/${mirror_path} ${LSBCodename}-security main restricted universe multiverse"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/${mirror_path} ${LSBCodename}-updates main restricted universe multiverse"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/${mirror_path} ${LSBCodename}-backports main restricted universe multiverse"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/${mirror_path} ${LSBCodename}-proposed main restricted universe multiverse"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/${mirror_path} ${LSBCodename}-security main restricted universe multiverse"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/${mirror_path} ${LSBCodename}-updates main restricted universe multiverse"
    )
    if [ ! -d "/etc/apt/sources.list.d" ]; then
        mkdir "/etc/apt/sources.list.d"
    fi
    rm -rf "/tmp/apt.autodeploy" && for mirror_list_task in "${!mirror_list[@]}"; do
        echo "${mirror_list[$mirror_list_task]}" >> "/tmp/apt.autodeploy"
    done && cat "/tmp/apt.autodeploy" > "/etc/apt/sources.list" && rm -rf "/tmp/apt.autodeploy"
}
# Set Readonly Flag
function SetReadonlyFlag() {
    file_list=(
        "/etc/apt/sources.list"
        "/etc/apt/sources.list.d/docker.list"
        "/etc/apt/sources.list.d/github-cli.list"
        "/etc/default/ufw"
        "/etc/docker/daemon.json"
        "/etc/hostname"
        "/etc/hosts"
        "/etc/netplan/netplan.yaml"
        "/etc/resolv.conf"
        "/etc/sysctl.conf"
        "/etc/systemd/resolved.conf.d/resolved.conf"
        "/etc/wsl.conf"
        "/etc/zsh/oh-my-zsh.zshrc"
    )
    if [ "${read_only}" == "TRUE" ]; then
        for file_list_task in "${!file_list[@]}"; do
            chattr +i "${file_list[$file_list_task]}" > "/dev/null" 2>&1
        done
    elif [ "${read_only}" == "FALSE" ]; then
        for file_list_task in "${!file_list[@]}"; do
            chattr -i "${file_list[$file_list_task]}" > "/dev/null" 2>&1
        done
    fi
}
# Configure Packages
function ConfigurePackages() {
    function ConfigureCrontab() {
        crontab_list=(
            "@reboot sudo rm -rf /root/.*_history"
        )
        which "crontab" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/tmp/crontab.autodeploy" && for crontab_list_task in "${!crontab_list[@]}"; do
                echo "${crontab_list[$crontab_list_task]}" >> "/tmp/crontab.autodeploy"
            done && crontab -u "root" "/tmp/crontab.autodeploy" && crontab -lu "root" && rm -rf "/tmp/crontab.autodeploy"
        fi
    }
    function ConfigureDockerEngine() {
        docker_list=(
            "{"
            "  \"experimental\": true,"
            "  \"fixed-cidr-v6\": \"2001:db8:1::/64\","
            "  \"ipv6\": true,"
            "  \"registry-mirrors\": ["
            "    \"https://docker.mirrors.ustc.edu.cn\""
            "  ]"
            "}"
        )
        which "docker" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            if [ ! -d "/docker" ]; then
                mkdir "/docker"
            fi
            if [ ! -d "/etc/docker" ]; then
                mkdir "/etc/docker"
            fi
            rm -rf "/tmp/docker.autodeploy" && for docker_list_task in "${!docker_list[@]}"; do
                echo "${docker_list[$docker_list_task]}" >> "/tmp/docker.autodeploy"
            done && cat "/tmp/docker.autodeploy" > "/etc/docker/daemon.json" && OPRATIONS="restart" && SERVICE_NAME="docker" && CallServiceController && rm -rf "/tmp/docker.autodeploy"
        fi
    }
    function ConfigureLandscape() {
        if [ -f "/usr/lib/python3/dist-packages/landscape/lib/network.py" ]; then
            cat "/usr/lib/python3/dist-packages/landscape/lib/network.py" | sed "s/tostring/tobytes/g" > "/tmp/landscape.autodeploy" && cat "/tmp/landscape.autodeploy" > "/usr/lib/python3/dist-packages/landscape/lib/network.py" && rm -rf "/tmp/landscape.autodeploy"
        fi
    }
    function ConfigureNetplan() {
        netplan_list=(
            "network:"
            "  version: 2"
            "  renderer: NetworkManager"
            "  ethernets:"
        )
        netplan_ethernets_list=(
            "      dhcp4: true"
            "      dhcp6: true"
        )
        network_interface=($(cat "/proc/net/dev" | grep -v "docker0\|lo" | grep "\:" | sed "s/[[:space:]]//g" | cut -d ":" -f 1 | sort | uniq))
        which "netplan" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ] && [ "${wsl_kernel}" == "FALSE" ]; then
            if [ ! -d "/etc/netplan" ]; then
                mkdir "/etc/netplan"
            else
                rm -rf /etc/netplan/*.yaml
            fi
            rm -rf "/tmp/netplan.autodeploy" && for netplan_list_task in "${!netplan_list[@]}"; do
                echo "${netplan_list[$netplan_list_task]}" >> "/tmp/netplan.autodeploy"
            done && for network_interface_task in "${!network_interface[@]}"; do
                echo "    ${network_interface[$network_interface_task]}:" >> "/tmp/netplan.autodeploy" && for netplan_ethernets_list_task in "${!netplan_ethernets_list[@]}"; do
                    echo "${netplan_ethernets_list[$netplan_ethernets_list_task]}" >> "/tmp/netplan.autodeploy"
                done
            done && cat "/tmp/netplan.autodeploy" > "/etc/netplan/netplan.yaml" && netplan apply && rm -rf "/tmp/netplan.autodeploy"
        fi
    }
    function ConfigurePostfix() {
        if [ -f "/etc/postfix/main.cf" ]; then
            CURRENT_HOSTNAME=$(cat "/etc/postfix/main.cf" | grep "myhostname\ \=\ " | sed "s/myhostname\ \=\ //g")
            cat "/etc/postfix/main.cf" | sed "s/$CURRENT_HOSTNAME/$NEW_HOSTNAME/g" > "/tmp/main.cf.autodeploy" && cat "/tmp/main.cf.autodeploy" > "/etc/postfix/main.cf" && rm -rf "/tmp/main.cf.autodeploy"
        fi
    }
    function ConfigureResolved() {
        resolved_list=(
            "[Resolve]"
            "DNS=223.5.5.5#dns.alidns.com 223.6.6.6#dns.alidns.com 2400:3200::1#dns.alidns.com 2400:3200:baba::1#dns.alidns.com"
            "DNSOverTLS=opportunistic"
            "DNSSEC=allow-downgrade"
            "DNSStubListener=false"
        )
        which "resolvectl" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ] && [ "${wsl_kernel}" == "FALSE" ]; then
            if [ -f "/etc/resolv.conf" ]; then
                rm -rf "/etc/resolv.conf" && ln -s "/run/systemd/resolve/resolv.conf" "/etc/resolv.conf"
            fi
            if [ ! -d "/etc/systemd/resolved.conf.d" ]; then
                mkdir "/etc/systemd/resolved.conf.d"
            else
                rm -rf /etc/systemd/resolved.conf.d/*.conf
            fi
            rm -rf "/tmp/resolved.autodeploy" && for resolved_list_task in "${!resolved_list[@]}"; do
                echo "${resolved_list[$resolved_list_task]}" >> "/tmp/resolved.autodeploy"
            done && cat "/tmp/resolved.autodeploy" > "/etc/systemd/resolved.conf.d/resolved.conf" && OPRATIONS="restart" && SERVICE_NAME="systemd-resolved" && CallServiceController && rm -rf "/tmp/resolved.autodeploy"
        fi
    }
    function ConfigureSshd() {
        if [ -f "/etc/ssh/sshd_config" ]; then
            cat "/etc/ssh/sshd_config" | sed "s/PasswordAuthentication\ no/PasswordAuthentication\ yes/g;s/\#PasswordAuthentication\ yes/PasswordAuthentication\ yes/g;s/\#PermitRootLogin\ prohibit\-password/PermitRootLogin\ yes/g" > "/tmp/sshd_config.autodeploy" && cat "/tmp/sshd_config.autodeploy" > "/etc/ssh/sshd_config" && rm -rf "/tmp/sshd_config.autodeploy"
        fi
    }
    function ConfigureSysctl() {
        sysctl_list=(
            "net.core.default_qdisc = fq"
            "net.ipv4.tcp_congestion_control = bbr"
            "net.ipv4.tcp_fastopen = 3"
        )
        which "sysctl" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/tmp/sysctl.autodeploy" && for sysctl_list_task in "${!sysctl_list[@]}"; do
                echo "${sysctl_list[$sysctl_list_task]}" >> "/tmp/sysctl.autodeploy"
            done && cat "/tmp/sysctl.autodeploy" > "/etc/sysctl.conf" && sysctl -p && rm -rf "/tmp/sysctl.autodeploy"
        fi
    }
    function ConfigureTuned() {
        which "tuned-adm" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            tuned-adm profile "$(tuned-adm recommend)" && tuned-adm active
        fi
    }
    function ConfigureUfw() {
        which "ufw" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ] && [ -f "/etc/default/ufw" ] && [ "${wsl_kernel}" == "FALSE" ]; then
            echo "$(cat '/etc/default/ufw' | sed 's/DEFAULT\_APPLICATION\_POLICY\=\"ACCEPT\"/DEFAULT\_APPLICATION\_POLICY\=\"REJECT\"/g;s/DEFAULT\_APPLICATION\_POLICY\=\"DROP\"/DEFAULT\_APPLICATION\_POLICY\=\"REJECT\"/g;s/DEFAULT\_APPLICATION\_POLICY\=\"SKIP\"/DEFAULT\_APPLICATION\_POLICY\=\"REJECT\"/g;s/DEFAULT\_FORWARD\_POLICY\=\"ACCEPT\"/DEFAULT\_FORWARD\_POLICY\=\"REJECT\"/g;s/DEFAULT\_FORWARD\_POLICY\=\"DROP\"/DEFAULT\_FORWARD\_POLICY\=\"REJECT\"/g;s/DEFAULT\_INPUT\_POLICY\=\"ACCEPT\"/DEFAULT\_INPUT\_POLICY\=\"REJECT\"/g;s/DEFAULT\_INPUT\_POLICY\=\"DROP\"/DEFAULT\_INPUT\_POLICY\=\"REJECT\"/g;s/DEFAULT\_OUTPUT\_POLICY\=\"DROP\"/DEFAULT\_OUTPUT\_POLICY\=\"ACCEPT\"/g;s/DEFAULT\_OUTPUT\_POLICY\=\"REJECT\"/DEFAULT\_OUTPUT\_POLICY\=\"ACCEPT\"/g;s/MANAGE\_BUILTINS\=yes/MANAGE\_BUILTINS\=no/g;s/IPV6\=no/IPV6\=yes/g')" > "/tmp/ufw.autodeploy"
            cat "/tmp/ufw.autodeploy" > "/etc/default/ufw" && ufw reload && rm -rf "/tmp/ufw.autodeploy" && ufw limit 22/tcp && ufw allow 9090/tcp && ufw enable && ufw status verbose
        fi
    }
    function ConfigureZsh() {
        omz_list=(
            "export DEBIAN_FRONTEND=\"noninteractive\""
            "export EDITOR=\"nano\""
            "export GPG_TTY=\$\(tty\)"
            "export PATH=\"/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin\""
            "export ZSH=\"\$HOME/.oh-my-zsh\""
            "plugins=(zsh-autosuggestions zsh-completions zsh-history-substring-search zsh-syntax-highlighting)"
            "ZSH_CACHE_DIR=\"\$ZSH/cache\""
            "ZSH_CUSTOM=\"\$ZSH/custom\""
            "ZSH_THEME=\"ys\""
            "DISABLE_AUTO_UPDATE=\"false\""
            "DISABLE_UPDATE_PROMPT=\"false\""
            "UPDATE_ZSH_DAYS=\"30\""
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
            done && cat "/tmp/omz.autodeploy" > "/etc/zsh/oh-my-zsh.zshrc" && rm -rf "/tmp/omz.autodeploy" && ln -s "/etc/zsh/oh-my-zsh" "/root/.oh-my-zsh" && ln -s "/etc/zsh/oh-my-zsh.zshrc" "/root/.zshrc"
        fi
    }
    ConfigureCrontab
    ConfigureDockerEngine
    ConfigureLandscape
    ConfigureNetplan
    ConfigurePostfix
    ConfigureResolved
    ConfigureSshd
    ConfigureSysctl
    ConfigureUfw
    ConfigureZsh
}
# Configure System
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
        done && cat "/tmp/hosts.autodeploy" > "/etc/hosts" && rm -rf "/tmp/hosts.autodeploy"
        rm -rf "/tmp/hostname.autodeploy" && echo "${NEW_HOSTNAME}" > "/tmp/hostname.autodeploy" && cat "/tmp/hostname.autodeploy" > "/etc/hostname" && rm -rf "/tmp/hostname.autodeploy"
    }
    function ConfigureLocales() {
        apt purge -qy locales && apt update && apt install -qy locales && locale-gen "en_US.UTF-8" && update-locale "en_US.UTF-8"
    }
    function ConfigureTimeZone() {
        if [ -f "/etc/localtime" ]; then
            rm -rf "/etc/localtime"
        fi && ln -s "/usr/share/zoneinfo/Asia/Shanghai" "/etc/localtime"
    }
    ConfigureDefaultShell
    ConfigureHostfile
    ConfigureLocales
    ConfigureTimeZone
}
# Install Custom Packages
function InstallCustomPackages() {
    function InstallDockerEngine() {
        app_list=(
            "containerd.io"
            "docker-ce"
            "docker-ce-cli"
        )
        curl -fsSL "https://mirrors.ustc.edu.cn/docker-ce/linux/ubuntu/gpg" | gpg --dearmor -o "/usr/share/keyrings/docker-archive-keyring.gpg"
        echo "deb [arch=${mirror_arch} signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://mirrors.ustc.edu.cn/docker-ce/linux/ubuntu ${LSBCodename} stable" > "/etc/apt/sources.list.d/docker.list"
        apt update && apt purge -qy containerd docker docker-engine docker.io runc && for app_list_task in "${!app_list[@]}"; do
            apt-cache show ${app_list[$app_list_task]} && if [ "$?" -eq "0" ]; then
                apt install -qy ${app_list[$app_list_task]}
            fi
        done
    }
    function InstallGitHubCLI() {
        curl -fsSL "https://cli.github.com/packages/githubcli-archive-keyring.gpg" | gpg --dearmor -o "/usr/share/keyrings/githubcli-archive-keyring.gpg"
        echo "deb [arch=${mirror_arch} signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" > "/etc/apt/sources.list.d/github-cli.list"
        apt update && apt-cache show gh && if [ "$?" -eq "0" ]; then
            apt install -qy gh
        fi
    }
    function InstallOhMyZsh() {
        plugin_list=(
            "zsh-autosuggestions"
            "zsh-completions"
            "zsh-history-substring-search"
            "zsh-syntax-highlighting"
        )
        rm -rf "/etc/zsh/oh-my-zsh" && git clone --depth=1 "https://github.com.cnpmjs.org/ohmyzsh/ohmyzsh.git" "/etc/zsh/oh-my-zsh" && if [ -d "/etc/zsh/oh-my-zsh/custom/plugins" ]; then
            for plugin_list_task in "${!plugin_list[@]}"; do
                rm -rf "/etc/zsh/oh-my-zsh/custom/plugins/${plugin_list[$plugin_list_task]}" && git clone --depth=1 "https://github.com.cnpmjs.org/zsh-users/${plugin_list[$plugin_list_task]}.git" "/etc/zsh/oh-my-zsh/custom/plugins/${plugin_list[$plugin_list_task]}"
            done
        fi
    }
    InstallDockerEngine
    InstallGitHubCLI
    InstallOhMyZsh
}
# Install Dependency Packages
function InstallDependencyPackages() {
    app_list=(
        "apt-transport-https"
        "ca-certificates"
        "cockpit"
        "cockpit-pcp"
        "curl"
        "dnsutils"
        "git"
        "git-flow"
        "git-lfs"
        "gnupg"
        "iperf3"
        "jq"
        "knot-dnsutils"
        "landscape-common"
        "lsb-release"
        "mailutils"
        "mercurial"
        "mtr-tiny"
        "nano"
        "neofetch"
        "net-tools"
        "netplan.io"
        "openssh-client"
        "openssh-server"
        "p7zip-full"
        "postfix"
        "rar"
        "realmd"
        "sudo"
        "systemd"
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
        "vim"
        "wget"
        "zip"
        "zsh"
    )
    apt update && for app_list_task in "${!app_list[@]}"; do
        apt-cache show ${app_list[$app_list_task]} && if [ "$?" -eq "0" ]; then
            apt install -qy ${app_list[$app_list_task]}
        fi
    done
}
# Upgrade Packages
function UpgradePackages() {
    apt update && apt dist-upgrade -qy && apt upgrade -qy && apt autoremove -qy
}
# Cleanup Temp Files
function CleanupTempFiles() {
    apt clean && rm -rf /root/.*_history /tmp/*
}

## Process
# Set DEBIAN_FRONTEND to "noninteractive"
export DEBIAN_FRONTEND="noninteractive"
# Set read_only="FALSE"; Call SetReadonlyFlag
read_only="FALSE" && SetReadonlyFlag
# Call GetSystemInformation
GetSystemInformation
# Set transport_protocol="http"; Call SetRepositoryMirror
transport_protocol="http" && SetRepositoryMirror
# Call InstallDependencyPackages
InstallDependencyPackages
# Set transport_protocol="https"; Call SetRepositoryMirror
transport_protocol="https" && SetRepositoryMirror
# Call UpgradePackages
UpgradePackages
# Call InstallCustomPackages
InstallCustomPackages
# Call ConfigurePackages
ConfigurePackages
# Call ConfigureSystem
ConfigureSystem
# Set read_only="TRUE"; Call SetReadonlyFlag
read_only="TRUE" && SetReadonlyFlag
# Call CleanupTempFiles
CleanupTempFiles
