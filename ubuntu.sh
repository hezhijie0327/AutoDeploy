#!/bin/bash

# Current Version: 1.2.4

## How to get and use?
# curl https://source.zhijie.online/AutoDeploy/main/ubuntu.sh | sudo bash
# wget -qO- https://source.zhijie.online/AutoDeploy/main/ubuntu.sh | sudo bash

## Function
# Get System Information
function GetSystemInformation() {
    function GetCPUArchitecture() {
        CPUArchitecture=$(case "$(uname -m)" in aarch64) echo "arm64" ;; amd64 | x64 | x86-64 | x86_64) echo "amd64" ;; armv5l) echo "armv5" ;; armv6l) echo "armv6" ;; armv7l) echo "armv7" ;; i386 | i486 | i586 | i686 | x86) echo "386" ;; esac)
        if [ "${CPUArchitecture}" != "386" ] && [ "${CPUArchitecture}" != "amd64" ]; then
            mirror_path="-ports"
        fi
    }
    function GetLSBCodename() {
        which "lsb_release" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            LSBCodename=$(lsb_release -cs)
        else
            LSBCodename="focal"
        fi
    }
    GetCPUArchitecture
    GetLSBCodename
}
# Set Repository Mirror
function SetRepositoryMirror() {
    mirror_list=(
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/ubuntu${mirror_path}/ ${LSBCodename} main restricted universe multiverse"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/ubuntu${mirror_path}/ ${LSBCodename}-backports main restricted universe multiverse"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/ubuntu${mirror_path}/ ${LSBCodename}-proposed main restricted universe multiverse"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/ubuntu${mirror_path}/ ${LSBCodename}-security main restricted universe multiverse"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/ubuntu${mirror_path}/ ${LSBCodename}-updates main restricted universe multiverse"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/ubuntu${mirror_path}/ ${LSBCodename}-backports main restricted universe multiverse"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/ubuntu${mirror_path}/ ${LSBCodename}-proposed main restricted universe multiverse"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/ubuntu${mirror_path}/ ${LSBCodename}-security main restricted universe multiverse"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/ubuntu${mirror_path}/ ${LSBCodename}-updates main restricted universe multiverse"
    )
    if [ ! -d "/etc/apt/sources.list.d" ]; then
        mkdir "/etc/apt/sources.list.d"
    fi
    rm -rf "/tmp/apt.tmp" && for mirror_list_task in "${!mirror_list[@]}"; do
        echo "${mirror_list[$mirror_list_task]}" >> "/tmp/apt.tmp"
    done && cat "/tmp/apt.tmp" > "/etc/apt/sources.list"
}
# Set Readonly Flag
function SetReadonlyFlag() {
    file_list=(
        "/etc/apt/sources.list"
        "/etc/default/ufw"
        "/etc/docker/daemon.json"
        "/etc/hostname"
        "/etc/hosts"
        "/etc/netplan/netplan.yaml"
        "/etc/sysctl.conf"
        "/etc/systemd/resolved.conf.d/resolved.conf"
    )
    if [ "${read_only}" == "true" ]; then
        for file_list_task in "${!file_list[@]}"; do
            chattr +i "${file_list[$file_list_task]}" > "/dev/null" 2>&1
        done
    elif [ "${read_only}" == "false" ]; then
        for file_list_task in "${!file_list[@]}"; do
            chattr -i "${file_list[$file_list_task]}" > "/dev/null" 2>&1
        done
    fi
}
# Configure Packages
function ConfigurePackages() {
    function ConfigureCrontab() {
        crontab_list=(
            "0 0 */7 * * sudo apt update && sudo apt dist-upgrade -y && sudo apt upgrade -y && sudo apt autoremove -y"
            "0 4 */7 * * sudo reboot"
        )
        which "crontab" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/tmp/crontab.tmp" && for crontab_list_task in "${!crontab_list[@]}"; do
                echo "${crontab_list[$crontab_list_task]}" >> "/tmp/crontab.tmp"
            done && crontab -u "root" "/tmp/crontab.tmp" && crontab -lu "root" && rm -rf "/tmp/crontab.tmp"
        fi
    }
    function ConfigureDockerEngine() {
        docker_list=(
            "{"
            "  \"registry-mirrors\": ["
            "    \"https://docker.mirrors.ustc.edu.cn\""
            "  ]"
            "}"
        )
        which "docker" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            if [ ! -d "/etc/docker" ]; then
                mkdir "/etc/docker"
            fi
            rm -rf "/tmp/docker.tmp" && for docker_list_task in "${!docker_list[@]}"; do
                echo "${docker_list[$docker_list_task]}" >> "/tmp/docker.tmp"
            done && cat "/tmp/docker.tmp" > "/etc/docker/daemon.json" && systemctl restart docker && rm -rf "/tmp/docker.tmp"
        fi
    }
    function ConfigureNetplan() {
        netplan_list=(
            "network:"
            "  version: 2"
            "  renderer: networkd"
            "  ethernets:"
        )
        netplan_ethernets_list=(
            "      dhcp4: true"
            "      dhcp6: true"
        )
        network_interface=($(cat "/proc/net/dev" | grep -v "docker0\|lo" | grep "\:" | sed "s/[[:space:]]//g" | cut -d ":" -f 1 | sort | uniq))
        which "netplan" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            if [ ! -d "/etc/netplan" ]; then
                mkdir "/etc/netplan"
            else
                rm -rf /etc/netplan/*.yaml
            fi
            rm -rf "/tmp/netplan.tmp" && for netplan_list_task in "${!netplan_list[@]}"; do
                echo "${netplan_list[$netplan_list_task]}" >> "/tmp/netplan.tmp"
            done && for network_interface_task in "${!network_interface[@]}"; do
                echo "    ${network_interface[$network_interface_task]}:" >> "/tmp/netplan.tmp" && for netplan_ethernets_list_task in "${!netplan_ethernets_list[@]}"; do
                    echo "${netplan_ethernets_list[$netplan_ethernets_list_task]}" >> "/tmp/netplan.tmp"
                done
            done && cat "/tmp/netplan.tmp" > "/etc/netplan/netplan.yaml" && netplan apply && rm -rf "/tmp/netplan.tmp"
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
        if [ "$?" -eq "0" ]; then
            if [ -f "/etc/resolv.conf" ]; then
                rm -rf "/etc/resolv.conf" && ln -s "/run/systemd/resolve/resolv.conf" "/etc/resolv.conf"
            fi
            if [ ! -d "/etc/systemd/resolved.conf.d" ]; then
                mkdir "/etc/systemd/resolved.conf.d"
            else
                rm -rf /etc/systemd/resolved.conf.d/*.conf
            fi
            rm -rf "/tmp/resolved.tmp" && for resolved_list_task in "${!resolved_list[@]}"; do
                echo "${resolved_list[$resolved_list_task]}" >> "/tmp/resolved.tmp"
            done && cat "/tmp/resolved.tmp" > "/etc/systemd/resolved.conf.d/resolved.conf" && systemctl restart systemd-resolved && rm -rf "/tmp/resolved.tmp"
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
            rm -rf "/tmp/sysctl.tmp" && for sysctl_list_task in "${!sysctl_list[@]}"; do
                echo "${sysctl_list[$sysctl_list_task]}" >> "/tmp/sysctl.tmp"
            done && cat "/tmp/sysctl.tmp" > "/etc/sysctl.conf" && sysctl -p && rm -rf "/tmp/sysctl.tmp"
        fi
    }
    function ConfigureUfw() {
        which "ufw" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ] && [ -f "/etc/default/ufw" ]; then
            echo "$(cat '/etc/default/ufw' | sed 's/DEFAULT\_APPLICATION\_POLICY\=\"ACCEPT\"/DEFAULT\_APPLICATION\_POLICY\=\"REJECT\"/g;s/DEFAULT\_APPLICATION\_POLICY\=\"DROP\"/DEFAULT\_APPLICATION\_POLICY\=\"REJECT\"/g;s/DEFAULT\_APPLICATION\_POLICY\=\"SKIP\"/DEFAULT\_APPLICATION\_POLICY\=\"REJECT\"/g;s/DEFAULT\_FORWARD\_POLICY\=\"ACCEPT\"/DEFAULT\_FORWARD\_POLICY\=\"REJECT\"/g;s/DEFAULT\_FORWARD\_POLICY\=\"DROP\"/DEFAULT\_FORWARD\_POLICY\=\"REJECT\"/g;s/DEFAULT\_INPUT\_POLICY\=\"ACCEPT\"/DEFAULT\_INPUT\_POLICY\=\"REJECT\"/g;s/DEFAULT\_INPUT\_POLICY\=\"DROP\"/DEFAULT\_INPUT\_POLICY\=\"REJECT\"/g;s/DEFAULT\_OUTPUT\_POLICY\=\"DROP\"/DEFAULT\_OUTPUT\_POLICY\=\"ACCEPT\"/g;s/DEFAULT\_OUTPUT\_POLICY\=\"REJECT\"/DEFAULT\_OUTPUT\_POLICY\=\"ACCEPT\"/g;s/MANAGE\_BUILTINS\=yes/MANAGE\_BUILTINS\=no/g;s/IPV6\=no/IPV6\=yes/g')" > "/tmp/ufw.tmp"
            cat "/tmp/ufw.tmp" > "/etc/default/ufw" && ufw reload && rm -rf "/tmp/ufw.tmp"
        fi
    }
    function ConfigureZsh() {
        omz_list=(
            "export ZSH=\"\$HOME/.oh-my-zsh\""
            "plugins=(zsh-autosuggestions zsh-syntax-highlighting)"
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
            rm -rf "/tmp/omz.tmp" && for omz_list_task in "${!omz_list[@]}"; do
                echo "${omz_list[$omz_list_task]}" >> "/tmp/omz.tmp"
            done && cat "/tmp/omz.tmp" > "/etc/zsh/oh-my-zsh.zshrc" && rm -rf "/tmp/omz.tmp"
        fi
    }
    ConfigureCrontab
    ConfigureDockerEngine
    ConfigureNetplan
    ConfigureResolved
    ConfigureSysctl
    ConfigureUfw
    ConfigureZsh
}
# Configure System
function ConfigureSystem() {
    function ConfigureDefaultShell() {
        if [ -f "/etc/passwd" ]; then
            echo "$(cat '/etc/passwd' | sed 's/\/bin\/bash/\/bin\/zsh/g;s/\/bin\/sh/\/bin\/zsh/g')" > "/tmp/shell.tmp"
            cat "/tmp/shell.tmp" > "/etc/passwd" && rm -rf "/tmp/shell.tmp"
        fi
    }
    function ConfigureHostfile() {
        host_name="ubuntu-$(date '+%Y%m%d%H%M%S')"
        host_list=(
            "127.0.0.1 localhost"
            "127.0.1.1 ${host_name}"
            "255.255.255.255 broadcasthost"
            "::1 ip6-localhost ip6-loopback localhost"
            "fe00::0 ip6-localnet"
            "ff00::0 ip6-mcastprefix"
            "ff02::1 ip6-allnodes"
            "ff02::2 ip6-allrouters"
            "ff02::3 ip6-allhosts"
        )
        rm -rf "/tmp/hosts.tmp" && for host_list_task in "${!host_list[@]}"; do
            echo "${host_list[$host_list_task]}" >> "/tmp/hosts.tmp"
        done && cat "/tmp/hosts.tmp" > "/etc/hosts" && rm -rf "/tmp/hosts.tmp"
        rm -rf "/tmp/hostname.tmp" && echo "${host_name}" > "/tmp/hostname.tmp" && cat "/tmp/hostname.tmp" > "/etc/hostname" && rm -rf "/tmp/hostname.tmp"
    }
    function ConfigureLocales() {
        apt purge -y locales && apt update && apt install -y locales && locale-gen "en_US.UTF-8" && update-locale "en_US.UTF-8"
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
        curl -fsSL "https://mirrors.ustc.edu.cn/docker-ce/linux/ubuntu/gpg" | gpg --dearmor -o "/usr/share/keyrings/docker-archive-keyring.gpg"
        if [ "${CPUArchitecture}" == "amd64" ] || [ "${CPUArchitecture}" == "arm64" ]; then
            CPUArchitecture="${CPUArchitecture}"
        elif [ "${CPUArchitecture}" == "armv5" ] || [ "${CPUArchitecture}" == "armv6" ] || [ "${CPUArchitecture}" == "armv7" ]; then
            CPUArchitecture="armhf"
        fi && echo "deb [arch=${CPUArchitecture} signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://mirrors.ustc.edu.cn/docker-ce/linux/ubuntu ${LSBCodename} stable" > /etc/apt/sources.list.d/docker.list
        apt update && apt purge -y containerd docker docker-engine docker.io runc && apt install -y containerd.io docker-ce docker-ce-cli
    }
    function InstallOhMyZsh() {
        plugin_list=(
            "zsh-autosuggestions"
            "zsh-syntax-highlighting"
        )
        rm -rf "/etc/zsh/oh-my-zsh" && git clone --depth=1 "https://hub.fastgit.org/robbyrussell/oh-my-zsh.git" "/etc/zsh/oh-my-zsh" && if [ "$?" -eq "1" ]; then
            git clone --depth=1 "https://github.com.cnpmjs.org/robbyrussell/oh-my-zsh.git" "/etc/zsh/oh-my-zsh" && if [ "$?" -eq "1" ]; then
                git clone --depth=1 "https://github.com/robbyrussell/oh-my-zsh.git" "/etc/zsh/oh-my-zsh"
            fi
        fi
        for plugin_list_task in "${!plugin_list[@]}"; do
            rm -rf "/etc/zsh/oh-my-zsh/custom/plugins/${plugin_list[$plugin_list_task]}" && git clone --depth=1 "https://hub.fastgit.org/zsh-users/${plugin_list[$plugin_list_task]}.git" "/etc/zsh/oh-my-zsh/custom/plugins/${plugin_list[$plugin_list_task]}" && if [ "$?" -eq "1" ]; then
                git clone --depth=1 "https://github.com.cnpmjs.org/zsh-users/${plugin_list[$plugin_list_task]}.git" "/etc/zsh/oh-my-zsh/custom/plugins/${plugin_list[$plugin_list_task]}" && if [ "$?" -eq "1" ]; then
                    git clone --depth=1 "https://github.com/zsh-users/${plugin_list[$plugin_list_task]}.git" "/etc/zsh/oh-my-zsh/custom/plugins/${plugin_list[$plugin_list_task]}"
                fi
            fi
        done
    }
    InstallDockerEngine
    InstallOhMyZsh
}
# Install Dependency Packages
function InstallDependencyPackages() {
    apt update && apt install -y apt-transport-https ca-certificates curl dnsutils git gnupg jq knot-dnsutils landscape-common lsb-release nano net-tools netplan.io systemd ufw update-notifier-common vim wget zsh
}
# Upgrade Packages
function UpgradePackages() {
    apt update && apt dist-upgrade -y && apt upgrade -y && apt autoremove -y
}

## Process
# Call GetSystemInformation
GetSystemInformation
# Set read_only="false"; Call SetReadonlyFlag
read_only="false" && SetReadonlyFlag
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
# Set read_only="true"; Call SetReadonlyFlag
read_only="true" && SetReadonlyFlag
