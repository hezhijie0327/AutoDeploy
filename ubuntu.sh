#!/bin/bash

# Current Version: 1.0.9

## How to get and use?
# curl https://source.zhijie.online/AutoDeploy/main/ubuntu.sh | sudo bash

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
    rm -rf "/tmp/apt.tmp" && for mirror_list_task in "${!mirror_list[@]}"; do
        echo "${mirror_list[$mirror_list_task]}" >> "/tmp/apt.tmp"
    done && cat "/tmp/apt.tmp" > "/etc/apt/sources.list"
}
# Set Readonly Flag
function SetReadonlyFlag() {
    file_list=(
        "/etc/apt/sources.list"
        "/etc/default/ufw"
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
            "0 4 */7 * * sudo reboot"
            "@daily sudo apt update && sudo apt dist-upgrade -y && sudo apt upgrade -y && sudo apt autoremove -y"
        )
        which "crontab" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/tmp/crontab.tmp" && for crontab_list_task in "${!crontab_list[@]}"; do
                echo "${crontab_list[$crontab_list_task]}" >> "/tmp/crontab.tmp"
            done && crontab -u "root" "/tmp/crontab.tmp" && crontab -lu "root"
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
            done && cat "/tmp/resolved.tmp" > "/etc/systemd/resolved.conf.d/resolved.conf" && systemctl restart systemd-resolved
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
            done && cat "/tmp/sysctl.tmp" > "/etc/sysctl.conf"
        fi && sysctl -p
    }
    function ConfigureUfw() {
        which "ufw" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ] && [ -f "/etc/default/ufw" ]; then
            echo "$(cat '/etc/default/ufw' | sed 's/DEFAULT\_APPLICATION\_POLICY\=\"ACCEPT\"/DEFAULT\_APPLICATION\_POLICY\=\"REJECT\"/g;s/DEFAULT\_APPLICATION\_POLICY\=\"DROP\"/DEFAULT\_APPLICATION\_POLICY\=\"REJECT\"/g;s/DEFAULT\_FORWARD\_POLICY\=\"ACCEPT\"/DEFAULT\_FORWARD\_POLICY\=\"REJECT\"/g;s/DEFAULT\_FORWARD\_POLICY\=\"DROP\"/DEFAULT\_FORWARD\_POLICY\=\"REJECT\"/g;s/DEFAULT\_INPUT\_POLICY\=\"ACCEPT\"/DEFAULT\_INPUT\_POLICY\=\"REJECT\"/g;s/DEFAULT\_INPUT\_POLICY\=\"DROP\"/DEFAULT\_INPUT\_POLICY\=\"REJECT\"/g;s/DEFAULT\_OUTPUT\_POLICY\=\"DROP\"/DEFAULT\_OUTPUT\_POLICY\=\"ACCEPT\"/g;s/DEFAULT\_OUTPUT\_POLICY\=\"REJECT\"/DEFAULT\_OUTPUT\_POLICY\=\"ACCEPT\"/g;s/MANAGE\_BUILTINS\=yes/MANAGE\_BUILTINS\=no/g;s/IPV6\=no/IPV6\=yes/g')" > "/tmp/ufw.tmp"
            cat "/tmp/ufw.tmp" > "/etc/default/ufw" && rm -rf "/tmp/ufw.tmp" && ufw reload
        fi
    }
    function ConfigureZsh() {
        zsh_list=(
            "bindkey \"^[[Z\" autosuggest-accept"
            "source \"/usr/share/zsh-autosuggestions/zsh-autosuggestions.zsh\""
            "source \"/usr/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh\""
        )
        which "zsh" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            cat "/etc/zsh/newuser.zshrc.recommended" > "/tmp/newuser.zshrc.recommended.bak" && rm -rf "/tmp/zsh.tmp" && for zsh_list_task in "${!zsh_list[@]}"; do
                echo "${zsh_list[$zsh_list_task]}" >> "/tmp/zsh.tmp"
            done && cat "/tmp/newuser.zshrc.recommended.bak" "/tmp/zsh.tmp" > "/etc/zsh/newuser.zshrc.recommended"
        fi && apt install -y zsh-autosuggestions zsh-syntax-highlighting
    }
    ConfigureCrontab
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
    function ConfigureTimeZone() {
        if [ -f "/etc/localtime" ]; then
            rm -rf "/etc/localtime"
        fi && ln -s "/usr/share/zoneinfo/Asia/Shanghai" "/etc/localtime"
    }
    ConfigureDefaultShell
    ConfigureTimeZone
}
# Install Packages
function InstallPackages() {
    apt update && apt install -y apt-transport-https ca-certificates curl dnsutils git jq knot-dnsutils landscape-common nano net-tools systemd ufw update-notifier-common wget zsh
}
# Upgrade Packages
function UpgradePackages() {
    apt update && apt dist-upgrade -y && apt upgrade -y && apt autoremove -y
}

## Process
GetSystemInformation
read_only="false" && SetReadonlyFlag
transport_protocol="http" && SetRepositoryMirror
InstallPackages
transport_protocol="https" && SetRepositoryMirror
UpgradePackages
ConfigurePackages
ConfigureSystem
read_only="true" && SetReadonlyFlag
