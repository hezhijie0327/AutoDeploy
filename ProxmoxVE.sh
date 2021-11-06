#!/bin/bash

# Current Version: 1.0.6

## How to get and use?
# curl "https://source.zhijie.online/AutoDeploy/main/ProxmoxVE.sh" | sudo bash
# wget -qO- "https://source.zhijie.online/AutoDeploy/main/ProxmoxVE.sh" | sudo bash

## Function
# Get System Information
function GetSystemInformation() {
    function GenerateDomain() {
        NEW_DOMAIN="localdomain"
    }
    function GenerateHostname() {
        NEW_HOSTNAME="ProxmoxVE-$(date '+%Y%m%d%H%M%S')"
    }
    function GetLSBCodename() {
        LSBCodename=$(cat "/etc/os-release" | grep "CODENAME" | cut -f 2 -d "=")
    }
    function GetManagementIPAddress() {
        CURRENT_MANAGEMENT_IP=$(ip address show vmbr0 | grep "inet" | awk '{print $2}' | sort | head -n 1 | sed "s/\/.*//")
    }
    GenerateDomain
    GenerateHostname
    GetLSBCodename
    GetManagementIPAddress
}
# Set Repository Mirror
function SetRepositoryMirror() {
    mirror_list=(
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/debian-security ${LSBCodename}-security main contrib non-free"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/debian ${LSBCodename} main contrib non-free"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/debian ${LSBCodename}-backports main contrib non-free"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/debian ${LSBCodename}-updates main contrib non-free"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/debian-security ${LSBCodename}-security main contrib non-free"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/debian ${LSBCodename} main contrib non-free"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/debian ${LSBCodename}-backports main contrib non-free"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/debian ${LSBCodename}-updates main contrib non-free"
    )
    proxmox_mirror_list=(
        "# deb ${transport_protocol}://enterprise.proxmox.com/debian/pve ${LSBCodename} pve-enterprise"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/proxmox/debian ${LSBCodename} pve-no-subscription"
        "# deb ${transport_protocol}://mirrors.ustc.edu.cn/proxmox/debian ${LSBCodename} pvetest"
    )
    if [ ! -d "/etc/apt/sources.list.d" ]; then
        mkdir "/etc/apt/sources.list.d"
    else
        rm -rf /etc/apt/sources.list.d/*.*
    fi
    rm -rf "/tmp/apt.autodeploy" && for mirror_list_task in "${!mirror_list[@]}"; do
        echo "${mirror_list[$mirror_list_task]}" >> "/tmp/apt.autodeploy"
    done && cat "/tmp/apt.autodeploy" > "/etc/apt/sources.list" && rm -rf "/tmp/apt.autodeploy"
    rm -rf "/tmp/apt.autodeploy" && for proxmox_mirror_list_task in "${!proxmox_mirror_list[@]}"; do
        echo "${proxmox_mirror_list[$proxmox_mirror_list_task]}" >> "/tmp/apt.autodeploy"
    done && cat "/tmp/apt.autodeploy" > "/etc/apt/sources.list.d/proxmox.list" && rm -rf "/tmp/apt.autodeploy" && sed -i "s/http\:\/\/download\.proxmox\.com/https\:\/\/mirrors\.ustc\.edu\.cn\/proxmox/g" "/usr/share/perl5/PVE/APLInfo.pm"
}
# Set Readonly Flag
function SetReadonlyFlag() {
    file_list=(
        "/etc/apt/sources.list"
        "/etc/apt/sources.list.d/proxmox.list"
        "/etc/hostname"
        "/etc/hosts"
        "/etc/modules"
        "/etc/zsh/oh-my-zsh.zshrc"
    )
    if [ "${read_only}" == "TRUE" ]; then
        for file_list_task in "${!file_list[@]}"; do
            if [ -d "${file_list[$file_list_task]}" ] || [ -f "${file_list[$file_list_task]}" ]; then
                chattr +i "${file_list[$file_list_task]}"
            fi
        done
    elif [ "${read_only}" == "FALSE" ]; then
        for file_list_task in "${!file_list[@]}"; do
            if [ -d "${file_list[$file_list_task]}" ] || [ -f "${file_list[$file_list_task]}" ]; then
                chattr -i "${file_list[$file_list_task]}"
            fi
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
    function ConfigureGrub() {
        which "update-grub" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            if [ -f "/usr/share/grub/default/grub" ]; then
                rm -rf "/tmp/grub.autodeploy" && cat "/usr/share/grub/default/grub" | sed "s/GRUB\_CMDLINE\_LINUX\_DEFAULT\=\"quiet\"/GRUB\_CMDLINE\_LINUX\_DEFAULT\=\"quiet\ iommu\=pt\"/g" > "/tmp/grub.autodeploy" && cat "/tmp/grub.autodeploy" > "/etc/default/grub" && update-grub && rm -rf "/tmp/grub.autodeploy"
            fi
        fi
    }
    function ConfigureModule() {
        module_list=(
            "vfio"
            "vfio_iommu_type1"
            "vfio_pci"
            "vfio_virqfd"
        )
        if [ -f "/etc/modules" ]; then
            rm -rf "/etc/modules"
        fi && rm -rf "/tmp/module.autodeploy" && for module_list_task in "${!module_list[@]}"; do
                echo "${module_list[$module_list_task]}" >> "/tmp/module.autodeploy"
            done && cat "/tmp/module.autodeploy" > "/etc/modules" && rm -rf "/tmp/module.autodeploy"
    }
    function ConfigurePostfix() {
        if [ -f "/etc/postfix/main.cf" ]; then
            CURRENT_HOSTNAME=$(cat "/etc/postfix/main.cf" | grep "myhostname\ \=\ " | sed "s/myhostname\ \=\ //g")
            cat "/etc/postfix/main.cf" | sed "s/$CURRENT_HOSTNAME/$NEW_HOSTNAME/g" > "/tmp/main.cf.autodeploy" && cat "/tmp/main.cf.autodeploy" > "/etc/postfix/main.cf" && rm -rf "/tmp/main.cf.autodeploy"
        fi
    }
    function ConfigureSshd() {
        if [ -f "/usr/share/openssh/sshd_config" ]; then
            cat "/usr/share/openssh/sshd_config" | sed "s/\#PasswordAuthentication\ yes/PasswordAuthentication\ yes/g;s/\#PermitRootLogin\ prohibit\-password/PermitRootLogin\ yes/g" > "/tmp/sshd_config.autodeploy" && cat "/tmp/sshd_config.autodeploy" > "/etc/ssh/sshd_config" && rm -rf "/tmp/sshd_config.autodeploy"
        fi
    }
    function ConfigureZsh() {
        omz_list=(
            "export DEBIAN_FRONTEND=\"noninteractive\""
            "export EDITOR=\"nano\""
            "export GPG_TTY=\$\(tty\)"
            "export PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\""
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
            done && cat "/tmp/omz.autodeploy" > "/etc/zsh/oh-my-zsh.zshrc" && rm -rf "/tmp/omz.autodeploy" && ln -s "/etc/zsh/oh-my-zsh" "/root/.oh-my-zsh" && ln -s "/etc/zsh/oh-my-zsh.zshrc" "/root/.zshrc"
        fi
    }
    ConfigureCrontab
    ConfigureGrub
    ConfigureModule
    ConfigurePostfix
    ConfigureSshd
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
            "${CURRENT_MANAGEMENT_IP} ${NEW_HOSTNAME}.${NEW_DOMAIN} ${NEW_HOSTNAME}"
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
        rm -rf "/tmp/hostname.autodeploy" && echo "${NEW_HOSTNAME}" > "/tmp/hostname.autodeploy" && cat "/tmp/hostname.autodeploy" > "/etc/hostname" && rm -rf "/tmp/hostname.autodeploy"
    }
    ConfigureDefaultShell
    ConfigureHostfile
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
        rm -rf "/etc/zsh/oh-my-zsh" && git clone --depth=1 "https://github.com.cnpmjs.org/ohmyzsh/ohmyzsh.git" "/etc/zsh/oh-my-zsh" && if [ -d "/etc/zsh/oh-my-zsh/custom/plugins" ]; then
            for plugin_list_task in "${!plugin_list[@]}"; do
                rm -rf "/etc/zsh/oh-my-zsh/custom/plugins/${plugin_list[$plugin_list_task]}" && git clone --depth=1 "https://github.com.cnpmjs.org/zsh-users/${plugin_list[$plugin_list_task]}.git" "/etc/zsh/oh-my-zsh/custom/plugins/${plugin_list[$plugin_list_task]}"
            done
        fi
    }
    InstallOhMyZsh
}
# Install Dependency Packages
function InstallDependencyPackages() {
    app_list=(
        "apt-file"
        "apt-transport-https"
        "ca-certificates"
        "curl"
        "dnsutils"
        "git"
        "git-flow"
        "git-lfs"
        "gnupg"
        "iperf3"
        "jq"
        "knot-dnsutils"
        "lsb-release"
        "mailutils"
        "mtr-tiny"
        "nano"
        "neofetch"
        "net-tools"
        "ntfs-3g"
        "openssh-client"
        "openssh-server"
        "p7zip-full"
        "postfix"
        "python3"
        "python3-pip"
        "rar"
        "sudo"
        "systemd"
        "tshark"
        "udisks2"
        "udisks2-bcache"
        "udisks2-btrfs"
        "udisks2-lvm2"
        "udisks2-zram"
        "unrar"
        "unzip"
        "vim"
        "wget"
        "whois"
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
