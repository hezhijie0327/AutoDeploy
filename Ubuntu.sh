#!/bin/bash

# Current Version: 3.7.1

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
        if [ "${OPRATIONS}" != "daemon-reload" ]; then
            echo "An error occurred during processing. Missing (SERVICE_NAME) value, please check it and try again."
            exit 1
        fi
    fi
    if [ "${container_environment}" == "lxc" ] || [ "${container_environment}" == "none" ]; then
        if [ "${OPRATIONS}" == "daemon-reload" ]; then
            systemctl daemon-reload
        else
            systemctl ${OPRATIONS} ${SERVICE_NAME}.service
        fi
    else
        service ${SERVICE_NAME} ${OPRATIONS}
    fi
}
# Get System Information
function GetSystemInformation() {
    function CheckDNSConfiguration() {
        CUSTOM_DNS=(
            "223.5.5.5"
            "223.6.6.6"
            "2400:3200::1"
            "2400:3200:baba::1"
        )
        DHCP_DNS=()
        CUSTOM_DNS_LINE="" && for CUSTOM_DNS_TASK in "${!CUSTOM_DNS[@]}"; do
            CUSTOM_DNS_LINE="${CUSTOM_DNS_LINE} ${CUSTOM_DNS[$CUSTOM_DNS_TASK]}"
            CUSTOM_DNS_LINE=$(echo "${CUSTOM_DNS_LINE}" | sed "s/^\ //g")
            CUSTOM_DNS_WG=$(echo "${CUSTOM_DNS_LINE}" | sed "s/\ /\,\ /g")
        done && CURRENT_DNS_EXCLUDE="$(echo ${DHCP_DNS[*]} ${CUSTOM_DNS_LINE} | sed 's/\ /\\\|/g')\|127.0.0.53"
        if [ -f "/etc/resolv.conf" ]; then
            CURRENT_DNS=(${DHCP_DNS[*]} $(cat "/etc/resolv.conf" | grep "nameserver\ " | sed "s/nameserver\ //g" | grep -v "${CURRENT_DNS_EXCLUDE}" | awk "{print $2}"))
            CURRENT_DNS_LINE="" && for CURRENT_DNS_TASK in "${!CURRENT_DNS[@]}"; do
                CURRENT_DNS_LINE="${CURRENT_DNS_LINE} ${CURRENT_DNS[$CURRENT_DNS_TASK]}"
                CURRENT_DNS_LINE=$(echo "${CURRENT_DNS_LINE}" | sed "s/^\ //g")
                CURRENT_DNS_WG=$(echo "${CURRENT_DNS_LINE}" | sed "s/\ /\,\ /g")
            done
        fi
    }
    function CheckMachineEnvironment() {
        function CheckContainerEnvironment() {
            if [ -f "/.dockerenv" ]; then
                container_environment="docker"
            elif [ "$(cat '/proc/1/environ' | grep -a 'lxc')" != "" ]; then
                container_environment="lxc"
            elif [ "$(uname -r | grep 'WSL')" != "" ]; then
                container_environment="wsl2"
                function Create_Startup_Script() {
                    startup_list=(
                        '#!/bin/bash'
                        "service chrony start > \"/dev/null\" 2>&1"
                        "service cron start > \"/dev/null\" 2>&1"
                        "service ssh start > \"/dev/null\" 2>&1"
                    )
                    rm -rf "/tmp/startup.autodeploy" && for startup_list_task in "${!startup_list[@]}"; do
                        echo "${startup_list[$startup_list_task]}" >> "/tmp/startup.autodeploy"
                    done && cat "/tmp/startup.autodeploy" > "/opt/startup.sh" && chmod +x "/opt/startup.sh" && rm -rf "/tmp/startup.autodeploy"
                    rm -rf "/tmp/startup.sudo.autodeploy" && if [ ! -d "/etc/sudoers.d" ]; then
                        mkdir "/etc/sudoers.d"
                    fi && echo "%sudo ALL=NOPASSWD: /opt/startup.sh" > "/etc/sudoers.d/startup" && rm -rf "/tmp/startup.sudo.autodeploy"
                }
                function Fix_Resolv_Conf_Issue() {
                    resolv_conf_list=(
                        ${CURRENT_DNS[@]}
                        ${CUSTOM_DNS[@]}
                    )
                    wsl_conf_list=(
                        "[boot]"
                        "command = bash \"/opt/startup.sh\""
                        "[interop]"
                        "appendWindowsPath = true"
                        "enabled = true"
                        "[network]"
                        "generateHosts = false"
                        "generateResolvConf = false"
                    )
                    wslconfig_list=(
                        "# [wsl2]"
                        "# memory = 1GB"
                        "# processors = 4"
                        "# swap = 2GB"
                    )
                    rm -rf "/tmp/resolv.autodeploy" && for resolv_conf_list_task in "${!resolv_conf_list[@]}"; do
                        echo "nameserver ${resolv_conf_list[$resolv_conf_list_task]}" >> "/tmp/resolv.autodeploy"
                    done && echo "search ${NEW_DOMAIN[*]}" >> "/tmp/resolv.autodeploy" && if [ -f "/etc/resolv.conf" ]; then
                        chattr -i "/etc/resolv.conf" > "/dev/null" 2>&1
                        if [ "$?" -eq "1" ]; then
                            rm -rf "/etc/resolv.conf"
                        fi
                    fi && rm -rf "/etc/resolv.conf" && cat "/tmp/resolv.autodeploy" > "/etc/resolv.conf" && rm -rf "/tmp/resolv.autodeploy" && chattr +i "/etc/resolv.conf"
                    rm -rf "/tmp/wsl.autodeploy" && for wsl_conf_list_task in "${!wsl_conf_list[@]}"; do
                        echo "${wsl_conf_list[$wsl_conf_list_task]}" >> "/tmp/wsl.autodeploy"
                    done && if [ -f "/etc/wsl.conf" ]; then chattr -i "/etc/wsl.conf"; fi && rm -rf "/etc/wsl.conf" && cat "/tmp/wsl.autodeploy" > "/etc/wsl.conf" && rm -rf "/tmp/wsl.autodeploy" && chattr +i "/etc/wsl.conf"
                    rm -rf "/tmp/wslconfig.autodeploy" && for wslconfig_list_task in "${!wslconfig_list[@]}"; do
                        echo "${wslconfig_list[$wslconfig_list_task]}" >> "/tmp/wslconfig.autodeploy"
                    done && cat "/tmp/wslconfig.autodeploy" > "/etc/.wslconfig" && rm -rf "/tmp/wslconfig.autodeploy"
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
            else
                container_environment="none"
            fi
        }
        function CheckHypervisorEnvironment() {
            which "virt-what" > "/dev/null" 2>&1
            if [ "$?" -eq "1" ]; then
                apt update && apt install virt-what -qy
                which "virt-what" > "/dev/null" 2>&1
                if [ "$?" -eq "1" ]; then
                    echo "virt-what has not been installed!"
                    exit 1
                fi
            fi && hypervisor_environment=$(virt-what) && if [ "${hypervisor_environment}" == "" ]; then
                hypervisor_environment="none"
            elif [ "${hypervisor_environment}" == "kvm" ]; then
                HYPERVISOR_AGENT=("qemu-guest-agent")
            elif [ "${hypervisor_environment}" == "vmware" ]; then
                HYPERVISOR_AGENT=("open-vm-tools")
            elif [ "${hypervisor_environment}" == "virtualbox" ]; then
                HYPERVISOR_AGENT=("virtualbox-guest-dkms")
            fi
        }
        CheckContainerEnvironment
        CheckHypervisorEnvironment
    }
    function GenerateDomain() {
        NEW_DOMAIN=("localdomain")
    }
    function GenerateHostname() {
        NEW_HOSTNAME="Ubuntu-$(date '+%Y%m%d%H%M%S')"
    }
    function GetLSBCodename() {
        LSBCodename_LTS="jammy"
        LSBCodename_NON_LTS="impish"
        Version_LTS="22.04"
        Version_NON_LTS="21.10"
        which "lsb_release" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            CURRENT_LSBCodename=$(lsb_release -cs)
            CURRENT_Version=$(lsb_release -rs)
            if [ "$(lsb_release -ds | grep 'LTS')" == "" ]; then
                LSBCodename="${LSBCodename_NON_LTS}"
            else
                LSBCodename="${LSBCodename_LTS}"
            fi
        else
            if [ -f '/etc/os-release' ]; then
                CURRENT_LSBCodename=$(cat "/etc/os-release" | grep "UBUNTU\_CODENAME\=" | sed "s/UBUNTU\_CODENAME\=//g")
                CURRENT_Version=$(cat "/etc/os-release" | grep "VERSION_ID\=" | sed "s/VERSION_ID\=//g" | tr -d "\"")
                if [ "$(cat '/etc/os-release' | grep "VERSION\=" | grep 'LTS')" == "" ]; then
                    LSBCodename="${LSBCodename_NON_LTS}"
                else
                    LSBCodename="${LSBCodename_LTS}"
                fi
            fi
        fi
        if [ "$(awk -v NUM1=$Version_LTS -v NUM2=$Version_NON_LTS 'BEGIN{print (NUM1 > NUM2) ? 1 : 0}')" -eq "1" ]; then
            LSBCodename="${LSBCodename_LTS}"
            LSBCodename_LATEST="${LSBCodename_LTS}"
        else
            LSBCodename_LATEST="${LSBCodename_NON_LTS}"
        fi
        if [ "$(awk -v NUM1=$CURRENT_Version -v NUM2=$Version_LTS 'BEGIN{print (NUM1 > NUM2) ? 1 : 0}')" -eq "1" ] && [ "$(awk -v NUM1=$CURRENT_Version -v NUM2=$Version_NON_LTS 'BEGIN{print (NUM1 > NUM2) ? 1 : 0}')" -eq "1" ]; then
            LSBCodename="${CURRENT_LSBCodename}"
        fi
        if [ "${LSBCodename}" == "" ]; then
            LSBCodename="${LSBCodename_LATEST}"
        fi
    }
    function GetOSArchitecture() {
        which "dpkg" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            OSArchitecture=$(dpkg --print-architecture)
        else
            if [ "$(uname -m)" == "aarch64" ]; then
                OSArchitecture="arm64"
            elif [ "$(uname -m)" == "x86_64" ]; then
                OSArchitecture="amd64"
            fi
        fi
        if [ "${OSArchitecture}" == "arm64" ]; then
            MIRROR_URL="ubuntu-ports"
        elif [ "${OSArchitecture}" == "amd64" ]; then
            MIRROR_URL="ubuntu"
        else
            echo "Unsupported architecture."
            exit 1
        fi
    }
    function SetGHProxyDomain() {
        export GHPROXY_URL="ghproxy.com"
    }
    CheckDNSConfiguration
    GenerateDomain && CheckMachineEnvironment
    GenerateHostname
    GetLSBCodename
    GetOSArchitecture
    SetGHProxyDomain
}
# Set Repository Mirror
function SetRepositoryMirror() {
    mirror_list=(
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/${MIRROR_URL} ${LSBCodename} main restricted universe multiverse"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/${MIRROR_URL} ${LSBCodename}-backports main restricted universe multiverse"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/${MIRROR_URL} ${LSBCodename}-security main restricted universe multiverse"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/${MIRROR_URL} ${LSBCodename}-updates main restricted universe multiverse"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/${MIRROR_URL} ${LSBCodename} main restricted universe multiverse"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/${MIRROR_URL} ${LSBCodename}-backports main restricted universe multiverse"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/${MIRROR_URL} ${LSBCodename}-security main restricted universe multiverse"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/${MIRROR_URL} ${LSBCodename}-updates main restricted universe multiverse"
    )
    if [ ! -d "/etc/apt/sources.list.d" ]; then
        mkdir "/etc/apt/sources.list.d"
    else
        rm -rf /etc/apt/sources.list.d/*.*
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
        "/etc/chrony/chrony.conf"
        "/etc/cockpit/cockpit.conf"
        "/etc/default/ufw"
        "/etc/docker/daemon.json"
        "/etc/fail2ban/fail2ban.local"
        "/etc/fail2ban/jail.local"
        "/etc/fail2ban/jail.d/fail2ban_default.conf"
        "/etc/hostname"
        "/etc/hosts"
        "/etc/netplan/netplan.yaml"
        "/etc/sysctl.conf"
        "/etc/systemd/resolved.conf.d/resolved.conf"
        "/etc/zsh/oh-my-zsh.zshrc"
    )
    if [ "${read_only}" == "TRUE" ]; then
        for file_list_task in "${!file_list[@]}"; do
            if [ -d "${file_list[$file_list_task]}" ] || [ -f "${file_list[$file_list_task]}" ]; then
                chattr +i "${file_list[$file_list_task]}" > "/dev/null" 2>&1
            fi
        done
    elif [ "${read_only}" == "FALSE" ]; then
        for file_list_task in "${!file_list[@]}"; do
            if [ -d "${file_list[$file_list_task]}" ] || [ -f "${file_list[$file_list_task]}" ]; then
                chattr -i "${file_list[$file_list_task]}" > "/dev/null" 2>&1
            fi
        done
    fi
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
            "cn.ntp.org.cn"
            "time.apple.com"
            "time.windows.com"
            "time.izatcloud.net"
            "pool.ntp.org"
            "asia.pool.ntp.org"
            "cn.pool.ntp.org"
            "${DHCP_NTP[@]}"
        )
        which "chronyc" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/tmp/chrony.autodeploy" && for chrony_list_task in "${!chrony_list[@]}"; do
                echo "${chrony_list[$chrony_list_task]}" >> "/tmp/chrony.autodeploy"
            done && for chrony_ntp_list_task in "${!chrony_ntp_list[@]}"; do
                if [ "${chrony_ntp_list[$chrony_ntp_list_task]}" == "ntp.ntsc.ac.cn" ] || [ "${chrony_ntp_list[$chrony_ntp_list_task]}" == "cn.ntp.org.cn" ] || [ "$(echo ${DHCP_NTP[@]} | grep ${chrony_ntp_list[$chrony_ntp_list_task]})" != "" ]; then
                    echo "server ${chrony_ntp_list[$chrony_ntp_list_task]} iburst prefer" >> "/tmp/chrony.autodeploy"
                else
                    echo "server ${chrony_ntp_list[$chrony_ntp_list_task]} iburst" >> "/tmp/chrony.autodeploy"
                fi
            done && cat "/tmp/chrony.autodeploy" > "/etc/chrony/chrony.conf" && rm -rf "/tmp/chrony.autodeploy" && OPRATIONS="restart" && SERVICE_NAME="chrony" && CallServiceController && sleep 5s && chronyc activity && chronyc tracking && chronyc clients && hwclock -w
        fi
    }
    function ConfigureCockpit() {
        cockpit_list=(
            "[Session]"
            "IdleTimeout = 60"
            "[WebService]"
            "MaxStartups = 3:75:5"
        )
        which "cockpit-bridge" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            if [ "${container_environment}" != "docker" ] && [ "${container_environment}" != "wsl2" ]; then
                rm -rf "/tmp/cockpit.autodeploy" && for cockpit_list_task in "${!cockpit_list[@]}"; do
                    echo "${cockpit_list[$cockpit_list_task]}" >> "/tmp/cockpit.autodeploy"
                done && cat "/tmp/cockpit.autodeploy" > "/etc/cockpit/cockpit.conf" && rm -rf "/tmp/cockpit.autodeploy" && if [ "${container_environment}" != "docker" ] && [ "${container_environment}" != "wsl2" ]; then
                    OPRATIONS="restart" && SERVICE_NAME="cockpit" && CallServiceController
                fi
            fi
        fi
    }
    function ConfigureCrontab() {
        crontab_list=(
            "0 0 * * 7 sudo apt update && sudo apt full-upgrade -qy && sudo apt -t ${LSBCodename}-backports full-upgrade -qy && sudo apt autoremove -qy"
            "@reboot sudo rm -rf /root/.*_history /root/.ssh/known_hosts*"
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
            if [ "${container_environment}" != "docker" ] && [ "${container_environment}" != "wsl2" ]; then
                if [ ! -d "/docker" ]; then
                    mkdir "/docker"
                fi && chown -R ${DEFAULT_USERNAME}:docker "/docker" && chmod -R 775 "/docker"
                if [ ! -d "/etc/docker" ]; then
                    mkdir "/etc/docker"
                fi
                rm -rf "/tmp/docker.autodeploy" && for docker_list_task in "${!docker_list[@]}"; do
                    echo "${docker_list[$docker_list_task]}" >> "/tmp/docker.autodeploy"
                done && cat "/tmp/docker.autodeploy" > "/etc/docker/daemon.json" && OPRATIONS="restart" && SERVICE_NAME="docker" && CallServiceController && rm -rf "/tmp/docker.autodeploy"
            fi
        fi
        if [ "${container_environment}" == "wsl2" ]; then
            if [ ! -d "/docker" ]; then
                mkdir "/docker"
            fi
        fi
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
            "port = 9022"
        )
        which "fail2ban-client" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            if [ "${container_environment}" != "docker" ] && [ "${container_environment}" != "wsl2" ]; then
                if [ -d "/etc/fail2ban/jail.d" ]; then
                    rm -rf /etc/fail2ban/jail.d/*
                else
                    mkdir "/etc/fail2ban/jail.d"
                fi
                if [ -f "/etc/fail2ban/fail2ban.conf" ]; then
                    cat "/etc/fail2ban/fail2ban.conf" > "/etc/fail2ban/fail2ban.local"
                fi
                if [ -f "/etc/fail2ban/jail.conf" ]; then
                    cat "/etc/fail2ban/jail.conf" | sed "s/action\ \=\ iptables\-allports/action\ \=\ ufw/g;s/banaction\ \=\ iptables\-multiport/banaction\ \=\ ufw/g;s/banaction\ \=\ iptables\-multiport\-log/banaction\ \=\ ufw/g;s/banaction\ \=\ ufw\-log/banaction\ \=\ ufw/g;s/banaction\_allports\ \=\ iptables\-allports/banaction\_allports\ \=\ ufw/g" > "/etc/fail2ban/jail.local"
                fi
                rm -rf "/tmp/fail2ban.autodeploy" && for fail2ban_list_task in "${!fail2ban_list[@]}"; do
                    echo "${fail2ban_list[$fail2ban_list_task]}" >> "/tmp/fail2ban.autodeploy"
                done && cat "/tmp/fail2ban.autodeploy" > "/etc/fail2ban/jail.d/fail2ban_default.conf" && rm -rf "/tmp/fail2ban.autodeploy" && if [ "${container_environment}" != "docker" ] && [ "${container_environment}" != "wsl2" ]; then
                    fail2ban-client reload && sleep 5s && fail2ban-client status
                fi
            fi
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
                if [ "${container_environment}" == "wsl2" ]; then
                    GIT_COMMIT_GPGSIGN="false"
                    GIT_USER_SIGNINGKEY=""
                fi
                if [ "${gitconfig_value_list[$gitconfig_list_task]}" != "" ]; then
                    git config --global ${gitconfig_key_list[$gitconfig_list_task]} "${gitconfig_value_list[$gitconfig_list_task]}"
                fi
            done
        fi
        if [ -f "/root/.gitconfig" ] && [ "${GIT_USER_CONFIG}" != "TRUE" ]; then
            mv "/root/.gitconfig" "/root/.gitconfig.bak" && GIT_COMMIT_GPGSIGN="" && GIT_GPG_PROGRAM="" && GIT_HTTP_PROXY="" && GIT_HTTPS_PROXY="" && GIT_USER_NAME="" && GIT_USER_EMAIL="" && GIT_USER_SIGNINGKEY="" && GIT_USER_CONFIG="TRUE" && ConfigureGit && mv "/root/.gitconfig" "/home/${DEFAULT_USERNAME}/.gitconfig" && chown -R $DEFAULT_USERNAME:$DEFAULT_USERNAME "/home/${DEFAULT_USERNAME}/.gitconfig" && mv "/root/.gitconfig.bak" "/root/.gitconfig"
        fi
    }
    function ConfigureGPG() {
        GPG_PUBKEY=""
        if [ "${GPG_PUBKEY}" == "" ]; then
            GPG_PUBKEY="DD982DAAB9C71C78F9563E5207EB56787030D792"
        fi
        which "gpg" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/home/${DEFAULT_USERNAME}/.gnupg" "/root/.gnupg" && gpg --keyserver hkps://keys.openpgp.org --recv ${GPG_PUBKEY} && gpg --keyserver hkps://keyserver.ubuntu.com --recv ${GPG_PUBKEY} && echo "${GPG_PUBKEY}" | awk 'BEGIN { FS = "\n" }; { print $1":6:" }' | gpg --import-ownertrust && GPG_PUBKEY_ID_A=$(gpg --list-keys --keyid-format LONG | grep "pub\|sub" | awk '{print $2, $4}' | grep "\[A\]" | awk '{print $1}' | awk -F '/' '{print $2}') && GPG_PUBKEY_ID_C=$(gpg --list-keys --keyid-format LONG | grep "pub\|sub" | awk '{print $2, $4}' | grep "\[C\]" | awk '{print $1}' | awk -F '/' '{print $2}')
            if [ "${GPG_PUBKEY_ID_A}" != "" ]; then
                if [ "$(apt list --installed | grep 'ubuntu-desktop')" != "" ]; then
                    PINENTRY_PROGRAM_NAME="pinentry-gnome3"
                else
                    PINENTRY_PROGRAM_NAME="pinentry-curses"
                fi
                gpg_agent_list=(
                    "enable-ssh-support"
                    "pinentry-program /usr/bin/${PINENTRY_PROGRAM_NAME}"
                )
                rm -rf "/root/.gnupg/gpg-agent.conf" && for gpg_agent_list_task in "${!gpg_agent_list[@]}"; do
                    echo "${gpg_agent_list[$gpg_agent_list_task]}" >> "/root/.gnupg/gpg-agent.conf"
                done && echo "${GPG_PUBKEY_ID_A}" > "/root/.gnupg/sshcontrol" && gpg --export-ssh-key ${GPG_PUBKEY_ID_C} > "/root/.gnupg/authorized_keys" && if [ -d "/root/.gnupg" ]; then
                    mv "/root/.gnupg" "/home/${DEFAULT_USERNAME}/.gnupg" && chown -R $DEFAULT_USERNAME:$DEFAULT_USERNAME "/home/${DEFAULT_USERNAME}/.gnupg"
                fi
            fi
        fi
        if [ "${container_environment}" == "wsl2" ]; then
            rm -rf "/home/${DEFAULT_USERNAME}/.gnupg/gpg-agent.conf" "/home/${DEFAULT_USERNAME}/.gnupg/sshcontrol"
        fi
    }
    function ConfigureGrub() {
        which "update-grub" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            if [ "${container_environment}" != "docker" ] && [ "${container_environment}" != "lxc" ] && [ "${container_environment}" != "wsl2" ]; then
                if [ -f "/usr/share/grub/default/grub" ]; then
                    rm -rf "/tmp/grub.autodeploy" && cat "/usr/share/grub/default/grub" > "/tmp/grub.autodeploy" && cat "/tmp/grub.autodeploy" > "/etc/default/grub" && update-grub && rm -rf "/tmp/grub.autodeploy"
                fi
            fi
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
        network_interface=($(cat "/proc/net/dev" | grep -v "docker0\|lo\|wg0" | grep "\:" | sed "s/[[:space:]]//g" | cut -d ":" -f 1 | sort | uniq))
        which "netplan" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            if [ "${container_environment}" != "docker" ] && [ "${container_environment}" != "wsl2" ]; then
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
                done && cat "/tmp/netplan.autodeploy" > "/etc/netplan/netplan.yaml" && rm -rf "/tmp/netplan.autodeploy"
                if [ "${container_environment}" != "docker" ] && [ "${container_environment}" != "wsl2" ]; then
                    netplan apply
                fi
            fi
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
            rm -rf "/home/${DEFAULT_USERNAME}/.ssh" && mkdir "/home/${DEFAULT_USERNAME}/.ssh" && if [ -f "/home/${DEFAULT_USERNAME}/.gnupg/authorized_keys" ]; then
                mv "/home/${DEFAULT_USERNAME}/.gnupg/authorized_keys" "/home/${DEFAULT_USERNAME}/.ssh/authorized_keys"
            else
                touch "/home/${DEFAULT_USERNAME}/.ssh/authorized_keys"
            fi && touch "/home/${DEFAULT_USERNAME}/.ssh/known_hosts" && ssh-keygen -t dsa -b 1024 -f "/home/${DEFAULT_USERNAME}/.ssh/id_dsa" -C "${DEFAULT_USERNAME}@${NEW_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ecdsa -b 384 -f "/home/${DEFAULT_USERNAME}/.ssh/id_ecdsa" -C "${DEFAULT_USERNAME}@${NEW_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ed25519 -f "/home/${DEFAULT_USERNAME}/.ssh/id_ed25519" -C "${DEFAULT_USERNAME}@${NEW_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t rsa -b 4096 -f "/home/${DEFAULT_USERNAME}/.ssh/id_rsa" -C "${DEFAULT_USERNAME}@${NEW_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && chown -R $DEFAULT_USERNAME:$DEFAULT_USERNAME "/home/${DEFAULT_USERNAME}/.ssh" && chown -R $DEFAULT_USERNAME:$DEFAULT_USERNAME /home/${DEFAULT_USERNAME}/.ssh/* && chmod 400 /home/${DEFAULT_USERNAME}/.ssh/id_* && chmod 600 "/home/${DEFAULT_USERNAME}/.ssh/authorized_keys" && chmod 644 "/home/${DEFAULT_USERNAME}/.ssh/known_hosts" && chmod 644 /home/${DEFAULT_USERNAME}/.ssh/id_*.pub && chmod 700 "/home/${DEFAULT_USERNAME}/.ssh"
        fi
    }
    function ConfigurePostfix() {
        if [ -f "/etc/postfix/main.cf" ]; then
            if [ "$(cat '/etc/postfix/main.cf' | grep 'myhostname\ \=\ ')" != "" ]; then
                CURRENT_HOSTNAME=$(cat "/etc/postfix/main.cf" | grep "myhostname\ \=\ " | sed "s/myhostname\ \=\ //g")
                cat "/etc/postfix/main.cf" | sed "s/$CURRENT_HOSTNAME/$NEW_HOSTNAME/g" > "/tmp/main.cf.autodeploy" && cat "/tmp/main.cf.autodeploy" > "/etc/postfix/main.cf" && rm -rf "/tmp/main.cf.autodeploy"
            fi
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
        if [ -f "/root/.config/pip/pip.conf" ]; then
            if [ ! -d "/home/${DEFAULT_USERNAME}/.config" ]; then
                mkdir "/home/${DEFAULT_USERNAME}/.config"
            fi
            if [ ! -d "/home/${DEFAULT_USERNAME}/.config/pip" ]; then
                mkdir "/home/${DEFAULT_USERNAME}/.config/pip"
            fi
            rm -rf "/home/${DEFAULT_USERNAME}/.config/pip/pip.conf" && cp -rf "/root/.config/pip/pip.conf" "/home/${DEFAULT_USERNAME}/.config/pip/pip.conf" && chown -R $DEFAULT_USERNAME:$DEFAULT_USERNAME "/home/${DEFAULT_USERNAME}/.config" && chown -R $DEFAULT_USERNAME:$DEFAULT_USERNAME "/home/${DEFAULT_USERNAME}/.config/pip" && chown -R $DEFAULT_USERNAME:$DEFAULT_USERNAME "/home/${DEFAULT_USERNAME}/.config/pip/pip.conf"
        fi
    }
    function ConfigureResolved() {
        resolved_list=(
            "[Resolve]"
            "DNS=${CURRENT_DNS_LINE} ${CUSTOM_DNS_LINE}"
            "DNSOverTLS=opportunistic"
            "DNSSEC=allow-downgrade"
            "DNSStubListener=false"
            "Domains=${NEW_DOMAIN[*]}"
        )
        which "resolvectl" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            if [ "${container_environment}" != "docker" ] && [ "${container_environment}" != "wsl2" ]; then
                if [ ! -d "/etc/systemd/resolved.conf.d" ]; then
                    mkdir "/etc/systemd/resolved.conf.d"
                else
                    rm -rf /etc/systemd/resolved.conf.d/*.conf
                fi
                rm -rf "/tmp/resolved.autodeploy" && for resolved_list_task in "${!resolved_list[@]}"; do
                    echo "${resolved_list[$resolved_list_task]}" | sed "s/DNS\=\ /DNS\=/g" >> "/tmp/resolved.autodeploy"
                done && cat "/tmp/resolved.autodeploy" > "/etc/systemd/resolved.conf.d/resolved.conf" && OPRATIONS="restart" && SERVICE_NAME="systemd-resolved" && CallServiceController && rm -rf "/tmp/resolved.autodeploy" && if [ -f "/etc/resolv.conf" ]; then
                    chattr -i "/etc/resolv.conf" > "/dev/null" 2>&1
                    rm -rf "/etc/resolv.conf" && ln -s "/run/systemd/resolve/resolv.conf" "/etc/resolv.conf"
                fi
            else
                resolv_conf_list=(
                    ${CURRENT_DNS[@]}
                    ${CUSTOM_DNS[@]}
                )
                rm -rf "/tmp/resolv.autodeploy" && for resolv_conf_list_task in "${!resolv_conf_list[@]}"; do
                    echo "nameserver ${resolv_conf_list[$resolv_conf_list_task]}" >> "/tmp/resolv.autodeploy"
                done && echo "search ${NEW_DOMAIN[*]}" >> "/tmp/resolv.autodeploy" && if [ -f "/etc/resolv.conf" ]; then
                    chattr -i "/etc/resolv.conf" > "/dev/null" 2>&1
                    if [ "$?" -eq "1" ]; then
                        rm -rf "/etc/resolv.conf"
                    fi
                fi && rm -rf "/etc/resolv.conf" && cat "/tmp/resolv.autodeploy" > "/etc/resolv.conf" && rm -rf "/tmp/resolv.autodeploy" && chattr +i "/etc/resolv.conf"
            fi
        else
            resolv_conf_list=(
                ${CURRENT_DNS[@]}
                ${CUSTOM_DNS[@]}
            )
            rm -rf "/tmp/resolv.autodeploy" && for resolv_conf_list_task in "${!resolv_conf_list[@]}"; do
                echo "nameserver ${resolv_conf_list[$resolv_conf_list_task]}" >> "/tmp/resolv.autodeploy"
            done && echo "search ${NEW_DOMAIN[*]}" >> "/tmp/resolv.autodeploy" && if [ -f "/etc/resolv.conf" ]; then
                chattr -i "/etc/resolv.conf" > "/dev/null" 2>&1
                if [ "$?" -eq "1" ]; then
                    rm -rf "/etc/resolv.conf"
                fi
            fi && rm -rf "/etc/resolv.conf" && cat "/tmp/resolv.autodeploy" > "/etc/resolv.conf" && rm -rf "/tmp/resolv.autodeploy" && chattr +i "/etc/resolv.conf"
        fi
    }
    function ConfigureSshd() {
        if [ -f "/usr/share/openssh/sshd_config" ]; then
            SSHD_CONFIG_ADDITIONAL="" && if [ "${container_environment}" != "docker" ] && [ "${container_environment}" != "wsl2" ]; then
                SSHD_CONFIG_ADDITIONAL="${SSHD_CONFIG_ADDITIONAL}s/\#Port\ 22/Port 9022/g;"
            fi && if [ "${container_environment}" != "wsl2" ]; then
                SSHD_CONFIG_ADDITIONAL="${SSHD_CONFIG_ADDITIONAL}s/\#PubkeyAuthentication\ yes/PubkeyAuthentication\ yes/g;"
            fi && cat "/usr/share/openssh/sshd_config" | sed "s/\#PasswordAuthentication\ yes/PasswordAuthentication\ yes/g;s/\#PermitRootLogin\ prohibit\-password/PermitRootLogin\ yes/g;${SSHD_CONFIG_ADDITIONAL}" > "/tmp/sshd_config.autodeploy" && cat "/tmp/sshd_config.autodeploy" > "/etc/ssh/sshd_config" && rm -rf "/tmp/sshd_config.autodeploy"
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
    function ConfigureTuned() {
        which "tuned-adm" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            if [ "${container_environment}" != "docker" ] && [ "${container_environment}" != "wsl2" ]; then
                tuned-adm profile "$(tuned-adm recommend)" && tuned-adm active
            fi
        fi
    }
    function ConfigureUfw() {
        which "ufw" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ] && [ -f "/etc/default/ufw" ]; then
            if [ "${container_environment}" != "docker" ] && [ "${container_environment}" != "wsl2" ]; then
                echo "$(cat '/etc/default/ufw' | sed 's/DEFAULT\_APPLICATION\_POLICY\=\"ACCEPT\"/DEFAULT\_APPLICATION\_POLICY\=\"REJECT\"/g;s/DEFAULT\_APPLICATION\_POLICY\=\"DROP\"/DEFAULT\_APPLICATION\_POLICY\=\"REJECT\"/g;s/DEFAULT\_APPLICATION\_POLICY\=\"SKIP\"/DEFAULT\_APPLICATION\_POLICY\=\"REJECT\"/g;s/DEFAULT\_FORWARD\_POLICY\=\"DROP\"/DEFAULT\_FORWARD\_POLICY\=\"ACCEPT\"/g;s/DEFAULT\_FORWARD\_POLICY\=\"REJECT\"/DEFAULT\_FORWARD\_POLICY\=\"ACCEPT\"/g;s/DEFAULT\_INPUT\_POLICY\=\"ACCEPT\"/DEFAULT\_INPUT\_POLICY\=\"REJECT\"/g;s/DEFAULT\_INPUT\_POLICY\=\"DROP\"/DEFAULT\_INPUT\_POLICY\=\"REJECT\"/g;s/DEFAULT\_OUTPUT\_POLICY\=\"DROP\"/DEFAULT\_OUTPUT\_POLICY\=\"ACCEPT\"/g;s/DEFAULT\_OUTPUT\_POLICY\=\"REJECT\"/DEFAULT\_OUTPUT\_POLICY\=\"ACCEPT\"/g;s/MANAGE\_BUILTINS\=yes/MANAGE\_BUILTINS\=no/g;s/IPV6\=no/IPV6\=yes/g')" > "/tmp/ufw.autodeploy" && cat "/tmp/ufw.autodeploy" > "/etc/default/ufw" && rm -rf "/tmp/ufw.autodeploy"
                if [ "${container_environment}" != "docker" ] && [ "${container_environment}" != "wsl2" ]; then
                    ufw reload && ufw reset && ufw allow 123/udp && ufw limit 22/tcp && ufw allow 323/udp && ufw allow 51820/udp && ufw limit 9022/tcp && ufw allow 9090/tcp && ufw enable && ufw status verbose
                else
                    ufw disable > "/dev/null" 2>&1
                fi
            fi
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
        fi && WAN_INTERFACE=$(cat '/proc/net/dev' | grep -v 'docker0\|lo\|wg0' | grep ':' | sed 's/[[:space:]]//g' | cut -d ':' -f 1 | sort | uniq | head -n 1)
        if [ ! -d "/etc/wireguard" ]; then
            mkdir "/etc/wireguard"
        else
            rm -rf /etc/wireguard/*
        fi
        which "wg" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            if [ "${container_environment}" != "docker" ] && [ "${container_environment}" != "wsl2" ]; then
                wireguard_list=(
                    "[Interface]"
                    "Address = ${TUNNEL_CLIENT_V4}, ${TUNNEL_CLIENT_V6}"
                    "DNS = ${CURRENT_DNS_WG[@]}, ${CUSTOM_DNS_WG[@]}"
                    "ListenPort = 51820"
                    "PostDown = rm -rf /etc/resolv.conf; ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf; ufw route delete allow in on wg0 out on ${WAN_INTERFACE}"
                    "PostUp = rm -rf /etc/resolv.conf; ln -s /run/resolvconf/resolv.conf /etc/resolv.conf; ufw route allow in on wg0 out on ${WAN_INTERFACE}"
                    "PreDown = iptables -t nat -D POSTROUTING -o ${WAN_INTERFACE} -j MASQUERADE; ip6tables -t nat -D POSTROUTING -o ${WAN_INTERFACE} -j MASQUERADE"
                    "PreUp = iptables -t nat -A POSTROUTING -o ${WAN_INTERFACE} -j MASQUERADE; ip6tables -t nat -A POSTROUTING -o ${WAN_INTERFACE} -j MASQUERADE"
                    "PrivateKey = $(wg genkey | tee '/tmp/wireguard.autodeploy')"
                    "# [Peer]"
                    "# AllowedIPs = ${TUNNEL_CLIENT_V4}, ${TUNNEL_CLIENT_V6}"
                    "# Endpoint = 127.0.0.1:51820"
                    "# PersistentKeepalive = 5"
                    "# PresharedKey = $(wg genpsk)"
                    "# PublicKey = $(cat '/tmp/wireguard.autodeploy' | wg pubkey)"
                )
                rm -rf "/tmp/wireguard.autodeploy" && for wireguard_list_task in "${!wireguard_list[@]}"; do
                    echo "${wireguard_list[$wireguard_list_task]}" | sed "s/\,\ $//g;s/^\,\ //g" >> "/tmp/wireguard.autodeploy"
                done && cat "/tmp/wireguard.autodeploy" > "/etc/wireguard/wg0.conf" && chown -R ${DEFAULT_USERNAME}:sudo "/etc/wireguard" && chmod -R 775 "/etc/wireguard" && chown -R ${DEFAULT_USERNAME}:${DEFAULT_USERNAME} "/etc/wireguard/wg0.conf" && chmod 600 "/etc/wireguard/wg0.conf" && rm -rf "/tmp/wireguard.autodeploy" && if [ "${container_environment}" != "docker" ] && [ "${container_environment}" != "wsl2" ]; then
                    OPRATIONS="enable" && SERVICE_NAME="wg-quick@wg0" && CallServiceController && if [ -f "/lib/systemd/system/wg-quick@.service" ]; then
                        if [ ! -f "/lib/systemd/system/wg-quick@.service.bak" ]; then
                            cp "/lib/systemd/system/wg-quick@.service" "/lib/systemd/system/wg-quick@.service.bak"
                        fi
                        cat "/lib/systemd/system/wg-quick@.service.bak" | sed "s/RestartSec\=5\nRestart\=always//g;s/RemainAfterExit\=yes/RemainAfterExit\=yes\nRestartSec\=5\nRestart\=always/g;s/Type\=oneshot/\#Type\=oneshot/g" > "/tmp/wireguard.autodeploy" && cat "/tmp/wireguard.autodeploy" > "/lib/systemd/system/wg-quick@.service" && rm -rf "/tmp/wireguard.autodeploy" && OPRATIONS="daemon-reload" && CallServiceController
                    fi && OPRATIONS="start" && CallServiceController && wg
                fi
            fi
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
                cp -rf "/etc/zsh/oh-my-zsh" "/home/${DEFAULT_USERNAME}/.oh-my-zsh" && chown -R $DEFAULT_USERNAME:$DEFAULT_USERNAME "/home/${DEFAULT_USERNAME}/.oh-my-zsh"
                if [ -f "/etc/zsh/oh-my-zsh.zshrc" ]; then
                    cp -rf "/etc/zsh/oh-my-zsh.zshrc" "/home/${DEFAULT_USERNAME}/.zshrc" && chown -R $DEFAULT_USERNAME:$DEFAULT_USERNAME "/home/${DEFAULT_USERNAME}/.zshrc"
                fi
            fi
        }
        GenerateCommandPath
        GenerateOMZProfile
    }
    ConfigureChrony
    ConfigureCockpit
    ConfigureCrontab
    ConfigureDockerEngine
    ConfigureFail2Ban
    ConfigureGPG && ConfigureGit
    ConfigureGrub
    ConfigureLandscape
    ConfigureNetplan
    ConfigureOpenSSH
    ConfigurePostfix
    ConfigurePythonPyPI
    ConfigureResolved
    ConfigureSshd
    ConfigureSysctl
    ConfigureUfw
    ConfigureWireGuard
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
    function ConfigureDefaultUser() {
        if [ "${container_environment}" != "docker" ]; then
            DEFAULT_FIRSTNAME="User"
            DEFAULT_LASTNAME="Ubuntu"
            DEFAULT_FULLNAME="${DEFAULT_LASTNAME} ${DEFAULT_FIRSTNAME}"
            DEFAULT_USERNAME="ubuntu"
            DEFAULT_PASSWORD='*Ubuntu123*'
            crontab_list=(
                "@reboot rm -rf /home/${DEFAULT_USERNAME}/.*_history /home/${DEFAULT_USERNAME}/.ssh/known_hosts*"
            )
            if [ -d "/home" ]; then
                USER_LIST=($(ls "/home" | grep -v "${DEFAULT_USERNAME}" | awk "{print $2}") ${DEFAULT_USERNAME})
            else
                mkdir "/home" && USER_LIST=(${DEFAULT_USERNAME})
            fi && for USER_LIST_TASK in "${!USER_LIST[@]}"; do
                userdel -rf "${USER_LIST[$USER_LIST_TASK]}" > "/dev/null" 2>&1
            done
            useradd -c "${DEFAULT_FULLNAME}" -d "/home/${DEFAULT_USERNAME}" -s "/bin/zsh" -m "${DEFAULT_USERNAME}" && echo $DEFAULT_USERNAME:$DEFAULT_PASSWORD | chpasswd && if [ "${container_environment}" != "docker" ] && [ "${container_environment}" != "wsl2" ]; then
                adduser "${DEFAULT_USERNAME}" "docker"
            fi && adduser "${DEFAULT_USERNAME}" "sudo"
            which "crontab" > "/dev/null" 2>&1
            if [ "$?" -eq "0" ]; then
                rm -rf "/tmp/crontab.autodeploy" && for crontab_list_task in "${!crontab_list[@]}"; do
                    echo "${crontab_list[$crontab_list_task]}" >> "/tmp/crontab.autodeploy"
                done && crontab -u "${DEFAULT_USERNAME}" "/tmp/crontab.autodeploy" && crontab -lu "${DEFAULT_USERNAME}" && rm -rf "/tmp/crontab.autodeploy"
            fi
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
    function ConfigureRootUser() {
        LOCK_ROOT="TRUE"
        ROOT_PASSWORD='R00t@123!'
        echo root:$ROOT_PASSWORD | chpasswd && if [ "${LOCK_ROOT}" == "TRUE" ]; then
            passwd -l "root"
        else
            passwd -u "root"
        fi
    }
    function ConfigureTimeZone() {
        if [ -f "/etc/localtime" ]; then
            rm -rf "/etc/localtime"
        fi && ln -s "/usr/share/zoneinfo/Asia/Shanghai" "/etc/localtime"
    }
    ConfigureDefaultShell
    ConfigureDefaultUser
    ConfigureHostfile
    ConfigureLocales
    ConfigureRootUser
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
        if [ "${container_environment}" != "docker" ] && [ "${container_environment}" != "wsl2" ]; then
            rm -rf "/usr/share/keyrings/docker-archive-keyring.gpg" && curl -fsSL "https://mirrors.ustc.edu.cn/docker-ce/linux/ubuntu/gpg" | gpg --dearmor -o "/usr/share/keyrings/docker-archive-keyring.gpg"
            echo "deb [arch=${OSArchitecture} signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://mirrors.ustc.edu.cn/docker-ce/linux/ubuntu ${LSBCodename} stable" > "/etc/apt/sources.list.d/docker.list"
            apt update && apt purge -qy containerd docker docker-engine docker.io runc && for app_list_task in "${!app_list[@]}"; do
                apt-cache show ${app_list[$app_list_task]} && if [ "$?" -eq "0" ]; then
                    apt install -qy ${app_list[$app_list_task]}
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
    InstallDockerEngine
    InstallOhMyZsh
}
# Install Dependency Packages
function InstallDependencyPackages() {
    app_extended_list=(
        "cockpit"
        "cockpit-pcp"
        "fail2ban"
        "netplan.io"
        "resolvconf"
        "systemd"
        "tuned"
        "ufw"
        "wireguard"
    )
    app_regular_list=(
        "apt-file"
        "apt-transport-https"
        "ca-certificates"
        "chrony"
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
        "mtr-tiny"
        "nano"
        "neofetch"
        "net-tools"
        "nfs-common"
        "nmap"
        "ntfs-3g"
        "openssh-client"
        "openssh-server"
        "p7zip-full"
        "pinentry-curses"
        "pinentry-gnome3"
        "postfix"
        "python3"
        "python3-pip"
        "qrencode"
        "rar"
        "realmd"
        "sudo"
        "tcpdump"
        "tshark"
        "udisks2"
        "udisks2-bcache"
        "udisks2-btrfs"
        "udisks2-lvm2"
        "udisks2-zram"
        "unrar"
        "unzip"
        "update-notifier-common"
        "vim"
        "virt-what"
        "wget"
        "whois"
        "zip"
        "zsh"
    )
    hypervisor_agent_list=(
        "qemu-guest-agent"
        "open-vm-tools"
        "virtualbox-guest-dkms"
    )
    if [ "${container_environment}" != "docker" ] && [ "${container_environment}" != "wsl2" ]; then
        app_list=(${app_regular_list[@]} ${app_extended_list[*]} ${HYPERVISOR_AGENT[*]})
    else
        app_list=(${app_regular_list[*]} ${HYPERVISOR_AGENT[*]})
    fi
    apt update && for app_list_task in "${!app_list[@]}"; do
        apt-cache show ${app_list[$app_list_task]} && if [ "$?" -eq "0" ]; then
            apt install -qy ${app_list[$app_list_task]}
        fi
    done && if [ "${container_environment}" == "docker" ] || [ "${container_environment}" == "wsl2" ]; then
        for app_extended_list_task in "${!app_extended_list[@]}"; do
            if [ "$(apt list --installed | grep ${app_extended_list[$app_extended_list_task]})" != "" ]; then
                apt purge -qy ${app_extended_list[$app_extended_list_task]} && apt autoremove -qy
            fi
        done
    fi && for hypervisor_agent_list_task in "${!hypervisor_agent_list[@]}"; do
        if [ "${hypervisor_agent_list[$hypervisor_agent_list_task]}" != "${HYPERVISOR_AGENT[*]}" ]; then
            if [ "$(apt list --installed | grep ${hypervisor_agent_list[$hypervisor_agent_list_task]})" != "" ]; then
                apt purge -qy ${hypervisor_agent_list[$hypervisor_agent_list_task]} && apt autoremove -qy
            fi
        fi
    done
}
# Upgrade Packages
function UpgradePackages() {
    apt update && apt full-upgrade -qy && apt -t ${LSBCodename}-backports full-upgrade -qy && apt autoremove -qy
}
# Cleanup Temp Files
function CleanupTempFiles() {
    cleanup_list=(
        "cockpit"
        "fail2ban"
        "netplan"
        "systemd"
        "tuned"
        "ufw"
        "wireguard"
    )
    if [ "${container_environment}" == "docker" ] || [ "${container_environment}" == "wsl2" ]; then
        for cleanup_list_task in "${!cleanup_list[@]}"; do
            FILE_LIST=($(find "/" \( -path "/dev" -o -path "/home" -o -path "/mnt" -o -path "/proc" -o -path "/root" -o -path "/sys" \) -prune -o -name "${cleanup_list[$cleanup_list_task]}" -print | awk "{print $2}"))
            for FILE_LIST_TASK in "${!FILE_LIST[@]}"; do
                chattr -Ri "${FILE_LIST[$FILE_LIST_TASK]}" > "/dev/null" 2>&1
                rm -rf "${FILE_LIST[$FILE_LIST_TASK]}"
            done
        done
    fi && apt clean && rm -rf /etc/ufw/*.$(date '+%Y%m%d')_* /root/.*_history /tmp/*
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
# Call ConfigureSystem
ConfigureSystem
# Call ConfigurePackages
ConfigurePackages
# Set read_only="TRUE"; Call SetReadonlyFlag
read_only="TRUE" && SetReadonlyFlag
# Call CleanupTempFiles
CleanupTempFiles
