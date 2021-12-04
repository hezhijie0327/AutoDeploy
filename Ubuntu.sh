#!/bin/bash

# Current Version: 2.3.0

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
    if [ "${wsl_environment}" == "TRUE" ]; then
        serivce ${SERVICE_NAME} ${OPRATIONS}
    elif [ "${wsl_environment}" == "FALSE" ]; then
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
    function IsContainerEnvironment() {
        function CheckDockerEnvironment() {
            if [ -f "/.dockerenv" ]; then
                docker_environment="TRUE"
            else
                docker_environment="FALSE"
            fi
        }
        function CheckLXCEnvironment() {
            if [ -f "/proc/1/environ" ]; then
                if [ "$(cat '/proc/1/environ' | grep -a 'lxc')" != "" ]; then
                    lxc_environment="TRUE"
                else
                    lxc_environment="FALSE"
                fi
            else
                lxc_environment="FALSE"
            fi
        }
        CheckDockerEnvironment
        CheckLXCEnvironment
    }
    function IsVirtualEnvironment() {
        function CheckKVMEnvironment() {
            which "lscpu" > "/dev/null" 2>&1
            if [ "$?" -eq "0" ]; then
                if [ "$(lscpu | grep 'Hypervisor vendor' | cut -d ':' -f 2 | tr -d ' ' | tr 'A-Z' 'a-z' | grep 'kvm\|qemu')" != "" ]; then
                    kvm_environment="TRUE"
                else
                    kvm_environment="FALSE"
                fi
            else
                kvm_environment="FALSE"
            fi
        }
        function CheckVMwareEnvironment() {
            which "lscpu" > "/dev/null" 2>&1
            if [ "$?" -eq "0" ]; then
                if [ "$(lscpu | grep 'Hypervisor vendor' | cut -d ':' -f 2 | tr -d ' ' | tr 'A-Z' 'a-z' | grep 'vmware')" != "" ]; then
                    vmware_environment="TRUE"
                else
                    vmware_environment="FALSE"
                fi
            else
                vmware_environment="FALSE"
            fi
        }
        function CheckVirtualBoxEnvironment() {
            which "lscpu" > "/dev/null" 2>&1
            if [ "$?" -eq "0" ]; then
                if [ "$(lscpu | grep 'Hypervisor vendor' | cut -d ':' -f 2 | tr -d ' ' | tr 'A-Z' 'a-z' | grep 'oracle\|virtualbox')" != "" ]; then
                    virtualbox_environment="TRUE"
                else
                    virtualbox_environment="FALSE"
                fi
            else
                virtualbox_environment="FALSE"
            fi
        }
        function CheckWSLEnvironment() {
            if [ "$(uname -r | grep 'WSL')" == "" ]; then
                wsl_environment="FALSE"
            else
                wsl_environment="TRUE"
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
                    done && if [ -f "/etc/resolv.conf" ]; then
                        chattr -i "/etc/resolv.conf" > "/dev/null" 2>&1
                        if [ "$?" -eq "1" ]; then
                            rm -rf "/etc/resolv.conf"
                        fi
                    fi && rm -rf "/etc/resolv.conf" && cat "/tmp/resolv.autodeploy" > "/etc/resolv.conf" && rm -rf "/tmp/resolv.autodeploy" && chattr +i "/etc/resolv.conf"
                    rm -rf "/tmp/wsl.autodeploy" && for wsl_conf_list_task in "${!wsl_conf_list[@]}"; do
                        echo "${wsl_conf_list[$wsl_conf_list_task]}" >> "/tmp/wsl.autodeploy"
                    done && if [ -f "/etc/wsl.conf" ]; then chattr -i "/etc/wsl.conf"; fi && rm -rf "/etc/wsl.conf" && cat "/tmp/wsl.autodeploy" > "/etc/wsl.conf" && rm -rf "/tmp/wsl.autodeploy" && chattr +i "/etc/wsl.conf"
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
        CheckKVMEnvironment
        CheckVMwareEnvironment
        CheckVirtualBoxEnvironment
        CheckWSLEnvironment
    }
    GenerateHostname
    GetLSBCodename
    IsArmArchitecture
    IsContainerEnvironment
    IsVirtualEnvironment
}
# Set Repository Mirror
function SetRepositoryMirror() {
    mirror_list=(
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/${mirror_path} ${LSBCodename} main restricted universe multiverse"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/${mirror_path} ${LSBCodename}-backports main restricted universe multiverse"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/${mirror_path} ${LSBCodename}-security main restricted universe multiverse"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/${mirror_path} ${LSBCodename}-updates main restricted universe multiverse"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/${mirror_path} ${LSBCodename} main restricted universe multiverse"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/${mirror_path} ${LSBCodename}-backports main restricted universe multiverse"
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
        "/etc/chrony/chrony.conf"
        "/etc/default/ufw"
        "/etc/docker/daemon.json"
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
        if [ "${docker_environment}" == "FALSE" ]; then
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
                "server ntp.ntsc.ac.cn iburst prefer"
                "server cn.ntp.org.cn iburst prefer"
                "server time.apple.com iburst"
                "server time.windows.com iburst"
                "server time.izatcloud.net iburst"
                "server pool.ntp.org iburst"
                "server asia.pool.ntp.org iburst"
                "server cn.pool.ntp.org iburst"
            )
            which "chronyc" > "/dev/null" 2>&1
            if [ "$?" -eq "0" ]; then
                chrony_environment="TRUE" && rm -rf "/tmp/chrony.autodeploy" && for chrony_list_task in "${!chrony_list[@]}"; do
                    echo "${chrony_list[$chrony_list_task]}" >> "/tmp/chrony.autodeploy"
                done && cat "/tmp/chrony.autodeploy" > "/etc/chrony/chrony.conf" && rm -rf "/tmp/chrony.autodeploy" && OPRATIONS="restart" && SERVICE_NAME="chrony" && CallServiceController && chronyc activity && chronyc tracking && chronyc clients
            fi
        fi
    }
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
            if [ "${docker_environment}" == "FALSE" ] && [ "${wsl_environment}" == "FALSE" ]; then
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
        fi
        if [ "${wsl_environment}" == "TRUE" ]; then
            if [ ! -d "/docker" ]; then
                mkdir "/docker"
            fi
        fi
    }
    function ConfigureGrub() {
        which "update-grub" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            if [ "${docker_environment}" == "FALSE" ] && [ "${lxc_environment}" == "FALSE" ] && [ "${wsl_environment}" == "FALSE" ]; then
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
            if [ "${docker_environment}" == "FALSE" ] && [ "${wsl_environment}" == "FALSE" ]; then
                netplan apply
            fi
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
            if [ "${docker_environment}" == "FALSE" ] && [ "${wsl_environment}" == "FALSE" ]; then
                if [ ! -d "/etc/systemd/resolved.conf.d" ]; then
                    mkdir "/etc/systemd/resolved.conf.d"
                else
                    rm -rf /etc/systemd/resolved.conf.d/*.conf
                fi
                rm -rf "/tmp/resolved.autodeploy" && for resolved_list_task in "${!resolved_list[@]}"; do
                    echo "${resolved_list[$resolved_list_task]}" >> "/tmp/resolved.autodeploy"
                done && cat "/tmp/resolved.autodeploy" > "/etc/systemd/resolved.conf.d/resolved.conf" && OPRATIONS="restart" && SERVICE_NAME="systemd-resolved" && CallServiceController && rm -rf "/tmp/resolved.autodeploy" && if [ -f "/etc/resolv.conf" ]; then
                    chattr -i "/etc/resolv.conf" > "/dev/null" 2>&1
                    rm -rf "/etc/resolv.conf" && ln -s "/run/systemd/resolve/resolv.conf" "/etc/resolv.conf"
                fi
            else
                resolv_conf_list=(
                    "223.5.5.5"
                    "223.6.6.6"
                    "2400:3200::1"
                    "2400:3200:baba::1"
                )
                rm -rf "/tmp/resolv.autodeploy" && for resolv_conf_list_task in "${!resolv_conf_list[@]}"; do
                    echo "nameserver ${resolv_conf_list[$resolv_conf_list_task]}" >> "/tmp/resolv.autodeploy"
                done && if [ -f "/etc/resolv.conf" ]; then
                    chattr -i "/etc/resolv.conf" > "/dev/null" 2>&1
                    if [ "$?" -eq "1" ]; then
                        rm -rf "/etc/resolv.conf"
                    fi
                fi && rm -rf "/etc/resolv.conf" && cat "/tmp/resolv.autodeploy" > "/etc/resolv.conf" && rm -rf "/tmp/resolv.autodeploy" && chattr +i "/etc/resolv.conf"
            fi
        else
            resolv_conf_list=(
                "223.5.5.5"
                "223.6.6.6"
                "2400:3200::1"
                "2400:3200:baba::1"
            )
            rm -rf "/tmp/resolv.autodeploy" && for resolv_conf_list_task in "${!resolv_conf_list[@]}"; do
                echo "nameserver ${resolv_conf_list[$resolv_conf_list_task]}" >> "/tmp/resolv.autodeploy"
            done && if [ -f "/etc/resolv.conf" ]; then
                chattr -i "/etc/resolv.conf" > "/dev/null" 2>&1
                if [ "$?" -eq "1" ]; then
                    rm -rf "/etc/resolv.conf"
                fi
            fi && rm -rf "/etc/resolv.conf" && cat "/tmp/resolv.autodeploy" > "/etc/resolv.conf" && rm -rf "/tmp/resolv.autodeploy" && chattr +i "/etc/resolv.conf"
        fi
    }
    function ConfigureSshd() {
        if [ -f "/usr/share/openssh/sshd_config" ]; then
            if [ "${docker_environment}" == "FALSE" ] && [ "${wsl_environment}" == "FALSE" ]; then
                SSHD_CONFIG_ADDITIONAL="s/\#Port\ 22/Port 9022/g"
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
            tuned-adm profile "$(tuned-adm recommend)" && tuned-adm active
        fi
    }
    function ConfigureUfw() {
        which "ufw" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ] && [ -f "/etc/default/ufw" ]; then
            echo "$(cat '/etc/default/ufw' | sed 's/DEFAULT\_APPLICATION\_POLICY\=\"ACCEPT\"/DEFAULT\_APPLICATION\_POLICY\=\"REJECT\"/g;s/DEFAULT\_APPLICATION\_POLICY\=\"DROP\"/DEFAULT\_APPLICATION\_POLICY\=\"REJECT\"/g;s/DEFAULT\_APPLICATION\_POLICY\=\"SKIP\"/DEFAULT\_APPLICATION\_POLICY\=\"REJECT\"/g;s/DEFAULT\_FORWARD\_POLICY\=\"DROP\"/DEFAULT\_FORWARD\_POLICY\=\"ACCEPT\"/g;s/DEFAULT\_FORWARD\_POLICY\=\"REJECT\"/DEFAULT\_FORWARD\_POLICY\=\"ACCEPT\"/g;s/DEFAULT\_INPUT\_POLICY\=\"ACCEPT\"/DEFAULT\_INPUT\_POLICY\=\"REJECT\"/g;s/DEFAULT\_INPUT\_POLICY\=\"DROP\"/DEFAULT\_INPUT\_POLICY\=\"REJECT\"/g;s/DEFAULT\_OUTPUT\_POLICY\=\"DROP\"/DEFAULT\_OUTPUT\_POLICY\=\"ACCEPT\"/g;s/DEFAULT\_OUTPUT\_POLICY\=\"REJECT\"/DEFAULT\_OUTPUT\_POLICY\=\"ACCEPT\"/g;s/MANAGE\_BUILTINS\=yes/MANAGE\_BUILTINS\=no/g;s/IPV6\=no/IPV6\=yes/g')" > "/tmp/ufw.autodeploy" && cat "/tmp/ufw.autodeploy" > "/etc/default/ufw" && rm -rf "/tmp/ufw.autodeploy"
            if [ "${docker_environment}" == "FALSE" ] && [ "${wsl_environment}" == "FALSE" ]; then
                ufw reload && ufw limit 22/tcp && if [ "${chrony_environment}" == "TRUE" ]; then
                    ufw insert 1 allow 123/udp && ufw allow 323/udp
                fi && if [ "${docker_environment}" == "FALSE" ] && [ "${wsl_environment}" == "FALSE" ]; then
                    ufw allow 51820/udp && ufw limit 9022/tcp
                fi && ufw allow 9090/tcp && ufw enable && ufw status verbose
            else
                ufw disable > "/dev/null" 2>&1
            fi
        fi
    }
    function ConfigureWireGuard() {
        WAN_INTERFACE=$(cat '/proc/net/dev' | grep -v 'docker0\|lo\|wg0' | grep ':' | sed 's/[[:space:]]//g' | cut -d ':' -f 1 | sort | uniq | head -n 1)
        wireguard_list=(
            "[Interface]"
            "Address = 192.168.224.$((RANDOM %253 + 1))/19"
            "ListenPort = 51820"
            "PreDown = ufw route delete allow in on wg0 out on ${WAN_INTERFACE}"
            "PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${WAN_INTERFACE} -j MASQUERADE"
            "PreDown = ip6tables -t nat -D POSTROUTING -o ${WAN_INTERFACE} -j MASQUERADE"
            "PostUp = ufw route allow in on wg0 out on ${WAN_INTERFACE}"
            "PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${WAN_INTERFACE} -j MASQUERADE"
            "PostUp = ip6tables -t nat -I POSTROUTING -o ${WAN_INTERFACE} -j MASQUERADE"
            "PrivateKey = $(wg genkey | tee '/etc/wireguard/private.key')"
            "#[Peer]"
            "#AllowedIPs = 192.168.224.0/19"
            "#Endpoint = 127.0.0.1:51820"
            "#PersistentKeepalive = 5"
            "#PublicKey = $(cat '/etc/wireguard/private.key' | wg pubkey | tee '/etc/wireguard/public.key')"
        )
        which "wg" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/tmp/wireguard.autodeploy" && for wireguard_list_task in "${!wireguard_list[@]}"; do
                echo "${wireguard_list[$wireguard_list_task]}" >> "/tmp/wireguard.autodeploy"
            done && cat "/tmp/wireguard.autodeploy" > "/etc/wireguard/wg0.conf" && rm -rf "/tmp/wireguard.autodeploy" && if [ "${docker_environment}" == "FALSE" ] && [ "${wsl_environment}" == "FALSE" ]; then
                OPRATIONS="enable" && SERVICE_NAME="wg-quick@wg0.service" && CallServiceController && OPRATIONS="start" && CallServiceController && wg
            fi
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
    ConfigureChrony
    ConfigureCrontab
    ConfigureDockerEngine
    ConfigureGrub
    ConfigureLandscape
    ConfigureNetplan
    ConfigurePostfix
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
        if [ "${docker_environment}" == "FALSE" ]; then
            DEFAULT_USERNAME="ubuntu"
            DEFAULT_PASSWORD="*Ubuntu123*"
            crontab_list=(
                "@reboot rm -rf /home/${DEFAULT_USERNAME}/.*_history"
            )
            userdel -rf "${DEFAULT_USERNAME}" > "/dev/null" 2>&1
            useradd -d "/home/${DEFAULT_USERNAME}" -s "/bin/zsh" -m "${DEFAULT_USERNAME}" && echo $DEFAULT_USERNAME:$DEFAULT_PASSWORD | chpasswd && adduser "${DEFAULT_USERNAME}" "sudo"
            if [ -d "/etc/zsh/oh-my-zsh" ]; then
                cp -rf "/etc/zsh/oh-my-zsh" "/home/${DEFAULT_USERNAME}/.oh-my-zsh" && chown -R $DEFAULT_USERNAME:$DEFAULT_USERNAME "/home/${DEFAULT_USERNAME}/.oh-my-zsh"
                if [ -f "/etc/zsh/oh-my-zsh.zshrc" ]; then
                    cp -rf "/etc/zsh/oh-my-zsh.zshrc" "/home/${DEFAULT_USERNAME}/.zshrc" && chown -R $DEFAULT_USERNAME:$DEFAULT_USERNAME "/home/${DEFAULT_USERNAME}/.zshrc"
                fi
            fi
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
    function ConfigureTimeZone() {
        if [ -f "/etc/localtime" ]; then
            rm -rf "/etc/localtime"
        fi && ln -s "/usr/share/zoneinfo/Asia/Shanghai" "/etc/localtime"
    }
    ConfigureDefaultShell
    ConfigureDefaultUser
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
        if [ "${docker_environment}" == "FALSE" ] && [ "${wsl_environment}" == "FALSE" ]; then
            curl -fsSL "https://mirrors.ustc.edu.cn/docker-ce/linux/ubuntu/gpg" | gpg --dearmor -o "/usr/share/keyrings/docker-archive-keyring.gpg"
            echo "deb [arch=${mirror_arch} signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://mirrors.ustc.edu.cn/docker-ce/linux/ubuntu ${LSBCodename} stable" > "/etc/apt/sources.list.d/docker.list"
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
        rm -rf "/etc/zsh/oh-my-zsh" && git clone --depth=1 "https://github.com.cnpmjs.org/ohmyzsh/ohmyzsh.git" "/etc/zsh/oh-my-zsh" && if [ -d "/etc/zsh/oh-my-zsh/custom/plugins" ]; then
            for plugin_list_task in "${!plugin_list[@]}"; do
                rm -rf "/etc/zsh/oh-my-zsh/custom/plugins/${plugin_list[$plugin_list_task]}" && git clone --depth=1 "https://github.com.cnpmjs.org/zsh-users/${plugin_list[$plugin_list_task]}.git" "/etc/zsh/oh-my-zsh/custom/plugins/${plugin_list[$plugin_list_task]}"
            done
        fi
    }
    InstallDockerEngine
    InstallOhMyZsh
}
# Install Dependency Packages
function InstallDependencyPackages() {
    app_list=(
        "apt-file"
        "apt-transport-https"
        "ca-certificates"
        "chrony"
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
        "mtr-tiny"
        "nano"
        "neofetch"
        "net-tools"
        "netplan.io"
        "nmap"
        "ntfs-3g"
        "openssh-client"
        "openssh-server"
        "p7zip-full"
        "postfix"
        "python3"
        "python3-pip"
        "rar"
        "realmd"
        "sudo"
        "systemd"
        "tshark"
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
        "whois"
        "wireguard"
        "zip"
        "zsh"
    )
    apt update && for app_list_task in "${!app_list[@]}"; do
        apt-cache show ${app_list[$app_list_task]} && if [ "$?" -eq "0" ]; then
            apt install -qy ${app_list[$app_list_task]}
        fi
    done && if [ "${kvm_environment}" == "TRUE" ]; then
        apt-cache show qemu-guest-agent && if [ "$?" -eq "0" ]; then
            apt install -qy qemu-guest-agent
        fi
    fi && if [ "${vmware_environment}" == "TRUE" ]; then
        apt-cache show open-vm-tools && if [ "$?" -eq "0" ]; then
            apt install -qy open-vm-tools
        fi
    fi && if [ "${virtualbox_environment}" == "TRUE" ]; then
        apt-cache show virtualbox-guest-dkms && if [ "$?" -eq "0" ]; then
            apt install -qy virtualbox-guest-dkms
        fi
    fi
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
