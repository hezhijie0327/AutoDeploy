#!/bin/bash

# Current Version: 4.8.3

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
            systemctl ${OPRATIONS} ${SERVICE_NAME}
        fi
    else
        service ${SERVICE_NAME} ${OPRATIONS}
    fi
}
# Get System Information
function GetSystemInformation() {
    function CheckDNSConfiguration() {
        USE_GLOBAL_DNS="false"
        if [ "${USE_GLOBAL_DNS}" == "true" ]; then
            CUSTOM_DNS=(
                "8.8.4.4"
                "8.8.8.8"
                "2001:4860:4860::8844"
                "2001:4860:4860::8888"
            )
        else
            CUSTOM_DNS=(
                "223.5.5.5"
                "223.6.6.6"
                "2400:3200::1"
                "2400:3200:baba::1"
            )
        fi
        DHCP_DNS=()
        CUSTOM_DNS_LINE="" && for CUSTOM_DNS_TASK in "${!CUSTOM_DNS[@]}"; do
            CUSTOM_DNS_LINE="${CUSTOM_DNS_LINE} ${CUSTOM_DNS[$CUSTOM_DNS_TASK]}"
            CUSTOM_DNS_LINE=$(echo "${CUSTOM_DNS_LINE}" | sed "s/^\ //g")
        done && CURRENT_DNS_EXCLUDE="$(echo ${DHCP_DNS[*]} ${CUSTOM_DNS_LINE} | sed 's/\ /\\\|/g')\|127.0.0.53"
        if [ -f "/etc/resolv.conf" ]; then
            CURRENT_DNS=(${DHCP_DNS[*]} $(cat "/etc/resolv.conf" | grep "nameserver\ " | sed "s/nameserver\ //g" | grep -v "${CURRENT_DNS_EXCLUDE}" | awk "{print $2}"))
            CURRENT_DNS_LINE="" && for CURRENT_DNS_TASK in "${!CURRENT_DNS[@]}"; do
                CURRENT_DNS_LINE="${CURRENT_DNS_LINE} ${CURRENT_DNS[$CURRENT_DNS_TASK]}"
                CURRENT_DNS_LINE=$(echo "${CURRENT_DNS_LINE}" | sed "s/^\ //g")
            done && DNS_LINE=$(echo "${CURRENT_DNS_LINE} ${CUSTOM_DNS_LINE}" | cut -d ' ' -f 1-3)
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
                    rm -rf "/tmp/resolv.autodeploy" && DNS_COUNT="1" && for resolv_conf_list_task in "${!resolv_conf_list[@]}"; do
                        if [ "${DNS_COUNT}" -gt "3" ]; then
                            break
                        else
                            echo "nameserver ${resolv_conf_list[$resolv_conf_list_task]}" >> "/tmp/resolv.autodeploy"
                        fi && DNS_COUNT=$(( ${DNS_COUNT} + 1 ))
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
                sed -i "s/[a-z]\{0,\}[.]\{0,\}archive.ubuntu.com/mirrors.ustc.edu.cn/g;s/[a-z]\{0,\}[.]\{0,\}ports.ubuntu.com/mirrors.ustc.edu.cn/g;s/[a-z]\{0,\}[.]\{0,\}security.ubuntu.com/mirrors.ustc.edu.cn/g" "/etc/apt/sources.list" && apt update && apt install virt-what -qy
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
        RESET_DOMAIN="false"
        if [ -f "/etc/resolv.conf" ]; then
            NEW_DOMAIN=($(cat "/etc/resolv.conf" | grep "^search " | cut -d " " -f 2- | awk "{print $2}"))
        fi
        if [ $(echo "${NEW_DOMAIN[*]}" | sed "s/\ /\\n/g" | wc -l ) -lt 1 ] || [ "${RESET_DOMAIN}" == "true" ]; then
            NEW_DOMAIN=("localdomain")
        fi
    }
    function GenerateHostname() {
        RESET_HOSTNAME="false"
        if [ -f "/etc/hostname" ]; then
            NEW_HOSTNAME=$(cat "/etc/hostname" | awk "{print $2}")
        fi
        if [ $(echo "${NEW_HOSTNAME}" | wc -l) -ne 1 ]; then
            which "hostname" > "/dev/null" 2>&1
            if [ "$?" -eq "0" ]; then
                NEW_HOSTNAME=$(hostname)
            fi
        fi
        if [ $(echo "${NEW_HOSTNAME}" | wc -l) -ne 1 ] || [ "${RESET_HOSTNAME}" == "true" ]; then
            NEW_HOSTNAME="Ubuntu-$(date '+%Y%m%d%H%M%S')"
        fi
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
    function GetLSBCodename() {
        LSBCodename_LTS="jammy"
        LSBCodename_NON_LTS="lunar"
        LSBVersion_LTS="22.04"
        LSBVersion_NON_LTS="23.04"
        which "lsb_release" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            LSBCodename_CURRENT=$(lsb_release -cs)
            LSBVersion_CURRENT=$(lsb_release -rs)
            if [ "$(lsb_release -ds | grep 'LTS')" == "" ]; then
                WHETHER_LTS_NON_TLS="FALSE"
            else
                WHETHER_LTS_NON_TLS="TRUE"
            fi
        else
            if [ -f '/etc/os-release' ]; then
                LSBCodename_CURRENT=$(cat "/etc/os-release" | grep "UBUNTU\_CODENAME\=" | sed "s/UBUNTU\_CODENAME\=//g")
                LSBVersion_CURRENT=$(cat "/etc/os-release" | grep "VERSION_ID\=" | sed "s/VERSION_ID\=//g" | tr -d "\"")
                if [ "$(cat '/etc/os-release' | grep "VERSION\=" | grep 'LTS')" == "" ]; then
                    WHETHER_LTS_NON_TLS="FALSE"
                else
                    WHETHER_LTS_NON_TLS="TRUE"
                fi
            fi
        fi
        if [ "$(awk -v NUM1=$LSBVersion_CURRENT -v NUM2=$LSBVersion_LTS 'BEGIN{print (NUM1 > NUM2) ? 1 : 0}')" -eq "1" ] && [ "$(awk -v NUM1=$LSBVersion_CURRENT -v NUM2=$LSBVersion_NON_LTS 'BEGIN{print (NUM1 > NUM2) ? 1 : 0}')" -eq "1" ]; then
            LSBCodename="${LSBCodename_CURRENT}"
            LSBVersion="${LSBVersion_CURRENT}"
        else
            if [ "${WHETHER_LTS_NON_TLS}" == "TRUE" ]; then
                LSBCodename="${LSBCodename_LTS}"
                LSBVersion="${LSBVersion_LTS}"
            else
                LSBCodename="${LSBCodename_NON_LTS}"
                LSBVersion="${LSBVersion_NON_LTS}"
            fi
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
        GHPROXY_URL=""
        if [ "${GHPROXY_URL}" != "" ]; then
            export GHPROXY_URL="https://${GHPROXY_URL}/"
        fi
    }
    CheckDNSConfiguration
    GenerateDomain && CheckMachineEnvironment
    GenerateHostname
    GetCPUVendorID
    GetLSBCodename
    GetOSArchitecture
    SetGHProxyDomain
}
# Set Repository Mirror
function SetRepositoryMirror() {
    mirror_list=(
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/${MIRROR_URL} ${LSBCodename} main multiverse restricted universe"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/${MIRROR_URL} ${LSBCodename}-backports main multiverse restricted universe"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/${MIRROR_URL} ${LSBCodename}-proposed main multiverse restricted universe"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/${MIRROR_URL} ${LSBCodename}-security main multiverse restricted universe"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/${MIRROR_URL} ${LSBCodename}-updates main multiverse restricted universe"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/${MIRROR_URL} ${LSBCodename} main multiverse restricted universe"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/${MIRROR_URL} ${LSBCodename}-backports main multiverse restricted universe"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/${MIRROR_URL} ${LSBCodename}-proposed main multiverse restricted universe"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/${MIRROR_URL} ${LSBCodename}-security main multiverse restricted universe"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/${MIRROR_URL} ${LSBCodename}-updates main multiverse restricted universe"
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
        "/etc/apt/preferences"
        "/etc/apt/sources.list"
        "/etc/apt/sources.list.d/amd.list"
        "/etc/apt/sources.list.d/cloudflare.list"
        "/etc/apt/sources.list.d/crowdsec.list"
        "/etc/apt/sources.list.d/docker.list"
        "/etc/apt/sources.list.d/intel.list"
        "/etc/apt/sources.list.d/nvidia.list"
        "/etc/chrony/chrony.conf"
        "/etc/cockpit/cockpit.conf"
        "/etc/default/ufw"
        "/etc/docker/daemon.json"
        "/etc/fail2ban/fail2ban.local"
        "/etc/fail2ban/filter.d/cockpit.conf"
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
    function ConfigureAPT() {
        apt_preference_list=(
            "${LSBCodename}-backports 990"
            "${LSBCodename}-security 500"
            "${LSBCodename}-updates 500"
            "${LSBCodename} 500"
            "${LSBCodename}-proposed 100"
        )
        if [ -d "/etc/apt/preferences.d" ]; then
            rm -rf "/etc/apt/preferences.d"
        fi && mkdir "/etc/apt/preferences.d"
        rm -rf "/tmp/apt_preference_list.autodeploy" && for apt_preference_list_task in "${!apt_preference_list[@]}"; do
            APT_PIN_RELEASE=$(echo "${apt_preference_list[$apt_preference_list_task]}" | cut -d " " -f 1)
            APT_PIN_PRIORITY=$(echo "${apt_preference_list[$apt_preference_list_task]}" | cut -d " " -f 2)
            if [ ! -z $(echo ${APT_PIN_PRIORITY} | grep "[a-z]\|[A-Z]\|-") ]; then
                APT_PIN_PRIORITY="500"
            fi
            echo -e "Package: *\nPin: release a=${APT_PIN_RELEASE}\nPin-Priority: ${APT_PIN_PRIORITY}\n" >> "/tmp/apt_preference_list.autodeploy"
        done && cat "/tmp/apt_preference_list.autodeploy" | sed '$d' > "/etc/apt/preferences"
    }
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
            "${DHCP_NTP[@]}"
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
            "0 0 * * 7 sudo apt update && sudo apt full-upgrade -qy && sudo apt autoremove -qy"
            "# 0 4 * * 7 sudo reboot"
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
            "crowdsecurity/sshd"
        )
        which "cscli" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            if [ "${container_environment}" != "docker" ] && [ "${container_environment}" != "wsl2" ]; then
                for crowdsec_hub_list_task in "${!crowdsec_hub_list[@]}"; do
                    cscli collections install ${crowdsec_hub_list[$crowdsec_hub_list_task]}
                done && OPRATIONS="restart" && SERVICE_NAME="crowdsec" && CallServiceController && cscli hub list
            fi
        fi
    }
    function ConfigureDockerEngine() {
        which "bc" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            which "sha1sum" > "/dev/null" 2>&1
            if [ "$?" -eq "0" ]; then
                which "uuidgen" > "/dev/null" 2>&1
                if [ "$?" -eq "0" ]; then
                    UNIQUE_PREFIX=$(echo $(date "+%s%N")$(uuidgen | tr -d "-" | tr "A-Z" "a-z") | sha1sum | cut -c 31-)
                    DOCKER_PREFIX="fd$(echo ${UNIQUE_PREFIX} | cut -c 1-2):$(echo ${UNIQUE_PREFIX} | cut -c 3-6):$(echo ${UNIQUE_PREFIX} | cut -c 7-10)"
                else
                    DOCKER_PREFIX="2001:db8:1"
                fi
            fi
        fi
        docker_list=(
            "{"
            "  \"experimental\": true,"
            "  \"fixed-cidr-v6\": \"${DOCKER_PREFIX}::/64\","
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
            "[cockpit]"
            "bantime = 604800"
            "enabled = true"
            "filter = cockpit"
            "findtime = 60"
            "logpath = /var/log/auth.log"
            "maxretry = 5"
            "port = 9090"
            "[sshd]"
            "bantime = 604800"
            "enabled = true"
            "filter = sshd"
            "findtime = 60"
            "logpath = /var/log/auth.log"
            "maxretry = 5"
            "port = 9022"
        )
        fail2ban_cockpit_list=(
            "[Definition]"
            "failregex = pam_unix\(cockpit:auth\): authentication failure; logname=.* uid=.* euid=.* tty=.* ruser=.* rhost=<HOST>"
            "journalmatch = SYSLOG_FACILITY=10 PRIORITY=5"
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
                rm -rf "/tmp/fail2ban.autodeploy" && for fail2ban_cockpit_list_task in "${!fail2ban_cockpit_list[@]}"; do
                    echo "${fail2ban_cockpit_list[$fail2ban_cockpit_list_task]}" >> "/tmp/fail2ban.autodeploy"
                done && cat "/tmp/fail2ban.autodeploy" > "/etc/fail2ban/filter.d/cockpit.conf" && rm -rf "/tmp/fail2ban.autodeploy"
                rm -rf "/tmp/fail2ban.autodeploy" && for fail2ban_list_task in "${!fail2ban_list[@]}"; do
                    echo "${fail2ban_list[$fail2ban_list_task]}" >> "/tmp/fail2ban.autodeploy"
                done && cat "/tmp/fail2ban.autodeploy" > "/etc/fail2ban/jail.d/fail2ban_default.conf" && rm -rf "/tmp/fail2ban.autodeploy" && if [ "${container_environment}" != "docker" ] && [ "${container_environment}" != "wsl2" ]; then
                    OPRATIONS="enable" && SERVICE_NAME="fail2ban" && CallServiceController && fail2ban-client reload && sleep 5s && fail2ban-client status
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
            "url.${GHPROXY_URL}https://github.com/.insteadOf"
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
            rm -rf "/home/${DEFAULT_USERNAME}/.gnupg" "/root/.gnupg" && gpg --keyserver hkps://keyserver.ubuntu.com:443 --recv ${GPG_PUBKEY} && echo "${GPG_PUBKEY}" | awk 'BEGIN { FS = "\n" }; { print $1":6:" }' | gpg --import-ownertrust && GPG_PUBKEY_ID_A=$(gpg --list-keys --keyid-format LONG | grep "pub\|sub" | awk '{print $2, $4}' | grep "\[A\]" | awk '{print $1}' | awk -F '/' '{print $2}') && GPG_PUBKEY_ID_C=$(gpg --list-keys --keyid-format LONG | grep "pub\|sub" | awk '{print $2, $4}' | grep "\[C\]" | awk '{print $1}' | awk -F '/' '{print $2}')
            if [ "${GPG_PUBKEY_ID_A}" != "" ]; then
                gpg_agent_list=(
                    "enable-ssh-support"
                    "pinentry-program /usr/bin/pinentry-tty"
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
        network_interface=($(cat "/proc/net/dev" | grep -v "docker0\|lo\|wg0" | grep "\:" | sed "s/[[:space:]]//g" | cut -d ":" -f 1 | sort | uniq | awk "{print $2}"))
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
    function ConfigureNut() {
        which "upsmon" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            function Generate_nut_conf() {
                echo "MODE=${NUT_MODE:-none}" > "/etc/nut/nut.conf"
            }
            function Generate_ups_conf() {
                ups_driver_list=(
                    "ups,usbhid-ups,auto"
                )
                ups_conf_list=(
                    "maxretry = 3"
                    "retrydelay = 5"
                )
                rm -rf "/tmp/ups.conf.autodeploy" && for ups_conf_list_task in "${!ups_conf_list[@]}"; do
                    echo "${ups_conf_list[$ups_conf_list_task]}" >> "/tmp/ups.conf.autodeploy"
                done && for ups_driver_list_task in "${!ups_driver_list[@]}"; do
                    UPS_NAME=$(echo "${ups_driver_list[$ups_driver_list_task]}" | cut -d ',' -f 1)
                    UPS_DRIVER=$(echo "${ups_driver_list[$ups_driver_list_task]}" | cut -d ',' -f 2)
                    UPS_PORT=$(echo "${ups_driver_list[$ups_driver_list_task]}" | cut -d ',' -f 3)
                    echo -e "[${UPS_NAME}]\n    driver = ${UPS_DRIVER}\n    port = ${UPS_PORT}" >> "/tmp/ups.conf.autodeploy"
                done && cat "/tmp/ups.conf.autodeploy" > "/etc/nut/ups.conf" && rm -rf "/tmp/ups.conf.autodeploy"
            }
            function Generate_upsd_conf() {
                if [ "${NUT_MODE}" == "standalone" ]; then
                    upsd_config_list=(
                        "CERTREQUEST 0"
                        "LISTEN 127.0.0.1 3493"
                        "LISTEN ::1 3493"
                        "MAXAGE 15"
                        "MAXCONN 1024"
                        "STATEPATH /var/run/nut"
                    )
                else
                    upsd_config_list=(
                        "CERTREQUEST 0"
                        "LISTEN 0.0.0.0 3493"
                        "LISTEN :: 3493"
                        "MAXAGE 15"
                        "MAXCONN 1024"
                        "STATEPATH /var/run/nut"
                    )
                fi
                rm -rf "/tmp/upsd.conf.autodeploy" && for upsd_config_list_task in "${!upsd_config_list[@]}"; do
                    echo "${upsd_config_list[$upsd_config_list_task]}" >> "/tmp/upsd.conf.autodeploy"
                done && cat "/tmp/upsd.conf.autodeploy" > "/etc/nut/upsd.conf" && rm -rf "/tmp/upsd.conf.autodeploy"
            }
            function Generate_upsd_users() {
                upsd_user_list=(
                    "admin,123456,master,FSD,SET"
                    "monuser,secret,slave,,"
                )
                rm -rf "/tmp/upsd.users.autodeploy" && for upsd_user_list_task in "${!upsd_user_list[@]}"; do
                    UPSD_USERNAME=$(echo "${upsd_user_list[$upsd_user_list_task]}" | cut -d ',' -f 1)
                    UPSD_PASSWORD=$(echo "${upsd_user_list[$upsd_user_list_task]}" | cut -d ',' -f 2)
                    UPSD_ROLE=$(echo "${upsd_user_list[$upsd_user_list_task]}" | cut -d ',' -f 3)
                    UPSD_ACTIONS=$(echo "${upsd_user_list[$upsd_user_list_task]}" | cut -d ',' -f 4-5 | tr ',' ' ' | sed 's/^ //g')
                    if [ "${UPSD_ACTIONS}" != "" ]; then
                        UPSD_ACTIONS="    actions = ${UPSD_ACTIONS}\n    instcmds = ALL\n"
                    fi
                    echo -e "[${UPSD_USERNAME}]\n${UPSD_ACTIONS}    password = ${UPSD_PASSWORD}\n    upsmon ${UPSD_ROLE}" >> "/tmp/upsd.users.autodeploy"
                done && cat "/tmp/upsd.users.autodeploy" > "/etc/nut/upsd.users" && chmod 0640 "/etc/nut/upsd.users" && rm -rf "/tmp/upsd.users.autodeploy"
            }
            function Generate_upsmon_conf() {
                upsmon_list=(
                    "DEADTIME 15"
                    "FINALDELAY 5"
                    "HOSTSYNC 15"
                    "MINSUPPLIES 1"
                    "NOCOMMWARNTIME 300"
                    "POLLFREQ 5"
                    "POLLFREQALERT 5"
                    "POWERDOWNFLAG /etc/killpower"
                    "RBWARNTIME 43200"
                    'SHUTDOWNCMD "/sbin/shutdown -h +0"'
                    "MONITOR ${UPSMON_SYSTEM} 1 ${UPSMON_USERNAME} ${UPSMON_PASSWORD} ${UPSMON_ROLE}"
                )
                rm -rf "/tmp/upsmon.conf.autodeploy" && for upsmon_list_task in "${!upsmon_list[@]}"; do
                    echo "${upsmon_list[$upsmon_list_task]}" >> "/tmp/upsmon.conf.autodeploy"
                done && cat "/tmp/upsmon.conf.autodeploy" > "/etc/nut/upsmon.conf" && chmod 0640 "/etc/nut/upsmon.conf" && rm -rf "/tmp/upsmon.conf.autodeploy"
            }
            function Generate_upssched_conf() {
                upssched_conf=(
                    "CMDSCRIPT /bin/upssched-cmd"
                )
            }
            NUT_MODE="" # netclient | netserver | none | standalone
            rm -rf /etc/nut/*.* && case ${NUT_MODE:-none} in
                netclient)
                    UPSMON_USERNAME=$(echo "${upsd_user_list[*]}" | cut -d ' ' -f 2 | cut -d ',' -f 1)
                    UPSMON_PASSWORD=$(echo "${upsd_user_list[*]}" | cut -d ' ' -f 2 | cut -d ',' -f 2)
                    UPSMON_ROLE=$(echo "${upsd_user_list[*]}" | cut -d ' ' -f 2 | cut -d ',' -f 3)
                    UPSMON_SYSTEM="${UPS_NAME-ups}@localhost"
                    nut_service_list=(
                        "nut-client,enabled"
                        "nut-driver,disabled"
                        "nut-monitor,enabled"
                        "nut-server,disabled"
                    )
                    Generate_nut_conf
                    Generate_upsmon_conf
                    Generate_upssched_conf
                    ;;
                netserver|standalone)
                    UPSMON_USERNAME=$(echo "${upsd_user_list[*]}" | cut -d ' ' -f 1 | cut -d ',' -f 1)
                    UPSMON_PASSWORD=$(echo "${upsd_user_list[*]}" | cut -d ' ' -f 1 | cut -d ',' -f 2)
                    UPSMON_ROLE=$(echo "${upsd_user_list[*]}" | cut -d ' ' -f 1 | cut -d ',' -f 3)
                    UPSMON_SYSTEM="${UPS_NAME-ups}@localhost"
                    nut_service_list=(
                        "nut-client,enabled"
                        "nut-driver,enabled"
                        "nut-monitor,enabled"
                        "nut-server,enabled"
                    )
                    Generate_nut_conf
                    Generate_ups_conf
                    Generate_upsd_conf
                    Generate_upsd_users
                    Generate_upsmon_conf
                    Generate_upssched_conf
                    ;;
                none)
                    nut_service_list=(
                        "nut-client,disable"
                        "nut-driver,disable"
                        "nut-monitor,disable"
                        "nut-server,disable"
                    )
                    Generate_nut_conf
                    ;;
            esac
            for nut_service_list_task in "${!nut_service_list[@]}"; do
                NUT_SERVICE_NAME=$(echo "${nut_service_list[$nut_service_list_task]}" | cut -d ',' -f 1)
                NUT_SERVICE_STATUS=$(echo "${nut_service_list[$nut_service_list_task]}" | cut -d ',' -f 2)
                OPRATIONS="${NUT_SERVICE_STATUS}" && SERVICE_NAME="${NUT_SERVICE_NAME}" && CallServiceController > "/dev/null" 2>&1
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
            "DNS=${DNS_LINE}"
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
                rm -rf "/tmp/resolv.autodeploy" && DNS_COUNT="1" && for resolv_conf_list_task in "${!resolv_conf_list[@]}"; do
                    if [ "${DNS_COUNT}" -gt "3" ]; then
                        break
                    else
                        echo "nameserver ${resolv_conf_list[$resolv_conf_list_task]}" >> "/tmp/resolv.autodeploy"
                    fi && DNS_COUNT=$(( ${DNS_COUNT} + 1 ))
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
            rm -rf "/tmp/resolv.autodeploy" && DNS_COUNT="1" && for resolv_conf_list_task in "${!resolv_conf_list[@]}"; do
                if [ "${DNS_COUNT}" -gt "3" ]; then
                    break
                else
                    echo "nameserver ${resolv_conf_list[$resolv_conf_list_task]}" >> "/tmp/resolv.autodeploy"
                fi && DNS_COUNT=$(( ${DNS_COUNT} + 1 ))
            done && echo "search ${NEW_DOMAIN[*]}" >> "/tmp/resolv.autodeploy" && if [ -f "/etc/resolv.conf" ]; then
                chattr -i "/etc/resolv.conf" > "/dev/null" 2>&1
                if [ "$?" -eq "1" ]; then
                    rm -rf "/etc/resolv.conf"
                fi
            fi && rm -rf "/etc/resolv.conf" && cat "/tmp/resolv.autodeploy" > "/etc/resolv.conf" && rm -rf "/tmp/resolv.autodeploy" && chattr +i "/etc/resolv.conf"
        fi
    }
    function ConfigureSNMP() {
        SNMP_AUTH_PASS="${DEFAULT_PASSWORD}"
        SNMP_PRIV_PASS="${ROOT_PASSWORD}"
        SNMP_SYS_CONTACT="${DEFAULT_FULLNAME}"
        SNMP_SYS_LOCATION="${NEW_HOSTNAME}"
        SNMP_SYS_NAME="${NEW_FULL_DOMAIN}"
        SNMP_USER="${DEFAULT_USERNAME}"
        snmp_list=(
            "agentaddress udp:161,udp6:161"
            "master agentx"
            "rouser ${SNMP_USER}"
            "sysContact ${SNMP_SYS_CONTACT}"
            "sysLocation ${SNMP_SYS_LOCATION}"
            "sysName ${SNMP_SYS_NAME}"
            "sysServices 76"
        )
        which "snmpwalk" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            OPRATIONS="stop" && SERVICE_NAME="snmpd" && CallServiceController
            kill $(ps -ef | grep snmp | grep -v 'grep' | cut -d ' ' -f 3) > "/dev/null" 2>&1
            sed -i 's/^mibs :/# mibs :/g' "/etc/snmp/snmp.conf"
            echo "createUser ${SNMP_USER} SHA \"${SNMP_AUTH_PASS}\" AES \"${SNMP_PRIV_PASS}\"" > "/var/lib/snmp/snmpd.conf"
            rm -rf "/tmp/snmp.autodeploy" && for snmp_list_task in "${!snmp_list[@]}"; do
                echo "${snmp_list[$snmp_list_task]}" >> "/tmp/snmp.autodeploy"
            done && cat "/tmp/snmp.autodeploy" | sort > "/etc/snmp/snmpd.conf" && rm -rf "/tmp/snmp.autodeploy" && OPRATIONS="start" && SERVICE_NAME="snmpd" && CallServiceController && snmpwalk -v3 -a SHA -A ${SNMP_AUTH_PASS} -x AES -X ${SNMP_PRIV_PASS} -l authPriv -u ${SNMP_USER} 127.0.0.1 | head
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
        DISABLE_ICMP_ECHO="false"
        if [ "${DISABLE_ICMP_ECHO}" == "true" ]; then
            icmp_echo=(
                "net.ipv4.icmp_echo_ignore_all = 1"
                "net.ipv6.icmp.echo_ignore_all = 1"
            )
        fi
        network_interface=(
            "all"
            "default"
            $(cat "/proc/net/dev" | grep -v "docker0\|lo\|wg0" | grep "\:" | sed "s/[[:space:]]//g" | cut -d ":" -f 1 | sort | uniq | awk "{print $2}")
        )
        sysctl_list=(
            "net.core.default_qdisc = fq"
            "net.core.rmem_max = 2500000"
            "net.ipv4.ip_forward = 1"
            "net.ipv4.tcp_congestion_control = bbr"
            "net.ipv4.tcp_fastopen = 3"
            "vm.overcommit_memory = 1"
            "vm.swappiness = 10"
            ${icmp_echo[@]}
        )
        which "sysctl" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/tmp/sysctl.autodeploy" && for sysctl_list_task in "${!sysctl_list[@]}"; do
                echo "${sysctl_list[$sysctl_list_task]}" >> "/tmp/sysctl.autodeploy"
            done && for network_interface_task in "${!network_interface[@]}"; do
                echo -e "net.ipv6.conf.${network_interface[$network_interface_task]}.accept_ra = 2\nnet.ipv6.conf.${network_interface[$network_interface_task]}.autoconf = 1\nnet.ipv6.conf.${network_interface[$network_interface_task]}.forwarding = 1" >> "/tmp/sysctl.autodeploy"
            done && cat "/tmp/sysctl.autodeploy" | sort | uniq > "/etc/sysctl.conf" && sysctl -p && rm -rf "/tmp/sysctl.autodeploy"
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
                    ufw reload && ufw reset && ufw allow 123/udp && ufw allow 161/udp && ufw limit 22/tcp && ufw allow 323/udp && ufw allow 3493/tcp && ufw allow 51820/udp && ufw limit 9022/tcp && ufw allow 9090/tcp && ufw enable && ufw status verbose
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
                    "# DNS = 127.0.0.1, ::1"
                    "ListenPort = 51820"
                    "PostDown = ufw delete allow from 192.168.224.0/19; ufw route delete allow in on wg0 out on ${WAN_INTERFACE}"
                    "PostUp = ufw allow from 192.168.224.0/19; ufw route allow in on wg0 out on ${WAN_INTERFACE}"
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
                "# function proxy_off(){ unset all_proxy; unset ftp_proxy; unset http_proxy; unset https_proxy; unset rsync_proxy }"
                "# function proxy_on(){ export all_proxy=\"socks5://vpn.zhijie.online:7890\"; export ftp_proxy=\"http://vpn.zhijie.online:7890\"; export http_proxy=\"http://vpn.zhijie.online:7890\"; export https_proxy=\"http://vpn.zhijie.online:7890\"; export rsync_proxy=\"http://vpn.zhijie.online:7890\" }"
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
    ConfigureAPT
    ConfigureChrony
    ConfigureCockpit
    ConfigureCrontab
    ConfigureCrowdSec
    ConfigureDockerEngine
    ConfigureFail2Ban
    ConfigureGPG && ConfigureGit
    ConfigureGrub
    ConfigureLandscape
    ConfigureNetplan
    ConfigureNut
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
    function ConfigureGPUDriver() {
        ENABLE_AMD_GPU_DRIVER_REPO="false"
        ENABLE_INTEL_GPU_DRIVER_REPO="false"
        ENABLE_NVIDIA_GPU_DRIVER_REPO="false"
        if [ "${OSArchitecture}" == "amd64" ]; then
            if [ "${ENABLE_AMD_GPU_DRIVER_REPO}" == "true" ]; then
                amd_repo_list=(
                    "deb [arch=${OSArchitecture} signed-by=/usr/share/keyrings/amd-archive-keyring.gpg] https://repo.radeon.com/amdgpu/latest/ubuntu ${LSBCodename} main proprietary"
                    "deb [arch=${OSArchitecture} signed-by=/usr/share/keyrings/amd-archive-keyring.gpg] https://repo.radeon.com/rocm/apt/latest ${LSBCodename} main proprietary"
                    "deb-src [arch=${OSArchitecture} signed-by=/usr/share/keyrings/amd-archive-keyring.gpg] https://repo.radeon.com/amdgpu/latest/ubuntu ${LSBCodename} main proprietary"
                )
                for amd_repo_list_task in "${!amd_repo_list[@]}"; do
                    echo "${amd_repo_list[$amd_repo_list_task]}" >> "/etc/apt/sources.list.d/amd.list"
                done && curl -s --connect-timeout 15 "https://repo.radeon.com/rocm/rocm.gpg.key" | gpg --dearmor > "/usr/share/keyrings/amd-archive-keyring.gpg"
            fi
            if [ "${ENABLE_INTEL_GPU_DRIVER_REPO}" == "true" ]; then
                intel_repo_list=(
                    "deb [arch=${OSArchitecture} signed-by=/usr/share/keyrings/intel-archive-keyring.gpg] https://repositories.intel.com/graphics/ubuntu ${LSBCodename} arc legacy"
                )
                for intel_repo_list_task in "${!intel_repo_list[@]}"; do
                    echo "${intel_repo_list[$intel_repo_list_task]}" >> "/etc/apt/sources.list.d/intel.list"
                done && curl -s --connect-timeout 15 "https://repositories.intel.com/graphics/intel-graphics.key" | gpg --dearmor > "/usr/share/keyrings/intel-archive-keyring.gpg"
            fi
        fi
        if [ "${OSArchitecture}" == "amd64" ] || [ "${OSArchitecture}" == "arm64" ]; then
            if [ "${ENABLE_NVIDIA_GPU_DRIVER_REPO}" == "true" ]; then
                if [ "${OSArchitecture}" == "amd64" ]; then
                    nvidia_repo_list=(
                        "# deb [arch=${OSArchitecture} signed-by=/usr/share/keyrings/libnvidia-archive-keyring.gpg] https://nvidia.github.io/libnvidia-container/stable/ubuntu18.04/${OSArchitecture} /"
                        "# deb [arch=${OSArchitecture} signed-by=/usr/share/keyrings/libnvidia-archive-keyring.gpg] https://nvidia.github.io/nvidia-container-runtime/stable/ubuntu18.04/${OSArchitecture} /"
                        "# deb [arch=${OSArchitecture} signed-by=/usr/share/keyrings/nvidia-archive-keyring.gpg] https://developer.download.nvidia.com/compute/cuda/repos/ubuntu${LSBVersion//./}/x86_64/ /"
                    )
                else
                    nvidia_repo_list=(
                        "# deb [arch=${OSArchitecture} signed-by=/usr/share/keyrings/libnvidia-archive-keyring.gpg] https://nvidia.github.io/libnvidia-container/stable/ubuntu18.04/${OSArchitecture} /"
                        "# deb [arch=${OSArchitecture} signed-by=/usr/share/keyrings/nvidia-archive-keyring.gpg] https://developer.download.nvidia.com/compute/cuda/repos/ubuntu${LSBVersion//./}/sbsa/ /"
                    )
                fi
                nvidia_patch_list=(
                    "https://raw.githubusercontent.com/keylase/nvidia-patch/master/patch-fbc.sh"
                    "https://raw.githubusercontent.com/keylase/nvidia-patch/master/patch.sh"
                )
                for nvidia_repo_list_task in "${!nvidia_repo_list[@]}"; do
                    echo "${nvidia_repo_list[$nvidia_repo_list_task]}" >> "/etc/apt/sources.list.d/nvidia.list"
                done && curl -s --connect-timeout 15 "https://developer.download.nvidia.com/compute/cuda/repos/wsl-ubuntu/x86_64/3bf863cc.pub" | gpg --dearmor > "/usr/share/keyrings/nvidia-archive-keyring.gpg" && curl -s --connect-timeout 15 "https://nvidia.github.io/libnvidia-container/gpgkey" | gpg --dearmor > "/usr/share/keyrings/libnvidia-archive-keyring.gpg"
                rm -rf /usr/bin/nvidia_patch* && for nvidia_patch_list_task in "${!nvidia_patch_list[@]}"; do
                    FILE_NAME=$(echo "${nvidia_patch_list[$nvidia_patch_list_task]}" | awk -F "/" '{print $NF}' | cut -d '.' -f 1 | tr "-" "_")
                    curl -s --connect-timeout 15 "${GHPROXY_URL}${nvidia_patch_list[$nvidia_patch_list_task]}" > /usr/bin/nvidia_${FILE_NAME} && chmod +x /usr/bin/nvidia_${FILE_NAME}
                done
            fi
        fi
    }
    function ConfigureHostfile() {
        NEW_FULL_DOMAIN="" && for NEW_DOMAIN_TASK in "${!NEW_DOMAIN[@]}"; do
            NEW_FULL_DOMAIN="${NEW_FULL_DOMAIN} ${NEW_HOSTNAME}.${NEW_DOMAIN[$NEW_DOMAIN_TASK]}"
            NEW_FULL_DOMAIN=$(echo "${NEW_FULL_DOMAIN}" | sed "s/^\ //g;s/^${NEW_HOSTNAME}.$//g")
        done
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
    function ConfigureSWAP() {
        function ClearSWAP() {
            sysctl_swap_list=(
                "vm.drop_caches=3"
                "vm.overcommit_memory=0"
                "vm.swappiness=0"
            )
            which "sysctl" > "/dev/null" 2>&1
            if [ "$?" -eq "0" ]; then
                sync && for sysctl_swap_list_task in "${!sysctl_swap_list[@]}"; do
                    sysctl -w "${sysctl_swap_list[$sysctl_swap_list_task]}"
                done
            fi
        }
        function CreateSWAP() {
            truncate -s 0 "/swapfile"
            chattr +C "/swapfile"
            fallocate -l ${CUSTOM_SWAP_SIZE:-${SWAP_SIZE}M} "/swapfile"
            chmod 600 "/swapfile"
            mkswap "/swapfile"
            swapon "/swapfile"
        }
        function GenerateSWAPSize() {
            RAM_SIZE=$(awk "BEGIN{print log($(free -m | grep -i "mem" | awk '{print $2}')) / log(2)}")
            if [ $(echo "${RAM_SIZE}" | grep "\.") != "" ]; then
                if [ $(echo "${RAM_SIZE}" | cut -d '.' -f 2 | cut -c 1) -gt 5 ]; then
                    RAM_SIZE=$(( $(echo "${RAM_SIZE}" | cut -d '.' -f 1 ) + 1 ))
                fi
            fi
            if [ "${RAM_SIZE}" -le 11 ]; then
                SWAP_SIZE=$(echo "2 ^ ${RAM_SIZE} * 2" | bc)
            elif [ "${RAM_SIZE}" -gt 11 ] && [ "${RAM_SIZE}" -le 13 ]; then
                SWAP_SIZE=$(echo "2 ^ ${RAM_SIZE}" | bc)
            elif [ "${RAM_SIZE}" -gt 13 ] && [ "${RAM_SIZE}" -le 16 ]; then
                SWAP_SIZE=$(echo "2 ^ 12" | bc)
            else
                SWAP_SIZE=$(echo "2 ^ 13" | bc)
            fi
        }
        function RemoveSWAP() {
            SWAPFILE_NAME=($(cat "/proc/swaps" | grep -v "Filename" | awk '{print $1}'))
            for SWAPFILE_NAME_TASK in "${!SWAPFILE_NAME[@]}"; do
                swapoff "${SWAPFILE_NAME[$SWAPFILE_NAME_TASK]}" > "/dev/null" 2>&1
                rm -rf "${SWAPFILE_NAME[$SWAPFILE_NAME_TASK]}"
            done
        }
        function UpdateFSTAB() {
            cat "/etc/fstab" | grep -v "swap" > "/tmp/fstab.autodeploy"
            if [ -f "/swapfile" ]; then
                echo "/swapfile none swap sw 0 0" >> "/tmp/fstab.autodeploy"
            fi
            cat "/tmp/fstab.autodeploy" > "/etc/fstab" && rm -rf "/tmp/fstab.autodeploy"
        }
        DISABLE_SWAP="false"
        if [ "${container_environment}" != "docker" ] && [ "${container_environment}" != "wsl2" ]; then
            if [ "${DISABLE_SWAP}" == "true" ]; then
                ClearSWAP
                RemoveSWAP
                UpdateFSTAB
            else
                CUSTOM_SWAP_SIZE="" # 1024M / 1G
                ClearSWAP
                RemoveSWAP
                GenerateSWAPSize
                CreateSWAP
                UpdateFSTAB
            fi
        fi
    }
    function ConfigureTimeZone() {
        if [ -f "/etc/localtime" ]; then
            rm -rf "/etc/localtime"
        fi && ln -s "/usr/share/zoneinfo/Asia/Shanghai" "/etc/localtime"
    }
    ConfigureDefaultShell
    ConfigureDefaultUser
    ConfigureGPUDriver
    ConfigureHostfile
    ConfigureLocales
    ConfigureRootUser
    ConfigureSWAP
    ConfigureTimeZone
}
# Install Custom Packages
function InstallCustomPackages() {
    function InstallCloudflarePackage() {
        app_list=(
            "cloudflare-warp"
#           "cloudflared"
        )
        if [ "${container_environment}" != "docker" ] && [ "${container_environment}" != "wsl2" ]; then
            rm -rf "/usr/share/keyrings/cloudflare-archive-keyring.gpg" && curl -fsSL "https://pkg.cloudflare.com/cloudflare-main.gpg" | gpg --dearmor -o "/usr/share/keyrings/cloudflare-archive-keyring.gpg"
            rm -rf "/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg" && curl -fsSL "https://pkg.cloudflareclient.com/pubkey.gpg" | gpg --dearmor -o "/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg"
            echo "deb [arch=${OSArchitecture} signed-by=/usr/share/keyrings/cloudflare-archive-keyring.gpg] https://pkg.cloudflare.com/cloudflared ${LSBCodename} main" > "/etc/apt/sources.list.d/cloudflare.list"
            echo "deb [arch=${OSArchitecture} signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com ${LSBCodename} main" >> "/etc/apt/sources.list.d/cloudflare.list"
            apt update && for app_list_task in "${!app_list[@]}"; do
                apt-cache show ${app_list[$app_list_task]} && if [ "$?" -eq "0" ]; then
                    apt install -qy ${app_list[$app_list_task]}
                fi
            done
            if [ ! -f "/usr/local/share/ca-certificates/managed-warp.pem" ]; then
                curl -fsSL "https://developers.cloudflare.com/cloudflare-one/static/documentation/connections/Cloudflare_CA.pem" > "/usr/local/share/ca-certificates/Cloudflare_CA.crt"
            else
                ln -s "/usr/local/share/ca-certificates/managed-warp.pem" "/usr/local/share/ca-certificates/Cloudflare_CA.crt"
            fi
            which "update-ca-certificates" > "/dev/null" 2>&1
            if [ "$?" -eq "0" ]; then
                update-ca-certificates
            fi
        fi
    }
    function InstallCrowdSec() {
        app_list=(
            "crowdsec"
            "crowdsec-firewall-bouncer-nftables"
        )
        if [ "${container_environment}" != "docker" ] && [ "${container_environment}" != "wsl2" ]; then
            rm -rf "/usr/share/keyrings/crowdsec-archive-keyring.gpg" && curl -fsSL "https://packagecloud.io/crowdsec/crowdsec/gpgkey" | gpg --dearmor -o "/usr/share/keyrings/crowdsec-archive-keyring.gpg"
            echo "deb [arch=${OSArchitecture} signed-by=/usr/share/keyrings/crowdsec-archive-keyring.gpg] https://packagecloud.io/crowdsec/crowdsec/ubuntu ${LSBCodename} main" > "/etc/apt/sources.list.d/crowdsec.list"
            echo "deb-src [arch=${OSArchitecture} signed-by=/usr/share/keyrings/crowdsec-archive-keyring.gpg] https://packagecloud.io/crowdsec/crowdsec/ubuntu ${LSBCodename} main" >> "/etc/apt/sources.list.d/crowdsec.list"
            which "cscli" > "/dev/null" 2>&1
            if [ "$?" -eq "0" ]; then
                bouncers_list=($(cscli bouncers list | grep 'FirewallBouncer' | cut -d ' ' -f 2))
                for bouncers_list_task in "${!bouncers_list[@]}"; do
                    cscli bouncers delete ${bouncers_list[$bouncers_list_task]}
                done
            fi
            apt update && for app_list_task in "${!app_list[@]}"; do
                apt-cache show ${app_list[$app_list_task]} && if [ "$?" -eq "0" ]; then
                    apt install -qy ${app_list[$app_list_task]}
                fi
            done
        fi
    }
    function InstallDockerEngine() {
        app_list=(
            "containerd.io"
            "docker-ce"
            "docker-ce-cli"
            "docker-compose-plugin"
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
            "    rm -rf \"\$HOME/.oh-my-zsh/custom/plugins/\${plugin_list[\$plugin_list_task]}\" && git clone --depth=1 \"${GHPROXY_URL}https://github.com/zsh-users/\${plugin_list[\$plugin_list_task]}.git\" \"\$HOME/.oh-my-zsh/custom/plugins/\${plugin_list[\$plugin_list_task]}\""
            'done'
        )
        rm -rf "/etc/zsh/oh-my-zsh" && git clone --depth=1 "${GHPROXY_URL}https://github.com/ohmyzsh/ohmyzsh.git" "/etc/zsh/oh-my-zsh" && if [ -d "/etc/zsh/oh-my-zsh/custom/plugins" ]; then
            for plugin_list_task in "${!plugin_list[@]}"; do
                rm -rf "/etc/zsh/oh-my-zsh/custom/plugins/${plugin_list[$plugin_list_task]}" && git clone --depth=1 "${GHPROXY_URL}https://github.com/zsh-users/${plugin_list[$plugin_list_task]}.git" "/etc/zsh/oh-my-zsh/custom/plugins/${plugin_list[$plugin_list_task]}"
            done
        fi && rm -rf "/etc/zsh/oh-my-zsh/oh-my-zsh-plugin.sh" && for plugin_upgrade_list_task in "${!plugin_upgrade_list[@]}"; do
            echo "${plugin_upgrade_list[$plugin_upgrade_list_task]}" >> "/etc/zsh/oh-my-zsh/oh-my-zsh-plugin.sh"
        done
    }
#   InstallCloudflarePackage
    InstallCrowdSec
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
        "cron"
        "curl"
        "dnsutils"
        "ethtool"
        "git"
        "git-flow"
        "git-lfs"
        "gnupg"
        "iperf3"
        "iputils-ping"
        "jq"
        "knot-dnsutils"
        "landscape-common"
        "libsnmp-dev"
        "lm-sensors"
        "lsb-release"
        "mailutils"
        "mtr-tiny"
        "nano"
        "neofetch"
        "net-tools"
        "nfs-common"
        "nmap"
        "ntfs-3g"
        "nut"
        "nut-i2c"
        "nut-ipmi"
        "nut-modbus"
        "nut-powerman-pdu"
        "nut-snmp"
        "nut-xml"
        "openssh-client"
        "openssh-server"
        "p7zip-full"
        "pinentry-tty"
        "postfix"
        "python3"
        "python3-pip"
        "qrencode"
        "rar"
        "realmd"
        "rsyslog"
        "snmp"
        "snmp-mibs-downloader"
        "snmpd"
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
        "uuid-runtime"
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
        app_list=(${app_regular_list[*]} ${HYPERVISOR_AGENT[*]} ${MICROCODE[*]})
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
    apt update && apt full-upgrade -qy && apt autoremove -qy
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
