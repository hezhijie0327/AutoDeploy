#!/bin/bash

# Current Version: 1.0.5

## How to get and use?
# curl "https://source.zhijie.online/AutoDeploy/main/OMV.sh" | sudo bash
# wget -qO- "https://source.zhijie.online/AutoDeploy/main/OMV.sh" | sudo bash

## Function
# Get System Information
function GetSystemInformation() {
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
            NEW_HOSTNAME="OMV-$(date '+%Y%m%d%H%M%S')"
        fi
    }
    function GenerateResolv() {
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
        fi
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
        fi && rm -rf "/etc/resolv.conf" && cat "/tmp/resolv.autodeploy" > "/etc/resolv.conf" && rm -rf "/tmp/resolv.autodeploy"
    }
    function GetCPUpsABILevel() {
        # https://dl.xanmod.org/check_x86-64_psabi.sh
        psABILevel=$(awk 'BEGIN{while(!/flags/)if(getline<"/proc/cpuinfo"!=1)exit 0;if(/lm/&&/cmov/&&/cx8/&&/fpu/&&/fxsr/&&/mmx/&&/syscall/&&/sse2/)l=1;if(l==1&&/cx16/&&/lahf/&&/popcnt/&&/sse4_1/&&/sse4_2/&&/ssse3/)l=2;if(l==2&&/avx/&&/avx2/&&/bmi1/&&/bmi2/&&/f16c/&&/fma/&&/abm/&&/movbe/&&/xsave/)l=3;if(l==3&&/avx512f/&&/avx512bw/&&/avx512cd/&&/avx512dq/&&/avx512vl/)l=4;print l}')
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
    function GetHostname() {
        if [ -f "/etc/hostname" ]; then
            OLD_HOSTNAME=$(cat "/etc/hostname" | awk "{print $2}")
        fi
        if [ $(echo "${OLD_HOSTNAME}" | wc -l) -ne 1 ]; then
            which "hostname" > "/dev/null" 2>&1
            if [ "$?" -eq "0" ]; then
                OLD_HOSTNAME=$(hostname)
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
    }
    function SetGHProxyDomain() {
        GHPROXY_URL=""
        if [ "${GHPROXY_URL}" != "" ]; then
            export GHPROXY_URL="https://${GHPROXY_URL}/"
        fi
    }
    function SetPackageCodename() {
        OMVCodename="shaitan"
        LSBCodename="bullseye"
    }
    GenerateDomain
    GenerateHostname
    GenerateResolv
    GetCPUpsABILevel
    GetCPUVendorID
    GetHostname
    GetOSArchitecture
    SetGHProxyDomain
    SetPackageCodename
}
# Set Repository Mirror
function SetRepositoryMirror() {
    mirror_list=(
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/debian-security ${LSBCodename}-security contrib main non-free non-free-firmware"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/debian ${LSBCodename} contrib main non-free non-free-firmware"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/debian ${LSBCodename}-backports contrib main non-free non-free-firmware"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/debian ${LSBCodename}-backports-sloppy contrib main non-free non-free-firmware"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/debian ${LSBCodename}-proposed-updates contrib main non-free non-free-firmware"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/debian ${LSBCodename}-updates contrib main non-free non-free-firmware"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/debian-security ${LSBCodename}-security contrib main non-free non-free-firmware"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/debian ${LSBCodename} contrib main non-free non-free-firmware"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/debian ${LSBCodename}-backports contrib main non-free non-free-firmware"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/debian ${LSBCodename}-backports-sloppy contrib main non-free non-free-firmware"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/debian ${LSBCodename}-proposed-updates contrib main non-free non-free-firmware"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/debian ${LSBCodename}-updates contrib main non-free non-free-firmware"
    )
    omv_mirror_list=(
        "deb ${transport_protocol}://mirrors.tuna.tsinghua.edu.cn/OpenMediaVault/public ${OMVCodename} main partner"
        "deb ${transport_protocol}://mirrors.tuna.tsinghua.edu.cn/OpenMediaVault/packages ${OMVCodename} main partner"
        "deb ${transport_protocol}://mirrors.tuna.tsinghua.edu.cn/OpenMediaVault/public ${OMVCodename}-proposed main"
        "deb ${transport_protocol}://mirrors.tuna.tsinghua.edu.cn/OpenMediaVault/packages ${OMVCodename}-proposed main"
    )
    if [ ! -d "/etc/apt/sources.list.d" ]; then
        mkdir "/etc/apt/sources.list.d"
    else
        rm -rf /etc/apt/sources.list.d/*.*
    fi
    rm -rf "/tmp/apt.autodeploy" && for mirror_list_task in "${!mirror_list[@]}"; do
        echo "${mirror_list[$mirror_list_task]}" >> "/tmp/apt.autodeploy"
    done && cat "/tmp/apt.autodeploy" > "/etc/apt/sources.list" && rm -rf "/tmp/apt.autodeploy"
    rm -rf "/tmp/apt.autodeploy" && for omv_mirror_list_task in "${!omv_mirror_list[@]}"; do
        echo "${omv_mirror_list[$omv_mirror_list_task]}" >> "/tmp/apt.autodeploy"
    done && cat "/tmp/apt.autodeploy" > "/etc/apt/sources.list.d/openmediavault.list" && rm -rf "/tmp/apt.autodeploy"
}
# Set Readonly Flag
function SetReadonlyFlag() {
    file_list=(
        "/etc/apt/preferences"
        "/etc/apt/preferences.d/omvextras.pref"
        "/etc/apt/preferences.d/openmediavault.pref"
        "/etc/apt/sources.list"
        "/etc/apt/sources.list.d/cloudflare.list"
        "/etc/apt/sources.list.d/crowdsec.list"
        "/etc/apt/sources.list.d/docker.list"
        "/etc/apt/sources.list.d/frrouting.list"
        "/etc/apt/sources.list.d/omvextras.list"
        "/etc/apt/sources.list.d/openmediavault.list"
        "/etc/apt/sources.list.d/xanmod.list"
        "/etc/chrony/chrony.conf"
        "/etc/default/lldpd"
        "/etc/docker/daemon.json"
        "/etc/fail2ban/fail2ban.local"
        "/etc/fail2ban/filter.d/openmediavault.conf"
        "/etc/fail2ban/jail.local"
        "/etc/fail2ban/jail.d/fail2ban_default.conf"
        "/etc/gai.conf"
        "/etc/hostname"
        "/etc/hosts"
        "/etc/sysctl.conf"
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
            "${LSBCodename}-backports-sloppy 990"
            "${LSBCodename}-backports 990"
            "${LSBCodename}-security 500"
            "${LSBCodename}-updates 500"
            "${LSBCodename} 500"
            "${LSBCodename}-proposed-updates 100"
        )
        omv_extras_repo_preference_list=(
            "${OMVCodename} 990"
            "${OMVCodename}-beta 100"
            "${OMVCodename}-testing 100"
        )
        omv_repo_preference_list=(
            "${OMVCodename} 990"
            "${OMVCodename}-proposed 100"
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
        rm -rf "/tmp/apt_preference_list.autodeploy" && for omv_extras_repo_preference_list_task in "${!omv_extras_repo_preference_list[@]}"; do
            OMV_EXTRAS_REPO_PIN_RELEASE=$(echo "${omv_extras_repo_preference_list[$omv_extras_repo_preference_list_task]}" | cut -d " " -f 1)
            OMV_EXTRAS_REPO_PIN_PRIORITY=$(echo "${omv_extras_repo_preference_list[$omv_extras_repo_preference_list_task]}" | cut -d " " -f 2)
            if [ ! -z $(echo ${OMV_EXTRAS_REPO_PIN_PRIORITY} | grep "[a-z]\|[A-Z]\|-") ]; then
                OMV_EXTRAS_REPO_PIN_PRIORITY="500"
            fi
            echo -e "Package: *\nPin: release a=${OMV_EXTRAS_REPO_PIN_RELEASE}\nPin-Priority: ${OMV_EXTRAS_REPO_PIN_PRIORITY}\n" >> "/tmp/apt_preference_list.autodeploy"
        done && cat "/tmp/apt_preference_list.autodeploy" | sed '$d' > "/etc/apt/preferences.d/omvextras.pref"
        rm -rf "/tmp/apt_preference_list.autodeploy" && for omv_repo_preference_list_task in "${!omv_repo_preference_list[@]}"; do
            OMV_REPO_PIN_RELEASE=$(echo "${omv_repo_preference_list[$omv_repo_preference_list_task]}" | cut -d " " -f 1)
            OMV_REPO_PIN_PRIORITY=$(echo "${omv_repo_preference_list[$omv_repo_preference_list_task]}" | cut -d " " -f 2)
            if [ ! -z $(echo ${OMV_REPO_PIN_PRIORITY} | grep "[a-z]\|[A-Z]\|-") ]; then
                OMV_REPO_PIN_PRIORITY="500"
            fi
            echo -e "Package: *\nPin: release a=${OMV_REPO_PIN_RELEASE}\nPin-Priority: ${OMV_REPO_PIN_PRIORITY}\n" >> "/tmp/apt_preference_list.autodeploy"
        done && cat "/tmp/apt_preference_list.autodeploy" | sed '$d' > "/etc/apt/preferences.d/openmediavault.pref"
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
                if [ "${chrony_ntp_list[$chrony_ntp_list_task]}" == "ntp.ntsc.ac.cn" ] || [ "${chrony_ntp_list[$chrony_ntp_list_task]}" == "ntp1.nim.ac.cn" ] || [ "${chrony_ntp_list[$chrony_ntp_list_task]}" == "ntp1.nim.ac.cn" ] || [ "$(echo ${DHCP_NTP[@]} | grep ${chrony_ntp_list[$chrony_ntp_list_task]})" != "" ]; then
                    echo "server ${chrony_ntp_list[$chrony_ntp_list_task]} iburst prefer" >> "/tmp/chrony.autodeploy"
                else
                    echo "server ${chrony_ntp_list[$chrony_ntp_list_task]} iburst" >> "/tmp/chrony.autodeploy"
                fi
            done && cat "/tmp/chrony.autodeploy" > "/etc/chrony/chrony.conf" && rm -rf "/tmp/chrony.autodeploy" && systemctl restart chrony.service && sleep 5s && chronyc activity && chronyc tracking && chronyc clients && hwclock -w
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
            for crowdsec_hub_list_task in "${!crowdsec_hub_list[@]}"; do
                cscli collections install ${crowdsec_hub_list[$crowdsec_hub_list_task]}
            done
        fi && systemctl restart crowdsec.service && cscli hub list
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
            if [ ! -d "/docker" ]; then
                mkdir "/docker"
            fi && chown -R ${DEFAULT_USERNAME}:docker "/docker" && chmod -R 775 "/docker"
            if [ ! -d "/etc/docker" ]; then
                mkdir "/etc/docker"
            fi
            rm -rf "/tmp/docker.autodeploy" && for docker_list_task in "${!docker_list[@]}"; do
                echo "${docker_list[$docker_list_task]}" >> "/tmp/docker.autodeploy"
            done && cat "/tmp/docker.autodeploy" > "/etc/docker/daemon.json" && systemctl restart docker.service && rm -rf "/tmp/docker.autodeploy"
        fi
    }
    function ConfigureFail2Ban() {
        fail2ban_list=(
            "[openmediavault]"
            "bantime = 604800"
            "enabled = true"
            "filter = openmediavault"
            "findtime = 60"
            "logpath = /var/log/auth.log"
            "maxretry = 5"
            "port = 80,443"
            "[sshd]"
            "bantime = 604800"
            "enabled = true"
            "filter = sshd"
            "findtime = 60"
            "logpath = /var/log/auth.log"
            "maxretry = 5"
            "port = 22"
        )
        fail2ban_omv_list=(
            "[Definition]"
            "failregex = .*\s+openmediavault-webgui\[\d+\]:\s+Unauthorized login attempt from\s+::[^:]+:<HOST>\s+.*"
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
            rm -rf "/tmp/fail2ban.autodeploy" && for fail2ban_openmediavault_list_task in "${!fail2ban_openmediavault_list[@]}"; do
                echo "${fail2ban_openmediavault_list[$fail2ban_openmediavault_list_task]}" >> "/tmp/fail2ban.autodeploy"
            done && cat "/tmp/fail2ban.autodeploy" > "/etc/fail2ban/filter.d/openmediavault.conf" && rm -rf "/tmp/fail2ban.autodeploy"
            rm -rf "/tmp/fail2ban.autodeploy" && for fail2ban_list_task in "${!fail2ban_list[@]}"; do
                echo "${fail2ban_list[$fail2ban_list_task]}" >> "/tmp/fail2ban.autodeploy"
            done && cat "/tmp/fail2ban.autodeploy" > "/etc/fail2ban/jail.d/fail2ban_default.conf" && rm -rf "/tmp/fail2ban.autodeploy" && systemctl enable fail2ban && fail2ban-client reload && sleep 5s && fail2ban-client status
        fi
    }
    function ConfigureFRRouting() {
        frrouting_list=(
            "frr defaults datacenter"
            "log syslog errors"
        )
        which "vtysh" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/tmp/frrouting.autodeploy" && for frrouting_list_task in "${!frrouting_list[@]}"; do
                echo "${frrouting_list[$frrouting_list_task]}" >> "/tmp/frrouting.autodeploy"
            done && cat "/tmp/frrouting.autodeploy" > "/etc/frr/frr.conf" && rm -rf "/tmp/frrouting.autodeploy"
            systemctl restart frr && sleep 5s && vtysh -c "show running-config" && vtysh -c "show ip route" && vtysh -c "show ipv6 route"
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
    }
    function ConfigureGrub() {
        which "update-grub" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            if [ -f "/usr/share/grub/default/grub" ]; then
                rm -rf "/tmp/grub.autodeploy" && cat "/usr/share/grub/default/grub" > "/tmp/grub.autodeploy" && cat "/tmp/grub.autodeploy" > "/etc/default/grub" && update-grub && rm -rf "/tmp/grub.autodeploy"
            fi
        fi
    }
    function ConfigureLLDPD() {
        which "lldpcli" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            echo 'DAEMON_ARGS="-c -e -f -s -x"' > "/tmp/lldpd.autodeploy" && cat "/tmp/lldpd.autodeploy" > "/etc/default/lldpd" && rm -rf "/tmp/lldpd.autodeploy"
            systemctl restart lldpd && lldpcli show neighbors detail
        fi
    }
    function ConfigureNut() {
        which "upsmon" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            function Create_upsd_users() {
                upsd_user_list=(
                    "admin,123456,master,FSD,SET"
                    "monuser,secret,slave,,"
                )
            }
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
                        "LISTEN 127.0.0.1 3493"
                        "LISTEN ::1 3493"
                        "MAXAGE 15"
                        "MAXCONN 1024"
                        "STATEPATH /var/run/nut"
                    )
                else
                    upsd_config_list=(
                        "LISTEN 0.0.0.0 3493"
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
                rm -rf "/tmp/upsd.users.autodeploy" && for upsd_user_list_task in "${!upsd_user_list[@]}"; do
                    UPSD_USERNAME=$(echo "${upsd_user_list[$upsd_user_list_task]}" | cut -d ',' -f 1)
                    UPSD_PASSWORD=$(echo "${upsd_user_list[$upsd_user_list_task]}" | cut -d ',' -f 2)
                    UPSD_ROLE=$(echo "${upsd_user_list[$upsd_user_list_task]}" | cut -d ',' -f 3)
                    UPSD_ACTIONS=$(echo "${upsd_user_list[$upsd_user_list_task]}" | cut -d ',' -f 4-5 | tr ',' ' ' | sed 's/^ //g')
                    if [ "${UPSD_ACTIONS}" != "" ]; then
                        UPSD_ACTIONS="    actions = ${UPSD_ACTIONS}\n    instcmds = ALL\n"
                    fi
                    echo -e "[${UPSD_USERNAME}]\n${UPSD_ACTIONS}    password = ${UPSD_PASSWORD}\n    upsmon ${UPSD_ROLE}" >> "/tmp/upsd.users.autodeploy"
                done && cat "/tmp/upsd.users.autodeploy" > "/etc/nut/upsd.users" && rm -rf "/tmp/upsd.users.autodeploy"
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
                done && cat "/tmp/upsmon.conf.autodeploy" > "/etc/nut/upsmon.conf" && rm -rf "/tmp/upsmon.conf.autodeploy"
            }
            function Generate_upssched_conf() {
                upssched_conf=(
                    "CMDSCRIPT /bin/upssched-cmd"
                )
            }
            NUT_MODE="" # netclient | netserver | none | standalone
            NUT_HOST="" # localhost
            rm -rf /etc/nut/*.* && case ${NUT_MODE:-none} in
                netclient)
                    Create_upsd_users
                    UPSMON_USERNAME=$(echo "${upsd_user_list[*]}" | cut -d ' ' -f 2 | cut -d ',' -f 1)
                    UPSMON_PASSWORD=$(echo "${upsd_user_list[*]}" | cut -d ' ' -f 2 | cut -d ',' -f 2)
                    UPSMON_ROLE=$(echo "${upsd_user_list[*]}" | cut -d ' ' -f 2 | cut -d ',' -f 3)
                    UPSMON_SYSTEM="${UPS_NAME-ups}@${NUT_HOST:-localhost}"
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
                    Create_upsd_users
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
            esac && chown -R root:nut "/etc/nut" && chmod 640 /etc/nut/*.*
            for nut_service_list_task in "${!nut_service_list[@]}"; do
                NUT_SERVICE_NAME=$(echo "${nut_service_list[$nut_service_list_task]}" | cut -d ',' -f 1)
                NUT_SERVICE_STATUS=$(echo "${nut_service_list[$nut_service_list_task]}" | cut -d ',' -f 2)
                systemctl ${NUT_SERVICE_STATUS} ${NUT_SERVICE_NAME} > "/dev/null" 2>&1
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
            if [ "$(cat '/etc/postfix/main.cf' | grep 'myhostname\=')" != "" ]; then
                CURRENT_HOSTNAME=$(cat "/etc/postfix/main.cf" | grep "myhostname\=" | sed "s/myhostname\=//g")
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
            systemctl stop snmpd
            kill $(ps -ef | grep snmp | grep -v 'grep' | cut -d ' ' -f 3) > "/dev/null" 2>&1
            sed -i 's/^mibs :/# mibs :/g' "/etc/snmp/snmp.conf"
            echo "createUser ${SNMP_USER} SHA \"${SNMP_AUTH_PASS}\" AES \"${SNMP_PRIV_PASS}\"" > "/var/lib/snmp/snmpd.conf"
            rm -rf "/tmp/snmp.autodeploy" && for snmp_list_task in "${!snmp_list[@]}"; do
                echo "${snmp_list[$snmp_list_task]}" >> "/tmp/snmp.autodeploy"
            done && cat "/tmp/snmp.autodeploy" | sort > "/etc/snmp/snmpd.conf" && rm -rf "/tmp/snmp.autodeploy" && systemctl start snmpd && snmpwalk -v3 -a SHA -A ${SNMP_AUTH_PASS} -x AES -X ${SNMP_PRIV_PASS} -l authPriv -u ${SNMP_USER} 127.0.0.1 | head
        fi
    }
    function ConfigureSshd() {
        if [ -f "/usr/share/openssh/sshd_config" ]; then
            cat "/usr/share/openssh/sshd_config" | sed "s/\#PasswordAuthentication\ yes/PasswordAuthentication\ yes/g;s/\#PermitRootLogin\ prohibit\-password/PermitRootLogin\ yes/g;s/\#PubkeyAuthentication\ yes/PubkeyAuthentication\ yes/g" > "/tmp/sshd_config.autodeploy" && cat "/tmp/sshd_config.autodeploy" > "/etc/ssh/sshd_config" && rm -rf "/tmp/sshd_config.autodeploy"
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
        bridge_interface=(
            "all"
            "default"
            $(cat "/proc/net/dev" | grep -v "docker0\|lo\|wg0" | grep "\:" | sed "s/[[:space:]]//g" | cut -d ":" -f 1 | sort | uniq | grep "vmbr" | awk "{print $2}")
        )
        sysctl_list=(
            "net.core.default_qdisc = fq_pie"
            "net.core.rmem_max = 2500000"
            "net.core.wmem_max = 2500000"
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
            done && for bridge_interface_task in "${!bridge_interface[@]}"; do
                echo -e "net.ipv6.conf.${bridge_interface[$bridge_interface_task]}.accept_ra = 2\nnet.ipv6.conf.${bridge_interface[$bridge_interface_task]}.autoconf = 1\nnet.ipv6.conf.${bridge_interface[$bridge_interface_task]}.forwarding = 1" >> "/tmp/sysctl.autodeploy"
            done && cat "/tmp/sysctl.autodeploy" | sort | uniq > "/etc/sysctl.conf" && sysctl -p && rm -rf "/tmp/sysctl.autodeploy"
        fi
    }
    function ConfigureTuned() {
        which "tuned-adm" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            tuned-adm profile "$(tuned-adm recommend)" && tuned-adm active
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
                "function proxy_off(){ unset all_proxy; unset ftp_proxy; unset http_proxy; unset https_proxy; unset rsync_proxy }"
                "function proxy_on(){ export all_proxy=\"socks5://vpn.zhijie.online:7891\"; export ftp_proxy=\"http://vpn.zhijie.online:7890\"; export http_proxy=\"http://vpn.zhijie.online:7890\"; export https_proxy=\"http://vpn.zhijie.online:7890\"; export rsync_proxy=\"http://vpn.zhijie.online:7890\" }"
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
    ConfigureCrontab
    ConfigureCrowdSec
    ConfigureDockerEngine
    ConfigureFail2Ban
    ConfigureFRRouting
    ConfigureGPG && ConfigureGit
    ConfigureGrub
    ConfigureLLDPD
    ConfigureNut
    ConfigureOpenSSH
    ConfigurePostfix
    ConfigurePythonPyPI
    ConfigureSNMP
    ConfigureSshd
    ConfigureSysctl
    ConfigureTuned
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
        DEFAULT_FIRSTNAME="User"
        DEFAULT_LASTNAME="OMV"
        DEFAULT_FULLNAME="${DEFAULT_LASTNAME} ${DEFAULT_FIRSTNAME}"
        DEFAULT_USERNAME="omv"
        DEFAULT_PASSWORD='*OMV123*'
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
        useradd -c "${DEFAULT_FULLNAME}" -d "/home/${DEFAULT_USERNAME}" -s "/bin/zsh" -m "${DEFAULT_USERNAME}" && echo $DEFAULT_USERNAME:$DEFAULT_PASSWORD | chpasswd && adduser "${DEFAULT_USERNAME}" "docker" && adduser "${DEFAULT_USERNAME}" "openmediavault-admin" && adduser "${DEFAULT_USERNAME}" "sudo"
        which "crontab" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/tmp/crontab.autodeploy" && for crontab_list_task in "${!crontab_list[@]}"; do
                echo "${crontab_list[$crontab_list_task]}" >> "/tmp/crontab.autodeploy"
            done && crontab -u "${DEFAULT_USERNAME}" "/tmp/crontab.autodeploy" && crontab -lu "${DEFAULT_USERNAME}" && rm -rf "/tmp/crontab.autodeploy"
        fi
    }
    function ConfigureGAI() {
        PREFER_IPV4="true"
        if [ "${PREFER_IPV4}" == "true" ]; then
            PREFER_IPV4_OPTION="precedence ::ffff:0:0/96 100"
        else
            PREFER_IPV4_OPTION="precedence ::ffff:0:0/96 10"
        fi
        gai_conf_list=(
            "label ::/0 1"
            "label ::1/128 0"
            "label 2001:0::/32 7"
            "label 2002::/16 2"
            "label ::/96 3"
            "label fc00::/7 6"
            "label fec0::/10 5"
            "label ::ffff:0:0/96 4"
            "precedence ::/0 40"
            "precedence ::1/128 50"
            "precedence 2002::/16 30"
            "precedence ::/96 20"
            "${PREFER_IPV4_OPTION}"
            "scopev4 ::ffff:0.0.0.0/96 14"
            "scopev4 ::ffff:127.0.0.0/104 2"
            "scopev4 ::ffff:169.254.0.0/112 2"
        )
        rm -rf "/tmp/gai.autodeploy" && for gai_conf_list_task in "${!gai_conf_list[@]}"; do
            echo "${gai_conf_list[$gai_conf_list_task]}" >> "/tmp/gai.autodeploy"
        done && cat "/tmp/gai.autodeploy" | sort | uniq > "/etc/gai.conf"
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
    function ConfigureRootUser() {
        LOCK_ROOT="TRUE"
        ROOT_PASSWORD='R00t@123!'
        echo root:$ROOT_PASSWORD | chpasswd && if [ "${LOCK_ROOT}" == "TRUE" ]; then
            passwd -l "root"
        else
            passwd -u "root"
        fi
    }
    ConfigureDefaultShell
    ConfigureDefaultUser
    ConfigureGAI
    ConfigureHostfile
    ConfigureRootUser
}
# Install Custom Packages
function InstallCustomPackages() {
    function InstallCloudflarePackage() {
        app_list=(
            "cloudflare-warp"
        )
        rm -rf "/etc/apt/keyrings/cloudflare-warp-archive-keyring.gpg" && curl -fsSL "https://pkg.cloudflareclient.com/pubkey.gpg" | gpg --dearmor -o "/etc/apt/keyrings/cloudflare-warp-archive-keyring.gpg"
        echo "deb [arch=${OSArchitecture} signed-by=/etc/apt/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com ${LSBCodename} main" > "/etc/apt/sources.list.d/cloudflare.list"
        apt update && for app_list_task in "${!app_list[@]}"; do
            apt-cache show ${app_list[$app_list_task]} && if [ "$?" -eq "0" ]; then
                apt install -qy ${app_list[$app_list_task]}
            fi
        done
        which "update-ca-certificates" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/usr/local/share/ca-certificates/Cloudflare_CA.crt" && curl -fsSL "https://developers.cloudflare.com/cloudflare-one/static/documentation/connections/Cloudflare_CA.pem" > "/usr/local/share/ca-certificates/Cloudflare_CA.crt" && update-ca-certificates
        fi
    }
    function InstallCrowdSec() {
        app_list=(
            "crowdsec"
            "crowdsec-firewall-bouncer-nftables"
        )
        if [ ! -d "/etc/apt/keyrings" ]; then
            mkdir "/etc/apt/keyrings"
        fi
        rm -rf "/etc/apt/keyrings/crowdsec-archive-keyring.gpg" && curl -fsSL "https://packagecloud.io/crowdsec/crowdsec/gpgkey" | gpg --dearmor -o "/etc/apt/keyrings/crowdsec-archive-keyring.gpg"
        echo "deb [arch=${OSArchitecture} signed-by=/etc/apt/keyrings/crowdsec-archive-keyring.gpg] https://packagecloud.io/crowdsec/crowdsec/debian ${LSBCodename} main" > "/etc/apt/sources.list.d/crowdsec.list"
        echo "deb-src [arch=${OSArchitecture} signed-by=/etc/apt/keyrings/crowdsec-archive-keyring.gpg] https://packagecloud.io/crowdsec/crowdsec/debian ${LSBCodename} main" >> "/etc/apt/sources.list.d/crowdsec.list"
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
    }
    function InstallDockerEngine() {
        app_list=(
            "containerd.io"
            "docker-ce"
            "docker-ce-cli"
            "docker-compose-plugin"
            "docker-compose"
        )
        if [ ! -d "/etc/apt/keyrings" ]; then
            mkdir "/etc/apt/keyrings"
        fi
        rm -rf "/etc/apt/keyrings/docker-archive-keyring.gpg" && curl -fsSL "https://mirrors.ustc.edu.cn/docker-ce/linux/debian/gpg" | gpg --dearmor -o "/etc/apt/keyrings/docker-archive-keyring.gpg"
        echo "deb [arch=${OSArchitecture} signed-by=/etc/apt/keyrings/docker-archive-keyring.gpg] https://mirrors.ustc.edu.cn/docker-ce/linux/debian ${LSBCodename} stable" > "/etc/apt/sources.list.d/docker.list"
        apt update && apt purge -qy containerd docker docker-engine docker.io runc && for app_list_task in "${!app_list[@]}"; do
            apt-cache show ${app_list[$app_list_task]} && if [ "$?" -eq "0" ]; then
                apt install -qy ${app_list[$app_list_task]}
            fi
        done
    }
    function InstallFRRouting() {
        apt_list=(
            "frr"
            "frr-pythontools"
            "frr-snmp"
        )
        rm -rf "/etc/apt/keyrings/frrouting-archive-keyring.gpg" && curl -fsSL "https://deb.frrouting.org/frr/keys.gpg" | gpg --dearmor -o "/etc/apt/keyrings/frrouting-archive-keyring.gpg"
        echo "deb [arch=${OSArchitecture} signed-by=/etc/apt/keyrings/frrouting-archive-keyring.gpg] https://deb.frrouting.org/frr ${LSBCodename} frr-stable" > "/etc/apt/sources.list.d/frrouting.list"
        apt update && for app_list_task in "${!app_list[@]}"; do
            apt-cache show ${app_list[$app_list_task]} && if [ "$?" -eq "0" ]; then
                apt install -qy ${app_list[$app_list_task]}
            fi
        done
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
    function InstallOMVExtras() {
        function SetOMVExtrasRepository() {
            echo "deb [arch=${OSArchitecture} signed-by=/etc/apt/keyrings/omvextras-archive-keyring.gpg] https://mirrors.tuna.tsinghua.edu.cn/OpenMediaVault/openmediavault-plugin-developers ${OMVCodename} main" > "/etc/apt/sources.list.d/omvextras.list"
            echo "deb [arch=${OSArchitecture} signed-by=/etc/apt/keyrings/omvextras-archive-keyring.gpg] https://mirrors.tuna.tsinghua.edu.cn/OpenMediaVault/openmediavault-plugin-developers ${OMVCodename}-beta main" >> "/etc/apt/sources.list.d/omvextras.list"
            echo "deb [arch=${OSArchitecture} signed-by=/etc/apt/keyrings/omvextras-archive-keyring.gpg] https://mirrors.tuna.tsinghua.edu.cn/OpenMediaVault/openmediavault-plugin-developers ${OMVCodename}-testing main" >> "/etc/apt/sources.list.d/omvextras.list"
        }
        apt_list=(
            "openmediavault-omvextrasorg"
        )
        rm -rf "/etc/apt/keyrings/omvextras-archive-keyring.gpg" && curl -fsSL "https://mirrors.tuna.tsinghua.edu.cn/OpenMediaVault/openmediavault-plugin-developers/omvextras2026.asc" | gpg --dearmor -o "/etc/apt/keyrings/omvextras-archive-keyring.gpg" && SetOMVExtrasRepository
        apt update && for app_list_task in "${!app_list[@]}"; do
            apt-cache show ${app_list[$app_list_task]} && if [ "$?" -eq "0" ]; then
                apt install -qy ${app_list[$app_list_task]}
            fi
        done && SetOMVExtrasRepository
    }
    function InstallXanModKernel() {
        # Note: The current NVIDIA, OpenZFS, VirtualBox, VMware Workstation / Player and some other dkms modules may not officially support EDGE and RT branch kernels.
        # How to fix "modinfo: ERROR: Module tcp_bbr not found." -> sudo depmod && modinfo tcp_bbr
        # How to remove? -> sudo apt autoremove linux-image-*.*.*-xanmod* linux-headers-*.*.*-xanmod* --purge
        XANMOD_BRANCH="" # disable, edge, lts, rt
        if [ "${XANMOD_BRANCH}" == "" ]; then
            XANMOD_BRANCH=""
        elif [ "${XANMOD_BRANCH}" == "edge" ] || [ "${XANMOD_BRANCH}" == "lts" ] || [ "${XANMOD_BRANCH}" == "rt" ]; then
            XANMOD_BRANCH="${XANMOD_BRANCH}-"
        fi
        if [ "${psABILevel}" == "1" ] && { [ "${XANMOD_BRANCH}" == "edge" ] || [ "${XANMOD_BRANCH}" == "rt" ]; }; then
            XANMOD_BRANCH=""
        fi

        apt_list=(
            "linux-xanmod-${XANMOD_BRANCH}x64v${psABILevel}"
        )
        if [ "${OSArchitecture}" == "amd64" ] && [ "${psABILevel}" != "0" ] && [ "${XANMOD_BRANCH}" != "disable" ]; then
            rm -rf "/etc/apt/keyrings/xanmod-archive-keyring.gpg" && curl -fsSL "https://dl.xanmod.org/archive.key" | gpg --dearmor -o "/etc/apt/keyrings/xanmod-archive-keyring.gpg"
            echo "deb [arch=${OSArchitecture} signed-by=/etc/apt/keyrings/xanmod-archive-keyring.gpg] https://deb.xanmod.org releases main" > "/etc/apt/sources.list.d/xanmod.list"
            apt update && for app_list_task in "${!app_list[@]}"; do
                apt-cache show ${app_list[$app_list_task]} && if [ "$?" -eq "0" ]; then
                    apt install -qy ${app_list[$app_list_task]}
                fi
            done
        fi
    }
    InstallCloudflarePackage
    InstallCrowdSec
    InstallDockerEngine
    InstallFRRouting
    InstallOhMyZsh
    InstallOMVExtras
    InstallXanModKernel
}
# Install Dependency Packages
function InstallDependencyPackages() {
    app_regular_list=(
        "apt-file"
        "apt-transport-https"
        "bc"
        "ca-certificates"
        "chrony"
        "curl"
        "dnsutils"
        "ethtool"
        "fail2ban"
        "git"
        "git-flow"
        "git-lfs"
        "gnupg"
        "iperf3"
        "jq"
        "knot-dnsutils"
        "libsnmp-dev"
        "lldpd"
        "lm-sensors"
        "lsb-release"
        "mailutils"
        "mtr-tiny"
        "nano"
        "neofetch"
        "net-tools"
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
        "snmp"
        "snmp-mibs-downloader"
        "snmpd"
        "sudo"
        "systemd"
        "tcpdump"
        "tshark"
        "tuned"
        "unrar"
        "unzip"
        "vim"
        "virt-what"
        "wget"
        "whois"
        "zip"
        "zsh"
    )
    app_list=(${app_regular_list[*]} ${MICROCODE[*]})
    apt update && for app_list_task in "${!app_list[@]}"; do
        apt-cache show ${app_list[$app_list_task]} && if [ "$?" -eq "0" ]; then
            apt install -qy ${app_list[$app_list_task]}
        fi
    done
}
# Upgrade Packages
function UpgradePackages() {
    apt update && apt full-upgrade -qy && apt autoremove -qy
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
# Call ConfigureSystem
ConfigureSystem
# Call ConfigurePackages
ConfigurePackages
# Set read_only="TRUE"; Call SetReadonlyFlag
read_only="TRUE" && SetReadonlyFlag
# Call CleanupTempFiles
CleanupTempFiles
