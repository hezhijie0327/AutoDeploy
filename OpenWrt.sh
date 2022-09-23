#!/bin/bash

# Current Version: 1.2.2

## How to get and use?
# curl "https://source.zhijie.online/AutoDeploy/main/OpenWrt.sh" | sudo bash
# wget -qO- "https://source.zhijie.online/AutoDeploy/main/OpenWrt.sh" | sudo bash

## How to install OpenWrt on Ubuntu?
# wget https://mirrors.ustc.edu.cn/openwrt/releases/22.03.0/targets/x86/64/openwrt-22.03.0-x86-64-generic-ext4-combined-efi.img.gz
# dd if=openwrt-*-x86-64-combined-ext4.img of=/dev/sda bs=4M; sync;
# parted /dev/sda print
# parted /dev/sda resizepart 2 <MAX SIZE>G
# resize2fs /dev/sda2

## Function
# Get System Information
function GetSystemInformation() {
    function DetectBASH() {
        if which "bash" > "/dev/null" 2>&1; then
            echo 'BASH has been installed!' > "/dev/null" 2>&1
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
    function GenerateDomain() {
        NEW_DOMAIN="localdomain"
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
    GenerateDomain
    GenerateHostname
    GetCPUVendorID
    SetGHProxyDomain
}
# Set Repository Mirror
function SetRepositoryMirror() {
    sed -i 's/downloads.openwrt.org/mirrors.ustc.edu.cn\/openwrt/g' "/etc/opkg/distfeeds.conf"
    rm -rf "/etc/opkg/customfeeds.conf" && touch "/etc/opkg/customfeeds.conf"
}
# Set Readonly Flag
function SetReadonlyFlag() {
    file_list=(
        "/etc/chrony/chrony.conf"
        "/etc/docker/daemon.json"
        "/etc/fail2ban/fail2ban.local"
        "/etc/fail2ban/jail.local"
        "/etc/fail2ban/jail.d/fail2ban_default.conf"
        "/etc/hostname"
        "/etc/hosts"
        "/etc/opkg/customfeeds.conf"
        "/etc/opkg/distfeeds.conf"
        "/etc/sysctl.conf"
        "/etc/zsh/oh-my-zsh.zshrc"
    )
    which "chattr" > "/dev/null" 2>&1
    if [ "$?" -eq "0" ]; then
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
        )
        which "chronyc" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/tmp/chrony.autodeploy" && for chrony_list_task in "${!chrony_list[@]}"; do
                echo "${chrony_list[$chrony_list_task]}" >> "/tmp/chrony.autodeploy"
            done && for chrony_ntp_list_task in "${!chrony_ntp_list[@]}"; do
                if [ "${chrony_ntp_list[$chrony_ntp_list_task]}" == "ntp.ntsc.ac.cn" ] || [ "${chrony_ntp_list[$chrony_ntp_list_task]}" == "ntp1.nim.ac.cn" ] || [ "${chrony_ntp_list[$chrony_ntp_list_task]}" == "ntp2.nim.ac.cn" ]; then
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
    function ConfigureDDNS() {
        uci set ddns.global.use_curl="1"
        uci -q delete ddns.myddns_ipv4 > "/dev/null" 2>&1
        uci -q delete ddns.myddns_ipv6 > "/dev/null" 2>&1
        uci commit ddns
    }
    function ConfigureDNSMasq() {
        uci set dhcp.@dnsmasq[0].allservers="1"
        uci set dhcp.@dnsmasq[0].authoritative="1"
        uci set dhcp.@dnsmasq[0].domain="${NEW_DOMAIN}"
        uci set dhcp.@dnsmasq[0].domainneeded="1"
        uci set dhcp.@dnsmasq[0].ednspacket_max="1232"
        uci set dhcp.@dnsmasq[0].expandhosts="1"
        uci set dhcp.@dnsmasq[0].filterwin2k="1"
        uci set dhcp.@dnsmasq[0].leasefile="/tmp/dhcp.leases"
        uci set dhcp.@dnsmasq[0].local="/${NEW_DOMAIN}/"
        uci set dhcp.@dnsmasq[0].localise_queries="1"
        uci set dhcp.@dnsmasq[0].localservice="1"
        uci set dhcp.@dnsmasq[0].nohosts="1"
        uci set dhcp.@dnsmasq[0].nonegcache="1"
        uci set dhcp.@dnsmasq[0].noresolv="1"
        uci set dhcp.@dnsmasq[0].port="53"
        uci set dhcp.@dnsmasq[0].quietdhcp="1"
        uci set dhcp.@dnsmasq[0].readethers="1"
        uci set dhcp.@dnsmasq[0].rebind_localhost="1"
        uci set dhcp.@dnsmasq[0].rebind_protection="1"
        uci set dhcp.@dnsmasq[0].sequential_ip="1"
        uci set dhcp.@dnsmasq[0].strictorder="1"
        uci set dhcp.lan.dhcpv6="hybrid"
        uci set dhcp.lan.leasetime="1h"
        uci set dhcp.lan.master="1"
        uci set dhcp.lan.ndp="hybrid"
        uci set dhcp.lan.ra="hybrid"
        uci commit dhcp
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
            fi && chown -R ${DEFAULT_USERNAME}:${DEFAULT_USERNAME} "/docker" && chmod -R 775 "/docker"
            if [ ! -d "/etc/docker" ]; then
                mkdir "/etc/docker"
            fi
            rm -rf "/tmp/docker.autodeploy" && for docker_list_task in "${!docker_list[@]}"; do
                echo "${docker_list[$docker_list_task]}" >> "/tmp/docker.autodeploy"
            done && cat "/tmp/docker.autodeploy" > "/etc/docker/daemon.json" && rm -rf "/tmp/docker.autodeploy"

            uci -q delete dockerd.globals
            uci set dockerd.globals="globals"
            uci set dockerd.globals.alt_config_file="/etc/docker/daemon.json"
            uci set dockerd.globals.data_root="/opt/docker/"
            uci set dockerd.globals.log_level="warn"
            uci set dockerd.globals.iptables="1"
            uci commit dockerd
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
    function ConfigureFirewall() {
        function ConfigureFirewallDefaults() {
            uci set firewall.@defaults[0].synflood_protect="1"
            uci set firewall.@defaults[0].drop_invalid="1"
            uci set firewall.@defaults[0].flow_offloading="1"
        }
        function ConfigureFirewallWireGuard() {
            uci -q delete firewall.wireguard
            uci set firewall.wireguard="rule"
            uci set firewall.wireguard.name="Allow-WireGuard"
            uci set firewall.wireguard.src="wan"
            uci set firewall.wireguard.dest_port="51820"
            uci set firewall.wireguard.proto="udp"
            uci set firewall.wireguard.target="ACCEPT"
            uci del_list firewall.@zone[0].network="wg0"
            uci add_list firewall.@zone[0].network="wg0"
        }
        ConfigureFirewallDefaults
        ConfigureFirewallWireGuard
        uci commit firewall
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
            rm -rf "/home/${DEFAULT_USERNAME}/.gnupg" "/root/.gnupg" && gpg --keyserver hkp://keys.openpgp.org --recv ${GPG_PUBKEY} && gpg --keyserver hkp://keyserver.ubuntu.com --recv ${GPG_PUBKEY} && echo "${GPG_PUBKEY}" | awk 'BEGIN { FS = "\n" }; { print $1":6:" }' | gpg --import-ownertrust && GPG_PUBKEY_ID_A=$(gpg --list-keys --keyid-format LONG | grep "pub\|sub" | awk '{print $2, $4}' | grep "\[A\]" | awk '{print $1}' | awk -F '/' '{print $2}') && GPG_PUBKEY_ID_C=$(gpg --list-keys --keyid-format LONG | grep "pub\|sub" | awk '{print $2, $4}' | grep "\[C\]" | awk '{print $1}' | awk -F '/' '{print $2}')
            if [ "${GPG_PUBKEY_ID_A}" != "" ]; then
                gpg_agent_list=(
                    "enable-ssh-support"
                )
                rm -rf "/root/.gnupg/gpg-agent.conf" && for gpg_agent_list_task in "${!gpg_agent_list[@]}"; do
                    echo "${gpg_agent_list[$gpg_agent_list_task]}" >> "/root/.gnupg/gpg-agent.conf"
                done && echo "${GPG_PUBKEY_ID_A}" > "/root/.gnupg/sshcontrol" && gpg --export-ssh-key ${GPG_PUBKEY_ID_C} > "/root/.gnupg/authorized_keys" && if [ -d "/root/.gnupg" ]; then
                    mv "/root/.gnupg" "/home/${DEFAULT_USERNAME}/.gnupg" && chown -R $DEFAULT_USERNAME:$DEFAULT_USERNAME "/home/${DEFAULT_USERNAME}/.gnupg"
                fi
            fi
        fi
    }
    function ConfigureLuci() {
        uci -d delete luci.flash_keep.dropbear > "/dev/null" 2>&1
        uci -d delete luci.flash_keep.openvpn > "/dev/null" 2>&1
        uci set luci.diag.dns="dns.alidns.com"
        uci set luci.diag.ping="dns.alidns.com"
        uci set luci.diag.route="dns.alidns.com"
    }
    function ConfigureNetwork() {
        dns_list=(
            "223.5.5.5"
            "223.6.6.6"
            "2400:3200::1"
            "2400:3200:baba::1"
        )
        uci set network.globals.packet_steering="1"
        uci del network.lan.dns > "/dev/null" 2>&1
        for dns_list_task in "${!dns_list[@]}"; do
            uci add_list network.lan.dns="${dns_list[$dns_list_task]}"
        done
        uci set network.lan.dns_search="${NEW_DOMAIN}"
        uci set network.lan.ip6assign="64"
        uci commit network
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
    function ConfigureQoS() {
        uci set nft-qos.default.limit_enable="1"
        uci set nft-qos.default.limit_mac_enable="1"
        uci set nft-qos.default.limit_type="static"
        uci set nft-qos.default.priority_enable="1"
        uci set nft-qos.default.priority_netdev="lan"
        uci set nft-qos.default.static_rate_dl="125"
        uci set nft-qos.default.static_rate_ul="125"
        uci set nft-qos.default.static_unit_dl="mbytes"
        uci set nft-qos.default.static_unit_ul="mbytes"
        uci commit nft-qos
    }
    function ConfigureRPCD() {
        uci -q delete rpcd.@login[2]
        uci add rpcd login
        uci set rpcd.@login[2]=login
        uci set rpcd.@login[2].timeout="300"
        uci set rpcd.@login[2].username="${DEFAULT_USERNAME}"
        uci set rpcd.@login[2].password="\$p\$${DEFAULT_USERNAME}"
        uci set rpcd.@login[2].read="*"
        uci set rpcd.@login[2].write="*"
        uci commit rpcd
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
    function ConfigureuHTTPd() {
        uci set uhttpd.defaults.days="90"
        uci set uhttpd.defaults.bits="4096"
        uci set uhttpd.defaults.ec_curve="ec-384"
        uci set uhttpd.main.redirect_https="on"
        uci commit uhttpd
    }
    function ConfigureUPnP() {
        uci set upnpd.config.enabled="1"
        uci set upnpd.config.igdv1="1"
        uci commit upnpd
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
        fi
        which "wg" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            uci -q delete network.wg0
            uci set network.wg0="interface"
            uci set network.wg0.proto="wireguard"
            uci set network.wg0.listen_port="51820"
            uci set network.wg0.private_key="$(wg genkey | tee '/tmp/wireguard.autodeploy')"
            uci add_list network.wg0.addresses="${TUNNEL_CLIENT_V4}"
            uci add_list network.wg0.addresses="${TUNNEL_CLIENT_V6}"
            uci commit network
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
    ConfigureCrontab
    ConfigureCrowdSec
    ConfigureDDNS
    ConfigureDNSMasq
    ConfigureDockerEngine
    ConfigureFail2Ban
    ConfigureFirewall
    ConfigureGit
    ConfigureGPG
    ConfigureLuci
    ConfigureNetwork
    ConfigureOpenSSH
    ConfigurePythonPyPI
    ConfigureQoS
    ConfigureRPCD
    ConfigureSshd
    ConfigureSysctl
    ConfigureuHTTPd
    ConfigureUPnP
    ConfigureWireGuard
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
    function ConfigureDefaultUser() {
        DEFAULT_FIRSTNAME="User"
        DEFAULT_LASTNAME="OpenWrt"
        DEFAULT_FULLNAME="${DEFAULT_LASTNAME} ${DEFAULT_FIRSTNAME}"
        DEFAULT_USERNAME="openwrt"
        DEFAULT_PASSWORD='*OpenWrt123*'
        crontab_list=(
            "@reboot rm -rf /home/${DEFAULT_USERNAME}/.*_history /home/${DEFAULT_USERNAME}/.ssh/known_hosts*"
        )
        if [ -d "/home" ]; then
            USER_LIST=($(ls "/home" | grep -v "${DEFAULT_USERNAME}" | awk "{print $2}") ${DEFAULT_USERNAME})
        else
            mkdir "/home" && USER_LIST=(${DEFAULT_USERNAME})
        fi && for USER_LIST_TASK in "${!USER_LIST[@]}"; do
            userdel -rf "${USER_LIST[$USER_LIST_TASK]}" > "/dev/null" 2>&1
            rm -rf "/home/${USER_LIST[$USER_LIST]}" "/etc/sudoers.d/${USER_LIST[$USER_LIST]}"
        done
        useradd -c "${DEFAULT_FULLNAME}" -d "/home/${DEFAULT_USERNAME}" -s "/usr/bin/zsh" -m "${DEFAULT_USERNAME}" && echo $DEFAULT_USERNAME:$DEFAULT_PASSWORD | chpasswd && echo "${DEFAULT_USERNAME} ALL=(ALL:ALL) ALL" > "/etc/sudoers.d/${DEFAULT_USERNAME}"
        which "crontab" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/tmp/crontab.autodeploy" && for crontab_list_task in "${!crontab_list[@]}"; do
                echo "${crontab_list[$crontab_list_task]}" >> "/tmp/crontab.autodeploy"
            done && crontab -u "${DEFAULT_USERNAME}" "/tmp/crontab.autodeploy" && crontab -lu "${DEFAULT_USERNAME}" && rm -rf "/tmp/crontab.autodeploy"
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
        LOCK_ROOT="FALSE"
        ROOT_PASSWORD='R00t@123!'
        echo root:$ROOT_PASSWORD | chpasswd && if [ "${LOCK_ROOT}" == "TRUE" ]; then
            passwd -l "root"
        else
            passwd -u "root"
        fi
    }
    function ConfigureSystemDefaults() {
        uci set system.@system[0].hostname="${NEW_HOSTNAME}"
        uci set system.@system[0].timezone="CST-8"
        uci set system.@system[0].zonename="Asia/Shanghai"
        uci set system.ntp.enabled="0"
        uci commit system
    }
    ConfigureDefaultShell
    ConfigureDefaultUser
    ConfigureHostfile
    ConfigureRootUser
    ConfigureSystemDefaults
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
        "bc"
        "bind-dig"
        "ca-certificates"
        "chattr"
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
        "dnsmasq"
        "dnsmasq-dhcpv6"
        "dnsmasq-full"
        "docker"
        "docker-compose"
        "dockerd"
        "drill"
        "etherwake"
        "ethtool"
        "fail2ban"
        "fail2ban-src"
        "fdisk"
        "gawk"
        "git"
        "git-http"
        "git-lfs"
        "gnupg2"
        "gnupg2-dirmngr"
        "gnupg2-utils"
        "grep"
        "iperf3-ssl"
        "jq"
        "kmod-tcp-bbr"
        "knot-dig"
        "lua-cs-bouncer"
        "luci"
        "luci-proto-3g"
        "luci-proto-bonding"
        "luci-proto-gre"
        "luci-proto-hnet"
        "luci-proto-ipip"
        "luci-proto-ipv6"
        "luci-proto-modemmanager"
        "luci-proto-ncm"
        "luci-proto-openconnect"
        "luci-proto-openfortivpn"
        "luci-proto-ppp"
        "luci-proto-pppossh"
        "luci-proto-qmi"
        "luci-proto-relay"
        "luci-proto-sstp"
        "luci-proto-vpnc"
        "luci-proto-vxlan"
        "luci-proto-wireguard"
        "luci-proto-xfrm"
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
        "shadow-chage"
        "shadow-chfn"
        "shadow-chgpasswd"
        "shadow-chpasswd"
        "shadow-chsh"
        "shadow-common"
        "shadow-expiry"
        "shadow-faillog"
        "shadow-gpasswd"
        "shadow-groupadd"
        "shadow-groupdel"
        "shadow-groupmems"
        "shadow-groupmod"
        "shadow-groups"
        "shadow-grpck"
        "shadow-grpconv"
        "shadow-grpunconv"
        "shadow-lastlog"
        "shadow-login"
        "shadow-logoutd"
        "shadow-newgidmap"
        "shadow-newgrp"
        "shadow-newuidmap"
        "shadow-newusers"
        "shadow-nologin"
        "shadow-passwd"
        "shadow-pwck"
        "shadow-pwconv"
        "shadow-pwunconv"
        "shadow-su"
        "shadow-useradd"
        "shadow-userdel"
        "shadow-usermod"
        "shadow-utils"
        "shadow-vipw"
        "sudo"
        "tcpdump"
        "uuidgen"
        "vim"
        "wget"
        "whois"
        "wireguard-tools"
        "zsh"
    )
    app_luci_list=(
        "luci-app-acl"
        "luci-app-ddns"
        "luci-app-dockerman"
        "luci-app-firewall"
        "luci-app-nft-qos"
        "luci-app-opkg"
        "luci-app-upnp"
        "luci-app-wireguard"
        "luci-app-wol"
    )
    app_luci_lang_list=(
        "luci-i18n-acl-zh-cn"
        "luci-i18n-base-zh-cn"
        "luci-i18n-ddns-zh-cn"
        "luci-i18n-dockerman-zh-cn"
        "luci-i18n-firewall-zh-cn"
        "luci-i18n-nft-qos-zh-cn"
        "luci-i18n-opkg-zh-cn"
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
        "dropbear"
    )
    opkg_config=($(find "/etc/config" -name "*-opkg" -print | awk "{print $2}"))
    for cleanup_list_task in "${!cleanup_list[@]}"; do
        opkg remove --force-remove "${cleanup_list[$cleanup_list_task]}" > "/dev/null" 2>&1
        uci -q delete ucitrack.@${cleanup_list[$cleanup_list_task]}[0] > "/dev/null" 2>&1
        uci commit ucitrack
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
# Set read_only="FALSE"; Call SetReadonlyFlag
read_only="FALSE" && SetReadonlyFlag
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
# Set read_only="TRUE"; Call SetReadonlyFlag
read_only="TRUE" && SetReadonlyFlag
# Call CleanupTempFiles
CleanupTempFiles
