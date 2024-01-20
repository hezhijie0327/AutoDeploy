#!/bin/bash

# Current Version: 1.6.1

## How to get and use?
# curl "https://source.zhijie.online/AutoDeploy/main/OpenWrt.sh" | sudo bash
# wget -qO- "https://source.zhijie.online/AutoDeploy/main/OpenWrt.sh" | sudo bash

# How to install OpenWrt on Proxmox VE?
# wget https://downloads.openwrt.org/releases/23.05.2/targets/x86/64/openwrt-23.05.2-x86-64-generic-ext4-combined-efi.img.gz
# gunzip openwrt-*.img.gz
# qm importdisk 102 openwrt-*.img local-btrfs

## How to resize disk on Proxmox VE?
# https://openwrt.org/docs/guide-user/installation/openwrt_x86
# sed -i 's/downloads.openwrt.org/mirrors.ustc.edu.cn\/openwrt/g' /etc/opkg/distfeeds.conf
# opkg update
# opkg install parted losetup resize2fs
# parted -f -s /dev/vda resizepart 2 100%
# losetup /dev/loop0 /dev/vda2 2 > /dev/null
# resize2fs -f /dev/loop0

## How to set up interface?
# uci export network
#
# uci set network.wan.device="eth0"
# uci set network.wan.proto="dhcp"
#
# uci set network.lan.device="eth1"
# uci set network.lan.ipaddr="192.168.0.1"
# uci set network.lan.netmask="255.255.255.0"
# uci set network.lan.proto="static"
#
# uci commit network
# service network restart

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
        "/etc/default/lldpd"
        "/etc/docker/daemon.json"
        "/etc/fail2ban/fail2ban.local"
        "/etc/fail2ban/filter.d/dropbear.conf"
        "/etc/fail2ban/filter.d/luci.conf"
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
            done && cat "/tmp/chrony.autodeploy" > "/etc/chrony/chrony.conf" && rm -rf "/tmp/chrony.autodeploy" && service chronyd restart && sleep 5s && chronyc activity && chronyc tracking && chronyc clients && hwclock -w
        fi
    }
    function ConfigureCrontab() {
        crontab_list=(
            "0 0 * * 7 opkg update && opkg list-upgradable | cut -f 1 -d ' ' | xargs opkg upgrade > '/dev/null' 2>&1"
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
        )
        which "cscli" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            for crowdsec_hub_list_task in "${!crowdsec_hub_list[@]}"; do
                cscli collections install ${crowdsec_hub_list[$crowdsec_hub_list_task]}
            done
        fi && service crowdsec restart && cscli hub list && cscli lapi status
    }
    function ConfigureDDNS() {
        uci set ddns.global.use_curl="1"
        uci -q delete ddns.myddns_ipv4 > "/dev/null" 2>&1
        uci -q delete ddns.myddns_ipv6 > "/dev/null" 2>&1
        uci commit ddns
    }
    function ConfigureDHCP() {
        # https://openwrt.org/docs/guide-user/base-system/dhcp_configuration#dhcp_pool_for_a_large_network
        CYRRENT_GW=$(uci get network.lan.ipaddr)
        dhcp_option_list=(
            "3,${CYRRENT_GW}" # Gateway
            "6,${CYRRENT_GW}" # DNS
            "42,${CYRRENT_GW}" # NTP
            "44" # WINS (DISABLE)
        )
        uci del dhcp.lan.dhcp_option > "/dev/null" 2>&1
        for dhcp_option_list_task in "${!dhcp_option_list[@]}"; do
            uci add_list dhcp.lan.dhcp_option="${dhcp_option_list[$dhcp_option_list_task]}"
        done
        uci set dhcp.lan.dhcpv4="hybrid"
        uci set dhcp.lan.dhcpv6="hybrid"
        uci set dhcp.lan.dns_service="0"
        uci del dhcp.lan.domain > "/dev/null" 2>&1
        uci add_list dhcp.lan.domain="${NEW_DOMAIN}"
        uci set dhcp.lan.interface="lan"
        uci set dhcp.lan.leasetime="1h"
        uci set dhcp.lan.limit="150"
        uci set dhcp.lan.ndp="hybrid"
        uci set dhcp.lan.ra="hybrid"
        uci del dhcp.lan.ra_flags > "/dev/null" 2>&1
        uci add_list dhcp.lan.ra_flags="managed-config"
        uci add_list dhcp.lan.ra_flags="other-config"
        uci set dhcp.lan.start="100"
        uci commit dhcp
    }
    function ConfigureDNSMasq() {
        dns_list=(
            "223.5.5.5"
            "223.6.6.6"
            "2400:3200::1"
            "2400:3200:baba::1"
        )
        DNS_PORT=""
        uci del dhcp.@dnsmasq[0] > "/dev/null" 2>&1
        uci add dhcp dnsmasq
        uci set dhcp.@dnsmasq[0].allservers="1"
        uci set dhcp.@dnsmasq[0].authoritative="1"
        uci set dhcp.@dnsmasq[0].domain="${NEW_DOMAIN}"
        uci set dhcp.@dnsmasq[0].domainneeded="1"
        uci set dhcp.@dnsmasq[0].ednspacket_max="1232"
        uci set dhcp.@dnsmasq[0].expandhosts="1"
        uci set dhcp.@dnsmasq[0].filterwin2k="1"
        uci set dhcp.@dnsmasq[0].leasefile="/tmp/dhcp.leases"
        uci set dhcp.@dnsmasq[0].local=""
        uci set dhcp.@dnsmasq[0].localise_queries="1"
        uci set dhcp.@dnsmasq[0].localservice="1"
        uci set dhcp.@dnsmasq[0].nohosts="1"
        uci set dhcp.@dnsmasq[0].nonegcache="1"
        uci set dhcp.@dnsmasq[0].noresolv="1"
        uci set dhcp.@dnsmasq[0].port="${DNS_PORT:-53}"
        uci set dhcp.@dnsmasq[0].quietdhcp="1"
        uci set dhcp.@dnsmasq[0].readethers="1"
        uci set dhcp.@dnsmasq[0].rebind_localhost="1"
        uci set dhcp.@dnsmasq[0].rebind_protection="1"
        uci set dhcp.@dnsmasq[0].sequential_ip="1"
        uci del dhcp.@dnsmasq[0].server > "/dev/null" 2>&1
        for dns_list_task in "${!dns_list[@]}"; do
            uci add_list dhcp.@dnsmasq[0].server="${dns_list[$dns_list_task]}"
        done
        uci set dhcp.@dnsmasq[0].strictorder="1"
        uci commit dhcp
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
            fi && chown -R root:docker "/docker" && chmod -R 775 "/docker"
            if [ ! -d "/etc/docker" ]; then
                mkdir "/etc/docker"
            fi
            rm -rf "/tmp/docker.autodeploy" && for docker_list_task in "${!docker_list[@]}"; do
                echo "${docker_list[$docker_list_task]}" >> "/tmp/docker.autodeploy"
            done && cat "/tmp/docker.autodeploy" > "/etc/docker/daemon.json" && rm -rf "/tmp/docker.autodeploy"
            uci -q delete dockerd.globals
            uci set dockerd.globals="globals"
            uci set dockerd.globals.alt_config_file="/etc/docker/daemon.json"
            uci set dockerd.globals.data_root="/docker"
            uci set dockerd.globals.log_level="warn"
            uci set dockerd.globals.iptables="1"
            uci commit dockerd
        fi
    }
    function ConfigureDropbear() {
        AUTHORIZED_KEYS="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHFxnNMm1Cs+cIgA5qWrW5Pt+ZfU/k2v0ydPazXueZF6 openpgp:0xB2193F4D"
        echo "${AUTHORIZED_KEYS}" > "/etc/dropbear/authorized_keys" && rm -rf "/etc/dropbear/authorized_keys" /etc/dropbear_*_host_key
        uci set dropbear.@dropbear[0].GatewayPorts="on"
        uci set dropbear.@dropbear[0].IdleTimeout="0"
        uci set dropbear.@dropbear[0].Interface="lan"
        uci set dropbear.@dropbear[0].MaxAuthTries="5"
        uci set dropbear.@dropbear[0].PasswordAuth="on"
        uci set dropbear.@dropbear[0].Port="22"
        uci set dropbear.@dropbear[0].RootLogin="on"
        uci set dropbear.@dropbear[0].RootPasswordAuth="on"
        uci set dropbear.@dropbear[0].SSHKeepAlive="900"
        uci set dropbear.@dropbear[0]=dropbear
        uci commit dropbear
    }
    function ConfigureFail2ban() {
        fail2ban_list=(
            "[dropbear]"
            "bantime = 604800"
            "enabled = true"
            "filter = dropbear"
            "findtime = 60"
            "logpath = /tmp/log/system.log"
            "maxretry = 5"
            "port = 22"
            "[luci]"
            "bantime = 604800"
            "enabled = true"
            "filter = luci"
            "findtime = 60"
            "logpath = /tmp/log/system.log"
            "maxretry = 5"
            "port = 80,443"
        )
        fail2ban_dropbear_list=(
            "[INCLUDES]"
            "before = common.conf"
            "[Definition]"
            "_daemon = dropbear"
            "failregex = ^%(__prefix_line)s[Ll]ogin attempt for nonexistent user ('.*' )?from <HOST>:\d+$"
            "^%(__prefix_line)s[Bb]ad (PAM )?password attempt for .+ from <HOST>(:\d+)?$"
            "^%(__prefix_line)s[Ee]xit before auth \(user '.+', \d+ fails\): Max auth tries reached - user '.+' from <HOST>:\d+\s*$"
            "^%(__prefix_line)s[Ee]xit before auth from <<HOST>:\d+>:\s.*$"
        )
        fail2ban_luci_list=(
            "[INCLUDES]"
            "before = common.conf"
            "[Definition]"
            "_daemon = luci"
            "prefregex = ^%(__prefix_line)s<F-CONTENT>(?:[Ff]ailed).+</F-CONTENT>$"
            "failregex = ^[Ff]ailed\s+login\s+on\s+/.*\s+for\s+.+\s+from\s+<HOST>(:\d+)?$"
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
            rm -rf "/tmp/fail2ban.autodeploy" && for fail2ban_dropbear_list_task in "${!fail2ban_dropbear_list[@]}"; do
                echo "${fail2ban_dropbear_list[$fail2ban_dropbear_list_task]}" >> "/tmp/fail2ban.autodeploy"
            done && cat "/tmp/fail2ban.autodeploy" > "/etc/fail2ban/filter.d/dropbear.conf" && rm -rf "/tmp/fail2ban.autodeploy"
            rm -rf "/tmp/fail2ban.autodeploy" && for fail2ban_luci_list_task in "${!fail2ban_luci_list[@]}"; do
                echo "${fail2ban_luci_list[$fail2ban_luci_list_task]}" >> "/tmp/fail2ban.autodeploy"
            done && cat "/tmp/fail2ban.autodeploy" > "/etc/fail2ban/filter.d/luci.conf" && rm -rf "/tmp/fail2ban.autodeploy"
            rm -rf "/tmp/fail2ban.autodeploy" && for fail2ban_list_task in "${!fail2ban_list[@]}"; do
                echo "${fail2ban_list[$fail2ban_list_task]}" >> "/tmp/fail2ban.autodeploy"
            done && cat "/tmp/fail2ban.autodeploy" > "/etc/fail2ban/jail.d/fail2ban_default.conf" && rm -rf "/tmp/fail2ban.autodeploy"
            fail2ban-client reload && sleep 5s && fail2ban-client status
        fi
    }
    function ConfigureFirewall() {
        function ConfigureFirewallDefaults() {
            uci set firewall.@defaults[0].drop_invalid="1"
            uci set firewall.@defaults[0].flow_offloading="1"
            uci set firewall.@defaults[0].forward="ACCEPT"
            uci set firewall.@defaults[0].input="REJECT"
            uci set firewall.@defaults[0].output="ACCEPT"
            uci set firewall.@defaults[0].synflood_protect="1"
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
            service frr restart && sleep 5s && vtysh -c "show running-config" && vtysh -c "show ip route" && vtysh -c "show ipv6 route"
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
    function ConfigureGPG() {
        GPG_PUBKEY=""
        if [ "${GPG_PUBKEY}" == "" ]; then
            GPG_PUBKEY="DD982DAAB9C71C78F9563E5207EB56787030D792"
        fi
        which "gpg" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/root/.gnupg" && gpg --keyserver hkps://keyserver.ubuntu.com:443 --recv ${GPG_PUBKEY} && echo "${GPG_PUBKEY}" | awk 'BEGIN { FS = "\n" }; { print $1":6:" }' | gpg --import-ownertrust && GPG_PUBKEY_ID_A=$(gpg --list-keys --keyid-format LONG | grep "pub\|sub" | awk '{print $2, $4}' | grep "\[A\]" | awk '{print $1}' | awk -F '/' '{print $2}') && GPG_PUBKEY_ID_C=$(gpg --list-keys --keyid-format LONG | grep "pub\|sub" | awk '{print $2, $4}' | grep "\[C\]" | awk '{print $1}' | awk -F '/' '{print $2}')
            if [ "${GPG_PUBKEY_ID_A}" != "" ]; then
                gpg_agent_list=(
                    "enable-ssh-support"
                    "pinentry-program /usr/bin/pinentry-tty"
                )
                rm -rf "/root/.gnupg/gpg-agent.conf" && for gpg_agent_list_task in "${!gpg_agent_list[@]}"; do
                    echo "${gpg_agent_list[$gpg_agent_list_task]}" >> "/root/.gnupg/gpg-agent.conf"
                done && echo "${GPG_PUBKEY_ID_A}" > "/root/.gnupg/sshcontrol" && gpg --export-ssh-key ${GPG_PUBKEY_ID_C} > "/root/.gnupg/authorized_keys"
            fi
        fi
    }
    function ConfigureLLDPD() {
        which "lldpcli" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            echo 'DAEMON_ARGS="-c -e -f -s -x"' > "/tmp/lldpd.autodeploy" && cat "/tmp/lldpd.autodeploy" > "/etc/default/lldpd" && rm -rf "/tmp/lldpd.autodeploy"
            service lldpd restart && lldpcli show neighbors
        fi
    }
    function ConfigureLuci() {
        uci set luci.diag.dns="dns.alidns.com"
        uci set luci.diag.ping="dns.alidns.com"
        uci set luci.diag.route="dns.alidns.com"
        uci commit luci
    }
    function ConfigureNetwork() {
        uci set network.globals.packet_steering="1"
        uci set network.lan.ip6assign="64"
        uci commit network
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
                service ${NUT_SERVICE_NAME} ${NUT_SERVICE_STATUS} > "/dev/null" 2>&1
            done
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
    function ConfigureSNMP() {
        SNMP_AUTH_PASS="${DEFAULT_PASSWORD:-$ROOT_PASSWORD}"
        SNMP_PRIV_PASS="${ROOT_PASSWORD}"
        SNMP_SYS_CONTACT="${DEFAULT_FULLNAME:-root}"
        SNMP_SYS_LOCATION="${NEW_HOSTNAME}"
        SNMP_SYS_NAME="${NEW_FULL_DOMAIN}"
        SNMP_USER="${DEFAULT_USERNAME:-root}"
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
            done && cat "/tmp/snmp.autodeploy" | sort > "/etc/snmp/snmpd.conf" && rm -rf "/tmp/snmp.autodeploy" && service snmpd restart && snmpwalk -v3 -a SHA -A ${SNMP_AUTH_PASS} -x AES -X ${SNMP_PRIV_PASS} -l authPriv -u ${SNMP_USER} 127.0.0.1 | head
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
        uci del uhttpd.main.listen_http > "/dev/null" 2>&1
        uci add_list uhttpd.main.listen_http="0.0.0.0:80"
        uci add_list uhttpd.main.listen_http="[::]:80"
        uci del uhttpd.main.listen_https > "/dev/null" 2>&1
        uci add_list uhttpd.main.listen_https="0.0.0.0:443"
        uci add_list uhttpd.main.listen_https="[::]:443"
        rm -rf "/etc/uhttpd.crt" "/etc/uhttpd.key"
        uci set uhttpd.defaults.days="90"
        uci set uhttpd.defaults.bits="4096"
        uci set uhttpd.defaults.ec_curve="P-384"
        uci set uhttpd.main.redirect_https="on"
        uci commit uhttpd
    }
    function ConfigureUPnP() {
        uci set upnpd.config.enabled="1"
        uci set upnpd.config.igdv1="1"
        uci commit upnpd
    }
    function ConfigureWireGuard() {
        TUNNEL_CLIENT_V4="10.172.$(shuf -i '224-255' -n 1).$(shuf -i '1-254' -n 1)/32"
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
        }
        GenerateCommandPath
        GenerateOMZProfile
    }
    ConfigureChrony
    ConfigureCrontab
    ConfigureCrowdSec
    ConfigureDDNS
    ConfigureDHCP
    ConfigureDNSMasq
    ConfigureDockerEngine
    ConfigureDropbear
    ConfigureFail2ban
    ConfigureFirewall
    ConfigureFRRouting
    ConfigureGit
    ConfigureGPG
    ConfigureLLDPD
    ConfigureLuci
    ConfigureNetwork
    ConfigureNut
    ConfigurePythonPyPI
    ConfigureQoS
    ConfigureSNMP
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
        echo root:$ROOT_PASSWORD | chpasswd && passwd -u "root"
    }
    function ConfigureSystemDefaults() {
        uci set system.@system[0].hostname="${NEW_HOSTNAME}"
        uci set system.@system[0].timezone="CST-8"
        uci set system.@system[0].zonename="Asia/Shanghai"
        uci set system.ntp.enabled="0"
        uci commit system
    }
    ConfigureDefaultShell
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
        "crowdsec"
        "crowdsec-firewall-bouncer"
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
        "dropbear"
        "etherwake"
        "ethtool"
        "fail2ban"
        "fdisk"
        "frr"
        "frr-babeld"
        "frr-bfdd"
        "frr-bgpd"
        "frr-eigrpd"
        "frr-fabricd"
        "frr-isisd"
        "frr-ldpd"
        "frr-libfrr"
        "frr-nhrpd"
        "frr-ospf6d"
        "frr-ospfd"
        "frr-pbrd"
        "frr-pimd"
        "frr-ripd"
        "frr-ripngd"
        "frr-staticd"
        "frr-vrrpd"
        "frr-vtysh"
        "frr-watchfrr"
        "frr-zebra"
        "gawk"
        "git"
        "git-http"
        "git-lfs"
        "gnupg"
        "grep"
        "iperf3-ssl"
        "jq"
        "knot-dig"
        "lldpd"
        "lm-sensors-detect"
        "lm-sensors"
        "lua-cs-bouncer"
        "luci"
        "luci-ssl-openssl"
        "luci-theme-bootstrap"
        "mtr-json"
        "nano"
        "nmap"
        "ntfs-3g"
        "nut-common"
        "parted"
        "python3"
        "python3-pip"
        "qemu-ga"
        "qrencode"
        "resize2fs"
        "snmpd"
        "sudo"
        "tcpdump"
        "uhttpd"
        "unrar"
        "unzip"
        "uuidgen"
        "vim"
        "wget"
        "whois"
        "wireguard-tools"
        "zip"
        "zsh"
    )
    app_extend_list=(
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
    )
    app_kmod_list=(
        "kmod-tcp-bbr"
    )
    app_luci_list=(
        "luci-app-crowdsec-firewall-bouncer"
        "luci-app-ddns"
        "luci-app-dockerman"
        "luci-app-firewall"
        "luci-app-nft-qos"
        "luci-app-nut"
        "luci-app-opkg"
        "luci-app-snmpd"
        "luci-app-ttyd"
        "luci-app-uhttpd"
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
        "luci-i18n-nut-zh-cn"
        "luci-i18n-opkg-zh-cn"
        "luci-i18n-snmpd-zh-cn"
        "luci-i18n-ttyd-zh-cn"
        "luci-i18n-upnp-zh-cn"
        "luci-i18n-wireguard-zh-cn"
        "luci-i18n-wol-zh-cn"
    )
    app_luci_proto_list=(
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
    )
    app_list=(${app_regular_list[@]} ${app_extend_list[@]} ${app_kmod_list[*]} ${app_luci_list[*]} ${app_luci_lang_list[*]} ${app_luci_proto_list[*]} ${MICROCODE[*]})
    opkg update && for app_list_task in "${!app_list[@]}"; do
        opkg install --force-overwrite ${app_list[$app_list_task]}
    done
}
# Upgrade Packages
function UpgradePackages() {
    opkg update && opkg list-upgradable | cut -f 1 -d ' ' | xargs opkg upgrade > "/dev/null" 2>&1
}
# Reload Modules
function ReloadModules() {
    modules_list=($(ls /lib/modules/*/ | cut -d '.' -f 1 | awk "{print $2}"))
    for modules_list_task in "${!modules_list[@]}"; do
        modprobe -v ${modules_list[$modules_list_task]} > "/dev/null" 2>&1
    done
}
# Restart Services
function RestartServices() {
    services_list=($(ls /etc/init.d/ | cut -d '.' -f 1 | awk "{print $2}"))
    for services_list_task in "${!services_list[@]}"; do
        service ${services_list[$services_list_task]} restart > "/dev/null" 2>&1
    done
}
# Cleanup Temp Files
function CleanupTempFiles() {
    cleanup_list=()
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
# Call ReloadModules
ReloadModules
# Call InstallCustomPackages
InstallCustomPackages
# Call RestartServices
RestartServices
# Call ConfigureSystem
ConfigureSystem
# Call ConfigurePackages
ConfigurePackages
# Set read_only="TRUE"; Call SetReadonlyFlag
read_only="TRUE" && SetReadonlyFlag
# Call RestartServices
RestartServices
# Call CleanupTempFiles
CleanupTempFiles
