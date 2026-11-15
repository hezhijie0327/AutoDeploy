# ============================================================================
# debian.sh - shared between Ubuntu and Proxmox VE (Debian-family, bash 4.4+)
# Part of the generated single-file scripts; not executable on its own.
# ============================================================================

## Function
# Get System Information (shared parts)
GenerateDomain() {
    RESET_DOMAIN="${RESET_DOMAIN:-false}"
    NEW_DOMAIN=()
    local resolv_conf="${RESOLV_CONF:-/etc/resolv.conf}" search_line
    if [ -f "$resolv_conf" ]; then
        search_line=$(awk '/^search/ {for (i = 2; i <= NF; i++) printf "%s ", $i; exit}' "$resolv_conf")
        if [ -n "$search_line" ]; then
            read -r -a NEW_DOMAIN <<< "$search_line"
        fi
    fi
    if [ "${#NEW_DOMAIN[@]}" -eq 0 ] || [ "$RESET_DOMAIN" = "true" ]; then
        NEW_DOMAIN=("localdomain")
    fi
}

GenerateHostname() {
    RESET_HOSTNAME="${RESET_HOSTNAME:-false}"
    NEW_HOSTNAME=""
    local hostname_file="${HOSTNAME_FILE:-/etc/hostname}"
    if [ -f "$hostname_file" ]; then
        NEW_HOSTNAME=$(awk '{print $1; exit}' "$hostname_file")
    fi
    if [ -z "$NEW_HOSTNAME" ] && HaveCommand hostname; then
        NEW_HOSTNAME=$(hostname)
    fi
    if [ -z "$NEW_HOSTNAME" ] || [ "$RESET_HOSTNAME" = "true" ]; then
        NEW_HOSTNAME="${HOSTNAME_PREFIX}-$(date '+%Y%m%d%H%M%S')"
    fi
}

# Sets CUSTOM_DNS / CURRENT_DNS / DHCP_DNS / DNS_LINE (first three, space joined)
CollectDNS() {
    USE_GLOBAL_DNS="${USE_GLOBAL_DNS:-false}"
    if [ "$USE_GLOBAL_DNS" = "true" ]; then
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
    CURRENT_DNS=()
    local resolv_conf="${RESOLV_CONF:-/etc/resolv.conf}" ns
    if [ -f "$resolv_conf" ]; then
        while IFS= read -r ns; do
            case " ${CUSTOM_DNS[*]} ${DHCP_DNS[*]:-} 127.0.0.53 " in
                *" ${ns} "*) ;;
                *) CURRENT_DNS+=("$ns") ;;
            esac
        done < <(awk '/^nameserver/ {print $2}' "$resolv_conf")
    fi
    DNS_LINE=$(printf '%s\n' ${CURRENT_DNS[@]+"${CURRENT_DNS[@]}"} "${CUSTOM_DNS[@]}" | head -n 3 | tr '\n' ' ')
    DNS_LINE="${DNS_LINE% }"
}

GetCPUVendorID() {
    CPU_VENDOR_ID=$(awk -F: '/vendor_id/ {gsub(/^[ \t]+/, "", $2); print $2; exit}' /proc/cpuinfo)
    # pcie_acs_override is a patched-kernel parameter (common homelab kernels);
    # mainline kernels ignore it with a warning. Kept intentionally.
    case "$CPU_VENDOR_ID" in
        AuthenticAMD)
            CPU_VENDOR_ID="AMD"
            ENABLE_IOMMU=" amd_iommu=on iommu=pt pci=assign-busses pcie_acs_override=downstream,multifunction"
            INTEL_GVT_MODULES=()
            INTEL_HDMI_AUDIO_MODULE=()
            MICROCODE=("amd64-microcode")
            NESTED_MODULES=("kvm_amd")
            ;;
        GenuineIntel)
            CPU_VENDOR_ID="Intel"
            ENABLE_IOMMU=" intel_iommu=on iommu=pt pci=assign-busses pcie_acs_override=downstream,multifunction"
            INTEL_GVT_MODULES=("i915" "kvmgt")
            INTEL_HDMI_AUDIO_MODULE=("snd_hda_intel")
            MICROCODE=("intel-microcode")
            NESTED_MODULES=("kvm_intel")
            ;;
        *)
            CPU_VENDOR_ID="Unknown"
            ENABLE_IOMMU=""
            INTEL_GVT_MODULES=()
            INTEL_HDMI_AUDIO_MODULE=()
            MICROCODE=()
            NESTED_MODULES=()
            ;;
    esac
}

ComputeFullDomain() {
    NEW_FULL_DOMAIN=""
    local domain
    for domain in "${NEW_DOMAIN[@]}"; do
        NEW_FULL_DOMAIN="${NEW_FULL_DOMAIN} ${NEW_HOSTNAME}.${domain}"
    done
    NEW_FULL_DOMAIN="${NEW_FULL_DOMAIN# }"
}

# Write /etc/resolv.conf with up to three nameservers plus the search domain.
WriteResolvConf() {
    local resolv_conf_list=()
    resolv_conf_list+=(${CURRENT_DNS[@]+"${CURRENT_DNS[@]}"})
    resolv_conf_list+=("${CUSTOM_DNS[@]}")
    local count=0 entry
    chattr -i /etc/resolv.conf > /dev/null 2>&1 || true
    rm -f /etc/resolv.conf
    {
        for entry in "${resolv_conf_list[@]}"; do
            if [ "$count" -ge 3 ]; then
                break
            fi
            printf 'nameserver %s\n' "$entry"
            count=$((count + 1))
        done
        printf 'search %s\n' "${NEW_DOMAIN[*]}"
    } > /etc/resolv.conf
}

# Configure Packages (shared)
# Platform must set: APT_PREFERENCES (array of "<release> <priority>")
ConfigureAPT() {
    local apt_conf_list=(
        '# Disable HTTP Pipelining'
        'Acquire::http::Pipeline-Depth "0";'
        '# Disable Phased Updates'
        'APT::Get::Always-Include-Phased-Updates true;'
        'Update-Manager::Always-Include-Phased-Updates true;'
    )
    mkdir -p /etc/apt/apt.conf.d
    printf '%s\n' "${apt_conf_list[@]}" > /etc/apt/apt.conf.d/99autodeploy
    rm -rf /etc/apt/preferences.d
    mkdir -p /etc/apt/preferences.d
    local entry release priority
    : > /etc/apt/preferences
    for entry in "${APT_PREFERENCES[@]}"; do
        release="${entry%% *}"
        priority="${entry##* }"
        case "$priority" in
            *[!0-9]*) priority="500" ;;
        esac
        printf 'Package: *\nPin: release a=%s\nPin-Priority: %s\n\n' "$release" "$priority" >> /etc/apt/preferences
    done
    apt modernize-sources
    rm -f /etc/apt/sources.list.bak /etc/apt/sources.list.d/*.bak
}

ConfigureBusybox() {
    HaveCommand busybox || return 0
    busybox --install -s
}

ConfigureChrony() {
    HaveCommand chronyc || return 0
    local chrony_list=(
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
    local chrony_ntp_list=(
        ${DHCP_NTP[@]+"${DHCP_NTP[@]}"}
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
    local prefer_list=("ntp.ntsc.ac.cn" "ntp1.nim.ac.cn" "ntp2.nim.ac.cn")
    local server suffix
    {
        printf '%s\n' "${chrony_list[@]}"
        for server in "${chrony_ntp_list[@]}"; do
            suffix=" iburst"
            case " ${prefer_list[*]} ${DHCP_NTP[*]:-} " in
                *" ${server} "*) suffix=" iburst prefer" ;;
            esac
            printf 'server %s%s\n' "$server" "$suffix"
        done
    } > /etc/chrony/chrony.conf
    systemctl restart chrony
    sleep 5
    chronyc activity
    chronyc tracking
    chronyc clients
    hwclock -w || true
}

ConfigureCrowdSec() {
    HaveCommand cscli || return 0
    local collection
    for collection in "crowdsecurity/iptables" "crowdsecurity/linux-lpe" "crowdsecurity/linux" "crowdsecurity/sshd"; do
        cscli collections install "$collection"
    done
    systemctl restart crowdsec
    cscli hub list
}

ConfigureDockerEngine() {
    HaveCommand docker || return 0
    DOCKER_REGISTRY_MIRRORS=()
    local docker_list=(
        "{"
        "  \"allow-direct-routing\": true,"
        "  \"experimental\": true,"
        "  \"firewall-backend\": \"nftables\","
        "  \"ip-forward\": true"
        "}"
    )
    if [ "${#DOCKER_REGISTRY_MIRRORS[@]}" -gt 0 ]; then
        docker_list=(
            "{"
            "  \"allow-direct-routing\": true,"
            "  \"experimental\": true,"
            "  \"firewall-backend\": \"nftables\","
            "  \"ip-forward\": true,"
            "  \"registry-mirrors\": ["
            "$(printf '    "%s",\n' "${DOCKER_REGISTRY_MIRRORS[@]}" | sed '$s/,$//')"
            "  ]"
            "}"
        )
    fi
    if [ ! -d "/docker" ]; then
        mkdir "/docker"
    fi
    chown -R "${DEFAULT_USERNAME}:docker" "/docker"
    chmod -R 775 "/docker"
    mkdir -p /etc/docker
    printf '%s\n' 'DOCKER_OPTS="--iptables=false"' > /etc/default/docker
    printf '%s\n' "${docker_list[@]}" > /etc/docker/daemon.json
    systemctl enable docker
    systemctl restart docker
}

# Platform must set: FAIL2BAN_JAILS (array), FAIL2BAN_BANACTION (ufw or default),
# and optionally FAIL2BAN_FILTER_NAME + FAIL2BAN_FILTER (array).
ConfigureFail2Ban() {
    HaveCommand fail2ban-client || return 0
    if [ -d /etc/fail2ban/jail.d ]; then
        rm -f /etc/fail2ban/jail.d/*
    else
        mkdir -p /etc/fail2ban/jail.d
    fi
    if [ -f /etc/fail2ban/fail2ban.conf ]; then
        cp /etc/fail2ban/fail2ban.conf /etc/fail2ban/fail2ban.local
    fi
    if [ -f /etc/fail2ban/jail.conf ]; then
        if [ "${FAIL2BAN_BANACTION}" = "ufw" ]; then
            sed -E \
                -e 's/action = iptables-allports/action = ufw/g' \
                -e 's/banaction = iptables-multiport(-log)?/banaction = ufw/g' \
                -e 's/banaction = ufw-log/banaction = ufw/g' \
                -e 's/banaction_allports = iptables-allports/banaction_allports = ufw/g' \
                /etc/fail2ban/jail.conf > /etc/fail2ban/jail.local
        else
            cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
        fi
    fi
    if [ -n "${FAIL2BAN_FILTER_NAME:-}" ]; then
        printf '%s\n' "${FAIL2BAN_FILTER[@]}" > "/etc/fail2ban/filter.d/${FAIL2BAN_FILTER_NAME}.conf"
    fi
    printf '%s\n' "${FAIL2BAN_JAILS[@]}" > /etc/fail2ban/jail.d/fail2ban_default.conf
    systemctl enable fail2ban
    fail2ban-client reload
    sleep 5
    fail2ban-client status
}

ConfigureFRRouting() {
    HaveCommand vtysh || return 0
    local frrouting_list=(
        "frr defaults datacenter"
        "log syslog errors"
    )
    printf '%s\n' "${frrouting_list[@]}" > /etc/frr/frr.conf
    systemctl restart frr
    sleep 5
    vtysh -c "show running-config"
    vtysh -c "show ip route"
    vtysh -c "show ipv6 route"
}

ConfigureLLDPD() {
    HaveCommand lldpcli || return 0
    printf '%s\n' 'DAEMON_ARGS="-c -e -f -s -x"' > /etc/default/lldpd
    systemctl restart lldpd
    lldpcli show neighbors detail
}

# Platform must set: MODULE_LIST_EXTRA (array, may be empty)
ConfigureModules() {
    if [ -d /etc/modprobe.d ]; then
        rm -rf /etc/modprobe.d
        mkdir -p /etc/modprobe.d
    fi
    rm -f /etc/modules
    local iommu_modules=()
    if [ -n "$ENABLE_IOMMU" ]; then
        iommu_modules=("vfio" "vfio_iommu_type1" "vfio_pci" "vfio_virqfd")
        printf '%s\n' "options vfio_iommu_type1 allow_unsafe_interrupts=1" > /etc/modprobe.d/vfio_iommu_type1.conf
    fi
    local module_list=(
        "kvm"
        "tls"
        ${INTEL_GVT_MODULES[@]+"${INTEL_GVT_MODULES[@]}"}
        ${INTEL_HDMI_AUDIO_MODULE[@]+"${INTEL_HDMI_AUDIO_MODULE[@]}"}
        ${iommu_modules[@]+"${iommu_modules[@]}"}
        ${NESTED_MODULES[@]+"${NESTED_MODULES[@]}"}
        ${MODULE_LIST_EXTRA[@]+"${MODULE_LIST_EXTRA[@]}"}
    )
    printf '%s\n' "${module_list[@]}" | sort -u > /etc/modules
    printf '%s\n' "options kvm ignore_msrs=1 report_ignored_msrs=0" >> /etc/modprobe.d/kvm.conf
    if [ "$CPU_VENDOR_ID" = "AMD" ]; then
        printf '%s\n' "options kvm-amd nested=1" > /etc/modprobe.d/kvm-amd.conf
    elif [ "$CPU_VENDOR_ID" = "Intel" ]; then
        # 0 | 1 - GuC | 2 - HuC | 3 - GuC / HuC
        printf '%s\n' "options i915 enable_guc=${I915_GUC_OPTION:-3} enable_gvt=1" > /etc/modprobe.d/i915.conf
        printf '%s\n' "options kvm-intel nested=Y" > /etc/modprobe.d/kvm-intel.conf
        printf '%s\n' "options snd-hda-intel enable_msi=1" > /etc/modprobe.d/snd-hda-intel.conf
    fi
}

ConfigureNut() {
    HaveCommand upsmon || return 0
    function Create_upsd_users() {
        NUT_ADMIN_PASSWORD="${NUT_ADMIN_PASSWORD:-123456}"
        NUT_MON_PASSWORD="${NUT_MON_PASSWORD:-secret}"
        WarnDefaultPassword "NUT_ADMIN_PASSWORD" "$NUT_ADMIN_PASSWORD" "123456"
        WarnDefaultPassword "NUT_MON_PASSWORD" "$NUT_MON_PASSWORD" "secret"
        upsd_user_list=(
            "admin,${NUT_ADMIN_PASSWORD},master,FSD,SET"
            "monuser,${NUT_MON_PASSWORD},slave,,"
        )
    }
    function Generate_nut_conf() {
        printf 'MODE=%s\n' "${NUT_MODE:-none}" > /etc/nut/nut.conf
    }
    function Generate_ups_conf() {
        local ups_driver_list=(
            "ups,usbhid-ups,auto"
        )
        local ups_conf_list=(
            "maxretry = 3"
            "retrydelay = 5"
        )
        local entry ups_name ups_driver ups_port
        {
            printf '%s\n' "${ups_conf_list[@]}"
            for entry in "${ups_driver_list[@]}"; do
                ups_name="${entry%%,*}"
                ups_driver=$(printf '%s' "$entry" | cut -d ',' -f 2)
                ups_port="${entry##*,}"
                printf '[%s]\n    driver = %s\n    port = %s\n' "$ups_name" "$ups_driver" "$ups_port"
            done
        } > /etc/nut/ups.conf
    }
    function Generate_upsd_conf() {
        local upsd_config_list=(
            "MAXAGE 15"
            "MAXCONN 1024"
            "STATEPATH /var/run/nut"
        )
        {
            if [ "${NUT_MODE}" = "standalone" ]; then
                printf '%s\n' "LISTEN 127.0.0.1 3493" "LISTEN ::1 3493"
            else
                printf '%s\n' "LISTEN 0.0.0.0 3493"
            fi
            printf '%s\n' "${upsd_config_list[@]}"
        } > /etc/nut/upsd.conf
    }
    function Generate_upsd_users() {
        local entry upsd_username upsd_password upsd_role upsd_actions
        {
            for entry in "${upsd_user_list[@]}"; do
                upsd_username=$(printf '%s' "$entry" | cut -d ',' -f 1)
                upsd_password=$(printf '%s' "$entry" | cut -d ',' -f 2)
                upsd_role=$(printf '%s' "$entry" | cut -d ',' -f 3)
                upsd_actions=$(printf '%s' "$entry" | cut -d ',' -f 4-5 | tr ',' ' ' | sed 's/^ //g;s/ $//g')
                printf '[%s]\n' "$upsd_username"
                if [ -n "$upsd_actions" ]; then
                    printf '    actions = %s\n    instcmds = ALL\n' "$upsd_actions"
                fi
                printf '    password = %s\n    upsmon %s\n' "$upsd_password" "$upsd_role"
            done
        } > /etc/nut/upsd.users
    }
    function Generate_upsmon_conf() {
        local upsmon_list=(
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
        printf '%s\n' "${upsmon_list[@]}" > /etc/nut/upsmon.conf
    }
    NUT_MODE="${NUT_MODE:-}" # netclient | netserver | none | standalone
    NUT_HOST="${NUT_HOST:-}" # localhost
    rm -f /etc/nut/*.*
    local nut_service_list=()
    case "${NUT_MODE:-none}" in
        netclient)
            Create_upsd_users
            UPSMON_USERNAME=$(printf '%s' "${upsd_user_list[1]}" | cut -d ',' -f 1)
            UPSMON_PASSWORD=$(printf '%s' "${upsd_user_list[1]}" | cut -d ',' -f 2)
            UPSMON_ROLE=$(printf '%s' "${upsd_user_list[1]}" | cut -d ',' -f 3)
            UPSMON_SYSTEM="${UPS_NAME:-ups}@${NUT_HOST:-localhost}"
            nut_service_list=(
                "nut-client,enable"
                "nut-driver,disable"
                "nut-monitor,enable"
                "nut-server,disable"
            )
            Generate_nut_conf
            Generate_upsmon_conf
            ;;
        netserver|standalone)
            Create_upsd_users
            UPSMON_USERNAME=$(printf '%s' "${upsd_user_list[0]}" | cut -d ',' -f 1)
            UPSMON_PASSWORD=$(printf '%s' "${upsd_user_list[0]}" | cut -d ',' -f 2)
            UPSMON_ROLE=$(printf '%s' "${upsd_user_list[0]}" | cut -d ',' -f 3)
            UPSMON_SYSTEM="${UPS_NAME:-ups}@localhost"
            nut_service_list=(
                "nut-client,enable"
                "nut-driver,enable"
                "nut-monitor,enable"
                "nut-server,enable"
            )
            Generate_nut_conf
            Generate_ups_conf
            Generate_upsd_conf
            Generate_upsd_users
            Generate_upsmon_conf
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
    chown -R root:nut /etc/nut
    chmod 640 /etc/nut/*.*
    local entry service_name service_status
    for entry in "${nut_service_list[@]}"; do
        service_name="${entry%%,*}"
        service_status="${entry##*,}"
        systemctl "$service_status" "$service_name" > /dev/null 2>&1 || true
    done
}

ConfigureOpenSSH() {
    HaveCommand ssh-keygen || return 0
    if [ -d /etc/ssh ]; then
        GenerateHostSSHKeys /etc/ssh "root@${NEW_HOSTNAME}"
    fi
    BackupPath /root/.ssh
    mkdir -p /root/.ssh
    touch /root/.ssh/authorized_keys /root/.ssh/known_hosts
    GenerateSSHKeys /root/.ssh "root@${NEW_HOSTNAME}"
    chmod 600 /root/.ssh/authorized_keys
    chmod 644 /root/.ssh/known_hosts
    chmod 700 /root/.ssh
    local user_ssh="/home/${DEFAULT_USERNAME}/.ssh"
    BackupPath "$user_ssh"
    mkdir -p "$user_ssh"
    if [ -f "/home/${DEFAULT_USERNAME}/.gnupg/authorized_keys" ]; then
        mv "/home/${DEFAULT_USERNAME}/.gnupg/authorized_keys" "${user_ssh}/authorized_keys"
    else
        touch "${user_ssh}/authorized_keys"
    fi
    touch "${user_ssh}/known_hosts"
    GenerateSSHKeys "$user_ssh" "${DEFAULT_USERNAME}@${NEW_HOSTNAME}"
    chown -R "$DEFAULT_USERNAME:$DEFAULT_USERNAME" "$user_ssh"
    chmod 600 "${user_ssh}/authorized_keys"
    chmod 644 "${user_ssh}/known_hosts"
    chmod 700 "$user_ssh"
}

ConfigurePostfix() {
    [ -f /etc/postfix/main.cf ] || return 0
    local current_hostname
    current_hostname=$(awk -F '=' '/^myhostname/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}' /etc/postfix/main.cf)
    if [ -n "$current_hostname" ]; then
        sed -i "s/${current_hostname}/${NEW_HOSTNAME}/g" /etc/postfix/main.cf
    fi
}

# Platform wrapper sets SNMP_USER, then calls this.
ConfigureSNMPBase() {
    HaveCommand snmpwalk || return 0
    if [ -z "${SNMP_AUTH_PASS:-}" ]; then
        SNMP_AUTH_PASS="${ROOT_PASSWORD}"
        LogWarn "SNMP_AUTH_PASS defaults to the root password; override it via SNMP_AUTH_PASS."
    fi
    if [ -z "${SNMP_PRIV_PASS:-}" ]; then
        SNMP_PRIV_PASS="${NEW_HOSTNAME}"
        LogWarn "SNMP_PRIV_PASS defaults to the hostname; override it via SNMP_PRIV_PASS."
    fi
    SNMP_SYS_CONTACT="${DEFAULT_FULLNAME}"
    SNMP_SYS_LOCATION="${NEW_HOSTNAME}"
    SNMP_SYS_NAME="${NEW_FULL_DOMAIN}"
    local snmp_list=(
        "agentaddress udp:161,udp6:161"
        "master agentx"
        "rouser ${SNMP_USER}"
        "sysContact ${SNMP_SYS_CONTACT}"
        "sysLocation ${SNMP_SYS_LOCATION}"
        "sysName ${SNMP_SYS_NAME}"
        "sysServices 76"
    )
    systemctl stop snmpd
    pkill -x snmpd > /dev/null 2>&1 || true
    sed -i 's/^mibs :/# mibs :/g' /etc/snmp/snmp.conf
    printf 'createUser %s SHA "%s" AES "%s"\n' "$SNMP_USER" "$SNMP_AUTH_PASS" "$SNMP_PRIV_PASS" > /var/lib/snmp/snmpd.conf
    printf '%s\n' "${snmp_list[@]}" | sort > /etc/snmp/snmpd.conf
    systemctl start snmpd
    # Verification only; head closes the pipe early, so ignore SIGPIPE.
    snmpwalk -v3 -a SHA -A "$SNMP_AUTH_PASS" -x AES -X "$SNMP_PRIV_PASS" -l authPriv -u "$SNMP_USER" 127.0.0.1 | head || true
}

# Root password login is intentional: the root account gets locked afterwards
# via LOCK_ROOT=TRUE (see ConfigureRootUser).
ConfigureSshd() {
    [ -f /usr/share/openssh/sshd_config ] || return 0
    sed -E \
        -e 's/^#?PasswordAuthentication .*/PasswordAuthentication yes/' \
        -e 's/^#?PermitRootLogin .*/PermitRootLogin yes/' \
        -e 's/^#?PubkeyAuthentication .*/PubkeyAuthentication yes/' \
        /usr/share/openssh/sshd_config > /etc/ssh/sshd_config
    rm -f /etc/ssh/sshd_config.d/*
}

# mode: include|exclude; pattern: extended regex matched against interface names
CollectInterfaces() {
    local mode="$1" pattern="$2" iface
    while IFS= read -r iface; do
        if [ "$mode" = "include" ]; then
            if [[ "$iface" =~ $pattern ]]; then
                printf '%s\n' "$iface"
            fi
        else
            if [[ ! "$iface" =~ $pattern ]]; then
                printf '%s\n' "$iface"
            fi
        fi
    done < <(awk -F: 'NR>2 {gsub(/^[ \t]+/, "", $1); print $1}' /proc/net/dev)
}

# Platform must set: SYSCTL_INTERFACE_MODE, SYSCTL_INTERFACE_PATTERN
ConfigureSysctl() {
    HaveCommand sysctl || return 0
    local icmp_echo=()
    if [ "${DISABLE_ICMP_ECHO:-false}" = "true" ]; then
        icmp_echo=(
            "net.ipv4.icmp_echo_ignore_all = 1"
            "net.ipv6.icmp.echo_ignore_all = 1"
        )
    fi
    local interface_list=("all" "default") iface
    while IFS= read -r iface; do
        interface_list+=("$iface")
    done < <(CollectInterfaces "$SYSCTL_INTERFACE_MODE" "$SYSCTL_INTERFACE_PATTERN")
    local sysctl_list=(
        "net.core.default_qdisc = fq_pie"
        "net.core.rmem_max = 7500000"
        "net.core.wmem_max = 7500000"
        "net.ipv4.ip_forward = 1"
        "net.ipv4.tcp_congestion_control = bbr"
        "net.ipv4.tcp_fastopen = 3"
        "vm.dirty_background_ratio = 5"
        "vm.dirty_ratio = 15"
        "vm.overcommit_memory = 1"
        "vm.page-cluster = 0"
        "vm.swappiness = 10"
        ${icmp_echo[@]+"${icmp_echo[@]}"}
    )
    mkdir -p /etc/sysctl.d
    if [ ! -f /etc/sysctl.d/99-sysctl.conf ]; then
        ln -s /etc/sysctl.conf /etc/sysctl.d/99-sysctl.conf
    fi
    {
        printf '%s\n' "${sysctl_list[@]}"
        for iface in "${interface_list[@]}"; do
            printf 'net.ipv6.conf.%s.accept_ra = 2\n' "$iface"
            printf 'net.ipv6.conf.%s.addr_gen_mode = 0\n' "$iface"
            printf 'net.ipv6.conf.%s.autoconf = 1\n' "$iface"
            printf 'net.ipv6.conf.%s.forwarding = 1\n' "$iface"
            printf 'net.ipv6.conf.%s.use_tempaddr = 0\n' "$iface"
        done
    } | sort -u > /etc/sysctl.d/99-autodeploy.conf
    sysctl -p
}

ConfigureTuned() {
    HaveCommand tuned-adm || return 0
    tuned-adm profile "$(tuned-adm recommend)"
    tuned-adm active
}

# Configure System (shared)
ConfigureGAI() {
    local prefer_ipv4_option
    if [ "${PREFER_IPV4:-true}" = "true" ]; then
        prefer_ipv4_option="precedence ::ffff:0:0/96 100"
    else
        prefer_ipv4_option="precedence ::ffff:0:0/96 10"
    fi
    local gai_conf_list=(
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
        "$prefer_ipv4_option"
        "scopev4 ::ffff:0.0.0.0/96 14"
        "scopev4 ::ffff:127.0.0.0/104 2"
        "scopev4 ::ffff:169.254.0.0/112 2"
    )
    printf '%s\n' "${gai_conf_list[@]}" | sort -u > /etc/gai.conf
}

# Only the deployment user switches to zsh; system accounts keep their shells.
ConfigureDefaultShell() {
    if HaveCommand zsh && [ -n "${DEFAULT_USERNAME:-}" ]; then
        usermod -s /bin/zsh "$DEFAULT_USERNAME"
    fi
    usermod -s /bin/bash root
}

ConfigureRootUser() {
    LOCK_ROOT="${LOCK_ROOT:-FALSE}"
    ROOT_PASSWORD="${ROOT_PASSWORD:-R00t@123!}"
    WarnDefaultPassword "ROOT_PASSWORD" "$ROOT_PASSWORD" 'R00t@123!'
    printf 'root:%s\n' "$ROOT_PASSWORD" | chpasswd
    if [ "$LOCK_ROOT" = "TRUE" ]; then
        passwd -l root
    else
        passwd -u root
    fi
}

# Swap size in MiB from RAM in MiB (pure, tested in tests/)
ComputeSwapSize() {
    local ram_mb="$1" ram_size frac_first
    ram_size=$(awk -v ram="$ram_mb" 'BEGIN{print log(ram)/log(2)}')
    if [[ "$ram_size" == *.* ]]; then
        frac_first=$(printf '%s' "$ram_size" | cut -d '.' -f 2 | cut -c 1)
        ram_size=${ram_size%%.*}
        if [ "$frac_first" -gt 5 ]; then
            ram_size=$((ram_size + 1))
        fi
    fi
    if [ "$ram_size" -le 11 ]; then
        printf '%s\n' $((2 ** ram_size * 2))
    elif [ "$ram_size" -le 13 ]; then
        printf '%s\n' $((2 ** ram_size))
    elif [ "$ram_size" -le 16 ]; then
        printf '%s\n' $((2 ** 12))
    else
        printf '%s\n' $((2 ** 13))
    fi
}

# Install / Upgrade / Cleanup (shared helpers)
InstallAptRepo() {
    local name="$1" key_url="$2" repo_line="$3"
    rm -f "/usr/share/keyrings/${name}-archive-keyring.gpg"
    curl -fsSL "$key_url" | gpg --dearmor -o "/usr/share/keyrings/${name}-archive-keyring.gpg"
    printf '%s\n' "$repo_line" > "/etc/apt/sources.list.d/${name}.list"
}

InstallAptPackages() {
    apt update
    local pkg
    for pkg in "$@"; do
        if apt-cache show "$pkg" > /dev/null 2>&1; then
            apt install -qy "$pkg"
        else
            LogWarn "package not available, skipped: ${pkg}"
        fi
    done
}

UpgradePackages() {
    apt update
    apt full-upgrade -qy
    apt autoremove -qy --purge
}

# Extra paths to remove may be passed as arguments. Never wipe all of /tmp.
CleanupTempFiles() {
    apt clean
    rm -f /root/.*_history /tmp/*.autodeploy "$@"
}

# Platform must set: KERNEL_PATTERN (grep -E matching installed kernel packages)
# Keeps the newest kernel, purges the rest.
CleanupOutageKernels() {
    local latest kernel
    latest=$(dpkg -l | grep -E "$KERNEL_PATTERN" | awk '{print $2}' | sort -V | tail -n 1 || true)
    if [ -z "$latest" ]; then
        return 0
    fi
    local kernel_list=()
    while IFS= read -r kernel; do
        if [ "$kernel" != "$latest" ]; then
            kernel_list+=("$kernel")
        fi
    done < <(dpkg -l | grep -E "$KERNEL_PATTERN" | awk '{print $2}' | sort -V || true)
    for kernel in ${kernel_list[@]+"${kernel_list[@]}"}; do
        apt purge -qy "$kernel"
    done
    apt autoremove -qy --purge
}
