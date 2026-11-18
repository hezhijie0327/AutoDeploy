# ============================================================================
# modules/debian/daemons.sh - shared Debian-family service configuration
# (Ubuntu / Proxmox VE, bash 4.4+)
# ConfigureDockerEngine optionally reads DOCKER_REGISTRY_MIRRORS (array).
# InstallDockerEngine needs DOCKER_APT_DISTRO (ubuntu | debian).
# InstallFRRouting needs FRR_APT_LINE and optionally FRR_EXTRA_PACKAGES.
# ConfigureNut reads the NUT_* knobs; ConfigureSNMP-related parts live in
# modules/debian/security.sh.
# ============================================================================

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
    mkdir -p "/docker"
    chown -R "${DEFAULT_USERNAME}:docker" "/docker"
    chmod -R 775 "/docker"
    mkdir -p /etc/docker
    printf '%s\n' 'DOCKER_OPTS="--iptables=false"' > /etc/default/docker
    printf '%s\n' "${docker_list[@]}" > /etc/docker/daemon.json
    systemctl enable docker
    systemctl restart docker
}

InstallDockerEngine() {
    InstallAptRepo "docker" "https://mirrors.cernet.edu.cn/docker-ce/linux/${DOCKER_APT_DISTRO}/gpg" \
        "deb [arch=${OS_ARCHITECTURE:-amd64} signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://mirrors.cernet.edu.cn/docker-ce/linux/${DOCKER_APT_DISTRO} ${LSB_CODENAME} stable"
    apt update
    apt purge -qy containerd docker-compose docker-doc docker.io podman-docker runc || true
    InstallAptPackages "containerd.io" "docker-buildx-plugin" "docker-ce" "docker-ce-cli" "docker-compose-plugin"
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

InstallFRRouting() {
    InstallAptRepo "frrouting" "https://deb.frrouting.org/frr/keys.gpg" "$FRR_APT_LINE"
    InstallAptPackages "frr" "frr-pythontools" ${FRR_EXTRA_PACKAGES[@]+"${FRR_EXTRA_PACKAGES[@]}"} "frr-snmp"
}

ConfigureLLDPD() {
    HaveCommand lldpcli || return 0
    printf '%s\n' 'DAEMON_ARGS="-c -e -f -s -x"' > /etc/default/lldpd
    systemctl restart lldpd
    lldpcli show neighbors detail
}

ConfigureNut() {
    HaveCommand upsmon || return 0
    CreateUpsdUsers() {
        NUT_ADMIN_PASSWORD="${NUT_ADMIN_PASSWORD:-123456}"
        NUT_MON_PASSWORD="${NUT_MON_PASSWORD:-secret}"
        WarnDefaultPassword "NUT_ADMIN_PASSWORD" "$NUT_ADMIN_PASSWORD" "123456"
        WarnDefaultPassword "NUT_MON_PASSWORD" "$NUT_MON_PASSWORD" "secret"
        upsd_user_list=(
            "admin,${NUT_ADMIN_PASSWORD},master,FSD,SET"
            "monuser,${NUT_MON_PASSWORD},slave,,"
        )
    }
    GenerateNutConf() {
        printf 'MODE=%s\n' "${NUT_MODE:-none}" > /etc/nut/nut.conf
    }
    GenerateUpsConf() {
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
    GenerateUpsdConf() {
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
    GenerateUpsdUsers() {
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
    GenerateUpsmonConf() {
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
            CreateUpsdUsers
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
            GenerateNutConf
            GenerateUpsmonConf
            ;;
        netserver|standalone)
            CreateUpsdUsers
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
            GenerateNutConf
            GenerateUpsConf
            GenerateUpsdConf
            GenerateUpsdUsers
            GenerateUpsmonConf
            ;;
        none)
            nut_service_list=(
                "nut-client,disable"
                "nut-driver,disable"
                "nut-monitor,disable"
                "nut-server,disable"
            )
            GenerateNutConf
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

ConfigurePostfix() {
    [ -f /etc/postfix/main.cf ] || return 0
    local current_hostname
    current_hostname=$(awk -F '=' '/^myhostname/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}' /etc/postfix/main.cf)
    if [ -n "$current_hostname" ]; then
        sed -i "s/${current_hostname}/${NEW_HOSTNAME}/g" /etc/postfix/main.cf
    fi
}
