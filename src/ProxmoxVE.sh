## Function
# Get System Information
function GetSystemInformation() {
    # Identity, credentials and release pinning live in the Configuration block.
    DEFAULT_FULLNAME="${DEFAULT_LASTNAME} ${DEFAULT_FIRSTNAME}"

    function GenerateResolv() {
        CollectDNS
        WriteResolvConf
    }
    function GetHostname() {
        OLD_HOSTNAME=""
        if [ -f "/etc/hostname" ]; then
            OLD_HOSTNAME=$(awk '{print $1; exit}' "/etc/hostname")
        fi
        if [ -z "$OLD_HOSTNAME" ] && HaveCommand hostname; then
            OLD_HOSTNAME=$(hostname)
        fi
    }
    function GetManagementIPAddress() {
        CURRENT_MANAGEMENT_IP=""
        if ip link show vmbr0 > /dev/null 2>&1; then
            CURRENT_MANAGEMENT_IP=$(ip address show vmbr0 | awk '/inet / {print $2}' | sort | head -n 1 | sed 's/\/.*//')
        fi
        if [ -z "$CURRENT_MANAGEMENT_IP" ]; then
            LogWarn "vmbr0 has no IPv4 address; /etc/hosts gets no management IP entry"
        fi
    }
    GenerateDomain
    GenerateHostname
    GenerateResolv
    GetCPUVendorID
    GetHostname
    GetManagementIPAddress
    SetGHProxyDomain
}

# Set Repository Mirror
function SetRepositoryMirror() {
    local mirror_list=(
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/debian-security ${LSB_CODENAME}-security contrib main non-free non-free-firmware"
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/debian ${LSB_CODENAME} contrib main non-free non-free-firmware"
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/debian ${LSB_CODENAME}-backports contrib main non-free non-free-firmware"
        "# deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/debian ${LSB_CODENAME}-backports-sloppy contrib main non-free non-free-firmware"
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/debian ${LSB_CODENAME}-proposed-updates contrib main non-free non-free-firmware"
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/debian ${LSB_CODENAME}-updates contrib main non-free non-free-firmware"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/debian-security ${LSB_CODENAME}-security contrib main non-free non-free-firmware"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/debian ${LSB_CODENAME} contrib main non-free non-free-firmware"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/debian ${LSB_CODENAME}-backports contrib main non-free non-free-firmware"
        "# deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/debian ${LSB_CODENAME}-backports-sloppy contrib main non-free non-free-firmware"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/debian ${LSB_CODENAME}-proposed-updates contrib main non-free non-free-firmware"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/debian ${LSB_CODENAME}-updates contrib main non-free non-free-firmware"
    )
    local proxmox_mirror_list=(
        "# deb ${TRANSPORT_PROTOCOL}://enterprise.proxmox.com/debian/ceph-${CEPH_CODENAME} ${LSB_CODENAME} enterprise"
        "# deb ${TRANSPORT_PROTOCOL}://enterprise.proxmox.com/debian/pve ${LSB_CODENAME} pve-enterprise"
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/proxmox/debian ${LSB_CODENAME} pve-no-subscription pve-test"
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/proxmox/debian/ceph-${CEPH_CODENAME} ${LSB_CODENAME} no-subscription test"
    )
    if [ ! -d "/etc/apt/sources.list.d" ]; then
        mkdir "/etc/apt/sources.list.d"
    else
        rm -f /etc/apt/sources.list.d/*.*
    fi
    printf '%s\n' "${mirror_list[@]}" > "/etc/apt/sources.list"
    printf '%s\n' "${proxmox_mirror_list[@]}" > "/etc/apt/sources.list.d/proxmox.list"
}

# Configure Packages
function ConfigurePackages() {
    function ConfigureAPTPVEExtras() {
        local pve_repo_preference_list=(
            "pve-enterprise 1000"
            "pve-no-subscription 990"
            "pve-test 100"
            "enterprise 1000"
            "no-subscription 990"
            "test 100"
        )
        local entry component priority
        : > "/etc/apt/preferences.d/proxmox.pref"
        for entry in "${pve_repo_preference_list[@]}"; do
            component="${entry%% *}"
            priority="${entry##* }"
            case "$priority" in
                *[!0-9]*) priority="500" ;;
            esac
            printf 'Package: *\nPin: release c=%s,o=Proxmox\nPin-Priority: %s\n\n' "$component" "$priority" >> "/etc/apt/preferences.d/proxmox.pref"
        done
        if [ -f "/etc/apt/sources.list.d/debian-backports.sources" ]; then
            sed -i 's|Signed-By:.*|Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg|g' "/etc/apt/sources.list.d/debian-backports.sources"
        fi
    }
    function ConfigureCrontab() {
        CRONTAB_USER="root"
        CRONTAB_ENTRIES=(
            "0 0 * * 7 sudo apt update && sudo apt full-upgrade -qy && sudo apt autoremove -qy --purge"
            "# 0 4 * * 7 sudo reboot"
            "@reboot sudo rm -rf ~/.*_history ~/.ssh/known_hosts*"
        )
        InstallCrontab
    }
    function ConfigureGrub() {
        local display_option="" sfp_option="" btrfs_option=""
        if [ "${DISABLE_DISPLAY:-false}" = "true" ]; then
            display_option=" video=efifb:off,vesafb:off"
        fi
        if [ "${PATCH_INTEL_82599_SFP:-false}" = "true" ]; then
            sfp_option=" ixgbe.allow_unsupported_sfp=1"
        fi
        if [ "$(findmnt -no FSTYPE / 2>/dev/null || true)" = "btrfs" ]; then
            btrfs_option=" rootflags=degraded"
        fi
        if HaveCommand update-grub && [ -f "/usr/share/grub/default/grub" ]; then
            sed -E \
                -e "s/GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"/GRUB_CMDLINE_LINUX_DEFAULT=\"quiet security=apparmor mitigations=auto,nosmt${btrfs_option}${sfp_option}${display_option}${ENABLE_IOMMU}\"/g" \
                -e 's/#GRUB_DISABLE_OS_PROBER=false/GRUB_DISABLE_OS_PROBER=true/g' \
                -e 's/GRUB_TIMEOUT=.*/GRUB_TIMEOUT=5/g' \
                -e '/GRUB_TIMEOUT_STYLE=/d' \
                "/usr/share/grub/default/grub" > "/etc/default/grub"
            update-grub
        fi
        if HaveCommand proxmox-boot-tool && [ -f "/etc/kernel/cmdline" ]; then
            if [ ! -f "/etc/kernel/cmdline.bak" ]; then
                cp "/etc/kernel/cmdline" "/etc/kernel/cmdline.bak"
            fi
            sed -E "s/boot=zfs/boot=zfs quiet security=apparmor mitigations=auto,nosmt${sfp_option}${display_option}${ENABLE_IOMMU}/g" \
                "/etc/kernel/cmdline.bak" > "/etc/kernel/cmdline"
            proxmox-boot-tool refresh
        fi
    }
    function ConfigureZfsModules() {
        if HaveCommand arcstat; then
            ZFS_ARC_MAX="${ZFS_ARC_MAX:-1}" # GiB
            printf 'options zfs zfs_arc_max=%s\n' "$((ZFS_ARC_MAX * 1024 * 1024 * 1024))" > "/etc/modprobe.d/zfs.conf"
            update-initramfs -u -k all
        fi
        if modinfo ixgbe > /dev/null 2>&1; then
            printf '%s\n' "options ixgbe allow_unsupported_sfp=1" > "/etc/modprobe.d/ixgbe.conf"
        fi
    }
    function ConfigurePVEPrivKeys() {
        [ -d "/etc/pve/priv" ] || return 0
        rm -f "/etc/pve/priv/authorized_keys" "/etc/pve/priv/known_hosts"
        touch "/etc/pve/priv/authorized_keys" "/etc/pve/priv/known_hosts"
        chmod 600 "/etc/pve/priv/authorized_keys" "/etc/pve/priv/known_hosts"
    }
    function ConfigurePVECeph() {
        if [ -d "/etc/systemd/system/ceph-mon.target.wants" ]; then
            local mon_path mon
            for mon_path in "/etc/systemd/system/ceph-mon.target.wants"/ceph-mon@*; do
                if [ -e "$mon_path" ]; then
                    mon="${mon_path##*/}"
                    systemctl stop "$mon"
                    systemctl disable "$mon"
                fi
            done
            rm -rf "/etc/ceph" "/etc/pve/ceph.conf" "/var/lib/ceph"
            mkdir -p "/etc/ceph" "/var/lib/ceph/mgr" "/var/lib/ceph/mon"
        fi
    }
    function ConfigurePVECluster() {
        RESET_CLUSTER="${RESET_CLUSTER:-true}"
        if [ "$RESET_CLUSTER" != "true" ]; then
            LogInfo "RESET_CLUSTER=false: leaving cluster configuration untouched"
            return 0
        fi
        LogWarn "RESET_CLUSTER=true: resetting corosync/pve-cluster state (standalone node assumed; set RESET_CLUSTER=false on clustered nodes)"
        systemctl stop pve-cluster || true
        systemctl stop corosync || true
        pmxcfs -l
        rm -f "/etc/pve/corosync.conf"
        rm -rf /etc/corosync/* /var/log/corosync/* /var/lib/corosync/*
        killall pmxcfs || true
        systemctl start pve-cluster
    }
    function ConfigurePVEContainer() {
        sed -Ezi.bak 's|http://download.proxmox.com|https://mirrors.cernet.edu.cn/proxmox|g' "/usr/share/perl5/PVE/APLInfo.pm"
        systemctl restart pvedaemon
    }
    function ConfigurePVEDashboard() {
        # Removes the "No valid subscription" nag; re-run after proxmox-widget-toolkit updates.
        sed -Ezi.bak "s/(Ext.Msg.show\(\{\s+title: gettext\('No valid sub)/void\(\{ \/\/\1/g" "/usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js"
        systemctl restart pveproxy
    }
    function ConfigurePVEFirewall() {
        local cluster_fw_list=(
            "[OPTIONS]"
            "ebtables: 1"
            "enable: 1"
            "log_ratelimit: burst=5,enable=1,rate=1/second"
            "policy_in: REJECT"
            "policy_out: ACCEPT"
            "[RULES]"
            "IN ACCEPT -p icmp -log nolog"
            "IN ACCEPT -p ipv6-icmp -log nolog"
            "IN ACCEPT -p tcp -dport 135 -log nolog"
            "IN ACCEPT -p udp -dport 135 -log nolog"
            "IN ACCEPT -p udp -dport 137:139 -log nolog"
            "IN ACCEPT -p tcp -dport 139 -log nolog"
            "IN ACCEPT -p udp -dport 1900 -log nolog"
            "IN ACCEPT -p tcp -dport 22 -log nolog"
            "IN ACCEPT -p tcp -dport 3128 -log nolog"
            "IN ACCEPT -p tcp -dport 43 -log nolog"
            "IN ACCEPT -p tcp -dport 445 -log nolog"
            "IN ACCEPT -p udp -dport 445 -log nolog"
            "IN ACCEPT -p udp -dport 5405:5412 -log nolog"
            "IN ACCEPT -p tcp -dport 5900:5999 -log nolog"
            "IN ACCEPT -p tcp -dport 8006 -log nolog"
        )
        local host_fw_list=(
            "[OPTIONS]"
            "enable: 1"
            "log_level_in: nolog"
            "log_level_out: nolog"
            "log_nf_conntrack: 0"
            "ndp: 1"
            "nf_conntrack_allow_invalid: 1"
            "nf_conntrack_max: 262144"
            "nf_conntrack_tcp_timeout_established: 432000"
            "nf_conntrack_tcp_timeout_syn_recv: 60"
            "nftables: 1"
            "nosmurfs: 0"
            "protection_synflood: 0"
            "protection_synflood_burst: 1000"
            "protection_synflood_rate: 200"
            "smurf_log_level: nolog"
            "tcp_flags_log_level: nolog"
            "tcpflags: 0"
            "[RULES]"
            "IN ACCEPT -p icmp -log nolog"
            "IN ACCEPT -p ipv6-icmp -log nolog"
            "IN ACCEPT -p udp -dport 111 -log nolog"
            "IN ACCEPT -p udp -dport 123 -log nolog"
            "IN ACCEPT -p udp -dport 161 -log nolog"
            "IN ACCEPT -p tcp -dport 22 -log nolog"
            "IN ACCEPT -p tcp -dport 3128 -log nolog"
            "IN ACCEPT -p tcp -dport 3493 -log nolog"
            "IN ACCEPT -p udp -dport 323 -log nolog"
            "IN ACCEPT -p udp -dport 5404:5405 -log nolog"
            "IN ACCEPT -p tcp -dport 5900:5999 -log nolog"
            "IN ACCEPT -p tcp -dport 60000:60050 -log nolog"
            "IN ACCEPT -p tcp -dport 8006 -log nolog"
        )
        local vm_container_fw_list=(
            "[OPTIONS]"
            "dhcp: 1"
            "enable: 0"
            "ipfilter: 0"
            "log_level_in: nolog"
            "log_level_out: nolog"
            "macfilter: 0"
            "ndp: 1"
            "policy_in: REJECT"
            "policy_out: ACCEPT"
            "radv: 1"
            "[RULES]"
            "IN ACCEPT -p icmp -log nolog"
            "IN ACCEPT -p ipv6-icmp -log nolog"
        )
        local vm_container_list=("template") conf_path vmid dir
        for dir in "/etc/pve/lxc" "/etc/pve/qemu-server"; do
            if [ -d "$dir" ]; then
                for conf_path in "$dir"/*.conf; do
                    if [ -e "$conf_path" ]; then
                        vmid="${conf_path##*/}"
                        vm_container_list+=("${vmid%.conf}")
                    fi
                done
            fi
        done
        if [ ! -d "/etc/pve/firewall" ]; then
            mkdir "/etc/pve/firewall"
            chown -R root:www-data "/etc/pve/firewall"
        fi
        if [ ! -d "/etc/pve/nodes" ]; then
            mkdir "/etc/pve/nodes"
            chown -R root:www-data "/etc/pve/nodes"
        fi
        printf '%s\n' "${cluster_fw_list[@]}" > "/etc/pve/firewall/cluster.fw"
        printf '%s\n' "${host_fw_list[@]}" > "/etc/pve/nodes/${NEW_HOSTNAME}/host.fw"
        local vm
        for vm in "${vm_container_list[@]}"; do
            printf '%s\n' "${vm_container_fw_list[@]}" > "/etc/pve/firewall/${vm}.fw"
        done
    }
    function ConfigureZfs() {
        HaveCommand zpool || return 0
        local pool
        while IFS= read -r pool; do
            zfs set compression=zstd "$pool"
            zpool set autotrim=on "$pool"
            systemctl enable --now "zfs-trim-weekly@${pool}.timer"
        done < <(zpool list -H -o name)
    }

    APT_PREFERENCES=(
        "${LSB_CODENAME}-backports-sloppy 990"
        "${LSB_CODENAME}-backports 990"
        "${LSB_CODENAME}-security 500"
        "${LSB_CODENAME}-updates 500"
        "${LSB_CODENAME} 500"
        "${LSB_CODENAME}-proposed-updates 100"
    )
    FAIL2BAN_BANACTION="default"
    FAIL2BAN_FILTER_NAME="proxmox"
    FAIL2BAN_FILTER=(
        "[Definition]"
        "failregex = pvedaemon\[.*authentication failure; rhost=<HOST> user=.* msg=.*"
        "journalmatch = _SYSTEMD_UNIT=pvedaemon.service"
    )
    FAIL2BAN_JAILS=(
        "[proxmox]"
        "backend = systemd"
        "bantime = 604800"
        "enabled = true"
        "filter = proxmox"
        "findtime = 60"
        "maxretry = 5"
        "port = 8006"
        "[sshd]"
        "bantime = 604800"
        "enabled = true"
        "filter = sshd"
        "findtime = 60"
        "logpath = /var/log/auth.log"
        "maxretry = 5"
        "port = 22"
    )
    MODULE_LIST_EXTRA=("ip_conntrack_ftp" "nfnetlink_queue")
    SYSCTL_INTERFACE_MODE="include"
    SYSCTL_INTERFACE_PATTERN='^vmbr'
    PROXYCHAINS_CONF="/etc/proxychains4.conf"
    GPG_HOME="/home/${DEFAULT_USERNAME}/.gnupg"
    GPG_KEYSERVER="hkps://keyserver.ubuntu.com:443"
    GPG_PINENTRY="/usr/bin/pinentry-tty"
    GPG_HOME_OWNER="${DEFAULT_USERNAME}:${DEFAULT_USERNAME}"
    ZSH_HOME="/home/${DEFAULT_USERNAME}"
    ZSH_OWNER="${DEFAULT_USERNAME}:${DEFAULT_USERNAME}"
    ZSH_PATH_LIST=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/usr/local/bin" "/usr/local/sbin" "/usr/lib/cargo/bin")
    ZSH_EXTRA_EXPORTS=("export DEBIAN_FRONTEND=\"noninteractive\"")
    ZSH_TRAPEXIT="false"

    RunStep "ConfigureAPT" ConfigureAPT
    RunStep "ConfigureAPTPVEExtras" ConfigureAPTPVEExtras
    RunStep "ConfigureBusybox" ConfigureBusybox
    RunStep "ConfigureChrony" ConfigureChrony
    RunStep "ConfigureCrontab" ConfigureCrontab
    RunStep "ConfigureCrowdSec" ConfigureCrowdSec
    RunStep "ConfigureDockerEngine" ConfigureDockerEngine
    RunStep "ConfigureFail2Ban" ConfigureFail2Ban
    RunStep "ConfigureFRRouting" ConfigureFRRouting
    RunStep "ConfigureGPG" ConfigureGPG
    RunStep "ConfigureGit" ConfigureGit
    RunStep "ConfigureGrub" ConfigureGrub
    RunStep "ConfigureLLDPD" ConfigureLLDPD
    RunStep "ConfigureModules" ConfigureModules
    RunStep "ConfigureZfsModules" ConfigureZfsModules
    RunStep "ConfigureNut" ConfigureNut
    RunStep "ConfigureOpenSSH" ConfigureOpenSSH
    RunStep "ConfigurePVEPrivKeys" ConfigurePVEPrivKeys
    RunStep "ConfigurePostfix" ConfigurePostfix
    RunStep "ConfigureProxyChains" ConfigureProxyChains
    RunStep "ConfigurePVECeph" ConfigurePVECeph
    RunStep "ConfigurePVECluster" ConfigurePVECluster
    RunStep "ConfigurePVEContainer" ConfigurePVEContainer
    RunStep "ConfigurePVEDashboard" ConfigurePVEDashboard
    RunStep "ConfigurePVEFirewall" ConfigurePVEFirewall
    RunStep "ConfigurePythonPyPI" ConfigurePythonPyPI
    RunStep "ConfigureSNMP" ConfigureSNMPBase
    RunStep "ConfigureSshd" ConfigureSshd
    RunStep "ConfigureSysctl" ConfigureSysctl
    RunStep "ConfigureTuned" ConfigureTuned
    RunStep "ConfigureZfs" ConfigureZfs
    RunStep "ConfigureZsh" ConfigureZsh
}

# Configure System
function ConfigureSystem() {
    function ConfigureDefaultUser() {
        WarnDefaultPassword "DEFAULT_PASSWORD" "$DEFAULT_PASSWORD" '*Proxmox123*'
        PURGE_OTHER_USERS="${PURGE_OTHER_USERS:-true}"
        if [ "$PURGE_OTHER_USERS" = "true" ]; then
            LogWarn "PURGE_OTHER_USERS=true: removing every other user under /home (set PURGE_OTHER_USERS=false to keep them)"
            local home_dir user
            for home_dir in /home/*; do
                if [ -d "$home_dir" ]; then
                    user="${home_dir##*/}"
                    if [ "$user" != "$DEFAULT_USERNAME" ]; then
                        userdel -rf "$user" > /dev/null 2>&1 || true
                        if HaveCommand pveum; then
                            pveum userdel "${user}@pam" > /dev/null 2>&1 || true
                        fi
                    fi
                fi
            done
        fi
        if id "$DEFAULT_USERNAME" > /dev/null 2>&1; then
            userdel -rf "$DEFAULT_USERNAME" > /dev/null 2>&1 || true
        fi
        useradd -c "$DEFAULT_FULLNAME" -d "/home/${DEFAULT_USERNAME}" -s "/bin/zsh" -m "$DEFAULT_USERNAME"
        printf '%s:%s\n' "$DEFAULT_USERNAME" "$DEFAULT_PASSWORD" | chpasswd
        adduser "$DEFAULT_USERNAME" "docker"
        adduser "$DEFAULT_USERNAME" "sudo"
        CRONTAB_USER="$DEFAULT_USERNAME"
        CRONTAB_ENTRIES=(
            "@reboot rm -rf ~/.*_history ~/.ssh/known_hosts*"
        )
        InstallCrontab
        if HaveCommand pveum; then
            if pveum group list | grep -q 'LADM'; then
                pveum group modify "LADM" -comment "Local Administrators"
            else
                pveum groupadd "LADM" -comment "Local Administrators"
            fi
            pveum aclmod "/" -group "LADM" -role "Administrator"
            if pveum user list | grep -q "${DEFAULT_USERNAME}@pam"; then
                pveum usermod "${DEFAULT_USERNAME}@pam" -comment "$DEFAULT_FULLNAME" -firstname "$DEFAULT_FIRSTNAME" -group "LADM" -lastname "$DEFAULT_LASTNAME"
            else
                pveum useradd "${DEFAULT_USERNAME}@pam" -comment "$DEFAULT_FULLNAME" -firstname "$DEFAULT_FIRSTNAME" -group "LADM" -lastname "$DEFAULT_LASTNAME"
            fi
            pveum usermod "root@pam" -comment "Proxmox Root" -firstname "Root" -group "LADM" -lastname "Proxmox"
        fi
    }
    function ConfigureHostfile() {
        ComputeFullDomain
        local host_list=()
        if [ -n "$CURRENT_MANAGEMENT_IP" ]; then
            host_list+=("${CURRENT_MANAGEMENT_IP} ${NEW_FULL_DOMAIN} ${NEW_HOSTNAME}")
        fi
        host_list+=(
            "127.0.0.1 localhost"
            "255.255.255.255 broadcasthost"
            "::1 ip6-localhost ip6-loopback localhost"
            "fe00::0 ip6-localnet"
            "ff00::0 ip6-mcastprefix"
            "ff02::1 ip6-allnodes"
            "ff02::2 ip6-allrouters"
            "ff02::3 ip6-allhosts"
        )
        printf '%s\n' "${host_list[@]}" > "/etc/hosts"
        printf '%s\n' "$NEW_HOSTNAME" > "/etc/hostname"
        hostnamectl set-hostname "$NEW_HOSTNAME"
    }
    function ConfigureProxmoxVENode() {
        if [ "$OLD_HOSTNAME" != "$NEW_HOSTNAME" ]; then
            if [ -d "/etc/pve/nodes/${OLD_HOSTNAME}" ]; then
                tar -czvf "/etc/pve/nodes/${OLD_HOSTNAME}.tar.gz" "/etc/pve/nodes/${OLD_HOSTNAME}"
                if [ -f "/etc/pve/nodes/${OLD_HOSTNAME}.tar.gz" ]; then
                    rm -rf "/etc/pve/nodes/${OLD_HOSTNAME}"
                fi
            fi
            if [ -f "/var/lib/rrdcached/db/pve2-node/${OLD_HOSTNAME}" ]; then
                cp -rf "/var/lib/rrdcached/db/pve2-node/${OLD_HOSTNAME}" "/var/lib/rrdcached/db/pve2-node/${NEW_HOSTNAME}"
                if [ -f "/var/lib/rrdcached/db/pve2-node/${NEW_HOSTNAME}" ]; then
                    rm -rf "/var/lib/rrdcached/db/pve2-node/${OLD_HOSTNAME}"
                fi
            fi
            if [ -d "/var/lib/rrdcached/db/pve2-storage/${OLD_HOSTNAME}" ]; then
                cp -rf "/var/lib/rrdcached/db/pve2-storage/${OLD_HOSTNAME}" "/var/lib/rrdcached/db/pve2-storage/${NEW_HOSTNAME}"
                if [ -d "/var/lib/rrdcached/db/pve2-storage/${NEW_HOSTNAME}" ]; then
                    rm -rf "/var/lib/rrdcached/db/pve2-storage/${OLD_HOSTNAME}"
                fi
            fi
        fi
    }
    function ConfigureSecureBoot() {
        if [ "$(findmnt -n -o FSTYPE / 2>/dev/null || true)" = "zfs" ]; then
            local esp
            while IFS= read -r esp; do
                proxmox-boot-tool init "$esp" grub
            done < <(lsblk -nr -o NAME,FSTYPE,SIZE | grep -v '^zd' | awk '$2=="vfat" {print "/dev/"$1}' || true)
        fi
    }
    function ConfigureSWAP() {
        function ClearSWAP() {
            HaveCommand sysctl || return 0
            sync
            sysctl -w vm.drop_caches=3 vm.overcommit_memory=0 vm.swappiness=0
        }
        function CreateSWAP() {
            local zram_conf_list=(
                "[zram0]"
                "compression-algorithm = zstd"
                "zram-size = min(ram / 2, 8192)"
            )
            rm -rf "/etc/systemd/zram-generator.conf.d"
            mkdir -p "/etc/systemd/zram-generator.conf.d"
            printf '%s\n' "${zram_conf_list[@]}" > "/etc/systemd/zram-generator.conf.d/zram.conf"
        }
        function RemoveSWAP() {
            local swapfile
            while IFS= read -r swapfile; do
                swapoff "$swapfile" > /dev/null 2>&1 || true
                if [[ "$swapfile" =~ ^/dev/dm- ]]; then
                    lvremove -f "/dev/mapper/pve-swap" > /dev/null 2>&1 || true
                    lvextend -l +100%FREE "/dev/mapper/pve-root"
                else
                    rm -f "$swapfile"
                fi
            done < <(awk 'NR>1 {print $1}' /proc/swaps)
        }
        function UpdateFSTAB() {
            grep -v "swap" /etc/fstab > "/tmp/fstab.autodeploy" || true
            cat "/tmp/fstab.autodeploy" > "/etc/fstab"
            rm -f "/tmp/fstab.autodeploy"
        }
        ClearSWAP
        RemoveSWAP
        CreateSWAP
        UpdateFSTAB
    }
    RunStep "ConfigureDefaultShell" ConfigureDefaultShell
    RunStep "ConfigureDefaultUser" ConfigureDefaultUser
    RunStep "ConfigureGAI" ConfigureGAI
    RunStep "ConfigureHostfile" ConfigureHostfile
    RunStep "ConfigureProxmoxVENode" ConfigureProxmoxVENode
    RunStep "ConfigureRootUser" ConfigureRootUser
    RunStep "ConfigureSecureBoot" ConfigureSecureBoot
    RunStep "ConfigureSWAP" ConfigureSWAP
}

# Install Custom Packages
function InstallCustomPackages() {
    function InstallCrowdSec() {
        InstallAptRepo "crowdsec" "https://packagecloud.io/crowdsec/crowdsec/gpgkey" \
            "deb [arch=amd64 signed-by=/usr/share/keyrings/crowdsec-archive-keyring.gpg] https://packagecloud.io/crowdsec/crowdsec/any any main
deb-src [arch=amd64 signed-by=/usr/share/keyrings/crowdsec-archive-keyring.gpg] https://packagecloud.io/crowdsec/crowdsec/any any main"
        if HaveCommand cscli; then
            local bouncer
            while IFS= read -r bouncer; do
                cscli bouncers delete "$bouncer"
            done < <(cscli bouncers list | grep 'FirewallBouncer' | awk '{print $1}' || true)
        fi
        InstallAptPackages "crowdsec" "crowdsec-firewall-bouncer-nftables"
    }
    function InstallDockerEngine() {
        InstallAptRepo "docker" "https://mirrors.cernet.edu.cn/docker-ce/linux/debian/gpg" \
            "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://mirrors.cernet.edu.cn/docker-ce/linux/debian ${LSB_CODENAME} stable"
        apt update
        apt purge -qy containerd docker-compose docker-doc docker.io podman-docker runc || true
        InstallAptPackages "containerd.io" "docker-buildx-plugin" "docker-ce" "docker-ce-cli" "docker-compose-plugin"
    }
    function InstallFRRouting() {
        InstallAptRepo "frrouting" "https://deb.frrouting.org/frr/keys.gpg" \
            "deb [arch=amd64 signed-by=/usr/share/keyrings/frrouting-archive-keyring.gpg] https://deb.frrouting.org/frr ${LSB_CODENAME} frr-stable"
        InstallAptPackages "frr" "frr-pythontools" "frr-snmp"
    }
    OMZ_HOME="/home/${DEFAULT_USERNAME}"
    OMZ_OWNER="${DEFAULT_USERNAME}:${DEFAULT_USERNAME}"
    RunStep "InstallCrowdSec" InstallCrowdSec
    RunStep "InstallDockerEngine" InstallDockerEngine
    RunStep "InstallFRRouting" InstallFRRouting
    RunStep "InstallOhMyZsh" InstallOhMyZsh
}

# Install Dependency Packages
function InstallDependencyPackages() {
    local apt_list=("${DEPENDENCY_PACKAGES[@]}")
    apt_list+=(${MICROCODE[@]+"${MICROCODE[@]}"})
    InstallAptPackages "${apt_list[@]}"
}

## Process
# Set DEBIAN_FRONTEND to "noninteractive"
export DEBIAN_FRONTEND="noninteractive"
RequireRoot
# Call GetSystemInformation (always runs: later steps need its globals)
GetSystemInformation
InitRun
# Set TRANSPORT_PROTOCOL="http"; Call SetRepositoryMirror
TRANSPORT_PROTOCOL="http"
RunStep "SetRepositoryMirror.http" SetRepositoryMirror
# Call InstallDependencyPackages
RunStep "InstallDependencyPackages" InstallDependencyPackages
# Set TRANSPORT_PROTOCOL="https"; Call SetRepositoryMirror
TRANSPORT_PROTOCOL="https"
RunStep "SetRepositoryMirror.https" SetRepositoryMirror
# Call UpgradePackages
RunStep "UpgradePackages" UpgradePackages
# Call InstallCustomPackages
InstallCustomPackages
# Call ConfigureSystem
ConfigureSystem
# Call ConfigurePackages
ConfigurePackages
# Call CleanupTempFiles
RunStep "CleanupTempFiles" CleanupTempFiles /etc/apt/sources.list.d/pve-enterprise.list*
# Call CleanupOutageKernels
KERNEL_PATTERN='(pve-kernel|proxmox-kernel)-[0-9].*-pve'
RunStep "CleanupOutageKernels" CleanupOutageKernels
RenderProgress "complete"
