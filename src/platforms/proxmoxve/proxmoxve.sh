## Function
# Get System Information
GetSystemInformation() {
    # Identity, credentials and release pinning live in the Configuration block.
    DEFAULT_FULLNAME="${DEFAULT_LASTNAME} ${DEFAULT_FIRSTNAME}"

    GenerateResolv() {
        CollectDNS
        WriteResolvConf
    }
    GetManagementIPAddress() {
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
    GetOSArchitecture
    GetManagementIPAddress
    SetGHProxyDomain
}

# Set Repository Mirror
SetRepositoryMirror() {
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
    mkdir -p "/etc/apt/sources.list.d"
    rm -f /etc/apt/sources.list.d/*.*
    printf '%s\n' "${mirror_list[@]}" > "/etc/apt/sources.list"
    printf '%s\n' "${proxmox_mirror_list[@]}" > "/etc/apt/sources.list.d/proxmox.list"
}

# Configure Packages
ConfigurePackages() {
    ConfigureAPTPVEExtras() {
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
    ConfigureGrub() {
        local display_option="" sfp_option="" btrfs_option=""
        if [ "$DISABLE_DISPLAY" = "true" ]; then
            display_option=" video=efifb:off,vesafb:off"
        fi
        if [ "$PATCH_INTEL_82599_SFP" = "true" ]; then
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
    ConfigureZfsModules() {
        if HaveCommand arcstat; then
            printf 'options zfs zfs_arc_max=%s\n' "$((ZFS_ARC_MAX * 1024 * 1024 * 1024))" > "/etc/modprobe.d/zfs.conf"
            update-initramfs -u -k all
        fi
        if modinfo ixgbe > /dev/null 2>&1; then
            printf '%s\n' "options ixgbe allow_unsupported_sfp=1" > "/etc/modprobe.d/ixgbe.conf"
        fi
    }
    ConfigurePVEPrivKeys() {
        [ -d "/etc/pve/priv" ] || return 0
        rm -f "/etc/pve/priv/authorized_keys" "/etc/pve/priv/known_hosts"
        touch "/etc/pve/priv/authorized_keys" "/etc/pve/priv/known_hosts"
        chmod 600 "/etc/pve/priv/authorized_keys" "/etc/pve/priv/known_hosts"
    }
    ConfigurePVECeph() {
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
    ConfigurePVECluster() {
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
    ConfigurePVEContainer() {
        sed -Ezi.bak 's|http://download.proxmox.com|https://mirrors.cernet.edu.cn/proxmox|g' "/usr/share/perl5/PVE/APLInfo.pm"
        systemctl restart pvedaemon
    }
    ConfigurePVEDashboard() {
        # Removes the "No valid subscription" nag; re-run after proxmox-widget-toolkit updates.
        sed -Ezi.bak "s/(Ext.Msg.show\(\{\s+title: gettext\('No valid sub)/void\(\{ \/\/\1/g" "/usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js"
        systemctl restart pveproxy
    }
    ConfigurePVEFirewall() {
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
        mkdir -p "/etc/pve/firewall"
        chown -R root:www-data "/etc/pve/firewall"
        mkdir -p "/etc/pve/nodes"
        chown -R root:www-data "/etc/pve/nodes"
        printf '%s\n' "${cluster_fw_list[@]}" > "/etc/pve/firewall/cluster.fw"
        printf '%s\n' "${host_fw_list[@]}" > "/etc/pve/nodes/${NEW_HOSTNAME}/host.fw"
        local vm
        for vm in "${vm_container_list[@]}"; do
            printf '%s\n' "${vm_container_fw_list[@]}" > "/etc/pve/firewall/${vm}.fw"
        done
    }
    ConfigureZfs() {
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
    # nftables over the distro default (iptables-multiport): PVE ships
    # nftables, not iptables, and the nftables actions are dual-stack.
    FAIL2BAN_BANACTION="nftables-multiport"
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
    DOCKER_APT_DISTRO="debian"
    FRR_APT_LINE="deb [arch=${OS_ARCHITECTURE} signed-by=/usr/share/keyrings/frrouting-archive-keyring.gpg] https://deb.frrouting.org/frr ${LSB_CODENAME} frr-stable"
    SetDebianGlobals
    ZSH_PATHS+=("/usr/lib/cargo/bin")

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
ConfigureSystem() {
    ConfigureHostfile() {
        ComputeFullDomain
        local mgmt_entry=""
        if [ -n "$CURRENT_MANAGEMENT_IP" ]; then
            mgmt_entry="${CURRENT_MANAGEMENT_IP} ${NEW_FULL_DOMAIN} ${NEW_HOSTNAME}"
        fi
        WriteHostfile ${mgmt_entry:+"$mgmt_entry"}
    }
    ConfigureProxmoxVENode() {
        if [ "$OLD_HOSTNAME" != "$NEW_HOSTNAME" ]; then
            if [ -d "/etc/pve/nodes/${OLD_HOSTNAME}" ]; then
                # Guest configs (qemu-server/lxc) must follow the rename,
                # otherwise VMs/CTs defined under the old node name would
                # disappear from the cluster config. VM disks are unaffected
                # - they live on storage, not in the node directory.
                local guest_dir conf
                for guest_dir in qemu-server lxc; do
                    if [ -d "/etc/pve/nodes/${OLD_HOSTNAME}/${guest_dir}" ]; then
                        mkdir -p "/etc/pve/nodes/${NEW_HOSTNAME}/${guest_dir}"
                        for conf in "/etc/pve/nodes/${OLD_HOSTNAME}/${guest_dir}"/*.conf; do
                            if [ -f "$conf" ]; then
                                cp -a "$conf" "/etc/pve/nodes/${NEW_HOSTNAME}/${guest_dir}/"
                                LogInfo "guest config moved: ${conf##*/} -> ${NEW_HOSTNAME}/${guest_dir}"
                            fi
                        done
                    fi
                done
                tar -czf "/etc/pve/nodes/${OLD_HOSTNAME}.tar.gz" -C "/etc/pve/nodes" "${OLD_HOSTNAME}"
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
            if [ -f "/var/lib/rrdcached/db/pve2-storage/${OLD_HOSTNAME}" ]; then
                cp -rf "/var/lib/rrdcached/db/pve2-storage/${OLD_HOSTNAME}" "/var/lib/rrdcached/db/pve2-storage/${NEW_HOSTNAME}"
                if [ -f "/var/lib/rrdcached/db/pve2-storage/${NEW_HOSTNAME}" ]; then
                    rm -rf "/var/lib/rrdcached/db/pve2-storage/${OLD_HOSTNAME}"
                fi
            fi
        fi
    }
    ConfigureSecureBoot() {
        if [ "$(findmnt -n -o FSTYPE / 2>/dev/null || true)" = "zfs" ]; then
            local esp
            while IFS= read -r esp; do
                proxmox-boot-tool init "$esp" grub
            done < <(lsblk -nr -o NAME,FSTYPE,SIZE | grep -v '^zd' | awk '$2=="vfat" {print "/dev/"$1}' || true)
        fi
    }
    ConfigureSWAP() {
        RemoveSWAP() {
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
        UpdateFSTAB() {
            sed -i '/swap/d' /etc/fstab
        }
        ClearSWAP
        RemoveSWAP
        CreateZRamSWAP
        UpdateFSTAB
    }
    # The user must exist before its login shell is modified.
    RunStep "ConfigureDefaultUser" ConfigureDefaultUser
    RunStep "ConfigureDefaultShell" ConfigureDefaultShell
    RunStep "ConfigureGAI" ConfigureGAI
    RunStep "ConfigureHostfile" ConfigureHostfile
    RunStep "ConfigureProxmoxVENode" ConfigureProxmoxVENode
    RunStep "ConfigureRootUser" ConfigureRootUser
    RunStep "ConfigureSecureBoot" ConfigureSecureBoot
    RunStep "ConfigureSWAP" ConfigureSWAP
}

# Install Custom Packages
InstallCustomPackages() {
    # Install-time structural globals: the Install* steps below run BEFORE
    # ConfigurePackages, where these used to be assigned.
    DOCKER_APT_DISTRO="debian"
    FRR_APT_LINE="deb [arch=${OS_ARCHITECTURE} signed-by=/usr/share/keyrings/frrouting-archive-keyring.gpg] https://deb.frrouting.org/frr ${LSB_CODENAME} frr-stable"
    SetDebianGlobals
    ZSH_PATHS+=("/usr/lib/cargo/bin")
    OMZ_HOME="/home/${DEFAULT_USERNAME}"
    OMZ_OWNER="${DEFAULT_USERNAME}:${DEFAULT_USERNAME}"
    RunStep "InstallCrowdSec" InstallCrowdSec
    RunStep "InstallDockerEngine" InstallDockerEngine
    RunStep "InstallFRRouting" InstallFRRouting
    RunStep "InstallOhMyZsh" InstallOhMyZsh
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
# Call ConfigureSystem (creates the default user before any Install*
# step that installs into its home directory)
ConfigureSystem
# Call InstallCustomPackages
InstallCustomPackages
# Call ConfigurePackages
ConfigurePackages
# Call CleanupTempFiles
RunStep "CleanupTempFiles" CleanupTempFiles /etc/apt/sources.list.d/pve-enterprise.list*
# Call CleanupOutageKernels
KERNEL_PATTERN='(pve-kernel|proxmox-kernel)-[0-9].*-pve'
RunStep "CleanupOutageKernels" CleanupOutageKernels
RenderProgress "complete"
