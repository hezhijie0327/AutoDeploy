## Function
# Get System Information
GetSystemInformation() {
    # Identity, credentials and release pinning live in the Configuration block.
    DEFAULT_FULLNAME="${DEFAULT_LASTNAME} ${DEFAULT_FIRSTNAME}"

    CheckMachineEnvironment() {
        CheckHypervisorEnvironment() {
            if ! HaveCommand virt-what; then
                local apt_sources_file="/etc/apt/sources.list"
                if [ ! -f "$apt_sources_file" ]; then
                    apt_sources_file="/etc/apt/sources.list.d/ubuntu.sources"
                fi
                sed -i -E \
                    -e 's/[a-z.]*archive\.ubuntu\.com/mirrors.cernet.edu.cn/g' \
                    -e 's/[a-z.]*ports\.ubuntu\.com/mirrors.cernet.edu.cn/g' \
                    -e 's/[a-z.]*security\.ubuntu\.com/mirrors.cernet.edu.cn/g' \
                    "$apt_sources_file"
                apt update
                apt install virt-what -qy
                HaveCommand virt-what || Die "virt-what has not been installed!"
            fi
            local hypervisor_environment
            hypervisor_environment=$(virt-what)
            HYPERVISOR_AGENT=()
            case "$hypervisor_environment" in
                kvm) HYPERVISOR_AGENT=("ksmtuned" "qemu-guest-agent") ;;
                vmware) HYPERVISOR_AGENT=("open-vm-tools") ;;
                virtualbox) HYPERVISOR_AGENT=("virtualbox-guest-dkms") ;;
            esac
        }
        CheckHypervisorEnvironment
    }
    GetPsabiLevel() {
        # https://dl.xanmod.org/check_x86-64_psabi.sh
        PSABI_LEVEL=$(awk 'BEGIN{while(!/flags/)if(getline<"/proc/cpuinfo"!=1)exit 0;if(/lm/&&/cmov/&&/cx8/&&/fpu/&&/fxsr/&&/mmx/&&/syscall/&&/sse2/)l=1;if(l==1&&/cx16/&&/lahf/&&/popcnt/&&/sse4_1/&&/sse4_2/&&/ssse3/)l=2;if(l==2&&/avx/&&/avx2/&&/bmi1/&&/bmi2/&&/f16c/&&/fma/&&/abm/&&/movbe/&&/xsave/)l=3;if(l==3&&/avx512f/&&/avx512bw/&&/avx512cd/&&/avx512dq/&&/avx512vl/)l=4;print l}')
    }
    GetUbuntuMirror() {
        GetOSArchitecture
        case "${OS_ARCHITECTURE:-}" in
            arm64) APT_MIRROR_REPO="ubuntu-ports" ;;
            amd64) APT_MIRROR_REPO="ubuntu" ;;
        esac
    }
    CollectDNS
    GenerateDomain
    CheckMachineEnvironment
    GenerateHostname
    GetPsabiLevel
    GetCPUVendorID
    GetUbuntuMirror
    SetGHProxyDomain
}

# Set Repository Mirror
SetRepositoryMirror() {
    local mirror_list=(
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${APT_MIRROR_REPO} ${LSB_CODENAME} main multiverse restricted universe"
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${APT_MIRROR_REPO} ${LSB_CODENAME}-backports main multiverse restricted universe"
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${APT_MIRROR_REPO} ${LSB_CODENAME}-proposed main multiverse restricted universe"
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${APT_MIRROR_REPO} ${LSB_CODENAME}-security main multiverse restricted universe"
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${APT_MIRROR_REPO} ${LSB_CODENAME}-updates main multiverse restricted universe"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${APT_MIRROR_REPO} ${LSB_CODENAME} main multiverse restricted universe"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${APT_MIRROR_REPO} ${LSB_CODENAME}-backports main multiverse restricted universe"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${APT_MIRROR_REPO} ${LSB_CODENAME}-proposed main multiverse restricted universe"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${APT_MIRROR_REPO} ${LSB_CODENAME}-security main multiverse restricted universe"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${APT_MIRROR_REPO} ${LSB_CODENAME}-updates main multiverse restricted universe"
    )
    mkdir -p "/etc/apt/sources.list.d"
    rm -f /etc/apt/sources.list.d/*.*
    printf '%s\n' "${mirror_list[@]}" > "/etc/apt/sources.list"
}

# Configure Packages
ConfigurePackages() {
    ConfigureCockpit() {
        HaveCommand cockpit-bridge || return 0
        mkdir -p /etc/cockpit
        local cockpit_conf_list=(
            "[Session]"
            "IdleTimeout = 60"
            "[WebService]"
            "MaxStartups = 3:75:5"
        )
        printf '%s\n' "${cockpit_conf_list[@]}" > /etc/cockpit/cockpit.conf
        if [ "$COCKPIT_PORT" != "9090" ]; then
            # cockpit.socket hardcodes 9090; a drop-in moves the listen port.
            mkdir -p /etc/systemd/system/cockpit.socket.d
            local socket_override_list=(
                "[Socket]"
                "ListenStream="
                "ListenStream=${COCKPIT_PORT}"
            )
            printf '%s\n' "${socket_override_list[@]}" > /etc/systemd/system/cockpit.socket.d/autodeploy.conf
            systemctl daemon-reload
        fi
        systemctl enable --now cockpit.socket
    }
    ConfigureCloudflareWARP() {
        # Get token from `https://<YOUR_TEAM_NAME>.cloudflareaccess.com/warp`
        # Login via `warp-cli registration token 'com.cloudflare.warp://<your-team-name>.cloudflareaccess.com/auth?token=<your-token>'`
        HaveCommand warp-cli || return 0
        ufw allow in on CloudflareWARP
    }
    ConfigureGrub() {
        HaveCommand update-grub || return 0
        rm -f "/etc/default/grub.d/50-cloudimg-settings.cfg"
        [ -f "/usr/share/grub/default/grub" ] || return 0
        sed -E \
            -e "s/GRUB_CMDLINE_LINUX_DEFAULT=\"quiet splash\"/GRUB_CMDLINE_LINUX_DEFAULT=\"quiet security=apparmor mitigations=auto,nosmt${ENABLE_IOMMU}\"/g" \
            -e 's/#GRUB_DISABLE_OS_PROBER=false/GRUB_DISABLE_OS_PROBER=true/g' \
            -e 's/GRUB_TIMEOUT=.*/GRUB_TIMEOUT=5/g' \
            -e '/GRUB_TIMEOUT_STYLE=/d' \
            "/usr/share/grub/default/grub" > "/etc/default/grub"
        update-grub
    }
    ConfigureLandscape() {
        [ -f "/usr/lib/python3/dist-packages/landscape/lib/network.py" ] || return 0
        sed -i 's/tostring/tobytes/g' "/usr/lib/python3/dist-packages/landscape/lib/network.py"
    }
    ConfigureNetplan() {
        HaveCommand netplan || return 0
        local static_ipv4_addr static_ipv4_gateway static_ipv6_addr static_ipv6_gateway
        static_ipv4_addr=$(printf '%s' "$STATIC_IPV4_CONFIG" | cut -d ',' -f 1)
        static_ipv4_gateway=$(printf '%s' "$STATIC_IPV4_CONFIG" | cut -d ',' -f 2)
        static_ipv6_addr=$(printf '%s' "$STATIC_IPV6_CONFIG" | cut -d ',' -f 1)
        static_ipv6_gateway=$(printf '%s' "$STATIC_IPV6_CONFIG" | cut -d ',' -f 2)
        if [ -z "$NIC_NAME" ]; then
            local iface_path
            for iface_path in /sys/class/net/*; do
                case "${iface_path##*/}" in
                    docker0|lo|wg0) ;;
                    *) NIC_NAME="${iface_path##*/}"; break ;;
                esac
            done
        fi
        local netplan_list=(
            "network:"
            "  version: 2"
            "  renderer: NetworkManager"
            "  ethernets:"
            "    ${NIC_NAME}:"
        )
        if [ -n "$static_ipv4_addr" ]; then
            netplan_list+=("      dhcp4: false")
        else
            netplan_list+=("      dhcp4: true")
        fi
        if [ -n "$static_ipv6_addr" ]; then
            netplan_list+=("      dhcp6: false")
        else
            netplan_list+=("      dhcp6: true")
        fi
        if [ -n "$static_ipv4_addr" ] || [ -n "$static_ipv6_addr" ]; then
            netplan_list+=("      addresses:")
            if [ -n "$static_ipv4_addr" ]; then
                netplan_list+=("        - ${static_ipv4_addr}")
            fi
            if [ -n "$static_ipv6_addr" ]; then
                netplan_list+=("        - ${static_ipv6_addr}")
            fi
        fi
        if [ -n "$static_ipv4_gateway" ] || [ -n "$static_ipv6_gateway" ]; then
            netplan_list+=("      routes:")
            if [ -n "$static_ipv4_gateway" ]; then
                netplan_list+=("        - to: 0.0.0.0/0")
                netplan_list+=("          via: ${static_ipv4_gateway}")
            fi
            if [ -n "$static_ipv6_gateway" ]; then
                netplan_list+=("        - to: ::/0")
                netplan_list+=("          via: ${static_ipv6_gateway}")
            fi
        fi
        mkdir -p /etc/netplan
        rm -f /etc/netplan/*.yaml
        printf '%s\n' "${netplan_list[@]}" > "/etc/netplan/netplan.yaml"
        chmod 600 "/etc/netplan/netplan.yaml"
        netplan apply
    }
    ConfigureResolved() {
        if HaveCommand resolvectl; then
            local resolved_list=(
                "[Resolve]"
                "DNS=${DNS_LINE}"
                "DNSOverTLS=opportunistic"
                "DNSSEC=allow-downgrade"
                "DNSStubListener=false"
                "Domains=${NEW_DOMAIN[*]}"
            )
            mkdir -p "/etc/systemd/resolved.conf.d"
            rm -f /etc/systemd/resolved.conf.d/*.conf
            printf '%s\n' "${resolved_list[@]}" > "/etc/systemd/resolved.conf.d/resolved.conf"
            systemctl restart systemd-resolved
            chattr -i /etc/resolv.conf > /dev/null 2>&1 || true
            rm -f /etc/resolv.conf
            ln -s "/run/systemd/resolve/resolv.conf" "/etc/resolv.conf"
        else
            WriteResolvConf
            chattr +i /etc/resolv.conf
        fi
    }
    ConfigureSystemd() {
        systemctl disable systemd-networkd-wait-online > /dev/null 2>&1 || true
    }
    ConfigureUfw() {
        HaveCommand ufw || return 0
        [ -f "/etc/default/ufw" ] || return 0
        sed -i -E \
            -e 's/DEFAULT_APPLICATION_POLICY="(ACCEPT|DROP|SKIP)"/DEFAULT_APPLICATION_POLICY="REJECT"/g' \
            -e 's/DEFAULT_FORWARD_POLICY="(DROP|REJECT)"/DEFAULT_FORWARD_POLICY="ACCEPT"/g' \
            -e 's/DEFAULT_INPUT_POLICY="(ACCEPT|DROP)"/DEFAULT_INPUT_POLICY="REJECT"/g' \
            -e 's/DEFAULT_OUTPUT_POLICY="(DROP|REJECT)"/DEFAULT_OUTPUT_POLICY="ACCEPT"/g' \
            -e 's/MANAGE_BUILTINS=yes/MANAGE_BUILTINS=no/g' \
            -e 's/IPV6=no/IPV6=yes/g' \
            "/etc/default/ufw"
        ufw --force reset
        ufw allow 123/udp
        ufw allow 161/udp
        ufw limit ${SSH_PORT}/tcp
        ufw allow ${COCKPIT_PORT}/tcp # cockpit web UI
        ufw allow 323/udp
        ufw allow 3493/tcp
        ufw allow 51820/udp
        ufw allow in on wg0
        ufw --force enable
        ufw status verbose
    }
    ConfigureWireGuard() {
        HaveCommand wg || return 0
        mkdir -p "/etc/wireguard"
        rm -f /etc/wireguard/*
        GenerateWireGuardConfig
        chown -R "${DEFAULT_USERNAME}:sudo" "/etc/wireguard"
        chmod -R 775 "/etc/wireguard"
        chown "${DEFAULT_USERNAME}:${DEFAULT_USERNAME}" "/etc/wireguard/wg0.conf"
        chmod 600 "/etc/wireguard/wg0.conf"
        systemctl enable wg-quick@wg0
        if [ -f "/lib/systemd/system/wg-quick@.service" ]; then
            if [ ! -f "/lib/systemd/system/wg-quick@.service.bak" ]; then
                cp "/lib/systemd/system/wg-quick@.service" "/lib/systemd/system/wg-quick@.service.bak"
            fi
            sed -E \
                -e 's/RemainAfterExit=yes/RemainAfterExit=yes\nRestartSec=5\nRestart=always/g' \
                -e 's/^Type=oneshot/#Type=oneshot/g' \
                "/lib/systemd/system/wg-quick@.service.bak" > "/lib/systemd/system/wg-quick@.service"
            systemctl daemon-reload
        fi
        systemctl start wg-quick@wg0
        wg
    }

    APT_PREFERENCES=(
        "${LSB_CODENAME}-backports 990"
        "${LSB_CODENAME}-security 500"
        "${LSB_CODENAME}-updates 500"
        "${LSB_CODENAME} 500"
        "${LSB_CODENAME}-proposed 100"
    )
    FAIL2BAN_BANACTION="ufw"
    FAIL2BAN_FILTER_NAME="cockpit"
    FAIL2BAN_FILTER=(
        "[Definition]"
        "failregex = ^\s*(?:\S+\s+)?(?:cockpit\[\d+\]: )?pam_unix\(cockpit:auth\): authentication failure;.*rhost=<HOST>"
        "journalmatch = _SYSTEMD_UNIT=cockpit.service"
    )
    FAIL2BAN_JAILS=(
        "[sshd]"
        "bantime = 604800"
        "enabled = true"
        "filter = sshd"
        "findtime = 60"
        "logpath = /var/log/auth.log"
        "maxretry = 5"
        "port = ${SSH_PORT}"
        "[cockpit]"
        "backend = systemd"
        "bantime = 604800"
        "enabled = true"
        "filter = cockpit"
        "findtime = 60"
        "maxretry = 5"
        "port = ${COCKPIT_PORT}"
    )
    MODULE_LIST_EXTRA=()
    SYSCTL_INTERFACE_MODE="exclude"
    SYSCTL_INTERFACE_PATTERN='^(docker0|lo|wg0)$'
    DOCKER_APT_DISTRO="ubuntu"
    FRR_APT_LINE="deb [arch=${OS_ARCHITECTURE} signed-by=/usr/share/keyrings/frrouting-archive-keyring.gpg] https://deb.frrouting.org/frr stable frr-stable"
    FRR_EXTRA_PACKAGES=("frr-rpki-rtrlib")
    SetDebianGlobals

    RunStep "ConfigureAPT" ConfigureAPT
    RunStep "ConfigureBusybox" ConfigureBusybox
    RunStep "ConfigureChrony" ConfigureChrony
    RunStep "ConfigureCloudflareWARP" ConfigureCloudflareWARP
    RunStep "ConfigureCockpit" ConfigureCockpit
    RunStep "ConfigureCrontab" ConfigureCrontab
    RunStep "ConfigureCrowdSec" ConfigureCrowdSec
    RunStep "ConfigureDockerEngine" ConfigureDockerEngine
    RunStep "ConfigureFail2Ban" ConfigureFail2Ban
    RunStep "ConfigureFRRouting" ConfigureFRRouting
    RunStep "ConfigureGPG" ConfigureGPG
    RunStep "ConfigureGit" ConfigureGit
    RunStep "ConfigureGrub" ConfigureGrub
    RunStep "ConfigureLandscape" ConfigureLandscape
    RunStep "ConfigureLLDPD" ConfigureLLDPD
    RunStep "ConfigureModules" ConfigureModules
    RunStep "ConfigureNetplan" ConfigureNetplan
    RunStep "ConfigureNut" ConfigureNut
    RunStep "ConfigureOpenSSH" ConfigureOpenSSH
    RunStep "ConfigurePostfix" ConfigurePostfix
    RunStep "ConfigureProxyChains" ConfigureProxyChains
    RunStep "ConfigurePythonPyPI" ConfigurePythonPyPI
    RunStep "ConfigureResolved" ConfigureResolved
    RunStep "ConfigureSNMP" ConfigureSNMPBase
    RunStep "ConfigureSshd" ConfigureSshd
    RunStep "ConfigureSysctl" ConfigureSysctl
    RunStep "ConfigureSystemd" ConfigureSystemd
    RunStep "ConfigureTuned" ConfigureTuned
    RunStep "ConfigureUfw" ConfigureUfw
    RunStep "ConfigureWireGuard" ConfigureWireGuard
    RunStep "ConfigureZsh" ConfigureZsh
}

# Configure System
ConfigureSystem() {
    ConfigureHostfile() {
        WriteHostfile "127.0.1.1 ${NEW_HOSTNAME}"
    }
    ConfigureLocales() {
        apt purge -qy locales
        apt update
        apt install -qy locales
        locale-gen "en_US.UTF-8"
        update-locale "en_US.UTF-8"
    }
    ConfigureSWAP() {
        CreateSWAP() {
            local ram_mb
            ram_mb=$(free -m | awk '/^Mem:/ {print $2}')
            SWAP_SIZE=$(ComputeSwapSize "$ram_mb")
            truncate -s 0 "/swapfile"
            if [ "$(stat -f -c %T "/swapfile" 2>/dev/null)" = "btrfs" ]; then
                chattr +C "/swapfile"
            fi
            fallocate -l "${SWAP_SIZE}M" "/swapfile"
            chmod 600 "/swapfile"
            mkswap "/swapfile"
            swapon "/swapfile"
        }
        RemoveSWAP() {
            local swapfile
            while IFS= read -r swapfile; do
                swapoff "$swapfile" > /dev/null 2>&1 || true
                rm -f "$swapfile"
            done < <(awk 'NR>1 {print $1}' /proc/swaps)
        }
        UpdateFSTAB() {
            sed -i '/swap/d' /etc/fstab
            if [ -f "/swapfile" ] && [ "$DISABLE_SWAP" = "false" ]; then
                printf '%s\n' "/swapfile none swap sw 0 0" >> "/etc/fstab"
            fi
        }
        ClearSWAP
        RemoveSWAP
        if [ "$DISABLE_SWAP" = "false" ]; then
            CreateSWAP
        fi
        CreateZRamSWAP
        UpdateFSTAB
    }
    ConfigureTimeZone() {
        rm -f "/etc/localtime"
        ln -s "/usr/share/zoneinfo/Asia/Shanghai" "/etc/localtime"
    }
    RunStep "ConfigureDefaultShell" ConfigureDefaultShell
    RunStep "ConfigureDefaultUser" ConfigureDefaultUser
    RunStep "ConfigureGAI" ConfigureGAI
    RunStep "ConfigureHostfile" ConfigureHostfile
    RunStep "ConfigureLocales" ConfigureLocales
    RunStep "ConfigureRootUser" ConfigureRootUser
    RunStep "ConfigureSWAP" ConfigureSWAP
    RunStep "ConfigureTimeZone" ConfigureTimeZone
}

# Install Custom Packages
InstallCustomPackages() {
    InstallCloudflareWARP() {
        [ "$INSTALL_CLOUDFLARE_WARP" = "true" ] || { LogInfo "INSTALL_CLOUDFLARE_WARP=false - skipped"; return 0; }
        InstallAptRepo "cloudflare-warp" "https://pkg.cloudflareclient.com/pubkey.gpg" \
            "deb [arch=${OS_ARCHITECTURE} signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com ${LSB_CODENAME} main"
        InstallAptPackages "cloudflare-warp"
    }
    InstallTor() {
        [ "$INSTALL_TOR" = "true" ] || { LogInfo "INSTALL_TOR=false - skipped"; return 0; }
        InstallAptRepo "tor" "https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc" \
            "deb [arch=${OS_ARCHITECTURE} signed-by=/usr/share/keyrings/tor-archive-keyring.gpg] https://deb.torproject.org/torproject.org stable main"
        InstallAptPackages "tor"
    }
    InstallXanModKernel() {
        # Note: NVIDIA, OpenZFS, VirtualBox, VMware and some other dkms modules
        # may not officially support EDGE and RT branch kernels.
        local branch="$XANMOD_BRANCH"
        # psABI v1 (legacy) CPUs are covered only by the LTS branch - main,
        # edge and rt publish x64v2/v3 packages only.
        if [ "$PSABI_LEVEL" = "1" ] && [ "$branch" != "lts" ]; then
            branch="lts"
        fi
        # no kernel benefit beyond v3
        local level="$PSABI_LEVEL"
        if [ "$level" = "4" ]; then
            level="3"
        fi
        # XanMod publishes amd64 packages only - the repo is added just when
        # a xanmod kernel will actually be installed; everything else stays
        # on the stock Ubuntu kernel (arm64 uses linux-generic: the HWE
        # kernels are amd64-only).
        if [ "$OS_ARCHITECTURE" = "amd64" ] && [ "$level" != "0" ] && [ "$branch" != "disable" ]; then
            local suffix=""
            if [ "$branch" != "main" ]; then
                suffix="${branch}-"
            fi
            InstallAptRepo "xanmod" "https://dl.xanmod.org/archive.key" \
                "deb [arch=amd64 signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] https://deb.xanmod.org ${LSB_CODENAME} main non-free"
            InstallAptPackages "linux-xanmod-${suffix}x64v${level}"
        elif [ "$OS_ARCHITECTURE" = "amd64" ]; then
            InstallAptPackages "linux-generic-hwe-${LSB_VERSION}"
        else
            InstallAptPackages "linux-generic"
        fi
    }
    OMZ_HOME="/home/${DEFAULT_USERNAME}"
    OMZ_OWNER="${DEFAULT_USERNAME}:${DEFAULT_USERNAME}"
    RunStep "InstallCloudflareWARP" InstallCloudflareWARP
    RunStep "InstallCrowdSec" InstallCrowdSec
    RunStep "InstallDockerEngine" InstallDockerEngine
    RunStep "InstallFRRouting" InstallFRRouting
    RunStep "InstallOhMyZsh" InstallOhMyZsh
    RunStep "InstallTor" InstallTor
    RunStep "InstallXanModKernel" InstallXanModKernel
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
RunStep "CleanupTempFiles" CleanupTempFiles /etc/ufw/*."$(date '+%Y%m%d')"*
# Call CleanupOutageKernels
KERNEL_PATTERN='(linux-image)-[0-9].*'
RunStep "CleanupOutageKernels" CleanupOutageKernels
RenderProgress "complete"
