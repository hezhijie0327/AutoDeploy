## Function
# Get System Information
function GetSystemInformation() {
    # Identity, credentials and release pinning live in the Configuration block.
    DEFAULT_FULLNAME="${DEFAULT_LASTNAME} ${DEFAULT_FIRSTNAME}"

    function CheckMachineEnvironment() {
        function CheckHypervisorEnvironment() {
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
    function GetCPUpsABILevel() {
        # https://dl.xanmod.org/check_x86-64_psabi.sh
        PSABI_LEVEL=$(awk 'BEGIN{while(!/flags/)if(getline<"/proc/cpuinfo"!=1)exit 0;if(/lm/&&/cmov/&&/cx8/&&/fpu/&&/fxsr/&&/mmx/&&/syscall/&&/sse2/)l=1;if(l==1&&/cx16/&&/lahf/&&/popcnt/&&/sse4_1/&&/sse4_2/&&/ssse3/)l=2;if(l==2&&/avx/&&/avx2/&&/bmi1/&&/bmi2/&&/f16c/&&/fma/&&/abm/&&/movbe/&&/xsave/)l=3;if(l==3&&/avx512f/&&/avx512bw/&&/avx512cd/&&/avx512dq/&&/avx512vl/)l=4;print l}')
    }
    function GetOSArchitecture() {
        if HaveCommand dpkg; then
            OS_ARCHITECTURE=$(dpkg --print-architecture)
        else
            case "$(uname -m)" in
                aarch64) OS_ARCHITECTURE="arm64" ;;
                x86_64) OS_ARCHITECTURE="amd64" ;;
            esac
        fi
        case "${OS_ARCHITECTURE:-}" in
            arm64) MIRROR_URL="ubuntu-ports" ;;
            amd64) MIRROR_URL="ubuntu" ;;
            *) Die "Unsupported architecture." ;;
        esac
    }
    CollectDNS
    GenerateDomain
    CheckMachineEnvironment
    GenerateHostname
    GetCPUpsABILevel
    GetCPUVendorID
    GetOSArchitecture
    SetGHProxyDomain
}

# Set Repository Mirror
function SetRepositoryMirror() {
    local mirror_list=(
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${MIRROR_URL} ${LSB_CODENAME} main multiverse restricted universe"
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${MIRROR_URL} ${LSB_CODENAME}-backports main multiverse restricted universe"
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${MIRROR_URL} ${LSB_CODENAME}-proposed main multiverse restricted universe"
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${MIRROR_URL} ${LSB_CODENAME}-security main multiverse restricted universe"
        "deb ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${MIRROR_URL} ${LSB_CODENAME}-updates main multiverse restricted universe"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${MIRROR_URL} ${LSB_CODENAME} main multiverse restricted universe"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${MIRROR_URL} ${LSB_CODENAME}-backports main multiverse restricted universe"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${MIRROR_URL} ${LSB_CODENAME}-proposed main multiverse restricted universe"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${MIRROR_URL} ${LSB_CODENAME}-security main multiverse restricted universe"
        "deb-src ${TRANSPORT_PROTOCOL}://mirrors.cernet.edu.cn/${MIRROR_URL} ${LSB_CODENAME}-updates main multiverse restricted universe"
    )
    if [ ! -d "/etc/apt/sources.list.d" ]; then
        mkdir "/etc/apt/sources.list.d"
    else
        rm -f /etc/apt/sources.list.d/*.*
    fi
    printf '%s\n' "${mirror_list[@]}" > "/etc/apt/sources.list"
}

# Configure Packages
function ConfigurePackages() {
    function ConfigureCloudflareWARP() {
        # Get token from `https://<YOUR_TEAM_NAME>.cloudflareaccess.com/warp`
        # Login via `warp-cli registration token 'com.cloudflare.warp://<your-team-name>.cloudflareaccess.com/auth?token=<your-token>'`
        HaveCommand warp-cli || return 0
        ufw allow in on CloudflareWARP
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
    function ConfigureLandscape() {
        [ -f "/usr/lib/python3/dist-packages/landscape/lib/network.py" ] || return 0
        sed -i 's/tostring/tobytes/g' "/usr/lib/python3/dist-packages/landscape/lib/network.py"
    }
    function ConfigureNetplan() {
        HaveCommand netplan || return 0
        NIC_NAME="${NIC_NAME:-}" # enp6s18 / ens18
        STATIC_IPV4_CONFIG="${STATIC_IPV4_CONFIG:-}" # 10.192.31.254/19,10.192.0.1
        STATIC_IPV6_CONFIG="${STATIC_IPV6_CONFIG:-}" # 2409:8a20:8800::254/64,2409:8a20:8800::1
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
    function ConfigureResolved() {
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
    function ConfigureSystemd() {
        systemctl disable systemd-networkd-wait-online > /dev/null 2>&1 || true
    }
    function ConfigureUfw() {
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
        ufw reload
        ufw --force reset
        ufw allow 123/udp
        ufw allow 161/udp
        ufw limit 22/tcp
        ufw allow 323/udp
        ufw allow 3493/tcp
        ufw allow 51820/udp
        ufw allow in on wg0
        ufw --force enable
        ufw status verbose
    }
    function ConfigureWireGuard() {
        HaveCommand wg || return 0
        if [ ! -d "/etc/wireguard" ]; then
            mkdir "/etc/wireguard"
        else
            rm -f /etc/wireguard/*
        fi
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
    FAIL2BAN_JAILS=(
        "[sshd]"
        "bantime = 604800"
        "enabled = true"
        "filter = sshd"
        "findtime = 60"
        "logpath = /var/log/auth.log"
        "maxretry = 5"
        "port = 22"
    )
    MODULE_LIST_EXTRA=()
    SYSCTL_INTERFACE_MODE="exclude"
    SYSCTL_INTERFACE_PATTERN='^(docker0|lo|wg0)$'
    PROXYCHAINS_CONF="/etc/proxychains4.conf"
    GPG_HOME="/home/${DEFAULT_USERNAME}/.gnupg"
    GPG_KEYSERVER="hkps://keyserver.ubuntu.com:443"
    GPG_PINENTRY="/usr/bin/pinentry-tty"
    GPG_HOME_OWNER="${DEFAULT_USERNAME}:${DEFAULT_USERNAME}"
    ZSH_HOME="/home/${DEFAULT_USERNAME}"
    ZSH_OWNER="${DEFAULT_USERNAME}:${DEFAULT_USERNAME}"
    ZSH_PATH_LIST=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/usr/local/bin" "/usr/local/sbin")
    ZSH_EXTRA_EXPORTS=("export DEBIAN_FRONTEND=\"noninteractive\"")
    ZSH_TRAPEXIT="false"

    RunStep "ConfigureAPT" ConfigureAPT
    RunStep "ConfigureBusybox" ConfigureBusybox
    RunStep "ConfigureChrony" ConfigureChrony
    RunStep "ConfigureCloudflareWARP" ConfigureCloudflareWARP
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
    RunStep "ConfigureSshd" ConfigureSshd
    RunStep "ConfigureSysctl" ConfigureSysctl
    RunStep "ConfigureSystemd" ConfigureSystemd
    RunStep "ConfigureTuned" ConfigureTuned
    RunStep "ConfigureUfw" ConfigureUfw
    RunStep "ConfigureWireGuard" ConfigureWireGuard
    RunStep "ConfigureZsh" ConfigureZsh
}

# Configure System
function ConfigureSystem() {
    function ConfigureDefaultUser() {
        WarnDefaultPassword "DEFAULT_PASSWORD" "$DEFAULT_PASSWORD" '*Ubuntu123*'
        PURGE_OTHER_USERS="${PURGE_OTHER_USERS:-true}"
        if [ "$PURGE_OTHER_USERS" = "true" ]; then
            LogWarn "PURGE_OTHER_USERS=true: removing every other user under /home (set PURGE_OTHER_USERS=false to keep them)"
            local home_dir user
            for home_dir in /home/*; do
                if [ -d "$home_dir" ]; then
                    user="${home_dir##*/}"
                    if [ "$user" != "$DEFAULT_USERNAME" ]; then
                        userdel -rf "$user" > /dev/null 2>&1 || true
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
    }
    function ConfigureHostfile() {
        ComputeFullDomain
        local host_list=(
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
        printf '%s\n' "${host_list[@]}" > "/etc/hosts"
        printf '%s\n' "$NEW_HOSTNAME" > "/etc/hostname"
        hostnamectl set-hostname "$NEW_HOSTNAME"
    }
    function ConfigureLocales() {
        apt purge -qy locales
        apt update
        apt install -qy locales
        locale-gen "en_US.UTF-8"
        update-locale "en_US.UTF-8"
    }
    function ConfigureSWAP() {
        function ClearSWAP() {
            HaveCommand sysctl || return 0
            sync
            sysctl -w vm.drop_caches=3 vm.overcommit_memory=0 vm.swappiness=0
        }
        function CreateSWAP() {
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
        function CreateZRamSWAP() {
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
                rm -f "$swapfile"
            done < <(awk 'NR>1 {print $1}' /proc/swaps)
        }
        function UpdateFSTAB() {
            grep -v "swap" /etc/fstab > "/tmp/fstab.autodeploy" || true
            if [ -f "/swapfile" ] && [ "$DISABLE_SWAP" = "false" ]; then
                printf '%s\n' "/swapfile none swap sw 0 0" >> "/tmp/fstab.autodeploy"
            fi
            cat "/tmp/fstab.autodeploy" > "/etc/fstab"
            rm -f "/tmp/fstab.autodeploy"
        }
        DISABLE_SWAP="${DISABLE_SWAP:-false}"
        ClearSWAP
        RemoveSWAP
        if [ "$DISABLE_SWAP" = "false" ]; then
            CreateSWAP
        fi
        CreateZRamSWAP
        UpdateFSTAB
    }
    function ConfigureTimeZone() {
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
function InstallCustomPackages() {
    function InstallCloudflareWARP() {
        InstallAptRepo "cloudflare-warp" "https://pkg.cloudflareclient.com/pubkey.gpg" \
            "deb [arch=${OS_ARCHITECTURE} signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com ${LSB_CODENAME} main"
        InstallAptPackages "cloudflare-warp"
    }
    function InstallCrowdSec() {
        InstallAptRepo "crowdsec" "https://packagecloud.io/crowdsec/crowdsec/gpgkey" \
            "deb [arch=${OS_ARCHITECTURE} signed-by=/usr/share/keyrings/crowdsec-archive-keyring.gpg] https://packagecloud.io/crowdsec/crowdsec/any any main
deb-src [arch=${OS_ARCHITECTURE} signed-by=/usr/share/keyrings/crowdsec-archive-keyring.gpg] https://packagecloud.io/crowdsec/crowdsec/any any main"
        if HaveCommand cscli; then
            local bouncer
            while IFS= read -r bouncer; do
                cscli bouncers delete "$bouncer"
            done < <(cscli bouncers list | grep 'FirewallBouncer' | awk '{print $1}' || true)
        fi
        InstallAptPackages "crowdsec" "crowdsec-firewall-bouncer-nftables"
    }
    function InstallDockerEngine() {
        InstallAptRepo "docker" "https://mirrors.cernet.edu.cn/docker-ce/linux/ubuntu/gpg" \
            "deb [arch=${OS_ARCHITECTURE} signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://mirrors.cernet.edu.cn/docker-ce/linux/ubuntu ${LSB_CODENAME} stable"
        apt update
        apt purge -qy containerd docker-compose docker-doc docker.io podman-docker runc || true
        InstallAptPackages "containerd.io" "docker-buildx-plugin" "docker-ce" "docker-ce-cli" "docker-compose-plugin"
    }
    function InstallFRRouting() {
        InstallAptRepo "frrouting" "https://deb.frrouting.org/frr/keys.gpg" \
            "deb [arch=${OS_ARCHITECTURE} signed-by=/usr/share/keyrings/frrouting-archive-keyring.gpg] https://deb.frrouting.org/frr stable frr-stable"
        InstallAptPackages "frr" "frr-pythontools" "frr-rpki-rtrlib" "frr-snmp"
    }
    function InstallTor() {
        InstallAptRepo "tor" "https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc" \
            "deb [arch=${OS_ARCHITECTURE} signed-by=/usr/share/keyrings/tor-archive-keyring.gpg] https://deb.torproject.org/torproject.org stable main"
        InstallAptPackages "tor"
    }
    function InstallXanModKernel() {
        # Note: NVIDIA, OpenZFS, VirtualBox, VMware and some other dkms modules
        # may not officially support EDGE and RT branch kernels.
        XANMOD_BRANCH="${XANMOD_BRANCH:-edge}" # disable | main | edge | lts | rt
        local branch="$XANMOD_BRANCH"
        # psABI v1 CPUs cannot run edge/rt builds (compare before suffixing!)
        if [ "$PSABI_LEVEL" = "1" ] && { [ "$branch" = "edge" ] || [ "$branch" = "rt" ]; }; then
            branch="main"
        fi
        # no kernel benefit beyond v3
        local level="$PSABI_LEVEL"
        if [ "$level" = "4" ]; then
            level="3"
        fi
        local apt_list=()
        if [ "$OS_ARCHITECTURE" = "amd64" ] && [ "$level" != "0" ] && [ "$branch" != "disable" ]; then
            local suffix=""
            if [ "$branch" != "main" ]; then
                suffix="${branch}-"
            fi
            apt_list=("linux-xanmod-${suffix}x64v${level}")
        else
            apt_list=("linux-generic-hwe-${LSB_VERSION}")
        fi
        InstallAptRepo "xanmod" "https://dl.xanmod.org/archive.key" \
            "deb [arch=${OS_ARCHITECTURE} signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] https://deb.xanmod.org ${LSB_CODENAME} main non-free"
        InstallAptPackages "${apt_list[@]}"
    }
    OMZ_HOME="/home/${DEFAULT_USERNAME}"
    OMZ_OWNER="${DEFAULT_USERNAME}:${DEFAULT_USERNAME}"
    #RunStep "InstallCloudflareWARP" InstallCloudflareWARP
    RunStep "InstallCrowdSec" InstallCrowdSec
    RunStep "InstallDockerEngine" InstallDockerEngine
    RunStep "InstallFRRouting" InstallFRRouting
    RunStep "InstallOhMyZsh" InstallOhMyZsh
    #RunStep "InstallTor" InstallTor
    RunStep "InstallXanModKernel" InstallXanModKernel
}

# Install Dependency Packages
function InstallDependencyPackages() {
    local apt_list=("${DEPENDENCY_PACKAGES[@]}")
    apt_list+=(${HYPERVISOR_AGENT[@]+"${HYPERVISOR_AGENT[@]}"} ${MICROCODE[@]+"${MICROCODE[@]}"})
    # Purge guest agents that do not belong to the detected hypervisor.
    local hypervisor_agent_list=("ksmtuned" "open-vm-tools" "qemu-guest-agent" "virtualbox-guest-dkms")
    local agent wanted keep
    for agent in "${hypervisor_agent_list[@]}"; do
        keep="false"
        for wanted in ${HYPERVISOR_AGENT[@]+"${HYPERVISOR_AGENT[@]}"}; do
            if [ "$agent" = "$wanted" ]; then
                keep="true"
            fi
        done
        if [ "$keep" = "false" ] && dpkg -l "$agent" 2>/dev/null | grep -q '^ii'; then
            apt purge -qy "$agent"
            apt autoremove -qy --purge
        fi
    done
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
RunStep "CleanupTempFiles" CleanupTempFiles /etc/ufw/*."$(date '+%Y%m%d')"*
# Call CleanupOutageKernels
KERNEL_PATTERN='(linux-image)-[0-9].*'
RunStep "CleanupOutageKernels" CleanupOutageKernels
RenderProgress "complete"
