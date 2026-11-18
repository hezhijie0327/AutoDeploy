# ============================================================================
# modules/debian/system.sh - system information gathering for Debian family
# (Ubuntu / Proxmox VE, bash 4.4+)
# Sets: NEW_DOMAIN, NEW_HOSTNAME, OLD_HOSTNAME, CURRENT_DNS, DNS_SERVERS,
# DNS_LINE, CPU_VENDOR_ID, ENABLE_IOMMU, MICROCODE,
# INTEL_GVT_MODULES, INTEL_HDMI_AUDIO_MODULE, NESTED_MODULES,
# OS_ARCHITECTURE, plus the Debian structural globals via SetDebianGlobals.
# ============================================================================

GenerateDomain() {
    RESET_DOMAIN="${RESET_DOMAIN:-false}"
    NEW_DOMAIN=()
    if [ -n "${CUSTOM_DOMAIN:-}" ]; then
        read -r -a NEW_DOMAIN <<< "$CUSTOM_DOMAIN"
        return 0
    fi
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

# Sets NEW_HOSTNAME (CUSTOM_HOSTNAME > hostname file > hostname command >
# HOSTNAME_PREFIX timestamp) and OLD_HOSTNAME (original hostname, used by the
# Proxmox VE node rename step).
GenerateHostname() {
    RESET_HOSTNAME="${RESET_HOSTNAME:-false}"
    OLD_HOSTNAME=""
    if [ -f "${HOSTNAME_FILE:-/etc/hostname}" ]; then
        OLD_HOSTNAME=$(awk '{print $1; exit}' "${HOSTNAME_FILE:-/etc/hostname}")
    fi
    if [ -z "$OLD_HOSTNAME" ] && HaveCommand hostname; then
        OLD_HOSTNAME=$(hostname)
    fi
    NEW_HOSTNAME=""
    if [ -n "${CUSTOM_HOSTNAME:-}" ]; then
        NEW_HOSTNAME="$CUSTOM_HOSTNAME"
        return 0
    fi
    NEW_HOSTNAME="$OLD_HOSTNAME"
    if [ -z "$NEW_HOSTNAME" ] || [ "$RESET_HOSTNAME" = "true" ]; then
        NEW_HOSTNAME="${HOSTNAME_PREFIX}-$(date '+%Y%m%d%H%M%S')"
    fi
}

# Parses CUSTOM_DNS and collects the nameservers still in use. Sets
# DNS_SERVERS / CURRENT_DNS / DNS_LINE (first three, space joined).
CollectDNS() {
    read -r -a DNS_SERVERS <<< "$CUSTOM_DNS"
    CURRENT_DNS=()
    local resolv_conf="${RESOLV_CONF:-/etc/resolv.conf}" ns
    if [ -f "$resolv_conf" ]; then
        while IFS= read -r ns; do
            case " ${DNS_SERVERS[*]} 127.0.0.53 " in
                *" ${ns} "*) ;;
                *) CURRENT_DNS+=("$ns") ;;
            esac
        done < <(awk '/^nameserver/ {print $2}' "$resolv_conf")
    fi
    DNS_LINE=$(printf '%s\n' ${CURRENT_DNS[@]+"${CURRENT_DNS[@]}"} "${DNS_SERVERS[@]}" | head -n 3 | tr '\n' ' ')
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
    resolv_conf_list+=("${DNS_SERVERS[@]}")
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

GetOSArchitecture() {
    if HaveCommand dpkg; then
        OS_ARCHITECTURE=$(dpkg --print-architecture)
    else
        case "$(uname -m)" in
            aarch64) OS_ARCHITECTURE="arm64" ;;
            x86_64) OS_ARCHITECTURE="amd64" ;;
        esac
    fi
    case "${OS_ARCHITECTURE:-}" in
        amd64|arm64) ;;
        *) Die "Unsupported architecture." ;;
    esac
}

# Structural globals shared by both Debian platforms; platform ConfigurePackages
# blocks may override any of them (e.g. Proxmox VE extends ZSH_PATH_LIST).
SetDebianGlobals() {
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
}
