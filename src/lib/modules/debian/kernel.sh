# ============================================================================
# modules/debian/kernel.sh - kernel modules, sysctl tuning and scheduler
# (Ubuntu / Proxmox VE, bash 4.4+)
# ConfigureModules needs CPU_VENDOR_ID, ENABLE_IOMMU, INTEL_GVT_MODULES,
# INTEL_HDMI_AUDIO_MODULE, NESTED_MODULES and MODULE_LIST_EXTRA (may be empty).
# ConfigureSysctl needs SYSCTL_INTERFACE_MODE (include|exclude) and
# SYSCTL_INTERFACE_PATTERN, plus the DISABLE_ICMP_ECHO switch.
# ============================================================================

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
