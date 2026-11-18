# ============================================================================
# modules/debian/storage.sh - swap helpers for Debian family
# (Ubuntu / Proxmox VE, bash 4.4+)
# Platform ConfigureSWAP orchestrators combine these with their own
# CreateSWAP / RemoveSWAP / UpdateFSTAB variants (swapfile vs LVM).
# ============================================================================

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

ClearSWAP() {
    HaveCommand sysctl || return 0
    sync
    sysctl -w vm.drop_caches=3 vm.overcommit_memory=0 vm.swappiness=0
}

# zram-generator config shared by both platforms (always-on compressed swap).
CreateZRamSWAP() {
    local zram_conf_list=(
        "[zram0]"
        "compression-algorithm = zstd"
        "zram-size = min(ram / 2, 8192)"
    )
    rm -rf "/etc/systemd/zram-generator.conf.d"
    mkdir -p "/etc/systemd/zram-generator.conf.d"
    printf '%s\n' "${zram_conf_list[@]}" > "/etc/systemd/zram-generator.conf.d/zram.conf"
}
