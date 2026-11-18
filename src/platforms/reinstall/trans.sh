#!/bin/sh
# ============================================================================
# AutoDeploy Ubuntu reinstall - phase 2 (installer).
# Runs inside the Alpine RAM system after the reboot staged by
# dist/Reinstall.sh. Written for busybox ash: no arrays, no [[ ]], no process
# substitution. All upstream fetches use http on purpose - the installer
# environment may not have a synced clock, which breaks TLS certificate
# validation.
#
# Kernel cmdline contract (set by dist/Reinstall.sh):
#   extra_img=      Ubuntu server cloud image (.img, qcow2) URL
#   extra_repo=     Alpine main repository URL (apk packages)
#   extra_mac=      management NIC MAC (replayed into netplan)
#   extra_iface=    management NIC name (kept via netplan set-name)
#   extra_ipv4=     current IPv4 as addr/prefix; missing -> dhcp4
#   extra_ipv4_gw=  IPv4 default gateway
#   extra_ipv6=     current IPv6 as addr/prefix; missing -> SLAAC
#   extra_ipv6_gw=  IPv6 default gateway
#   extra_dns=      comma-separated resolvers
#   extra_disk=     partition-table UUID (PTUUID) of the boot disk
#   extra_efi=      1 when the host booted via UEFI
#   extra_arch=     amd64 | arm64
#   extra_codename= Ubuntu codename (apt mirror rewrite)
#   extra_partsize= installer staging partition size in MiB
# /configs (baked into the initramfs) carries password / ssh_keys.
# ============================================================================

CMDLINE="$(cat /proc/cmdline)"
DONE_BANNER=""

log() {
    printf '[Reinstall] %s\n' "$*"
}

die() {
    printf '[Reinstall] ERROR: %s\n' "$*" >&2
    exit 1
}

# Read an extra_* cmdline parameter (optionally with a fallback value).
get_extra() {
    key="$1"
    fallback="${2:-}"
    value=""
    for token in $CMDLINE; do
        case "$token" in
            "extra_${key}="*) value="${token#extra_${key}=}" ;;
        esac
    done
    if [ -n "$value" ]; then
        printf '%s\n' "$value"
    else
        printf '%s\n' "$fallback"
    fi
}

# Mount and inspect a partition; echoes "root" / "boot" / "efi" / "".
probe_image_partition() {
    part="$1"
    probe_fstype=$(blkid -s TYPE -o value "$part" 2> /dev/null || true)
    mkdir -p /img
    if ! mount -o ro "$part" /img 2> /dev/null; then
        printf '\n'
        return 0
    fi
    if [ "$probe_fstype" = "vfat" ] && [ -d /img/EFI ]; then
        printf 'efi\n'
    elif [ -f /img/etc/os-release ]; then
        printf 'root\n'
    elif ls /img/vmlinuz* > /dev/null 2>&1 || [ -d /img/grub ]; then
        printf 'boot\n'
    fi
    umount /img
}

## Network
setup_network() {
    # resolv.conf first so wget can resolve the mirrors.
    : > /etc/resolv.conf
    dns_list=$(get_extra dns "223.5.5.5,223.6.6.6")
    old_ifs=$IFS
    IFS=,
    for ns in $dns_list; do
        [ -n "$ns" ] && printf 'nameserver %s\n' "$ns" >> /etc/resolv.conf
    done
    IFS=$old_ifs

    mgmt_mac=$(get_extra mac "")
    mgmt_iface=$(get_extra iface "")
    iface=""
    for sys_path in /sys/class/net/*; do
        dev="${sys_path##*/}"
        [ "$dev" = "lo" ] && continue
        if [ -n "$mgmt_mac" ] && [ "$(cat "$sys_path/address")" = "$mgmt_mac" ]; then
            iface="$dev"
            break
        fi
        [ -z "$iface" ] && iface="$dev"
    done
    [ -n "$iface" ] || die "no network interface found"
    log "using NIC ${iface} (mac ${mgmt_mac:-unknown})"
    ip link set "$iface" up

    ipv4_addr=$(get_extra ipv4 "")
    ipv4_gw=$(get_extra ipv4_gw "")
    if [ -n "$ipv4_addr" ]; then
        if ! udhcpc -i "$iface" -q -t 8 -T 2 > /dev/null 2>&1; then
            log "dhcp failed on ${iface}; falling back to the previous static address"
        fi
        if ! ip -4 addr show dev "$iface" | grep -q inet; then
            ip -4 addr flush dev "$iface"
            ip -4 addr add "$ipv4_addr" dev "$iface"
            [ -n "$ipv4_gw" ] && ip -4 route add default via "$ipv4_gw" dev "$iface"
        fi
        ip -4 addr show dev "$iface" | grep -q inet || die "no IPv4 address on ${iface}"
    else
        udhcpc -i "$iface" -q -t 8 -T 2 > /dev/null 2>&1 || die "dhcp failed on ${iface} and no static IPv4 is known"
    fi

    ipv6_addr=$(get_extra ipv6 "")
    ipv6_gw=$(get_extra ipv6_gw "")
    if [ -n "$ipv6_addr" ]; then
        ip -6 addr add "$ipv6_addr" dev "$iface" 2> /dev/null || true
        [ -n "$ipv6_gw" ] && ip -6 route add default via "$ipv6_gw" dev "$iface" 2> /dev/null || true
    fi
}

wait_for_upstream() {
    repo_url="$1"
    apk_arch="$2"
    i=0
    while [ "$i" -lt 15 ]; do
        if wget -q -T 5 -O /dev/null "${repo_url}/${apk_arch}/APKINDEX.tar.gz" 2> /dev/null; then
            return 0
        fi
        i=$((i + 1))
        sleep 2
    done
    die "no upstream connectivity via ${repo_url} - check the network and reboot to retry"
}

## Disk helpers
part_dev() {
    case "$1" in
        *nvme*|*mmcblk*) printf '%s\n' "$1p$2" ;;
        *) printf '%s\n' "$1$2" ;;
    esac
}

find_target_disk() {
    want_ptuuid=$(get_extra disk "")
    target_disk=""
    fallback_disk=""
    fallback_size=0
    for sys_path in /sys/block/*; do
        dev="${sys_path##*/}"
        case "$dev" in
            loop*|ram*|zram*|nbd*|sr*|fd*|dm-*) continue ;;
        esac
        [ -f "${sys_path}/removable" ] && [ "$(cat "${sys_path}/removable")" = "1" ] && continue
        dev_ptuuid=$(lsblk -no PTUUID "/dev/${dev}" 2> /dev/null || true)
        if [ -n "$want_ptuuid" ] && [ "$dev_ptuuid" = "$want_ptuuid" ]; then
            target_disk="/dev/${dev}"
            break
        fi
        dev_size=$(cat "${sys_path}/size")
        if [ "${dev_size:-0}" -gt "$fallback_size" ]; then
            fallback_size="$dev_size"
            fallback_disk="/dev/${dev}"
        fi
    done
    if [ -z "$target_disk" ]; then
        [ -n "$fallback_disk" ] || die "no usable disk found"
        log "disk with PTUUID ${want_ptuuid} not found; using largest disk ${fallback_disk}"
        target_disk="$fallback_disk"
    fi
    log "target disk: ${target_disk}"
}

# Partition the disk: ESP/bios_grub + root + trailing installer staging area.
partition_disk() {
    partsize=$(get_extra partsize "2048")
    parted -s "$target_disk" mklabel gpt
    if [ "$(get_extra efi 0)" = "1" ]; then
        parted -s "$target_disk" mkpart esp fat32 1MiB 101MiB
        parted -s "$target_disk" set 1 esp on
        root_start="101MiB"
    else
        parted -s "$target_disk" mkpart bios grub 1MiB 2MiB
        parted -s "$target_disk" set 1 bios_grub on
        root_start="2MiB"
    fi
    parted -s "$target_disk" mkpart root ext4 "$root_start" "-${partsize}MiB"
    parted -s "$target_disk" mkpart installer ext4 "-${partsize}MiB" 100%
    partprobe "$target_disk"
    sleep 1
    installer_part=$(part_dev "$target_disk" 3)
    mkfs.ext4 -F -L installer "$installer_part" > /dev/null 2>&1 || die "mkfs.ext4 on the installer partition failed"
    mkdir -p /installer
    mount "$installer_part" /installer || die "cannot mount the installer partition"
}

download_image() {
    image_url=$(get_extra img "")
    [ -n "$image_url" ] || die "extra_img missing on the cmdline"
    log "downloading ${image_url}"
    wget -O /installer/cloud.qcow2 "$image_url" || die "cloud image download failed"
    image_bytes=$(wc -c < /installer/cloud.qcow2)
    [ "${image_bytes:-0}" -gt 104857600 ] || die "cloud image looks truncated (${image_bytes} bytes)"
}

# Attach the qcow2 and map its partitions (root/boot/efi).
attach_and_probe_image() {
    modprobe nbd 2> /dev/null || true
    modprobe ext4 2> /dev/null || true
    modprobe vfat 2> /dev/null || true
    qemu-nbd -c /dev/nbd0 /installer/cloud.qcow2 || die "qemu-nbd failed"
    sleep 1
    partprobe /dev/nbd0
    img_root_part=""
    img_boot_part=""
    img_efi_part=""
    for part_num in 1 2 3 4 5; do
        part="/dev/nbd0p${part_num}"
        [ -b "$part" ] || continue
        kind=$(probe_image_partition "$part")
        case "$kind" in
            root) img_root_part="$part" ;;
            boot) img_boot_part="$part" ;;
            efi) img_efi_part="$part" ;;
        esac
    done
    [ -n "$img_root_part" ] || die "could not locate the root partition inside the cloud image"
    log "image partitions: root=${img_root_part} boot=${img_boot_part:-none} efi=${img_efi_part:-none}"
}

# Format the target partitions and copy the image content over.
format_and_copy() {
    root_part=$(part_dev "$target_disk" 2)
    # Preserve the image's root UUID/label so any baked-in references stay valid.
    root_uuid=$(blkid -s UUID -o value "$img_root_part" || true)
    root_label=$(blkid -s LABEL -o value "$img_root_part" || true)
    mkfs_args=""
    [ -n "$root_uuid" ] && mkfs_args="-U $root_uuid"
    [ -n "$root_label" ] && mkfs_args="$mkfs_args -L $root_label"
    mkfs.ext4 -F $mkfs_args "$root_part" > /dev/null 2>&1 || die "mkfs.ext4 on ${root_part} failed"
    mkdir -p /os
    mount "$root_part" /os || die "cannot mount the new root partition"

    if [ -n "$img_boot_part" ]; then
        mkdir -p /img
        mount -o ro "$img_boot_part" /img
        mkdir -p /os/boot
        cp -a /img/. /os/boot/
        umount /img
    fi
    if [ "$(get_extra efi 0)" = "1" ]; then
        esp_part=$(part_dev "$target_disk" 1)
        mkfs.vfat -F 32 -n ESP "$esp_part" > /dev/null 2>&1 || die "mkfs.vfat on ${esp_part} failed"
        mkdir -p /os/boot/efi
        mount "$esp_part" /os/boot/efi || die "cannot mount the ESP"
        if [ -n "$img_efi_part" ]; then
            mkdir -p /img
            mount -o ro "$img_efi_part" /img
            cp -a /img/. /os/boot/efi/
            umount /img
        fi
    fi

    mkdir -p /img
    mount -o ro "$img_root_part" /img
    cp -a /img/. /os/
    umount /img
    rm -rf /img
}

# Configure the freshly copied system inside a chroot.
chroot_configure() {
    codename=$(get_extra codename "noble")
    arch=$(get_extra arch "amd64")
    for mount_path in dev proc sys run; do
        mkdir -p "/os/${mount_path}"
        case "$mount_path" in
            proc) mount -t proc proc "/os/${mount_path}" ;;
            dev) mount --bind /dev "/os/${mount_path}" ;;
            sys) mount --bind /sys "/os/${mount_path}" ;;
            run) mount --bind /run "/os/${mount_path}" ;;
        esac
    done
    cp /etc/resolv.conf /os/etc/resolv.conf

    # CN-first apt mirrors; cloud images default to upstream.
    for sources in /os/etc/apt/sources.list /os/etc/apt/sources.list.d/*.sources /os/etc/apt/sources.list.d/*.list; do
        [ -f "$sources" ] || continue
        sed -i -E \
            -e 's|http://[a-z.]*archive\.ubuntu\.com/ubuntu|http://mirrors.cernet.edu.cn/ubuntu|g' \
            -e 's|http://[a-z.]*security\.ubuntu\.com/ubuntu|http://mirrors.cernet.edu.cn/ubuntu|g' \
            -e 's|http://[a-z.]*ports\.ubuntu\.com/ubuntu-ports|http://mirrors.cernet.edu.cn/ubuntu-ports|g' \
            "$sources"
    done

    # Credentials: hashed password and/or ssh keys baked into /configs.
    if [ -f /configs/password ]; then
        chroot /os chpasswd -e < /configs/password
        sed -i -E \
            -e 's/^#?PermitRootLogin .*/PermitRootLogin yes/' \
            -e 's/^#?PasswordAuthentication .*/PasswordAuthentication yes/' \
            /os/etc/ssh/sshd_config
        grep -q '^PermitRootLogin' /os/etc/ssh/sshd_config || printf '%s\n' 'PermitRootLogin yes' >> /os/etc/ssh/sshd_config
        grep -q '^PasswordAuthentication' /os/etc/ssh/sshd_config || printf '%s\n' 'PasswordAuthentication yes' >> /os/etc/ssh/sshd_config
        log "root password applied; ssh password login enabled"
    fi
    if [ -f /configs/ssh_keys ]; then
        mkdir -p /os/root/.ssh
        cp /configs/ssh_keys /os/root/.ssh/authorized_keys
        chmod 700 /os/root/.ssh
        chmod 600 /os/root/.ssh/authorized_keys
        chown root:root /os/root/.ssh /os/root/.ssh/authorized_keys
        log "ssh keys installed for root"
    fi
    if [ ! -f /configs/password ] && [ -f /os/root/.ssh/authorized_keys ]; then
        chroot /os passwd -l root > /dev/null 2>&1 || true
        log "key-only install: root password locked"
    fi

    # Fresh machine identity: no cloud-init, no stale host keys or ids.
    [ -d /os/etc/cloud ] && touch /os/etc/cloud/cloud-init.disabled
    : > /os/etc/machine-id
    rm -f /os/var/lib/dbus/machine-id /os/etc/ssh/ssh_host_*

    # netplan replays the previous network by MAC address.
    mkdir -p /os/etc/netplan
    mgmt_mac=$(get_extra mac "")
    mgmt_iface=$(get_extra iface "eth0")
    mgmt_mac_upper=$(printf '%s' "$mgmt_mac" | tr '[:lower:]' '[:upper:]')
    addr_lines=""
    route_lines=""
    ipv4_addr=$(get_extra ipv4 "")
    ipv4_gw=$(get_extra ipv4_gw "")
    ipv6_addr=$(get_extra ipv6 "")
    ipv6_gw=$(get_extra ipv6_gw "")
    if [ -n "$ipv4_addr" ]; then
        addr_lines="${addr_lines}        - ${ipv4_addr}"$'\n'
        if [ -n "$ipv4_gw" ]; then
            route_lines="${route_lines}        - to: 0.0.0.0/0"$'\n'
            route_lines="${route_lines}          via: ${ipv4_gw}"$'\n'
        fi
    fi
    if [ -n "$ipv6_addr" ]; then
        addr_lines="${addr_lines}        - ${ipv6_addr}"$'\n'
        if [ -n "$ipv6_gw" ]; then
            route_lines="${route_lines}        - to: ::/0"$'\n'
            route_lines="${route_lines}          via: ${ipv6_gw}"$'\n'
        fi
    fi
    {
        printf '%s\n' "network:"
        printf '%s\n' "  version: 2"
        printf '%s\n' "  ethernets:"
        printf '%s\n' "    ${mgmt_iface}:"
        printf '%s\n' "      match:"
        printf '%s\n' "        macaddress: \"${mgmt_mac_upper}\""
        printf '%s\n' "      set-name: ${mgmt_iface}"
        if [ -n "$addr_lines" ]; then
            printf '%s\n' "      dhcp4: false"
            printf '%s' "      addresses:"$'\n'"${addr_lines}"
        else
            printf '%s\n' "      dhcp4: true"
        fi
        if [ -n "$route_lines" ]; then
            printf '%s' "      routes:"$'\n'"${route_lines}"
        fi
        printf '%s\n' "      nameservers:"
        printf '%s\n' "        addresses: [$(get_extra dns "223.5.5.5,223.6.6.6")]"
    } > /os/etc/netplan/99-autodeploy.yaml

    # Regenerate fstab: root keeps the image UUID; the ESP is mounted explicitly.
    root_part_uuid=$(blkid -s UUID -o value "$(part_dev "$target_disk" 2)")
    {
        if [ -n "$root_part_uuid" ]; then
            printf '%s\n' "UUID=${root_part_uuid} / ext4 defaults 0 1"
        fi
        if [ "$(get_extra efi 0)" = "1" ]; then
            esp_uuid=$(blkid -s UUID -o value "$(part_dev "$target_disk" 1)")
            [ -n "$esp_uuid" ] && printf '%s\n' "UUID=${esp_uuid} /boot/efi vfat umask=0077 0 1"
        fi
    } > /os/etc/fstab

    # Bootloader: reinstall grub so NVRAM/MBR reference this disk for sure.
    if [ "$(get_extra efi 0)" = "1" ]; then
        case "$arch" in
            arm64) grub_target="arm64-efi" ;;
            *) grub_target="x86_64-efi" ;;
        esac
        chroot /os grub-install "--target=${grub_target}" --efi-directory=/boot/efi --bootloader-id=ubuntu --recheck > /dev/null 2>&1 || die "grub-install (efi) failed"
    else
        chroot /os grub-install --target=i386-pc --recheck "$target_disk" > /dev/null 2>&1 || die "grub-install (bios) failed"
    fi
    chroot /os update-grub > /dev/null 2>&1 || die "update-grub failed"
}

# Delete the staging partition and grow the root filesystem to fill the disk.
resize_rootfs() {
    for mount_path in run sys proc dev boot/efi; do
        mountpoint -q "/os/${mount_path}" 2> /dev/null && umount "/os/${mount_path}" || true
    done
    umount /os 2> /dev/null || true
    qemu-nbd -d /dev/nbd0 > /dev/null 2>&1 || true
    umount /installer 2> /dev/null || true
    modloop_mount=$(awk '$3 == "squashfs" {print $2; exit}' /proc/mounts)
    [ -n "$modloop_mount" ] && umount "$modloop_mount" 2> /dev/null || true
    losetup -D 2> /dev/null || true

    parted -s "$target_disk" rm 3
    parted -s "$target_disk" resizepart 2 100%
    root_part=$(part_dev "$target_disk" 2)
    e2fsck -fp "$root_part" > /dev/null 2>&1 || true
    resize2fs "$root_part" > /dev/null 2>&1 || true
    sync
}

## Process
log "installer started: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
# Last-second escape hatch: typing CANCEL on the console within 10s aborts
# and reboots back to the old system - the disk is untouched until
# partition_disk. Unattended boots fall through after the timeout; stdin
# must be /dev/console because OpenRC services have no controlling terminal.
printf '%s' 'Reinstall starts in 10s - type CANCEL to abort: '
if read -t 10 answer < /dev/console && [ "$answer" = "CANCEL" ]; then
    log "cancelled; rebooting back to the old system"
    sync
    reboot
fi
printf '%s\n' ''
setup_network
apk_arch=$(get_extra arch "amd64")
case "$apk_arch" in
    arm64) apk_arch="aarch64" ;;
    *) apk_arch="x86_64" ;;
esac
repo_url=$(get_extra repo "http://mirrors.cernet.edu.cn/alpine/latest-stable/main")
printf '%s\n' "$repo_url" > /etc/apk/repositories
wait_for_upstream "$repo_url" "$apk_arch"
apk add --no-cache parted e2fsprogs e2fsprogs-extra dosfstools util-linux qemu-img > /dev/null 2>&1 || die "apk install failed"
find_target_disk
partition_disk
download_image
attach_and_probe_image
format_and_copy
chroot_configure
resize_rootfs
log "============================================================"
log "Ubuntu installed successfully. Reboot to boot the new system."
log "============================================================"
exit 0
