#!/bin/sh
# ============================================================================
# ZJDeploy Ubuntu reinstall - phase 2 (installer).
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
#   extra_efi=      1 when the installed system should boot via UEFI
#                   (auto-detected, or forced by REINSTALL_BOOT_MODE)
#   extra_arch=     amd64 | arm64
#   extra_codename= Ubuntu codename of the installed release
#   extra_partsize= installer staging partition size in MiB
# The initramfs carries /configs; the injection copies it to
# /etc/configs in the booted installer, which is what runs.
# ============================================================================

CMDLINE="$(cat /proc/cmdline)"
DONE_BANNER=""

# The whole install runs through "main | tee" so the progress is also
# readable over ssh. busybox ash has no PIPESTATUS and die() then only
# exits the pipeline's subshell, so it leaves this marker for the tail.
LOG_FILE="/zjdeploy.log"

log() {
    printf '[ZJDeploy] %s\n' "$*"
}

# Same separator the phase-1 script prints (core.sh LogSeparator); this
# file runs under busybox ash and cannot reuse it.
separator() {
    separator
}

die() {
    : > /zjdeploy.fail
    printf '[ZJDeploy] ERROR: %s\n' "$*" >&2
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
        # bonding_masters and friends are pseudo files, not interfaces.
        [ -d "$sys_path" ] || continue
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
        # The facts were collected from this very machine minutes ago, so
        # reassert them (the initramfs ip= already did) - running udhcpc
        # here would move the installer to a lease address and the
        # operator's ssh target with it.
        ip -4 addr flush dev "$iface"
        ip -4 addr add "$ipv4_addr" dev "$iface"
        [ -n "$ipv4_gw" ] && ip -4 route add default via "$ipv4_gw" dev "$iface"
    else
        udhcpc -i "$iface" -q -t 8 -T 2 > /dev/null 2>&1 || die "dhcp failed on ${iface} and no static IPv4 is known"
    fi
    ip -4 addr show dev "$iface" | grep -q inet || die "no IPv4 address on ${iface}"

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

# Start dropbear so the operator can watch or repair the install over ssh.
# Credentials are the same ones the final system gets - /configs is baked
# into the initramfs by dist/Reinstall.sh (phase 1).
setup_installer_ssh() {
    if [ -f /etc/configs/password ]; then
        chpasswd -e < /etc/configs/password
    fi
    if [ -f /etc/configs/ssh_keys ]; then
        mkdir -p /root/.ssh
        cp /etc/configs/ssh_keys /root/.ssh/authorized_keys
        chmod 700 /root/.ssh
        chmod 600 /root/.ssh/authorized_keys
    fi
    # -R generates the host keys on first connection; no openrc involved.
    # dropbear listens on both families; announce every address it serves.
    if dropbear -R 2> /dev/null; then
        addr="root@$(ip -4 addr show "$iface" | awk '/inet / {print $2; exit}' | cut -d/ -f1)"
        v6=$(ip -6 addr show "$iface" 2> /dev/null | awk '/inet6/ && !/temporary/ {print $2; exit}')
        [ -n "$v6" ] && addr="${addr} / root@${v6}"
        log "installer ssh ready: ${addr} (log: tail -f ${LOG_FILE})"
    else
        log "installer ssh failed to start; continue on the console"
    fi
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
    # Same-session reruns and manual diagnosis can leave target partitions
    # mounted; mkfs refuses busy devices, so clear strays first. sort -r
    # unmounts nested children (e.g. /os/boot/efi) before their parents.
    # p? covers both naming styles: vda1 vs nvme0n1p1.
    umount /os/boot/efi /os /img /installer /mnt 2> /dev/null || true
    disk_name=${target_disk##*/}
    grep -oE "^/dev/${disk_name}p?[0-9]* [^ ]*" /proc/mounts | cut -d" " -f2 | sort -r |
        while IFS= read -r mp; do
            umount "$mp" 2> /dev/null || true
        done
    # Absolute MiB positions instead of negative sizes: getopt keeps
    # scanning arguments after the device name, so '-2048MiB' was eaten as
    # a short-option cluster and both mkpart calls died.
    disk_mib=$(( $(cat "/sys/block/${target_disk##*/}/size") * 512 / 1048576 ))
    part_end=$(( disk_mib - partsize ))
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
    parted -s "$target_disk" mkpart root ext4 "$root_start" "${part_end}MiB"
    parted -s "$target_disk" mkpart installer ext4 "${part_end}MiB" 100%
    partprobe "$target_disk"
    sleep 1
    # devtmpfs occasionally skips partition nodes after a re-scan (vda1
    # vanished while vda2/vda3 existed); mdev -s rebuilds them from sysfs.
    mdev -s 2> /dev/null || true
    installer_part=$(part_dev "$target_disk" 3)
    mkfs.ext4 -F -L installer "$installer_part" || die "mkfs.ext4 on the installer partition failed"
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
    # Iterate every partition: ubuntu cloud images keep their ESP at
    # partition 15 and a bios_grub filler at 14, so a 1..5 loop silently
    # missed the ESP and the installed system lost its bootloader.
    for part in /dev/nbd0p[0-9]*; do
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
    mkdir -p /os
    mkfs.ext4 -F $mkfs_args "$root_part" || die "mkfs.ext4 on ${root_part} failed"
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
        mkfs.vfat -F 32 -n ESP "$esp_part" || die "mkfs.vfat on ${esp_part} failed"
        mkdir -p /os/boot/efi
        mount "$esp_part" /os/boot/efi || die "cannot mount the ESP"
        if [ -n "$img_efi_part" ]; then
            mkdir -p /img
            mount -o ro "$img_efi_part" /img
            cp -a /img/. /os/boot/efi/
            umount /img
        fi
        # Without the image's signed grub the ESP stays empty and the
        # firmware drops into its setup UI on the next boot.
        find /os/boot/efi -iname '*.efi' | grep -q . || die "the cloud image carries no esp to copy"
        # The image's own grub.cfg keys the root on its PARTUUID, which a
        # fresh partition table does not preserve - rewrite both copies to
        # look the root up by filesystem UUID (kept verbatim above).
        for cfg_dir in /os/boot/efi/EFI/ubuntu /os/boot/efi/EFI/BOOT; do
            if [ -d "$cfg_dir" ]; then
                printf '%s\n' \
                    "search --no-floppy --set=root --fs-uuid ${root_uuid}" \
                    "set prefix=(\$root)'/boot/grub'" \
                    'configfile $prefix/grub.cfg' > "$cfg_dir/grub.cfg"
            fi
        done
    fi

    mkdir -p /img
    mount -o ro "$img_root_part" /img
    cp -a /img/. /os/
    umount /img
    rm -rf /img
}

# Configure the freshly copied system inside a chroot.
chroot_configure() {
    codename=$(get_extra codename "resolute")
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
    if [ -f /etc/configs/password ]; then
        chroot /os chpasswd -e < /etc/configs/password
        # Cloud images ship sshd_config.d snippets (60-cloudimg-settings.conf
        # sets PasswordAuthentication no); sshd keeps the first value it reads
        # and sshd_config.d is included before the main file, so the snippets
        # would override the sed below. Clear them like ConfigureSshd does in
        # the deployment scripts.
        rm -f /os/etc/ssh/sshd_config.d/*.conf
        sed -i -E \
            -e 's/^#?PermitRootLogin .*/PermitRootLogin yes/' \
            -e 's/^#?PasswordAuthentication .*/PasswordAuthentication yes/' \
            /os/etc/ssh/sshd_config
        grep -q '^PermitRootLogin' /os/etc/ssh/sshd_config || printf '%s\n' 'PermitRootLogin yes' >> /os/etc/ssh/sshd_config
        grep -q '^PasswordAuthentication' /os/etc/ssh/sshd_config || printf '%s\n' 'PasswordAuthentication yes' >> /os/etc/ssh/sshd_config
        log "root password applied; ssh password login enabled"
    fi
    if [ -f /etc/configs/ssh_keys ]; then
        mkdir -p /os/root/.ssh
        cp /etc/configs/ssh_keys /os/root/.ssh/authorized_keys
        chmod 700 /os/root/.ssh
        chmod 600 /os/root/.ssh/authorized_keys
        chown root:root /os/root/.ssh /os/root/.ssh/authorized_keys
        log "ssh keys installed for root"
    fi
    if [ ! -f /etc/configs/password ] && [ -f /os/root/.ssh/authorized_keys ]; then
        chroot /os passwd -l root > /dev/null 2>&1 || true
        log "key-only install: root password locked"
    fi

    # Fresh machine identity: no cloud-init, no stale host keys or ids.
    [ -d /os/etc/cloud ] && touch /os/etc/cloud/cloud-init.disabled
    : > /os/etc/machine-id
    rm -f /os/var/lib/dbus/machine-id /os/etc/ssh/ssh_host_*
    # resolute's cloud image no longer ships openssh-server, and the host
    # keys would normally be regenerated by the very cloud-init we just
    # disabled - install the package and create the keys right here.
    chroot /os apt-get update -qq || die "apt-get update in the chroot failed"
    chroot /os apt-get install -y openssh-server || die "openssh-server install failed"
    chroot /os ssh-keygen -A > /dev/null

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
            # on-link keeps the route usable when the gateway is outside the
            # interface subnet (VPS /32, /30); harmless when it is not.
            route_lines="${route_lines}        - to: 0.0.0.0/0"$'\n'
            route_lines="${route_lines}          via: ${ipv4_gw}"$'\n'
            route_lines="${route_lines}          on-link: true"$'\n'
        fi
    fi
    if [ -n "$ipv6_addr" ]; then
        addr_lines="${addr_lines}        - ${ipv6_addr}"$'\n'
        if [ -n "$ipv6_gw" ]; then
            route_lines="${route_lines}        - to: ::/0"$'\n'
            route_lines="${route_lines}          via: ${ipv6_gw}"$'\n'
            route_lines="${route_lines}          on-link: true"$'\n'
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
    } > /os/etc/netplan/99-zjdeploy.yaml

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

    # Bootloader: on EFI, chroot grub-install is the canonical writer -
    # it lays down the shim+grub pair and registers the NVRAM entry. The
    # image's ESP (copied in format_and_copy) stays underneath as a
    # fallback, and the installer env re-registers the entry if the chroot
    # could not (missing efibootmgr). BIOS still installs grub to the MBR
    # gap.
    if [ "$(get_extra efi 0)" = "1" ]; then
        # Wipe every firmware entry (template leftovers, previous installs)
        # before the new one is written.
        for entry in $(efibootmgr 2> /dev/null | awk '$1 ~ /^Boot[0-9]/ {print $1}'); do
            bootnum="${entry#Boot}"
            bootnum="${bootnum%\*}"
            efibootmgr --delete-bootnum --bootnum "$bootnum" > /dev/null 2>&1 || true
        done
        case "$arch" in
            arm64) grub_target="arm64-efi" ;;
            *) grub_target="x86_64-efi" ;;
        esac
        if ! chroot /os grub-install "--target=${grub_target}" --efi-directory=/boot/efi \
            --bootloader-id=ubuntu --recheck > /dev/null 2>&1; then
            log "WARNING: chroot grub-install (efi) failed; relying on the copied image ESP"
        fi
        # Belt: re-register the entry from the installer env when the
        # chroot could not (no efibootmgr inside the image).
        efibootmgr 2> /dev/null | grep -qi ubuntu || \
            efibootmgr --create --disk "$target_disk" --part 1 \
                --label ubuntu --loader '\EFI\ubuntu\shimx64.efi' > /dev/null 2>&1 || true
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
main() {
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
        exit 0
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
    # qemu-img lives in community, not main; derive the sibling repo from the
    # main URL the same way the upstream installer does.
    printf '%s\n' "${repo_url%/main}/community" >> /etc/apk/repositories
    wait_for_upstream "$repo_url" "$apk_arch"
    # Output stays visible: it is tee'd into $LOG_FILE and apk failures
    # used to be invisible behind a redirect here.
    apk add --no-cache parted e2fsprogs e2fsprogs-extra dosfstools util-linux qemu-img dropbear efibootmgr || die "apk install failed"
    setup_installer_ssh
    find_target_disk
    partition_disk
    download_image
    attach_and_probe_image
    format_and_copy
    chroot_configure
    resize_rootfs
    log "============================================================"
    log "Ubuntu installed successfully; rebooting into the new system"
    log "============================================================"
    sleep 3
    reboot
}

# tee also writes /dev/console: openrc swallows service stdout, so without
# it the install would only ever be visible in the log file.
main 2>&1 | tee "$LOG_FILE" /dev/console
if [ -f /zjdeploy.fail ]; then
    exit 1
fi
exit 0
