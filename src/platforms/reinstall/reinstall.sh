## Function
# Reinstall this Ubuntu machine to a fresh Ubuntu release after reboot.
# Phase 1 (this script): collect facts, stage an Alpine netboot installer in
# the initramfs, queue a one-time GRUB entry. The actual install runs in
# phase 2 (src/reinstall/trans.sh) after the reboot. Only the Ubuntu family
# is supported as the source system.

GetUbuntuCodename() {
    # LTS releases only.
    case "$1" in
        20.04) UBUNTU_CODENAME="focal" ;;
        22.04) UBUNTU_CODENAME="jammy" ;;
        24.04) UBUNTU_CODENAME="noble" ;;
        26.04) UBUNTU_CODENAME="resolute" ;;
        *) Die "unsupported Ubuntu release: $1 (supported LTS: 20.04 22.04 24.04 26.04)" ;;
    esac
}

# CheckReinstallEnvironment
# Only Debian/Ubuntu hosts with apt, grub and a supported architecture.
CheckReinstallEnvironment() {
    HaveCommand apt || Die "only Ubuntu/Debian hosts are supported (apt not found)"
    GetOSArchitecture
    HaveCommand grub-reboot || Die "grub-reboot not found; this tool expects a GRUB-booted Ubuntu host"
    [ -d /boot/grub ] || Die "/boot/grub not found; this tool expects a GRUB-booted Ubuntu host"
    HaveCommand openssl || apt-get install -qy openssl
    HaveCommand cpio || apt-get install -qy cpio
    if [ "$(free -m | awk '/^Mem:/ {print $2}')" -lt 1024 ]; then
        LogWarn "less than 1 GiB RAM; the installer may be slow or fail"
    fi
    free_mb=$(df -Pm / | awk 'NR==2 {print $4}')
    if [ "$free_mb" -lt 512 ]; then
        Die "less than 512 MiB free on / ; needed for the Alpine netboot files"
    fi
    LogInfo "architecture: ${OS_ARCHITECTURE}, firmware: $([ -d /sys/firmware/efi ] && echo efi || echo bios)"
}

# CollectReinstallFacts
# Network facts are replayed into the new system via netplan; the boot disk is
# located by partition-table UUID so the installer cannot pick the wrong disk.
CollectReinstallFacts() {
    MGMT_IFACE=$(ip -4 route show default | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i + 1); exit}}')
    [ -n "$MGMT_IFACE" ] || Die "no default IPv4 route found"
    MGMT_MAC=$(cat "/sys/class/net/${MGMT_IFACE}/address")
    MGMT_IPV4=$(ip -4 addr show "$MGMT_IFACE" scope global | awk '/inet / {print $2; exit}')
    MGMT_IPV4_GW=$(ip -4 route show default | awk '{print $3; exit}')
    MGMT_IPV6=$(ip -6 addr show "$MGMT_IFACE" scope global 2>/dev/null | awk '/inet6/ && !/temporary/ {print $2; exit}')
    MGMT_IPV6_GW=$(ip -6 route show default 2>/dev/null | awk '/default/ {print $3; exit}')
    DNS_SERVERS=$(awk '/^nameserver/ {print $2}' /etc/resolv.conf | grep -v '^127\.' | head -n 3 | paste -sd, -)
    [ -n "$DNS_SERVERS" ] || DNS_SERVERS="223.5.5.5,223.6.6.6"

    root_source=$(findmnt -no SOURCE /)
    REINSTALL_DISK="/dev/$(lsblk -no PKNAME "$root_source" | head -n 1)"
    [ -b "$REINSTALL_DISK" ] || Die "could not resolve the boot disk from ${root_source}"
    MAIN_DISK_PTSIGN=$(lsblk -no PTUUID "$REINSTALL_DISK")
    [ -n "$MAIN_DISK_PTSIGN" ] || Die "disk ${REINSTALL_DISK} has no partition table signature"

    # modloop provides the kernel modules (nbd, filesystems) inside Alpine.
    if HaveCommand systemd-detect-virt && systemd-detect-virt -c -v > /dev/null 2>&1; then
        ALPINE_FLAVOUR="virt"
    elif HaveCommand virt-what && [ -n "$(virt-what)" ]; then
        ALPINE_FLAVOUR="virt"
    else
        ALPINE_FLAVOUR="lts"
    fi
    LogInfo "management NIC ${MGMT_IFACE} (${MGMT_IPV4:-dhcp}), disk ${REINSTALL_DISK}, alpine flavour ${ALPINE_FLAVOUR}"
}

# PrepareReinstallCredentials
# Password: env override, or generated (printed once). Keys: env override, or
# this host's existing root authorized_keys. Key-only installs lock the root
# password inside the new system.
PrepareReinstallCredentials() {
    REINSTALL_CREDENTIALS_MODE=""
    if [ -n "$REINSTALL_SSH_KEYS" ] && [ -f "$REINSTALL_SSH_KEYS" ]; then
        SSH_KEYS_CONTENT=$(cat "$REINSTALL_SSH_KEYS")
    elif [ -n "$REINSTALL_SSH_KEYS" ]; then
        SSH_KEYS_CONTENT="$REINSTALL_SSH_KEYS"
    elif [ -f /root/.ssh/authorized_keys ] && [ -s /root/.ssh/authorized_keys ]; then
        SSH_KEYS_CONTENT=$(cat /root/.ssh/authorized_keys)
        LogInfo "reusing the existing /root/.ssh/authorized_keys in the new system"
    else
        SSH_KEYS_CONTENT=""
    fi
    if [ -n "$REINSTALL_PASSWORD" ]; then
        REINSTALL_PASSWORD_HASH=$(openssl passwd -6 "$REINSTALL_PASSWORD")
        REINSTALL_CREDENTIALS_MODE="password"
    else
        REINSTALL_PASSWORD=$(head -c 16 /dev/urandom | base64 | tr -d '=+/' | head -c 16)
        REINSTALL_PASSWORD_HASH=$(openssl passwd -6 "$REINSTALL_PASSWORD")
        REINSTALL_CREDENTIALS_MODE="generated-password"
        LogWarn "no REINSTALL_PASSWORD given; generated: ${REINSTALL_PASSWORD} (store it now - it is shown only this once)"
    fi
}

# DownloadInstallerFiles
# Alpine netboot kernel/initrd/modloop plus the phase-2 installer script.
DownloadInstallerFiles() {
    GetUbuntuCodename "$REINSTALL_RELEASE"
    # China mirrors only (CERNET); http so an unsynced installer clock cannot
    # break the download.
    ALPINE_MIRROR="http://mirrors.cernet.edu.cn/alpine"
    IMAGE_MIRROR="http://mirrors.cernet.edu.cn/ubuntu-cloud-images"
    if [ "$REINSTALL_ALPINE_VERSION" = "auto" ]; then
        REINSTALL_ALPINE_VERSION=$(curl -fsSL "${ALPINE_MIRROR}/" | grep -oE 'v3\.[0-9]+' | sort -uV | tail -n 1 | tr -d v || true)
    fi
    case "$REINSTALL_ALPINE_VERSION" in
        3.[0-9][0-9]) ;;
        *) REINSTALL_ALPINE_VERSION="3.22" ;;
    esac
    case "$OS_ARCHITECTURE" in
        amd64) ALPINE_ARCH="x86_64" ;;
        arm64) ALPINE_ARCH="aarch64" ;;
    esac
    ALPINE_BASE="${ALPINE_MIRROR}/v${REINSTALL_ALPINE_VERSION}/releases/${ALPINE_ARCH}/netboot"
    REINSTALL_CLOUD_IMAGE="${IMAGE_MIRROR}/releases/${UBUNTU_CODENAME}/release/ubuntu-${REINSTALL_RELEASE}-server-cloudimg-${OS_ARCHITECTURE}.img"
    ALPINE_REPO="${ALPINE_MIRROR}/v${REINSTALL_ALPINE_VERSION}/main"

    curl -fsSL -o /reinstall-vmlinuz "${ALPINE_BASE}/vmlinuz-${ALPINE_FLAVOUR}"
    curl -fsSL -o /reinstall-initrd "${ALPINE_BASE}/initramfs-${ALPINE_FLAVOUR}"
    curl -fsSL -o /reinstall-modloop "${ALPINE_BASE}/modloop-${ALPINE_FLAVOUR}"
    curl -fsSL -o /reinstall-trans.sh "${REINSTALL_CONFHOME}/trans.sh"
    [ -s /reinstall-trans.sh ] || Die "failed to download the installer script from ${REINSTALL_CONFHOME}/trans.sh"
    for file in /reinstall-vmlinuz /reinstall-initrd /reinstall-modloop; do
        [ -s "$file" ] || Die "failed to download ${file}"
    done
    LogInfo "staged alpine v${REINSTALL_ALPINE_VERSION} (${ALPINE_FLAVOUR}) and Ubuntu ${REINSTALL_RELEASE} (${UBUNTU_CODENAME}) cloud image"
}

# BuildInstallerInitrd
# Unpack the Alpine initramfs, drop in trans.sh plus /configs, and patch the
# initramfs init to copy them into the RAM system before switch_root; the
# installer then runs via the OpenRC local service.
BuildInstallerInitrd() {
    workdir="/tmp/reinstall-initrd.autodeploy"
    rm -rf "$workdir"
    mkdir -p "$workdir"
    zcat /reinstall-initrd | cpio -idm -D "$workdir" > /dev/null 2>&1
    if [ ! -f "$workdir/init" ]; then
        Die "unexpected initramfs layout: no init script found"
    fi
    if ! grep -q '^exec switch_root' "$workdir/init"; then
        Die "could not find the switch_root call in the alpine init; aborting"
    fi
    mkdir -p "$workdir/configs"
    printf 'root:%s\n' "$REINSTALL_PASSWORD_HASH" > "$workdir/configs/password"
    if [ -n "$SSH_KEYS_CONTENT" ]; then
        printf '%s\n' "$SSH_KEYS_CONTENT" > "$workdir/configs/ssh_keys"
    fi
    cp /reinstall-trans.sh "$workdir/trans.sh"
    chmod +x "$workdir/trans.sh"
    awk '
        { print }
        /^exec switch_root/ && !injected {
            print "mkdir -p /sysroot/etc/local.d /sysroot/etc/runlevels/default"
            print "cp /trans.sh /sysroot/etc/local.d/trans.start"
            print "chmod +x /sysroot/etc/local.d/trans.start"
            print "cp -r /configs /sysroot/etc/configs"
            print "ln -sf /etc/init.d/local /sysroot/etc/runlevels/default/local"
            injected = 1
        }
    ' "$workdir/init" > "$workdir/init.autodeploy"
    mv "$workdir/init.autodeploy" "$workdir/init"
    chmod +x "$workdir/init"
    (cd "$workdir" && find . | cpio -o -H newc -R 0:0 | gzip -1) > /reinstall-initrd
    rm -rf "$workdir" /reinstall-trans.sh
    LogInfo "installer initramfs built with trans.sh and credentials baked in"
}

# InstallBootEntry
# Queue a one-time GRUB boot into the installer; the next reboot wipes the
# disk, so nothing of the host setup survives beyond this script.
InstallBootEntry() {
    if grep -q '^GRUB_DEFAULT=' /etc/default/grub; then
        sed -i 's/^GRUB_DEFAULT=.*/GRUB_DEFAULT=saved/' /etc/default/grub
    else
        printf '%s\n' 'GRUB_DEFAULT=saved' >> /etc/default/grub
    fi
    grub-mkconfig -o /boot/grub/grub.cfg > /dev/null

    cmdline="quiet"
    cmdline="${cmdline} extra_img=${REINSTALL_CLOUD_IMAGE}"
    cmdline="${cmdline} extra_repo=${ALPINE_REPO}"
    cmdline="${cmdline} extra_mac=${MGMT_MAC}"
    cmdline="${cmdline} extra_iface=${MGMT_IFACE}"
    cmdline="${cmdline} extra_disk=${MAIN_DISK_PTSIGN}"
    cmdline="${cmdline} extra_arch=${OS_ARCHITECTURE}"
    cmdline="${cmdline} extra_codename=${UBUNTU_CODENAME}"
    cmdline="${cmdline} extra_partsize=${REINSTALL_INSTALLER_PART_SIZE_MB}"
    cmdline="${cmdline} extra_efi=$([ -d /sys/firmware/efi ] && echo 1 || echo 0)"
    if [ -n "$MGMT_IPV4" ]; then
        cmdline="${cmdline} extra_ipv4=${MGMT_IPV4} extra_ipv4_gw=${MGMT_IPV4_GW}"
    fi
    if [ -n "$MGMT_IPV6" ]; then
        cmdline="${cmdline} extra_ipv6=${MGMT_IPV6} extra_ipv6_gw=${MGMT_IPV6_GW}"
    fi
    cmdline="${cmdline} extra_dns=${DNS_SERVERS}"

    {
        printf '%s\n' 'menuentry "AutoDeploy Reinstall" --id autodeploy-reinstall {'
        printf '%s\n' '    search --no-floppy --file --set=root /reinstall-vmlinuz'
        printf '%s\n' "    linux /reinstall-vmlinuz ${cmdline}"
        printf '%s\n' '    initrd /reinstall-initrd'
        printf '%s\n' '}'
    } > /boot/grub/custom.cfg
    grub-reboot "AutoDeploy Reinstall"
    LogInfo "one-time boot entry installed; next reboot starts the reinstall"
}

RenderSummary() {
    LogInfo "============================================================"
    LogInfo "reinstall prepared: Ubuntu ${REINSTALL_RELEASE} (${UBUNTU_CODENAME}) on ${REINSTALL_DISK}"
    LogInfo "login: root"
    if [ "$REINSTALL_CREDENTIALS_MODE" = "generated-password" ]; then
        LogInfo "password (generated): ${REINSTALL_PASSWORD}"
    elif [ "$REINSTALL_CREDENTIALS_MODE" = "password" ]; then
        LogInfo "password: the value you passed in REINSTALL_PASSWORD"
    else
        LogInfo "password: locked (key-only login)"
    fi
    if [ -n "$SSH_KEYS_CONTENT" ]; then
        LogInfo "ssh keys: installed to /root/.ssh/authorized_keys"
    fi
    LogInfo "network: ${MGMT_IPV4:-dhcp4} on ${MGMT_IFACE} (mac ${MGMT_MAC})"
    LogInfo "reboot now with: reboot"
    LogInfo "============================================================"
}

## Process
RequireRoot
InitRun
RunStep "CheckReinstallEnvironment" CheckReinstallEnvironment
RunStep "CollectReinstallFacts" CollectReinstallFacts
RunStep "PrepareReinstallCredentials" PrepareReinstallCredentials
RunStep "DownloadInstallerFiles" DownloadInstallerFiles
RunStep "BuildInstallerInitrd" BuildInstallerInitrd
RunStep "InstallBootEntry" InstallBootEntry
RenderSummary
RenderProgress "complete"
rm -f /tmp/*.autodeploy > /dev/null 2>&1 || true
