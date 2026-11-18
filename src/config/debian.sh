# ============================================================================
# Configuration - shared between Ubuntu and Proxmox VE (Debian family)
# Knobs shared by both Debian-family platforms. Platform config files
# (Ubuntu.sh / ProxmoxVE.sh) add the platform deltas on top of these.
# ============================================================================

## Credentials (defaults are intentional; change them after deployment)
ROOT_PASSWORD="${ROOT_PASSWORD:-R00t@123!}"
LOCK_ROOT="${LOCK_ROOT:-FALSE}" # TRUE locks the root account after deployment
NUT_ADMIN_PASSWORD="${NUT_ADMIN_PASSWORD:-123456}"
NUT_MON_PASSWORD="${NUT_MON_PASSWORD:-secret}"
SNMP_AUTH_PASS="${SNMP_AUTH_PASS:-}" # empty -> root password (warns)
SNMP_PRIV_PASS="${SNMP_PRIV_PASS:-}" # empty -> hostname (warns)

## Behavior switches
PURGE_OTHER_USERS="${PURGE_OTHER_USERS:-true}" # remove other /home users (fresh-install assumption)
RESET_DOMAIN="${RESET_DOMAIN:-false}"
RESET_HOSTNAME="${RESET_HOSTNAME:-false}"
CUSTOM_HOSTNAME="${CUSTOM_HOSTNAME:-}" # explicit hostname; overrides auto-detection and RESET_HOSTNAME
CUSTOM_DOMAIN="${CUSTOM_DOMAIN:-}" # explicit search domain(s), space-separated; overrides RESET_DOMAIN
DISABLE_ICMP_ECHO="${DISABLE_ICMP_ECHO:-false}"
PREFER_IPV4="${PREFER_IPV4:-true}"
I915_GUC_OPTION="${I915_GUC_OPTION:-3}" # 0 | 1 GuC | 2 HuC | 3 GuC/HuC
NUT_MODE="${NUT_MODE:-none}" # netclient | netserver | none | standalone
NUT_HOST="${NUT_HOST:-localhost}" # NUT server host (netclient mode)
UPS_NAME="${UPS_NAME:-ups}" # UPS device name on the NUT server

## Network
CUSTOM_DNS="${CUSTOM_DNS:-223.5.5.5 223.6.6.6 2400:3200::1 2400:3200:baba::1}" # resolvers, space-separated (AliDNS)

## Proxy / mirrors
DOCKER_REGISTRY_MIRRORS=()

## Dependency packages (apt) - Debian family base
# Architecture-neutral packages present on both platforms. Platform configs
# extend via: DEPENDENCY_PACKAGES=("${DEPENDENCY_PACKAGES_BASE[@]}" <extras>)
DEPENDENCY_PACKAGES_BASE=(
    "apparmor"
    "apparmor-profiles"
    "apparmor-profiles-extra"
    "apparmor-utils"
    "apt-file"
    "apt-transport-https"
    "busybox"
    "ca-certificates"
    "chrony"
    "curl"
    "bind9-dnsutils"
    "ethtool"
    "fail2ban"
    "fastfetch"
    "fonts-noto-cjk"
    "fonts-noto-color-emoji"
    "fwupd"
    "git"
    "git-lfs"
    "gnupg"
    "iperf3"
    "jq"
    "knot-dnsutils"
    "libsnmp-dev"
    "lldpd"
    "lm-sensors"
    "lsb-release"
    "mailutils"
    "mtr-tiny"
    "nano"
    "net-tools"
    "nmap"
    "nut"
    "nut-i2c"
    "nut-ipmi"
    "nut-modbus"
    "nut-powerman-pdu"
    "nut-snmp"
    "nut-xml"
    "openssh-client"
    "openssh-server"
    "7zip"
    "pinentry-tty"
    "postfix"
    "proxychains4" # renamed from proxychains-ng in resolute/trixie
    "python3"
    "python3-pip"
    "qrencode"
    "rar"
    "rsyslog"
    "snmp"
    "snmp-mibs-downloader"
    "snmpd"
    "sudo-rs" # rust sudo is the 26.04 / trixie direction; classic sudo.ws stays out
    "systemd"
    "systemd-zram-generator"
    "tcpdump"
    "tshark"
    "tuned"
    "udisks2"
    "udisks2-bcache"
    "udisks2-btrfs"
    "udisks2-lvm2"
    "udisks2-zram"
    "unrar"
    "unzip"
    "uuid-runtime"
    "vim"
    "virt-what"
    "wget"
    "whois"
    "zip"
    "zsh"
)
