# ============================================================================
# Configuration - Proxmox VE
# The single place to tune a deployment. Edit defaults here, or override any
# knob via environment variable before running, e.g.:
#   ROOT_PASSWORD='...' RESET_CLUSTER=false curl .../ProxmoxVE.sh | sudo bash
# ============================================================================

## Resume / progress
# State lives under the running user's home. AUTODEPLOY_FORCE=true re-runs all.
AUTODEPLOY_STATE_DIR="${AUTODEPLOY_STATE_DIR:-${HOME}/.autodeploy}"
AUTODEPLOY_FORCE="${AUTODEPLOY_FORCE:-false}"
AUTODEPLOY_STEP_TOTAL=50 # must match the RunStep count (lint.sh checks)

## Credentials (defaults are intentional; change them after deployment)
ROOT_PASSWORD="${ROOT_PASSWORD:-R00t@123!}"
DEFAULT_PASSWORD="${DEFAULT_PASSWORD:-*Proxmox123*}"
LOCK_ROOT="${LOCK_ROOT:-FALSE}" # TRUE locks the root account after deployment
NUT_ADMIN_PASSWORD="${NUT_ADMIN_PASSWORD:-123456}"
NUT_MON_PASSWORD="${NUT_MON_PASSWORD:-secret}"
SNMP_AUTH_PASS="${SNMP_AUTH_PASS:-}" # empty -> root password (warns)
SNMP_PRIV_PASS="${SNMP_PRIV_PASS:-}" # empty -> hostname (warns)
SNMP_USER="${SNMP_USER:-proxmox}"
OPENSSH_PASSWORD="${OPENSSH_PASSWORD:-}"
GPG_PUBKEY="${GPG_PUBKEY:-DD982DAAB9C71C78F9563E5207EB56787030D792}"

## Identity
DEFAULT_USERNAME="${DEFAULT_USERNAME:-proxmox}"
DEFAULT_FIRSTNAME="${DEFAULT_FIRSTNAME:-User}"
DEFAULT_LASTNAME="${DEFAULT_LASTNAME:-Proxmox}"
HOSTNAME_PREFIX="${HOSTNAME_PREFIX:-ProxmoxVE}"
GIT_USER_NAME="${GIT_USER_NAME:-}"
GIT_USER_EMAIL="${GIT_USER_EMAIL:-}"
GIT_USER_SIGNINGKEY="${GIT_USER_SIGNINGKEY:-}"
GIT_COMMIT_GPGSIGN="${GIT_COMMIT_GPGSIGN:-false}"
GIT_GPG_PROGRAM="${GIT_GPG_PROGRAM:-gpg}"
GIT_HTTP_PROXY="${GIT_HTTP_PROXY:-}"
GIT_HTTPS_PROXY="${GIT_HTTPS_PROXY:-}"

## Behavior switches
PURGE_OTHER_USERS="${PURGE_OTHER_USERS:-true}" # remove other /home users (fresh-install assumption)
RESET_CLUSTER="${RESET_CLUSTER:-true}" # FALSE on clustered nodes! resets corosync state
USE_GLOBAL_DNS="${USE_GLOBAL_DNS:-false}" # true -> Google DNS, false -> AliDNS
RESET_DOMAIN="${RESET_DOMAIN:-false}"
RESET_HOSTNAME="${RESET_HOSTNAME:-false}"
CUSTOM_HOSTNAME="${CUSTOM_HOSTNAME:-}" # explicit hostname; overrides auto-detection and RESET_HOSTNAME
CUSTOM_DOMAIN="${CUSTOM_DOMAIN:-}" # explicit search domain(s), space-separated; overrides RESET_DOMAIN
DISABLE_ICMP_ECHO="${DISABLE_ICMP_ECHO:-false}"
PREFER_IPV4="${PREFER_IPV4:-true}"
DISABLE_DISPLAY="${DISABLE_DISPLAY:-false}" # disable efifb/vesafb (GPU passthrough)
PATCH_INTEL_82599_SFP="${PATCH_INTEL_82599_SFP:-false}" # allow unsupported SFP on ixgbe
ZFS_ARC_MAX="${ZFS_ARC_MAX:-1}" # ZFS ARC max, GiB
I915_GUC_OPTION="${I915_GUC_OPTION:-3}" # 0 | 1 GuC | 2 HuC | 3 GuC/HuC
NUT_MODE="${NUT_MODE:-}" # netclient | netserver | none | standalone
NUT_HOST="${NUT_HOST:-}"

## Release pinning (intentionally the latest PVE release; bump each release)
LSB_CODENAME="${LSB_CODENAME:-trixie}"
CEPH_CODENAME="${CEPH_CODENAME:-tentacle}"

## Network
CUSTOM_DNS_CN=(
    "223.5.5.5"
    "223.6.6.6"
    "2400:3200::1"
    "2400:3200:baba::1"
)
CUSTOM_DNS_GLOBAL=(
    "8.8.4.4"
    "8.8.8.8"
    "2001:4860:4860::8844"
    "2001:4860:4860::8888"
)

## Proxy / mirrors
GHPROXY_URL="${GHPROXY_URL:-}" # GitHub proxy: bare domain or full URL (scheme optional)
PROXY_URL="${PROXY_URL:-http://vpn.zhijie.online:7890}" # zsh proxy_on helper
PROXY_PROTOCOL="${PROXY_PROTOCOL:-socks5}" # proxychains upstream
PROXY_IP="${PROXY_IP:-127.0.0.1}"
PROXY_PORT="${PROXY_PORT:-7891}"
PROXY_USERNAME="${PROXY_USERNAME:-}"
PROXY_PASSWORD="${PROXY_PASSWORD:-}"
DOCKER_REGISTRY_MIRRORS=()

## Zsh
ZSH_THEME="${ZSH_THEME:-ys}"
ZSH_BUILD_IN_PLUGINS="${ZSH_BUILD_IN_PLUGINS:-aliases colored-man-pages command-not-found common-aliases debian docker docker-compose extract git history ssh sudo systemd}"

## Dependency packages (apt)
DEPENDENCY_PACKAGES=(
    "apparmor"
    "apparmor-profiles"
    "apparmor-profiles-extra"
    "apparmor-utils"
    "apt-file"
    "apt-transport-https"
    "busybox"
    "ca-certificates"
    "ceph"
    "chrony"
    "curl"
    "dnsutils"
    "efibootmgr"
    "efitools"
    "efivar"
    "ethtool"
    "fail2ban"
    "fastfetch"
    "fonts-noto-cjk"
    "fonts-noto-color-emoji"
    "fwupd"
    "git"
    "git-lfs"
    "gnupg"
    "grub-efi-amd64-signed"
    "iperf3"
    "jq"
    "knot-dnsutils"
    "libsnmp-dev"
    "lldpd"
    "lm-sensors"
    "lsb-release"
    "mailutils"
    "mokutil"
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
    "openvswitch-switch"
    "p7zip-full"
    "pinentry-tty"
    "postfix"
    "proxmox-secure-boot-support"
    "proxychains-ng"
    "python3"
    "python3-pip"
    "qrencode"
    "rar"
    "rsyslog"
    "sbsigntool"
    "shim-signed"
    "snmp"
    "snmp-mibs-downloader"
    "snmpd"
    "sudo"
    "sudo-rs"
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
