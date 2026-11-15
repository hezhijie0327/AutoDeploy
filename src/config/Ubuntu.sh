# ============================================================================
# Configuration - Ubuntu
# The single place to tune a deployment. Edit defaults here, or override any
# knob via environment variable before running, e.g.:
#   ROOT_PASSWORD='...' PURGE_OTHER_USERS=false curl .../Ubuntu.sh | sudo bash
# ============================================================================

## Resume / progress
# State lives under the running user's home. AUTODEPLOY_FORCE=true re-runs all.
AUTODEPLOY_STATE_DIR="${AUTODEPLOY_STATE_DIR:-${HOME}/.autodeploy}"
AUTODEPLOY_FORCE="${AUTODEPLOY_FORCE:-false}"
AUTODEPLOY_STEP_TOTAL=48 # must match the RunStep count (lint.sh checks)

## Credentials (defaults are intentional; change them after deployment)
ROOT_PASSWORD="${ROOT_PASSWORD:-R00t@123!}"
DEFAULT_PASSWORD="${DEFAULT_PASSWORD:-*Ubuntu123*}"
LOCK_ROOT="${LOCK_ROOT:-FALSE}" # TRUE locks the root account after deployment
NUT_ADMIN_PASSWORD="${NUT_ADMIN_PASSWORD:-123456}"
NUT_MON_PASSWORD="${NUT_MON_PASSWORD:-secret}"
SNMP_AUTH_PASS="${SNMP_AUTH_PASS:-}" # empty -> root password (warns)
SNMP_PRIV_PASS="${SNMP_PRIV_PASS:-}" # empty -> hostname (warns)
OPENSSH_PASSWORD="${OPENSSH_PASSWORD:-}"
GPG_PUBKEY="${GPG_PUBKEY:-DD982DAAB9C71C78F9563E5207EB56787030D792}"

## Identity
DEFAULT_USERNAME="${DEFAULT_USERNAME:-ubuntu}"
DEFAULT_FIRSTNAME="${DEFAULT_FIRSTNAME:-User}"
DEFAULT_LASTNAME="${DEFAULT_LASTNAME:-Ubuntu}"
HOSTNAME_PREFIX="${HOSTNAME_PREFIX:-Ubuntu}"
GIT_USER_NAME="${GIT_USER_NAME:-}"
GIT_USER_EMAIL="${GIT_USER_EMAIL:-}"
GIT_USER_SIGNINGKEY="${GIT_USER_SIGNINGKEY:-}"
GIT_COMMIT_GPGSIGN="${GIT_COMMIT_GPGSIGN:-false}"
GIT_GPG_PROGRAM="${GIT_GPG_PROGRAM:-gpg}"
GIT_HTTP_PROXY="${GIT_HTTP_PROXY:-}"
GIT_HTTPS_PROXY="${GIT_HTTPS_PROXY:-}"

## Behavior switches
PURGE_OTHER_USERS="${PURGE_OTHER_USERS:-true}" # remove other /home users (fresh-install assumption)
USE_GLOBAL_DNS="${USE_GLOBAL_DNS:-false}" # true -> Google DNS, false -> AliDNS
RESET_DOMAIN="${RESET_DOMAIN:-false}"
RESET_HOSTNAME="${RESET_HOSTNAME:-false}"
CUSTOM_HOSTNAME="${CUSTOM_HOSTNAME:-}" # explicit hostname; overrides auto-detection and RESET_HOSTNAME
CUSTOM_DOMAIN="${CUSTOM_DOMAIN:-}" # explicit search domain(s), space-separated; overrides RESET_DOMAIN
DISABLE_SWAP="${DISABLE_SWAP:-false}"
DISABLE_ICMP_ECHO="${DISABLE_ICMP_ECHO:-false}"
PREFER_IPV4="${PREFER_IPV4:-true}"
XANMOD_BRANCH="${XANMOD_BRANCH:-edge}" # disable | main | edge | lts | rt
I915_GUC_OPTION="${I915_GUC_OPTION:-3}" # 0 | 1 GuC | 2 HuC | 3 GuC/HuC
NUT_MODE="${NUT_MODE:-}" # netclient | netserver | none | standalone
NUT_HOST="${NUT_HOST:-}"

## Release pinning (intentionally the latest release; bump each release)
LSB_CODENAME="${LSB_CODENAME:-resolute}"
LSB_VERSION="${LSB_VERSION:-26.04}"

## Network (STATIC_*_CONFIG format: address/prefix,gateway)
NIC_NAME="${NIC_NAME:-}" # e.g. enp6s18 / ens18; empty -> auto-detect
STATIC_IPV4_CONFIG="${STATIC_IPV4_CONFIG:-}" # e.g. 10.192.31.254/19,10.192.0.1
STATIC_IPV6_CONFIG="${STATIC_IPV6_CONFIG:-}" # e.g. 2409:8a20:8800::254/64,2409:8a20:8800::1
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
ZSH_BUILD_IN_PLUGINS="${ZSH_BUILD_IN_PLUGINS:-aliases colored-man-pages command-not-found common-aliases docker docker-compose extract git history ssh sudo systemd ubuntu ufw}"

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
    "chrony"
    "cron"
    "curl"
    "dnsutils"
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
    "iputils-ping"
    "jq"
    "knot-dnsutils"
    "landscape-common"
    "libsnmp-dev"
    "lldpd"
    "lm-sensors"
    "lsb-release"
    "mailutils"
    "mtr-tiny"
    "nano"
    "netplan.io"
    "net-tools"
    "nfs-common"
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
    "p7zip-full"
    "pinentry-tty"
    "postfix"
    "proxychains-ng"
    "python3"
    "python3-pip"
    "qrencode"
    "rar"
    "realmd"
    "resolvconf"
    "rsyslog"
    "snmp"
    "snmpd"
    "snmp-mibs-downloader"
    "socat"
    "sudo"
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
    "ufw"
    "unrar"
    "unzip"
    "update-notifier-common"
    "uuid-runtime"
    "vim"
    "virt-what"
    "wget"
    "whois"
    "wireguard"
    "zip"
    "zsh"
)
