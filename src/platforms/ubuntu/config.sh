# ============================================================================
# Configuration - Ubuntu
# Platform additions on top of config/common.sh + config/debian.sh. Override
# any knob via environment variable before running, e.g.:
#   ROOT_PASSWORD='...' PURGE_OTHER_USERS=false curl .../Ubuntu.sh | sudo bash
# ============================================================================

## Resume / progress
AUTODEPLOY_STEP_TOTAL=51 # must match the RunStep count (lint.sh checks)

## Credentials
DEFAULT_PASSWORD_DEFAULT='*Ubuntu123*' # baseline for the default-password warning
DEFAULT_PASSWORD="${DEFAULT_PASSWORD:-${DEFAULT_PASSWORD_DEFAULT}}"

## Identity
DEFAULT_USERNAME="${DEFAULT_USERNAME:-ubuntu}"
DEFAULT_FIRSTNAME="${DEFAULT_FIRSTNAME:-User}"
DEFAULT_LASTNAME="${DEFAULT_LASTNAME:-Ubuntu}"

## Behavior switches
DISABLE_SWAP="${DISABLE_SWAP:-false}"
XANMOD_BRANCH="${XANMOD_BRANCH:-edge}" # disable | main | edge | lts | rt; psABI v1 CPUs are forced to lts
INSTALL_CLOUDFLARE_WARP="${INSTALL_CLOUDFLARE_WARP:-false}" # install cloudflare-warp from the Cloudflare repo
INSTALL_TOR="${INSTALL_TOR:-false}" # install tor from the torproject repo
SSH_PORT="${SSH_PORT:-9022}" # sshd listen port (fail2ban jail + ufw follow this)
COCKPIT_PORT="${COCKPIT_PORT:-9090}" # cockpit web UI port (cockpit.socket override)

## Release pinning (intentionally the latest release; bump each release)
LSB_CODENAME="${LSB_CODENAME:-resolute}"
LSB_VERSION="${LSB_VERSION:-26.04}"

## Network (STATIC_*_CONFIG format: address/prefix,gateway)
NIC_NAME="${NIC_NAME:-}" # e.g. enp6s18 / ens18; empty -> auto-detect
STATIC_IPV4_CONFIG="${STATIC_IPV4_CONFIG:-}" # e.g. 10.192.31.254/19,10.192.0.1
STATIC_IPV6_CONFIG="${STATIC_IPV6_CONFIG:-}" # e.g. 2409:8a20:8800::254/64,2409:8a20:8800::1

## Zsh
ZSH_BUILD_IN_PLUGINS="${ZSH_BUILD_IN_PLUGINS:-aliases colored-man-pages command-not-found common-aliases docker docker-compose extract git history ssh sudo systemd ubuntu ufw}"

## Dependency packages (apt) - Ubuntu additions
DEPENDENCY_PACKAGES=("${DEPENDENCY_PACKAGES_BASE[@]}"
    "cockpit"
    "cron"
    "iputils-ping"
    "landscape-common"
    "netplan.io"
    "nfs-common"
    "realmd"
    "socat"
    "ufw"
    "update-notifier-common"
    "wireguard"
)
