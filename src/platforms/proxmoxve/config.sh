# ============================================================================
# Configuration - Proxmox VE
# Platform additions on top of config/common.sh + config/debian.sh. Override
# any knob via environment variable before running, e.g.:
#   ROOT_PASSWORD='...' RESET_CLUSTER=false curl .../ProxmoxVE.sh | sudo bash
# ============================================================================

## Resume / progress
AUTODEPLOY_STEP_TOTAL=50 # must match the RunStep count (lint.sh checks)

## Credentials
DEFAULT_PASSWORD_DEFAULT='*Proxmox123*' # baseline for the default-password warning
DEFAULT_PASSWORD="${DEFAULT_PASSWORD:-${DEFAULT_PASSWORD_DEFAULT}}"
SNMP_USER="${SNMP_USER:-proxmox}"

## Identity
DEFAULT_USERNAME="${DEFAULT_USERNAME:-proxmox}"
DEFAULT_LASTNAME="${DEFAULT_LASTNAME:-Proxmox}"
HOSTNAME_PREFIX="${HOSTNAME_PREFIX:-ProxmoxVE}"

## Behavior switches
RESET_CLUSTER="${RESET_CLUSTER:-true}" # FALSE on clustered nodes! resets corosync state
DISABLE_DISPLAY="${DISABLE_DISPLAY:-false}" # disable efifb/vesafb (GPU passthrough)
PATCH_INTEL_82599_SFP="${PATCH_INTEL_82599_SFP:-false}" # allow unsupported SFP on ixgbe
ZFS_ARC_MAX="${ZFS_ARC_MAX:-1}" # ZFS ARC max, GiB
SSH_PORT="${SSH_PORT:-22}" # keep 22: PVE cluster nodes talk SSH to each other on port 22

## Release pinning (intentionally the latest PVE release; bump each release)
LSB_CODENAME="${LSB_CODENAME:-trixie}"
CEPH_CODENAME="${CEPH_CODENAME:-tentacle}"

## Zsh
ZSH_BUILD_IN_PLUGINS="${ZSH_BUILD_IN_PLUGINS:-aliases colored-man-pages command-not-found common-aliases debian docker docker-compose extract git history ssh sudo systemd}"

## Dependency packages (apt) - Proxmox VE additions
# The signed GRUB package differs per architecture (PVE supports amd64 and arm64).
case "$(dpkg --print-architecture 2> /dev/null || echo amd64)" in
    arm64) GRUB_SIGNED_PACKAGE="grub-efi-arm64-signed" ;;
    *) GRUB_SIGNED_PACKAGE="grub-efi-amd64-signed" ;;
esac
DEPENDENCY_PACKAGES=("${DEPENDENCY_PACKAGES_BASE[@]}"
    "ceph"
    "efibootmgr"
    "efitools"
    "efivar"
    "${GRUB_SIGNED_PACKAGE}"
    "mokutil"
    "openvswitch-switch"
    "proxmox-secure-boot-support"
    "sbsigntool"
    "shim-signed"
    "sudo-rs"
)
