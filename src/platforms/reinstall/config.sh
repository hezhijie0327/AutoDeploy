# ============================================================================
# Configuration - Reinstall (Ubuntu only)
# Knobs for the network reinstall entry script. Runs as root via sudo.
# Override any knob via environment variable before running, e.g.:
#   REINSTALL_RELEASE='26.04' REINSTALL_PASSWORD='...' curl \
#     .../dist/Reinstall.sh | sudo bash
# ============================================================================

## Resume / progress
ZJDEPLOY_STEP_TOTAL=6 # must match the RunStep count (lint.sh checks)

## Target system
# Release pinning: defaults to the latest LTS (bump each cycle). Env override
# is allowed but must be one of the LTS releases mapped in GetUbuntuCodename.
REINSTALL_RELEASE="${REINSTALL_RELEASE:-26.04}"
REINSTALL_INSTALLER_PART_SIZE_MB="${REINSTALL_INSTALLER_PART_SIZE_MB:-2048}" # staging partition for the cloud image
REINSTALL_CANCEL="${REINSTALL_CANCEL:-false}" # true = undo a staged reinstall (clears the one-time boot entry) and exit
# Boot mode of the installed system: auto follows the running host; efi/bios
# force it. Forcing efi only makes sense when the firmware supports UEFI -
# on a CSM-booted host the installer cannot write NVRAM, so the firmware
# must be switched to UEFI boot by hand after the reboot.
REINSTALL_BOOT_MODE="${REINSTALL_BOOT_MODE:-auto}"

## Installer bootstrap (Alpine netboot files run the install after reboot)
REINSTALL_CONFHOME="${REINSTALL_CONFHOME:-https://source.zhijie.online/ZJDeploy/main/src/platforms/reinstall}" # trans.sh location

## Identity of the freshly installed system
REINSTALL_PASSWORD="${REINSTALL_PASSWORD:-}" # empty -> generate one (printed) or key-only
REINSTALL_SSH_KEYS="${REINSTALL_SSH_KEYS:-}" # authorized_keys content, or a file path; empty -> reuse this host's root keys
