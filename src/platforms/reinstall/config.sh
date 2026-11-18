# ============================================================================
# Configuration - Reinstall (Ubuntu only)
# Knobs for the network reinstall entry script. Runs as root via sudo.
# Override any knob via environment variable before running, e.g.:
#   REINSTALL_RELEASE='24.04' REINSTALL_PASSWORD='...' curl \
#     .../dist/Reinstall.sh | sudo bash
# ============================================================================

## Resume / progress
AUTODEPLOY_STEP_TOTAL=6 # must match the RunStep count (lint.sh checks)

## Target system
# Release pinning: defaults to the latest LTS (bump each cycle). Env override
# is allowed but must be one of the LTS releases mapped in GetUbuntuCodename.
REINSTALL_RELEASE="${REINSTALL_RELEASE:-26.04}"
REINSTALL_INSTALLER_PART_SIZE_MB="${REINSTALL_INSTALLER_PART_SIZE_MB:-2048}" # staging partition for the cloud image

## Installer bootstrap (Alpine netboot files run the install after reboot)
REINSTALL_ALPINE_VERSION="${REINSTALL_ALPINE_VERSION:-auto}" # auto = detect newest, or pin e.g. 3.22
REINSTALL_CONFHOME="${REINSTALL_CONFHOME:-https://source.zhijie.online/AutoDeploy/main/src/platforms/reinstall}" # trans.sh location
REINSTALL_CN_MIRROR="${REINSTALL_CN_MIRROR:-true}" # false -> official upstream mirrors

## Identity of the freshly installed system
REINSTALL_PASSWORD="${REINSTALL_PASSWORD:-}" # empty -> generate one (printed) or key-only
REINSTALL_SSH_KEYS="${REINSTALL_SSH_KEYS:-}" # authorized_keys content, or a file path; empty -> reuse this host's root keys
