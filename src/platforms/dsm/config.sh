# ============================================================================
# Configuration - Synology DSM
# Platform additions on top of config/common.sh. Runs as root via sudo; the
# operator account is taken from SUDO_USER.
# ============================================================================

## Resume / progress
AUTODEPLOY_STEP_TOTAL=8 # must match the RunStep count (lint.sh checks)

## Zsh
ZSH_BUILD_IN_PLUGINS="${ZSH_BUILD_IN_PLUGINS:-aliases colored-man-pages command-not-found common-aliases docker docker-compose extract git history ssh sudo}"
