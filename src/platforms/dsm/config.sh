# ============================================================================
# Configuration - Synology DSM
# Platform additions on top of config/common.sh. Runs as root via sudo; the
# operator account is taken from SUDO_USER.
# ============================================================================

## Resume / progress
AUTODEPLOY_STEP_TOTAL=11 # must match the RunStep count (lint.sh checks)

## Package Center (third-party feeds + packages to install)
# PKG_SOURCES entries are "name|url"; they are merged into
# /usr/syno/etc/packages/feeds (existing feeds are kept, deduped by URL).
# PKG_PACKAGES are feed package ids, installed via
# `synopkg install_from_server` and left on their default autostart; list
# installed ids with `synopkg list`. The set below is what a fresh DSM needs
# for the rest of this script to be effective (git/zsh/gnuPG are required by
# the OMZ, zsh and GPG steps) plus the SynoCli suite.
PKG_SOURCES=(
    "SynoCommunity|https://packages.synocommunity.com/"
    "Kuangshen SPK|https://spk7.imnks.com/"
)
PKG_PACKAGES=(
    "git" # required by InstallOhMyZsh
    "gnupg" # required by ConfigureGPG
    "vim"
    "zsh-static" # required by ConfigureZsh / ConfigureDefaultShell
    "python314"
    "ffmpeg8"
    "synocli-file"
    "synocli-disk"
    "synocli-monitor"
    "synocli-net"
    "synocli-misc"
    "synocli-videodriver"
    "synocli-videodriver-tools"
)

## Package auto-update
# Weekly synopkg upgradeall through /etc/crontab (Sunday 04:15, right
# after the 04:05 maintenance slot). /etc/crontab is the layer DSM itself
# executes - GUI tasks only appear there as synoschedtask indirections.
PKG_AUTO_UPDATE="${PKG_AUTO_UPDATE:-true}"

## Docker (Container Manager) registry mirrors
# Empty by default: dockerd.json is left untouched (your existing mirrors
# are kept). Fill the list to have the registry-mirrors value rewritten
# declaratively - only that key changes; data-root, the DSM "db" log-driver
# and storage-driver stay untouched. The package is restarted to apply. In
# the Package Center registry settings keep the checkmark on the v2
# "Docker Hub" entry, not "Docker Hub (v1)".
DOCKER_REGISTRY_MIRRORS=()

## Zsh
ZSH_BUILD_IN_PLUGINS="${ZSH_BUILD_IN_PLUGINS:-aliases colored-man-pages command-not-found common-aliases docker docker-compose extract git history ssh sudo}"
