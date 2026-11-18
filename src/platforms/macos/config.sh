# ============================================================================
# Configuration - macOS
# Platform additions on top of config/common.sh. Runs as the operator (no
# root). Override any knob via environment variable before running.
# ============================================================================

## Resume / progress
AUTODEPLOY_STEP_TOTAL=14 # must match the RunStep count (lint.sh checks)

## Behavior switches
REINSTALL_BREW="${REINSTALL_BREW:-false}" # true wipes and reinstalls Homebrew

## Zsh
ZSH_BUILD_IN_PLUGINS="${ZSH_BUILD_IN_PLUGINS:-aliases brew colored-man-pages command-not-found common-aliases docker docker-compose extract git history macos ssh sudo}"

## Homebrew formulae
BREW_PACKAGES=(
    "bash"
    "cloudflared"
    "coreutils"
    "curl"
    "fastfetch"
    "fd"
    "ffmpeg"
    "findutils"
    "gawk"
    "git"
    "git-lfs"
    "gnupg"
    "gnutls"
    "grep"
    "iperf3"
    "iproute2mac"
    "jq"
    "knot"
    "mailutils"
    "mas"
    "mtr"
    "nano"
    "nmap"
    "openssh"
    "p7zip"
    "pinentry"
    "proxychains-ng"
    "python3"
    "qrencode"
    "rar"
    "ripgrep"
    "tcpdump"
    "the_silver_searcher"
    "unzip"
    "vim"
    "wget"
    "whois"
    "wireguard-tools"
    "wireshark"
    "ykman"
    "youtube-dl"
    "zip"
    "zsh"
)

## Homebrew casks (installed only if InstallAppFromCask is enabled)
CASK_APPS=(
    "blackhole-16ch" # BlackHole 16ch
    "blackhole-2ch" # BlackHole 2ch
    "blackhole-64ch" # BlackHole 64ch
    "docker" # Docker
    "drawio" # Draw.io
    "iina" # IINA
    "jordanbaird-ice" # Ice
    "keka" # Keka
    "kekaexternalhelper" # Keka External Helper
    "lm-studio" # LM Studio
    "microsoft-edge" # Microsoft Edge
    "obs" # OBS
    "onyx" # OnyX
    "rectangle" # Rectangle
    "stats" # Stats
    "visual-studio-code" # Visual Studio Code
)

## Mac App Store ids (installed only if InstallAppFromMAS is enabled)
MAS_APPS=(
    "1136220934" # Infuse
    "1289583905" # Pixelmator Pro
    "1352778147" # Bitwarden
    "409222199" # Cyberduck
    "424389933" # Final Cut Pro
    "424390742" # Compressor
    "434290957" # Motion
    "451108668" # QQ
    "462054704" # Microsoft Word
    "462058435" # Microsoft Excel
    "462062816" # Microsoft PowerPoint
    "497799835" # Xcode
    "595615424" # QQ音乐
    "634148309" # Logic Pro
    "634159523" # MainStage
    "823766827" # OneDrive
    "836500024" # Wechat
    "985367838" # Microsoft Outlook
)
