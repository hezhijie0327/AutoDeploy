# ============================================================================
# Configuration - macOS
# The single place to tune a deployment. Edit defaults here, or override any
# knob via environment variable before running. Runs as the operator (no root).
# ============================================================================

## Resume / progress
# State lives under the running user's home. AUTODEPLOY_FORCE=true re-runs all.
AUTODEPLOY_STATE_DIR="${AUTODEPLOY_STATE_DIR:-${HOME}/.autodeploy}"
AUTODEPLOY_FORCE="${AUTODEPLOY_FORCE:-false}"
AUTODEPLOY_STEP_TOTAL=14 # must match the RunStep count (lint.sh checks)

## Credentials
OPENSSH_PASSWORD="${OPENSSH_PASSWORD:-}"
GPG_PUBKEY="${GPG_PUBKEY:-DD982DAAB9C71C78F9563E5207EB56787030D792}"

## Identity (Git)
GIT_USER_NAME="${GIT_USER_NAME:-}"
GIT_USER_EMAIL="${GIT_USER_EMAIL:-}"
GIT_USER_SIGNINGKEY="${GIT_USER_SIGNINGKEY:-}"
GIT_COMMIT_GPGSIGN="${GIT_COMMIT_GPGSIGN:-false}"
GIT_GPG_PROGRAM="${GIT_GPG_PROGRAM:-gpg}"
GIT_HTTP_PROXY="${GIT_HTTP_PROXY:-}"
GIT_HTTPS_PROXY="${GIT_HTTPS_PROXY:-}"

## Behavior switches
REINSTALL_BREW="${REINSTALL_BREW:-false}" # true wipes and reinstalls Homebrew

## Proxy / mirrors
GHPROXY_URL="${GHPROXY_URL:-}" # GitHub proxy: bare domain or full URL (scheme optional)
PROXY_URL="${PROXY_URL:-http://vpn.zhijie.online:7890}" # zsh proxy_on helper
PROXY_PROTOCOL="${PROXY_PROTOCOL:-socks5}" # proxychains upstream
PROXY_IP="${PROXY_IP:-127.0.0.1}"
PROXY_PORT="${PROXY_PORT:-7891}"
PROXY_USERNAME="${PROXY_USERNAME:-}"
PROXY_PASSWORD="${PROXY_PASSWORD:-}"

## Zsh
ZSH_THEME="${ZSH_THEME:-ys}"
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
