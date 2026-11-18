# ============================================================================
# Configuration - shared across all platforms
# Common knobs shared by every generated script. Platform config files add
# platform-specific defaults on top of these. Every knob is env-overridable.
# ============================================================================

## Resume / progress
# State lives under the running user's home. AUTODEPLOY_FORCE=true re-runs all.
AUTODEPLOY_STATE_DIR="${AUTODEPLOY_STATE_DIR:-${HOME}/.autodeploy}"
AUTODEPLOY_FORCE="${AUTODEPLOY_FORCE:-false}"

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
