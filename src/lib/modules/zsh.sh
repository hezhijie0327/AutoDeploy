# ============================================================================
# modules/zsh.sh - oh-my-zsh installation and .zshrc generation
# (all platforms, bash 3.2+)
# Platform must set: ZSH_PATH_LIST (array). ConfigureZsh additionally needs
# ZSH_HOME, ZSH_BUILD_IN_PLUGINS, ZSH_EXTRA_EXPORTS (array, may be empty),
# ZSH_TRAPEXIT (true/false), ZSH_OWNER (may be empty); InstallOhMyZsh needs
# OMZ_HOME, OMZ_OWNER (may be empty).
# ============================================================================

GenerateCommandPath() {
    DEFAULT_PATH=""
    local path_entry
    for path_entry in "${ZSH_PATH_LIST[@]}"; do
        DEFAULT_PATH="${path_entry}:${DEFAULT_PATH}"
    done
    DEFAULT_PATH="${DEFAULT_PATH%:}"
}

GenerateOMZProfile() {
    local proxy_url="${PROXY_URL:-http://vpn.zhijie.online:7890}"
    local no_proxy='localhost,127.0.0.1,::1'
    local external_plugins="zsh-autosuggestions zsh-completions zsh-history-substring-search zsh-syntax-highlighting"
    local omz_list=(
        "export EDITOR=\"nano\""
        "export GPG_TTY=\$(tty)"
        ${ZSH_EXTRA_EXPORTS[@]+"${ZSH_EXTRA_EXPORTS[@]}"}
        "export PATH=\"${DEFAULT_PATH}:\$PATH\""
        "export SSH_AUTH_SOCK=\"\$(gpgconf --list-dirs agent-ssh-socket)\" && gpgconf --launch gpg-agent && gpg-connect-agent updatestartuptty /bye > \"/dev/null\" 2>&1"
        "export ZSH=\"\$HOME/.oh-my-zsh\""
        "function proxy_off(){ unset all_proxy; unset ftp_proxy; unset http_proxy; unset https_proxy; unset rsync_proxy; unset no_proxy }"
        "function proxy_on(){ export all_proxy=\"${proxy_url}\"; export ftp_proxy=\"${proxy_url}\"; export http_proxy=\"${proxy_url}\"; export https_proxy=\"${proxy_url}\"; export rsync_proxy=\"${proxy_url}\"; export no_proxy=\"${no_proxy}\" }"
        "plugins=(${ZSH_BUILD_IN_PLUGINS} ${external_plugins})"
        "ZSH_CACHE_DIR=\"\$ZSH/cache\""
        "ZSH_CUSTOM=\"\$ZSH/custom\""
        "ZSH_THEME=\"${ZSH_THEME:-ys}\""
        "DISABLE_AUTO_UPDATE=\"true\""
        "DISABLE_UPDATE_PROMPT=\"true\""
        "UPDATE_ZSH_DAYS=\"7\""
        "ZSH_COMPDUMP=\"\$ZSH_CACHE_DIR/.zcompdump\""
        "ZSH_DISABLE_COMPFIX=\"false\""
        "CASE_SENSITIVE=\"true\""
        "COMPLETION_WAITING_DOTS=\"true\""
        "DISABLE_AUTO_TITLE=\"false\""
        "DISABLE_LS_COLORS=\"false\""
        "DISABLE_MAGIC_FUNCTIONS=\"true\""
        "DISABLE_UNTRACKED_FILES_DIRTY=\"false\""
        "ENABLE_CORRECTION=\"true\""
        "HIST_STAMPS=\"yyyy-mm-dd\""
        "HYPHEN_INSENSITIVE=\"false\""
        "ZSH_THEME_RANDOM_QUIET=\"true\""
        "ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE=\"bg=250,fg=238,bold,underline\""
        "ZSH_AUTOSUGGEST_STRATEGY=(match_prev_cmd history completion)"
        "ZSH_AUTOSUGGEST_USE_ASYNC=\"true\""
        "source \"\$ZSH/oh-my-zsh.sh\""
    )
    if [ "${ZSH_TRAPEXIT:-false}" = "true" ]; then
        omz_list+=('TRAPEXIT() { rm -rf ~/.zsh_history(N) ~/.ssh/known_hosts*(N) }')
    fi
    printf '%s\n' "${omz_list[@]}" > "${ZSH_HOME}/.zshrc"
    if [ -n "${ZSH_OWNER:-}" ]; then
        chown "$ZSH_OWNER" "${ZSH_HOME}/.zshrc"
    fi
}

ConfigureZsh() {
    HaveCommand zsh || return 0
    [ -d "${ZSH_HOME}/.oh-my-zsh" ] || return 0
    GenerateCommandPath
    GenerateOMZProfile
}

InstallOhMyZsh() {
    HaveCommand git || Die "git is required to install oh-my-zsh"
    local plugin_list=(
        "zsh-autosuggestions"
        "zsh-completions"
        "zsh-history-substring-search"
        "zsh-syntax-highlighting"
    )
    local omz_dir="${OMZ_HOME}/.oh-my-zsh"
    BackupPath "$omz_dir"
    git clone --depth=1 "${GHPROXY_URL:-}https://github.com/ohmyzsh/ohmyzsh.git" "$omz_dir"
    local plugin
    for plugin in "${plugin_list[@]}"; do
        git clone --depth=1 "${GHPROXY_URL:-}https://github.com/zsh-users/${plugin}.git" "${omz_dir}/custom/plugins/${plugin}"
    done
    # Single quotes are intentional: this script is generated, not expanded here.
    # shellcheck disable=SC2016
    local plugin_upgrade_list=(
        '#!/bin/bash'
        'plugin_list=($(ls "$HOME/.oh-my-zsh/custom/plugins" | grep -v "^example$"))'
        'for plugin_list_task in "${!plugin_list[@]}"; do'
        "    rm -rf \"\$HOME/.oh-my-zsh/custom/plugins/\${plugin_list[\$plugin_list_task]}\" && git clone --depth=1 \"${GHPROXY_URL:-}https://github.com/zsh-users/\${plugin_list[\$plugin_list_task]}.git\" \"\$HOME/.oh-my-zsh/custom/plugins/\${plugin_list[\$plugin_list_task]}\""
        'done'
    )
    printf '%s\n' "${plugin_upgrade_list[@]}" > "${omz_dir}/oh-my-zsh-plugin.sh"
    if [ -n "${OMZ_OWNER:-}" ]; then
        chown -R "$OMZ_OWNER" "$omz_dir"
    fi
}
