#!/bin/bash

# Current Version: 1.0.3

## How to get and use?
# /bin/bash -c "$(curl -fsSL 'https://source.zhijie.online/AutoDeploy/main/macOS.sh')"
# /bin/bash -c "$(wget -qO- 'https://source.zhijie.online/AutoDeploy/main/macOS.sh')"

## Function
# Get System Information
function GetSystemInformation() {
    function GetCurrentUsername() {
        CurrentUsername=$(whoami)
    }
    GetCurrentUsername
}
# Configure Packages
function ConfigurePackages() {
    function ConfigureCrontab() {
        crontab_list=(
            "0 0 */7 * * brew update && brew upgrade && brew cleanup && softwareupdate -ai"
        )
        which "crontab" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/tmp/crontab.tmp" && for crontab_list_task in "${!crontab_list[@]}"; do
                echo "${crontab_list[$crontab_list_task]}" >> "/tmp/crontab.tmp"
            done && sudo crontab -u "${CurrentUsername}" "/tmp/crontab.tmp" && sudo crontab -lu "${CurrentUsername}" && rm -rf "/tmp/crontab.tmp"
        fi
    }
    function ConfigureHomebrew() {
        tap_list=(
            "homebrew-cask"
            "homebrew-cask-drivers"
            "homebrew-cask-fonts"
            "homebrew-cask-versions"
        )
        for tap_list_task in "${!tap_list[@]}"; do
            rm -rf "/usr/local/Homebrew/Library/Taps/homebrew/${tap_list[$tap_list_task]}" && git clone --depth=1 "https://mirrors.tuna.tsinghua.edu.cn/git/homebrew/${tap_list[$tap_list_task]}.git" "/usr/local/Homebrew/Library/Taps/homebrew/${tap_list[$tap_list_task]}"
        done
    }
    function ConfigureZsh() {
        omz_list=(
            "export HOMEBREW_BOTTLE_DOMAIN=\"https://mirrors.tuna.tsinghua.edu.cn/homebrew-bottles\""
            "export PATH=\"/usr/local/sbin:\$PATH\""
            "export ZSH=\"\$HOME/.oh-my-zsh\""
            "plugins=(zsh-autosuggestions zsh-completions zsh-history-substring-search zsh-syntax-highlighting)"
            "ZSH_CACHE_DIR=\"\$ZSH/cache\""
            "ZSH_CUSTOM=\"\$ZSH/custom\""
            "ZSH_THEME=\"ys\""
            "DISABLE_AUTO_UPDATE=\"false\""
            "DISABLE_UPDATE_PROMPT=\"false\""
            "UPDATE_ZSH_DAYS=\"30\""
            "ZSH_COMPDUMP=\"\$ZSH_CACHE_DIR/.zcompdump\""
            "ZSH_DISABLE_COMPFIX=\"false\""
            "CASE_SENSITIVE=\"true\""
            "COMPLETION_WAITING_DOTS=\"true\""
            "DISABLE_AUTO_TITLE=\"false\""
            "DISABLE_LS_COLORS=\"false\""
            "DISABLE_MAGIC_FUNCTIONS=\"false\""
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
        which "zsh" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ] && [ -d "/usr/local/Cellar/zsh/oh-my-zsh" ]; then
            rm -rf "/tmp/omz.tmp" && for omz_list_task in "${!omz_list[@]}"; do
                echo "${omz_list[$omz_list_task]}" >> "/tmp/omz.tmp"
            done && cat "/tmp/omz.tmp" > "/usr/local/Cellar/zsh/oh-my-zsh/oh-my-zsh.zshrc" && rm -rf "/tmp/omz.tmp"
        fi
    }
    ConfigureCrontab
    ConfigureHomebrew
    ConfigureZsh
}
# Configure System
function ConfigureSystem() {
    function ConfigureHostfile() {
        host_list=(
            "127.0.0.1 localhost"
            "255.255.255.255 broadcasthost"
            "::1 ip6-localhost ip6-loopback localhost"
            "fe00::0 ip6-localnet"
            "ff00::0 ip6-mcastprefix"
            "ff02::1 ip6-allnodes"
            "ff02::2 ip6-allrouters"
            "ff02::3 ip6-allhosts"
        )
        rm -rf "/tmp/hosts.tmp" && for host_list_task in "${!host_list[@]}"; do
            echo "${host_list[$host_list_task]}" >> "/tmp/hosts.tmp"
        done && sudo cat "/tmp/hosts.tmp" > "/etc/hosts" && rm -rf "/tmp/hosts.tmp"
    }
    ConfigureHostfile
}
# Install Custom Packages
function InstallCustomPackages() {
    function InstallOhMyZsh() {
        plugin_list=(
            "zsh-autosuggestions"
            "zsh-completions"
            "zsh-history-substring-search"
            "zsh-syntax-highlighting"
        )
        rm -rf "/usr/local/Cellar/zsh/oh-my-zsh" && git clone --depth=1 "https://hub.fastgit.org/ohmyzsh/ohmyzsh.git" "/usr/local/Cellar/zsh/oh-my-zsh" && if [ "$?" -eq "1" ]; then
            git clone --depth=1 "https://github.com.cnpmjs.org/ohmyzsh/ohmyzsh.git" "/usr/local/Cellar/zsh/oh-my-zsh" && if [ "$?" -eq "1" ]; then
                git clone --depth=1 "https://github.com/ohmyzsh/ohmyzsh.git" "/usr/local/Cellar/zsh/oh-my-zsh"
            fi
        fi
        for plugin_list_task in "${!plugin_list[@]}"; do
            rm -rf "/usr/local/Cellar/zsh/oh-my-zsh/custom/plugins/${plugin_list[$plugin_list_task]}" && git clone --depth=1 "https://hub.fastgit.org/zsh-users/${plugin_list[$plugin_list_task]}.git" "/usr/local/Cellar/zsh/oh-my-zsh/custom/plugins/${plugin_list[$plugin_list_task]}" && if [ "$?" -eq "1" ]; then
                git clone --depth=1 "https://github.com.cnpmjs.org/zsh-users/${plugin_list[$plugin_list_task]}.git" "/usr/local/Cellar/zsh/oh-my-zsh/custom/plugins/${plugin_list[$plugin_list_task]}" && if [ "$?" -eq "1" ]; then
                    git clone --depth=1 "https://github.com/zsh-users/${plugin_list[$plugin_list_task]}.git" "/usr/local/Cellar/zsh/oh-my-zsh/custom/plugins/${plugin_list[$plugin_list_task]}"
                fi
            fi
        done
    }
    InstallOhMyZsh
}
# Install Dependency Packages
function InstallDependencyPackages() {
    export HOMEBREW_BOTTLE_DOMAIN="https://mirrors.tuna.tsinghua.edu.cn/homebrew-bottles"
    which "brew" > "/dev/null" 2>&1
    if [ "$?" -eq "1" ]; then
        /bin/bash -c "$(curl -fsSL 'https://cdn.jsdelivr.net/gh/Homebrew/install@master/install.sh' | sed 's/https\:\/\/github\.com\/Homebrew\/brew/https\:\/\/mirrors\.tuna\.tsinghua\.edu\.cn\/git\/homebrew\/brew\.git/g;s/https\:\/\/github\.com\/Homebrew\/homebrew\-core/https\:\/\/mirrors\.tuna\.tsinghua\.edu\.cn\/git\/homebrew\/homebrew\-core\.git/g')"
    fi && brew update && brew install bash curl git jq knot nano neofetch vim wget zsh && brew cleanup
}
# Upgrade Packages
function UpgradePackages() {
    brew update && brew upgrade && brew cleanup && softwareupdate -ai
}

## Process
# Call GetSystemInformation
GetSystemInformation
# Call InstallDependencyPackages
InstallDependencyPackages
# Call UpgradePackages
UpgradePackages
# Call InstallCustomPackages
InstallCustomPackages
# Call ConfigurePackages
ConfigurePackages
# Call ConfigureSystem
ConfigureSystem
